import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
  UnprocessableEntityException,
  InternalServerErrorException,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { JwtModule, JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UserService } from '../user/user.service';
import { RoleService } from '../role/role.service';
import { RedisService } from '../redis/redis.service';
import { DatabaseService } from '../database/database.service';
import { ConfigService } from '@nestjs/config';
import { generateOTP } from 'src/common/auth.util';
import axios from 'axios';
import { rmSync } from 'fs';
('../../common/auth.util');

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly redisService: RedisService,
    private readonly roleService: RoleService,
    private readonly jwtService: JwtService,
    private readonly config: ConfigService,
    private readonly db: DatabaseService,
  ) {}

  async registerRequest(userData: {
    fullname: string;
    password: string;
    phone: string;
    email: string;
    date_of_birth: string;
    gender: string;
  }) {
    if (!userData.email) {
      throw new UnprocessableEntityException('Email must not be empty!');
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(userData.email)) {
      throw new UnprocessableEntityException('Invalid email format!');
    }

    const exists: any = await this.db.query(
      `select email from users where email = ?`,
      [userData.email],
    );

    if (exists.length > 0) {
      throw new BadRequestException('Email đã tồn tại!');
    }

    if (!userData.fullname || userData.fullname.length <= 5) {
      throw new UnprocessableEntityException(
        'Fullname must be larger than 5 characters!',
      );
    }

    if (!userData.phone) {
      throw new UnprocessableEntityException('Phone must not be empty!');
    }

    const hash = await bcrypt.hash(userData.password, 10);

    const role: any = await this.db.query(
      `select id from roles where lower(name) = 'user'`,
    );

    if (!role[0].id) {
      throw new InternalServerErrorException('Server error!');
    }

    // Store pending user in Redis instead of database
    const pendingUserData = {
      fullname: userData.fullname,
      password: hash,
      phone: userData.phone,
      email: userData.email,
      date_of_birth: userData.date_of_birth,
      gender: userData.gender,
      role_id: role[0].id,
    };

    const redisKey = `pending_user:${userData.email}`;
    await this.redisService.set(
      redisKey,
      JSON.stringify(pendingUserData),
      600, // 10 minutes TTL
    );

    let OTPexisted = true;
    let count = 0;
    let otp: any = null;
    while (OTPexisted && count < 3) {
      otp = await generateOTP();

      const existingOTP = await this.redisService.get(
        `otp:${otp}:verify:gmail`,
      );

      if (!existingOTP) {
        OTPexisted = false;
      }

      count++;
    }

    if (!otp) {
      throw new InternalServerErrorException('Error generating OTP!');
    }

    // Store OTP in Redis with 2 minutes TTL
    const otpRedisKey = `otp:${otp}:verify:gmail`;
    const otpData = JSON.stringify({
      status: 'pending',
      channel: 'gmail',
      type: 'verify',
      code: otp,
      user_identifier: userData.email,
      otp_used: 0,
    });
    await this.redisService.set(otpRedisKey, otpData, 120); // 2 minutes TTL

    await this.sendVerifyMail(
      userData.email,
      userData.fullname,
      String(otp),
      'gmail',
      'verify',
    );
  }

  async register(otp: string) {
    const existedOTP = await this.verifyValidOTP(otp, 'verify', 'gmail');
    
    if(!existedOTP) {
      throw new InternalServerErrorException('Server error.');
    }

    // Get pending user from Redis
    const redisKey = `pending_user:${existedOTP.user_identifier}`;
    const pendingUserJson = await this.redisService.get(redisKey);

    if (!pendingUserJson) {
      throw new BadRequestException(`User didn't registered yet!`);
    }

    const pendingUser = JSON.parse(pendingUserJson);

    // Convert date from DD/MM/YYYY to YYYY-MM-DD
    const [day, month, year] = pendingUser.date_of_birth.split('/');
    const formattedDate = `${year}-${month}-${day}`;

    const newUser: any = await this.db.query(
      `
      insert into users(fullname, email, phone, date_of_birth, password, gender, role_id) VALUES(?, ?, ?, ?, ?, ?, ?)`,
      [
        pendingUser.fullname,
        pendingUser.email,
        pendingUser.phone,
        formattedDate,
        pendingUser.password,
        pendingUser.gender,
        pendingUser.role_id,
      ],
    );

    const insertedId = newUser.insertId;

    if (!insertedId) {
      throw new InternalServerErrorException('Registration failed!');
    }

    const getToken = await this.getTokens(
      insertedId,
      pendingUser.email,
      pendingUser.role_id,
    );

    // Delete pending user from Redis
    await this.redisService.del(redisKey);

    const hashedRt = await bcrypt.hash(getToken.refresh_token, 10);

    await this.db.query(
      `
      update users 
      set refresh_token = ?,
          refresh_expires_at = DATE_ADD(NOW(), INTERVAL 7 DAY)
      where id = ?`,
      [hashedRt, insertedId],
    );

    const result = await this.userService.findById(insertedId);

    return {
      data: result.data,
      token: getToken,
    };
  }

  async setNewPasswordRequest(
    userId: number,
    password: string,
    confirmPassword: string
  ) {
    const users = await this.userService.findById(userId);
    
    console.log(users.data.email);

    if (!users) {
      throw new BadRequestException('This user does not exist.');
    }

    if (
      !(password || password.toString().trim()) &&
      !(confirmPassword || confirmPassword.toString().trim())
    ) {
      throw new BadRequestException(
        'Please fill with password and confirm password',
      );
    }

    if (!(password.toString().trim() === confirmPassword.toString().trim())) {
      throw new BadRequestException(
        'Password must match with confirm password',
      );
    }

    const hashedPassword: any = await bcrypt.hash(password, 10);

    // Store pending password in Redis instead of database
    const pendingPasswordKey = `pending_password:${users.data.email}`;
    await this.redisService.set(
      pendingPasswordKey,
      JSON.stringify({
        email: users.data.email,
        password: hashedPassword,
      }),
      600, // 10 minutes TTL
    );

    let OTPexisted = true;
    let count = 0;
    let otp: any = null;
    while (OTPexisted && count < 3) {
      otp = await generateOTP();

      const existingOTP = await this.redisService.get(
        `otp:${otp}:reset password:email`,
      );

      if (!existingOTP) {
        OTPexisted = false;
      }

      count++;
    }

    if (!otp) {
      throw new InternalServerErrorException('Error generating OTP!');
    }

    // Store OTP in Redis with 2 minutes TTL
    const otpRedisKey = `otp:${otp}:reset password:email`;
    const otpData = JSON.stringify({
      status: 'pending',
      channel: 'email',
      type: 'reset password',
      code: otp,
      user_identifier: users.data.email,
      otp_used: 0,
    });
    await this.redisService.set(otpRedisKey, otpData, 120); // 2 minutes TTL

    await this.sendVerifyMail(
      users.data.email,
      users.data.fullname,
      String(otp),
      'email',
      'reset password',
    );
  }

  async setNewPassword(
    otp: string,
  ) {
    const validOTP = await this.verifyValidOTP(otp, 'reset password', 'email');

    if (!validOTP) {
      throw new InternalServerErrorException('Fail to reset password!');
    }

    // Get pending password from Redis
    const pendingPasswordKey = `pending_password:${validOTP.user_identifier}`;
    const pendingPasswordJson = await this.redisService.get(pendingPasswordKey);

    if (!pendingPasswordJson) {
      throw new BadRequestException('This password request is invalid or expired');
    }

    const pendingPasswordData = JSON.parse(pendingPasswordJson);

    const newPassword = await this.db.query(`
      update users
      set password = ?
      where email = ?`,
      [pendingPasswordData.password, pendingPasswordData.email]);

    if (newPassword.affectedRows === 0) {
      throw new InternalServerErrorException('Error setting new password');
    }

    // Delete pending password from Redis
    await this.redisService.del(pendingPasswordKey);

    return {
      success: true,
    };
  }

  async login(email: string, password: string) {
    const rows = await this.db.query(
      'select id, email, password, role_id from users where email = ?',
      [email],
    );
    const user = rows[0];

    if (!user) {
      throw new UnauthorizedException('Email or password is wrong!');
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      throw new UnauthorizedException('Email or password is wrong!');
    }

    const getToken = await this.getTokens(user.id, user.email, user.role_id);

    if (!getToken) {
      throw new InternalServerErrorException('Error getting token!');
    }

    const hashedRt = await bcrypt.hash(getToken.refresh_token, 10);

    await this.db.query(
      `
      update users
      set refresh_token = ?,
          refresh_expires_at = DATE_ADD(NOW(), INTERVAL 7 DAY)
      where id = ?    
      `,
      [hashedRt, user.id],
    );

    const result = await this.userService.findById(user.id);

    return {
      data: result.data,
      token: getToken,
    };
  }

  async googleLogin(req) {
    if (!req.user) {
      return 'No user from google';
    }

    // console.log(req.user);

    let existedUser: any = null;

    let insertedId: any = null;

    try {
      const row: any = await this.userService.findyEmail(req.user.email);
      existedUser = row;
    } catch (err: any) {}

    if (!existedUser) {
      const role: any = await this.db.query(
        `select id from roles where lower(name) = 'user'`,
      );

      if (!role[0].id) {
        throw new InternalServerErrorException('Server error!');
      }

      const result = await this.db.query(
        `
        insert into users (fullname, phone, email, role_id, avatar)
        values(?, ?, ?, ?, ?)`,
        [
          req.user.displayName,
          '',
          req.user.email,
          role[0].id,
          req.user.picture,
        ],
      );

      insertedId = result.insertId;

      if (!insertedId) {
        throw new InternalServerErrorException('Server error!');
      }
    } else {
      insertedId = existedUser.data.id;
    }

    const { data } = await this.userService.findById(insertedId);

    const getToken = await this.getTokens(insertedId, data.email, data.role_id);

    const hashedRt = await bcrypt.hash(getToken.refresh_token, 10);

    await this.db.query(
      `
      update users
      set refresh_token = ?,
          refresh_expires_at = DATE_ADD(NOW(), INTERVAL 7 DAY)
      where id = ?    
      `,
      [hashedRt, insertedId],
    );

    return {
      data,
      token: getToken,
    };
  }

  async refreshToken(userId: number, refreshToken: string) {
    const user = await this.userService.findById(userId);

    if (!user || !user.token.refresh_token) {
      throw new ForbiddenException('Access denied');
    }

    const rMatch = await bcrypt.compare(refreshToken, user.token.refresh_token);

    if (!rMatch) {
      throw new ForbiddenException('Invalid refresh token');
    }

    const access_token = this.jwtService.sign(
      { sub: userId, email: user.data.email, role_id: user.data.role_id },
      { secret: this.config.get('JWT_SECRET'), expiresIn: '15m' },
    );

    return {
      access_token: access_token,
    };
  }

  async logout(userId: number) {
    const result = await this.db.query(
      `
       update users 
       set refresh_token = null, refresh_expires_at = null 
       where id = ?`,
      [userId],
    );

    const success = result.affectedRows > 0;

    if (!success) {
      throw new NotFoundException(`User with id ${userId} not found!`);
    }

    return success;
  }

  async sendVerifyMail(
    email: string,
    fullname: string,
    otp: string,
    channel: string,
    type: string,
  ) {
    if (!email) {
      throw new BadRequestException('Email is empty');
    }

    await this.db.query(
      `
      insert into verification_codes(status, channel, type, code, user_identifier, otp_used, expires_at)
      values(?, ?, ?, ?, ?, ?, NOW() + INTERVAL 2 MINUTE)`,
      ['pending', channel, type, otp, email, 0],
    );

    const response = await axios.post(
      `${process.env.BREVO_SMTP_URL || 'https://api.brevo.com/v3/smtp'}/email`,
      {
        sender: {
          name: 'PChat Verification',
          email: 'phamlac10@gmail.com',
        },
        to: [
          {
            email,
            name: fullname,
          },
        ],
        subject: 'OTP to verify your account',
        htmlContent: `
          <div style="font-family: Arial, sans-serif; color: #333;">
            <h2>Hello ${fullname},</h2>
            <p>This is your OTP:</p>
            <h1 style="color:#1976d2; letter-spacing:4px; font-weight:bold">${otp}</h1>
            <hr />
            <p style="font-size:12px; color:#777;">If you didn't request this OTP. Please skip this.</p>
          </div>
        `,
        textContent: `OTP verification`,
      },
      {
        headers: {
          'api-key': process.env.BREVO_API_KEY || '',
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
      },
    );

    // console.log(response.data);

    return response;
  }

  async verifyValidOTP(otp: string, type: string, channel: string) {
    if (!otp || otp.toString().trim() === '') {
      throw new BadRequestException('OTP is not valid!');
    }

    // Check OTP from Redis
    const otpRedisKey = `otp:${otp}:${type}:${channel}`;
    const existedOTPJson = await this.redisService.get(otpRedisKey);

    if (!existedOTPJson) {
      throw new BadRequestException('OTP is not valid or expired!');
    }

    const existedOTP = JSON.parse(existedOTPJson);

    if (existedOTP.otp_used === 1 || existedOTP.status !== 'pending') {
      throw new BadRequestException('OTP is not valid or expired!');
    }

    if (!existedOTP.user_identifier) {
      throw new BadRequestException('Email is not valid!');
    }

    // Update OTP status in Redis
    const verifiedOtpData = JSON.stringify({
      ...existedOTP,
      otp_used: 1,
      status: 'verified',
    });
    await this.redisService.set(otpRedisKey, verifiedOtpData, 120); // Keep for 2 more minutes

    return existedOTP;
  }

  async getTokens(userId: number, email: string, roleId: number) {
    if (!userId) {
      throw new BadRequestException('Error geting token!');
    }

    if (!email) {
      throw new BadRequestException('Error geting token!');
    }

    if (!roleId) {
      throw new BadRequestException('Error geting token!');
    }

    const access_token = this.jwtService.sign(
      { sub: userId, email: email, role_id: roleId },
      { secret: this.config.get('JWT_SECRET'), expiresIn: '15m' },
    );

    const refresh_token = this.jwtService.sign(
      { sub: userId },
      { secret: this.config.get('JWT_REFRESH_SECRET'), expiresIn: '7d' },
    );

    return {
      access_token,
      refresh_token,
    };
  }

  async verify_access_token(token: string) {
    try {
      const payload = await this.jwtService.verifyAsync(token, {
        secret: this.config.get<string>('JWT_SECRET'),
      });

      return {
        valid: true,
        payload,
      };
    } catch (error: any) {
      throw new UnauthorizedException('Invalid or expired access token');
    }
  }

  async verify_refresh_token(token: string) {
    try {
      const payload = await this.jwtService.verifyAsync(token, {
        secret: this.config.get<string>('JWT_REFRESH_SECRET'),
      });

      return {
        valid: true,
        payload,
      };
    } catch (error: any) {
      throw new UnauthorizedException('Invalid or expired refresh_token');
    }
  }
}
