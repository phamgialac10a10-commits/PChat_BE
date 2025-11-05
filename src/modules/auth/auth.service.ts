import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { JwtModule, JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UserService } from '../user/user.service';
import { RoleService } from '../role/role.service';
import { DatabaseService } from '../database/database.service';
import { ConfigService } from '@nestjs/config';
import { User } from '../../models/users.model';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly roleService: RoleService,
    private readonly jwtService: JwtService,
    private readonly config: ConfigService,
    private readonly db: DatabaseService,
  ) {}

  async register(userData: {
    fullname: string;
    password: string;
    phone: string;
    email: string;
    date_of_birth: string;
    gender: string;
  }) {
    if (!userData.email) {
      throw new BadRequestException('Email must not be empty!');
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(userData.email)) {
      throw new BadRequestException('Invalid email format!');
    }

    const exists: any = await this.db.query(
      `select email from users where email = ?`,
      [userData.email],
    );

    if (exists.length > 0) {
      throw new BadRequestException('Email đã tồn tại!');
    }

    if (!userData.fullname || userData.fullname.length <= 5) {
      throw new BadRequestException(
        'Fullname must be larger than 5 characters!',
      );
    }

    if (!userData.phone) {
      throw new BadRequestException('Phone must not be empty!');
    }

    const hash = await bcrypt.hash(userData.password, 10);

    const role: any = await this.db.query(
      `select id from roles where lower(name) = 'user'`,
    );

    if (!role[0].id) {
      throw new InternalServerErrorException('Server error!');
    }

    const newUser: any = await this.db.query(
      `
        insert into users (fullname, password, phone, email, date_of_birth, gender, role_id)
        values (?, ?, ?, ?, STR_TO_DATE(?, '%d/%m/%Y'), ?, ?)`,
      [
        userData.fullname,
        hash,
        userData.phone,
        userData.email,
        userData.date_of_birth,
        userData.gender,
        role[0].id,
      ],
    );

    const insertedId = newUser.insertId;

    return {
      newUser: await this.userService.findById(insertedId),
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

    const access_token = this.jwtService.sign(
      { sub: user.id, email: user.email, role_id: user.role_id },
      { secret: this.config.get('JWT_SECRET'), expiresIn: '15m' },
    );

    const refresh_token = this.jwtService.sign(
      { sub: user.id },
      { secret: this.config.get('JWT_REFRESH_SECRET'), expiresIn: '7d' },
    );

    await this.db.query(
      `
      update users
      set access_token = ?, refresh_token = ?,
      access_expires_at = DATE_ADD(NOW(), INTERVAL 15 MINUTE),
      refresh_expires_at = DATE_ADD(NOW(), INTERVAL 7 DAY)
      where id = ?`,
      [access_token, refresh_token, user.id],
    );

    return await this.userService.findLoginUser(user.id);
  }

  async logout(userId: number) {
    const result = await this.db.query(
      `
       update users 
       set access_token = null, refresh_token = null, access_expires_at = null, refresh_expires_at = null 
       where id = ?`,
      [userId],
    );

    const success = result.affectedRows > 0;

    if (!success) {
      throw new NotFoundException(`User with id ${userId} not found!`);
    }

    return success;
  }

  async getToken(userId: number, email:string, roleId: number) {
    if(!userId) {
      throw new BadRequestException('Error geting token!');
    }

    if(!email) {
      throw new BadRequestException('Error geting token!');
    }

    if(!roleId) {
      throw new BadRequestException('Error geting token!');
    }

    const access_token = this.jwtService.sign(
      { sub: userId, email: email, role_id: roleId },
      { secret: this.config.get('JWT_SECRET'), expiresIn: '15m' },
    );

    await this.db.query(
      `
      update users
      set access_token = ?,
      access_expires_at = DATE_ADD(NOW(), INTERVAL 15 MINUTE),
      where id = ?`,
      [access_token, userId],
    );

    return access_token;
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
