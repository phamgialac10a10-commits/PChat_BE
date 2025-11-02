import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
  InternalServerErrorException
} from '@nestjs/common';
import { JwtModule, JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UserService } from '../user/user.service';
import { RoleService } from '../role/role.service';
import { DatabaseService } from '../database/database.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly roleService: RoleService,
    private readonly jwtService: JwtService,
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

    const [exists]: any = await this.db.query(
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

    const role: any = await this.db.query(`select id from roles where lower(name) = 'user'`);

     if (!role.id) {
        throw new InternalServerErrorException('Server error!');
     }

    const newUser: any = await this.db.query(
      `
        insert into users (fullname, password, phone, email, date_of_birth, gender, role_id)
        values (?, ?, ?, ?, ?)`,
      [
        userData.fullname,
        hash,
        userData.phone,
        userData.email,
        userData.date_of_birth,
        userData.gender,
        role.id
      ],
    );

    const insertedId = newUser.insertedId;

    return {
      newUser: this.userService.findById(insertedId),
    };
  }

  async login(username: string, password: string) {}

  async logout(userId: number) {
    await this.db.query(
      `
       update users 
       set access_token = null, refresh_token = null, access_expires_at = null, refresh_expires_at = null 
       where id = ?`,
      [userId],
    );
    return true;
  }
}
