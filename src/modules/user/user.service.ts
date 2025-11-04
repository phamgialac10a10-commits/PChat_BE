import { Injectable } from '@nestjs/common';
import { DatabaseService } from '../database/database.service';
import { User } from 'src/models/users.model';
import { access } from 'fs';

@Injectable()
export class UserService {
  constructor(private readonly db: DatabaseService) {}

  async findAll(): Promise<User[]> {
    const rows = await this.db.query('select id, fullname, phone, email, date_of_birth, is_active, created_at from users');
    return rows;
  }

  async findById(userId: number): Promise<User> {
    const user = await this.db.query(
      `
      select u.id, u.fullname, u.email, u.phone, u.date_of_birth, u.is_active, u.gender, r.name as role
      from users u inner join roles r on u.role_id = r.id 
      where u.id = ?`,
      [userId],
    );

    return user;
  }

  async findLoginUser(userId: number): Promise<{ data: any, token: any }> {
    const user = await this.db.query(`select * from users where id = ? and access_token is not null`, [userId]);

    return {
      data: {
        id: user[0].id,
        fullname: user[0].fullname,
        gender: user[0].gender
      },
      token: {
        access_token: user[0].access_token,
        access_expires_at: user[0].access_expires_at,
        refresh_token: user[0].refresh_token,
        refresh_expires_at: user[0].refresh_expires_at
      }
    }
  }
}
