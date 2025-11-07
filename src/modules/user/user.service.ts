import { Injectable, NotFoundException } from '@nestjs/common';
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

  async findById(userId: number): Promise<{ data: any, token: any }> {
    const user = await this.db.query(
      `
      select u.id, u.fullname, u.email, u.phone, u.date_of_birth, u.is_active, u.gender, r.id as role_id, r.name as role, u.created_at, u.updated_at, u.access_token, u.access_expires_at, u.refresh_token, u.refresh_expires_at
      from users u inner join roles r on u.role_id = r.id 
      where u.id = ?`,
      [userId],
    );

    if(!user || user.length === 0) {
      throw new NotFoundException('User not found!');
    }

    return {
      data: {
        id: user[0].id,
        fullname: user[0].fullname,
        email: user[0].email,
        phone: user[0].phone,
        date_of_birth: user[0].date_of_birth,
        is_active: user[0].is_active,
        role_id: user[0].role_id,
        role: user[0].role,
        gender: user[0].gender,
        created_at: user[0].created_at,
        updated_at: user[0].updated_at,
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
