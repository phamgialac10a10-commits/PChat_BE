import { Injectable } from '@nestjs/common';
import { DatabaseService } from '../database/database.service';
import { User } from 'src/models/users.model';

@Injectable()
export class UserService {
  constructor(private readonly db: DatabaseService) {}

  async findAll(): Promise<User[]> {
    const rows = await this.db.query('select * from users');
    return rows;
  }

  async findById(userId: number): Promise<User> {
    const user = await this.db.query(
      `
      select u.id, u.fullname, u.email, u.phone, u.date_of_birth, u.is_active, u.gender, r.name as role
      from users u inner join roles r 
      where u.id = ?`,
      [userId],
    );

    return user;
  }
}
