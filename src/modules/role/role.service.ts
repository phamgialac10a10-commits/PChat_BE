import { Injectable, NotFoundException, BadRequestException, } from '@nestjs/common';
import { DatabaseService } from '../database/database.service';
import { Role } from '../../models/roles.model';

@Injectable()
export class RoleService {
  constructor(private readonly db: DatabaseService) {}

  async findAll(): Promise<Role[]> {
    const rows = await this.db.query('select * from roles order by id asc');
    return rows;
  }

  async findById(id: number): Promise<Role | null> {
    const rows: any = await this.db.query('select * from roles where id = ?', [
      id,
    ]);
    return rows;
  }

  async create(role: Omit<Role, 'id' | 'created_at' | 'updated_at'>) {
    const result = await this.db.query(
      `
            insert into roles(name, description, created_at, updated_at) 
            values(?, ?, now(), now())`,
      [role.name, role.description],
    );
    const newRole = await this.findById(result.insertId);
    return newRole;
  }

  async update(id: number, role: Partial<Role>) {

    if (!id || isNaN(id)) {
      throw new BadRequestException(`Invalid role's Id!`);
    }

    if (!role.name || role.name.trim() === '') {
      throw new BadRequestException(`Role's name must not be empty!`);
    }

    if (!role.description || role.description.trim() === '') {
      throw new BadRequestException(`Role's description must not be empty!`);
    }

    await this.db.query(
      `update roles 
       set name = ?, description = ?, updated_at = now()
       where id = ?`,
      [role.name, role.description, id],
    );

    const updatedRole = await this.findById(id);
    return updatedRole;
  }
}
