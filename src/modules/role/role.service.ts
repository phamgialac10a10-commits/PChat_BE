import { Injectable, NotFoundException, BadRequestException, InternalServerErrorException} from '@nestjs/common';
import { DatabaseService } from '../database/database.service';
import { Role } from '../../models/roles.model';

@Injectable()
export class RoleService {
  constructor(private readonly db: DatabaseService) { }

  async findAll(): Promise<{ data: Role[]; total: number }> {
    const rows = await this.db.query('select * from roles');

    const countRows = await this.db.query('select count(*) as count from roles');

    return {
      data: rows,
      total: countRows[0].count
    };
  }

  async findById(id: number): Promise<Role | null> {
    const rows: any = await this.db.query('select * from roles where id = ?', [
      id,
    ]);
    
    if (!rows[0]) {
      throw new NotFoundException('Role not found!');
    }

    return rows;
  }

  async create(role: Omit<Role, 'id' | 'created_at' | 'updated_at'>) {

    if (!role.name || role.name.trim() === '') {
      throw new BadRequestException(`Role's name must not be empty!`);
    }

    if (!role.description || role.description.trim() === '') {
      throw new BadRequestException(`Role's description must not be empty!`);
    }

    try {
      const result = await this.db.query(
        `
            insert into roles(name, description, created_at, updated_at) 
            values(?, ?, now(), now())`,
        [role.name, role.description],
      );

      return await this.findById(result.insertId);
    } catch (error: any) {
      if (error.code === 'ER_DUP_ENTRY') {
        throw new BadRequestException(`Role name "${role.name}" already exists!`);
      }
      throw new InternalServerErrorException(error.message);
    }
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
    
    try {
      await this.db.query(
        `update roles 
         set name = ?, description = ?, updated_at = now()
         where id = ?`,
        [role.name, role.description, id],
      );
  
      return await this.findById(id);;
    } catch (error: any) {
      if (error.code === 'ER_DUP_ENTRY') {
        throw new BadRequestException(`Role name "${role.name}" already exists!`);
      }
      throw new InternalServerErrorException(error.message);
    }

  }
}
