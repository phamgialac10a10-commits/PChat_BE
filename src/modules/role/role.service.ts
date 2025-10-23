import { Injectable } from "@nestjs/common";
import { DatabaseService } from "../database/database.service";
import { Role } from "../../models/roles.model";


@Injectable()
export class RoleService {
    constructor(private readonly db: DatabaseService) {}

    async findAll(): Promise<Role[]>{
        const rows = await this.db.query('select * from roles order by id asc');
        return rows;
    }

    async findById(id: number): Promise<Role | null> {
        const rows: any = await this.db.query('select * from roles where id = ?', [id])
        return rows;
    }

    async create(role: Omit<Role, 'id' | 'created_at' | 'updated_at'>){
        const result = await this.db.query(`
            insert into roles(name, description, created_at, updated_at) 
            values(?, ?, now(), now())`, [role.name, role.description]);
            const newRole = await this.findById(result.insertId);
        return newRole;    
    }

    async update(id: number, role: Partial<Role>) {
        const result = await this.db.query(
            `update roles 
             set name = ?, description = ?, updated_at = now()
             where id = ?`, [role.name, role.description, id]
        )

        const updatedRole = await this.findById(id);
        return updatedRole;
    }
}