import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createMySQLConnection } from '../../config/mysql.config';
import { Pool } from 'mysql2/promise';

@Injectable()
export class DatabaseService implements OnModuleInit, OnModuleDestroy {
  private pool: Pool;

  constructor(private readonly configService: ConfigService) {}

  async onModuleInit() {
    this.pool = await createMySQLConnection(this.configService);
  }

  async query(sql: string, params?: any[]): Promise<any> {
    if (!this.pool) throw new Error('❌ Database not initialized!');
    const [rows] = await this.pool.query(sql, params);
    return rows;
  }

  getPool(): Pool {
    return this.pool;
  }

  async onModuleDestroy() {
    if (this.pool) {
      await this.pool.end();
      console.log('🧹 MySQL connection closed.');
    }
  }
}
