import { ConfigService } from '@nestjs/config';
import * as mysql from 'mysql2/promise';

export async function createMySQLConnection(config: ConfigService) {
  const pool = await mysql.createPool({
    host: config.get<string>('MYSQL_HOST'),
    user: config.get<string>('MYSQL_USER'),
    password: config.get<string>('MYSQL_PASSWORD'),
    database: config.get<string>('MYSQL_DATABASE'),
    waitForConnections: true,
    // connectionLimit: 10,
  });
  console.log(`✅ MySQL connected: ${config.get('MYSQL_DATABASE')}`);
  return pool;
}

