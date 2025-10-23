import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { MongoConfig } from './config/mongo.config';
import { createMySQLConnection } from './config/mysql.config';

@Module({
  imports: [
    // ✅ Đọc file .env toàn cục
    ConfigModule.forRoot({ isGlobal: true }),

    // ✅ Kết nối MongoDB
    MongoConfig,
  ],

  controllers: [AppController],
  providers: [
    AppService,

    // ✅ Provider MySQL
    {
      provide: 'MYSQL_CONNECTION',
      inject: [ConfigService],
      useFactory: async (config: ConfigService) => {
        const pool = await createMySQLConnection(config);
        return pool;
      },
    },
  ],
})
export class AppModule {}