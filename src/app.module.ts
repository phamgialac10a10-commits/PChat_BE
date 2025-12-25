import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { MongoConfig } from './config/mongo.config';
import { AppModules } from './modules/index';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    MongoConfig,
    ...AppModules
  ],

  controllers: [AppController],
  providers: [
    AppService,
  ],
})
export class AppModule {}