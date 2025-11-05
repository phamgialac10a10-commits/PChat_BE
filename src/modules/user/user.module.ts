import { Module } from '@nestjs/common';
import { UserService } from "./user.service";
import { UserController } from "./user.controller";
import { DatabaseModule } from "../database/database.module";
import { ConfigModule } from '@nestjs/config';
import { JwtStrategy } from '../auth/jwt.strategy';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';

@Module({
    imports: [
        DatabaseModule,
        PassportModule.register({ defaultStrategy: 'jwt' })
    ],
    controllers: [UserController],
    providers: [UserService, JwtStrategy],
    exports: [UserService],
})

export class UserModule {}
