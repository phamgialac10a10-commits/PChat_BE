import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
  UnprocessableEntityException,
  InternalServerErrorException,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { JwtModule, JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UserService } from '../user/user.service';

@Injectable()
export class FriendshipService{
    constructor(private readonly userService: UserService){}

    async listPendingFriend() {
        
    }
}