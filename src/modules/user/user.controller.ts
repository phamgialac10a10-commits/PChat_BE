import {  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  ParseIntPipe,
  NotFoundException,
  BadRequestException,
  UseGuards,
  Req
} from '@nestjs/common';
import { UserService } from './user.service';
import { ApiBody, ApiParam, ApiTags, ApiBearerAuth } from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';


@Controller('users')
export class UserController {
    constructor (private readonly userService: UserService) {}

    @Get()
    async getAll() {
        const users = await this.userService.findAll();
        return {
            message: 'Take list of users successfully!',
            data: users
        };
    }
    

    @ApiBearerAuth()
    @UseGuards(AuthGuard('jwt'))
    @Get('/me')
    async getById(@Req() req) {
        const userId = req.user.sub;
        const { data } = await this.userService.finProfile(userId);
        return {
            message: 'Take info of user successfully!',
            data
        }
    }
}