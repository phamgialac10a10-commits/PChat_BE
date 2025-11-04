import {  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  ParseIntPipe,
  NotFoundException,
  BadRequestException,} from '@nestjs/common';
import { UserService } from './user.service';
import { ApiBody, ApiParam, ApiTags } from '@nestjs/swagger';

ApiTags('User')
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

    @Get('/:id')
    async getById(@Param('id', ParseIntPipe) id: number) {
        const user = await this.userService.findById(id);
        return {
            message: 'Take info of user successfully!',
            data: user
        }
    }
}