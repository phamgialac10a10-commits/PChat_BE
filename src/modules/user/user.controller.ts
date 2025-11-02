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

@Controller()
export class UserController {
    constructor (private readonly userService: UserService) {}

    @Get()
    async getAll() {
        const users = await this.userService.findAll();
        return {
            message: 'Lấy danh sách users thành công',
            data: users
        };
    }
}