import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  ParseIntPipe,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { RoleService } from './role.service';

@Controller('roles')
export class RoleController {
  constructor(private readonly roleService: RoleService) {}

  @Put('/update/:id')
  async update(
    @Param('id', ParseIntPipe) id: number,
    @Body() body: { name: string; description?: string },
  ) {
    if(!id || isNaN(id)){
        throw new BadRequestException('Id không hợp lệ');
    }

    if(!body.name || body.name.trim() === ''){
        throw new BadRequestException('Tên role không được để trống');
    }

    if(!body.description || body.description.trim() === ''){
        throw new BadRequestException('Mô tả không được để trống');
    }

    const result = await this.roleService.update(id, body);
    return {
        message: 'Role was updated',
        data: result
    }
  }

  @Post('/create')
  async create(@Body() body: { name: string; description?: string }) {
    const result = await this.roleService.create(body);
    return {
      message: 'Role created successfully',
      data: result,
    };
  }

  @Get()
  async getAll() {
    const roles = await this.roleService.findAll();
    return {
      message: 'Lấy danh sách roles thành công',
      data: roles,
    };
  }

  @Get('get-role-by/:id')
  async getById(@Param('id', ParseIntPipe) id: number) {
    const role = await this.roleService.findById(id);

    if (!role) {
      throw new NotFoundException('Không tìm thấy role');
    }

    return {
      message: 'Lấy role thành công',
      data: role,
    };
  }
}
