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
import { ApiBody, ApiParam, ApiTags } from '@nestjs/swagger';
import { RoleService } from './role.service';

@ApiTags('roles')
@Controller('roles')
export class RoleController {
  constructor(private readonly roleService: RoleService) {}

  @Put('/update/:id')
  @ApiParam({ name: 'id', type: Number, description: 'Role ID' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        name: { type: 'string', example: 'Admin' },
        description: { type: 'string', example: 'Administrator role' },
      },
      required: ['name'],
    },
  })
  @Put('/update/:id')
  async update(
    @Param('id', ParseIntPipe) id: number,
    @Body() body: { name: string; description?: string },
  ) {
    const result = await this.roleService.update(id, body);
    return {
        message: 'Role was updated successfully!',
        data: result
    }
  }
  
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        name: { type: 'string', example: 'Admin' },
        description: { type: 'string', example: 'Administrator role' },
      },
      required: ['name', 'description'],
    },
  })
  @Post('/create')
  async create(@Body() body: { name: string; description?: string }) {
    const result = await this.roleService.create(body);
    return {
      message: 'Role was created successfully',
      data: result,
    };
  }
d
  @Get()
  async getAll() {
    const roles = await this.roleService.findAll();
    return {
      message: 'Take list of roles successfully!',
      data: roles,
    };
  }

  @Get('get-role-by-id/:id')
  async getById(@Param('id', ParseIntPipe) id: number) {
    const role = await this.roleService.findById(id);

    if (!role) {
      throw new NotFoundException('Role not found!');
    }

    return {
      message: 'Take role successfully!',
      data: role,
    };
  }
}
