import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  ParseIntPipe,
} from '@nestjs/common';
import { ApiBody, ApiParam, ApiTags } from '@nestjs/swagger';
import { RoleService } from './role.service';

@ApiTags('Roles')
@Controller('roles')
export class RoleController {
  constructor(private readonly roleService: RoleService) {}

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
  @Put('/:id')
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
  @Post()
  async create(@Body() body: { name: string; description?: string }) {
    const result = await this.roleService.create(body);
    return {
      message: 'Role was created successfully',
      data: result,
    };
  }

  @Get()
  async getAll() {
    const { data, total } = await this.roleService.findAll();

    return {
      message: 'Take list of roles successfully!',
      data,
      total
    };
  }

  @Get('/:id')
  async getById(@Param('id', ParseIntPipe) id: number) {
    const role = await this.roleService.findById(id);

    return {
      message: 'Take info of role successfully!',
      data: role,
    };
  }
}
