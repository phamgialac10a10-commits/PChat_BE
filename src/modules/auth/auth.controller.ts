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
import { AuthService } from './auth.service';

@ApiTags('Auth')
@Controller('auth')
export class AuthController{
    constructor (private readonly authService: AuthService){}
    
    @ApiBody({
      schema: {
        type: 'object',
        properties: {
          fullname: { type: 'string', example: 'Phạm Gia Lạc' },
          password: { type: 'string', example: '12345' },
          phone: { type: 'string', example: '0837773347' },
          email: { type: 'string', example: 'phamlac10@gmail.com' },
          date_of_birth: { type: 'string', example: '31/12/2005' },
          gender: { type: 'string', example: 'm' }
        },
        required: ['fullname', 'password'],
      }
    })
    @Post('/registration')
    async register (@Body() body) {
      const userData = body;
      return {
        message: 'Register successfully!',
        data: await this.authService.register(userData)
      }
    }
    
    @ApiBody({
      schema: {
        type: 'object',
        properties:{
          email: { type: 'string', example: 'phamlac10@gmail.com' },
          password: { type: 'string', example: '12345' }
        },
        required: ['email', 'password'],
      }
    })
    @Post('/login')
    async login (@Body() body: { email: string; password: string }) {
      const { email, password } = body;
      const { data, token } = await this.authService.login(email, password)
      return {
        message: 'Login successfully!',
        data,
        token
      }
    }
    

    @ApiBody({
      schema: {
        type: 'object',
        properties: {
          access_token: { type: 'string', example: '' }
        },
        required: ['access_token'],
      }
    })
    @Post('/access-token')
    async verifyAccessToken(@Body() body: { access_token: string }) {
      const { access_token } = body;
      return await this.authService.verify_access_token(access_token)
    }


    @ApiBody({
      schema: {
        type: 'object',
        properties: {
          refresh_token: { type: 'string', example: '' }
        },
        required: ['refresh_token'],
      }
    })
    @Post('/refresh-token')
    async verifyRefreshToken(@Body() body: { refresh_token: string }) {
      const { refresh_token } = body;
      return await this.authService.verify_refresh_token(refresh_token)
    }

    @Get('/logout')
    async logout() {
      const success = await this.authService.logout(1);
      return {
        message: 'Logout successfully!',

      }
    }
}