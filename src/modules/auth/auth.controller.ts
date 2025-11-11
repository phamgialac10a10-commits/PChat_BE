import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  ParseIntPipe,
  UseGuards,
  Req,
} from '@nestjs/common';
import { ApiBody, ApiParam, ApiTags, ApiBearerAuth, ApiOperation } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { AuthGuard } from '@nestjs/passport';
@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        fullname: { type: 'string', example: 'Phạm Gia Lạc' },
        password: { type: 'string', example: '12345' },
        phone: { type: 'string', example: '0837773347' },
        email: { type: 'string', example: 'phamlac10@gmail.com' },
        date_of_birth: { type: 'string', example: '31/12/2005' },
        gender: { type: 'string', example: 'm' },
      },
      required: ['fullname', 'password'],
    },
  })
  @Post('/registration')
  async register(@Body() body) {
    const userData = body;
    // const { data, token } = await this.authService.register(userData)
    const result = await this.authService.registerRequest(userData);
    return {
      message: 'Send OTP successfully!',
      result,
    };
  }

  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        otp: { type: 'string', example: '123456' },
      },
      required: ['otp'],
    },
  })
  @Post('/verified-otp-registration')
  async verifiedRegistrartion(@Body() body) {
    const { otp } = body;

    const result = await this.authService.register(otp);

    return {
      message: 'Registration successfully!',
      result,
    };
  }

  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        email: { type: 'string', example: 'phamlac10@gmail.com' },
        password: { type: 'string', example: '12345' },
      },
      required: ['email', 'password'],
    },
  })
  @Post('/login')
  async login(@Body() body: { email: string; password: string }) {
    const { email, password } = body;
    const { data, token } = await this.authService.login(email, password);
    return {
      message: 'Login successfully!',
      data,
      token,
    };
  }

  @ApiOperation({
    summary: 'Google login redirect',
    description:
      'Click [here](http://localhost:3000/auth/google) to login with Google.',
  })
  @Get('/google')
  @UseGuards(AuthGuard('google'))
  async googleAuth() {}

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(@Req() req) {
    const { data, token }: any = await this.authService.googleLogin(req);
    return {
      message: 'User information from google',
      data,
      token
    };
  }

  @ApiBearerAuth()
  @UseGuards(AuthGuard('jwt-refresh'))
  @Post('/refresh')
  async refresh(@Req() req) {
    const result = await this.authService.refreshToken(
      req.user.payload.sub,
      req.user.refreshToken,
    );
    if (result) {
      return {
        message: 'Token refreshed successfully',
        result,
      };
    }
  }

  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        access_token: { type: 'string', example: '' },
      },
      required: ['access_token'],
    },
  })
  @Post('/verify-access-token')
  async verifyAccessToken(@Body() body: { access_token: string }) {
    const { access_token } = body;
    return await this.authService.verify_access_token(access_token);
  }

  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        refresh_token: { type: 'string', example: '' },
      },
      required: ['refresh_token'],
    },
  })
  @Post('/verify-refresh-token')
  async verifyRefreshToken(@Body() body: { refresh_token: string }) {
    const { refresh_token } = body;
    return await this.authService.verify_refresh_token(refresh_token);
  }

  @ApiBearerAuth()
  @UseGuards(AuthGuard('jwt'))
  @Post('/logout')
  async logout(@Req() req) {
    const userId = req.user.sub;

    await this.authService.logout(userId);
    return {
      message: 'Logout successfully!',
    };
  }

  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        password: { type: 'string', example: '123456' },
        confirmPassword: { type: 'string', example: '123456' },
      },
      required: ['refresh_token'],
    },
  })
  @ApiBearerAuth()
  @UseGuards(AuthGuard('jwt'))
  @Post('/set-new-password')
  async setNewPassword(@Req() req, @Body() body) {
    const userId = req.user.sub;
    const { password, confirmPassword }: any = body;
    console.log(password);
    console.log(confirmPassword);
    await this.authService.setNewPassword(userId, password, confirmPassword);

    return {
      message: 'Updated new password successfully!',
    };
  }
}
