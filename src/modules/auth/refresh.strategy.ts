import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Request } from 'express';
import { ConfigService } from '@nestjs/config';
import { UserService } from '../user/user.service';

@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  constructor(
    private config: ConfigService,
    private usersService: UserService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req: Request) => req?.cookies?.refresh_token, // lấy từ cookie
      ]),
      secretOrKey: config.get<string>('JWT_REFRESH_SECRET'),
      passReqToCallback: true, // cho phép lấy thêm info từ request
    } as any);
  }

  async validate(req: Request, payload: any) {
    const refreshToken = req?.cookies?.refresh_token;
    if (!refreshToken) throw new UnauthorizedException('Missing refresh token');

    const user = await this.usersService.findById(payload.sub);
    if (!user) throw new UnauthorizedException('User not found');

    // OPTIONAL: kiểm tra trong DB refresh token hash có hợp lệ không
    // const tokenValid = await this.usersService.validateRefreshToken(user.id, refreshToken);
    // if (!tokenValid) throw new UnauthorizedException('Invalid refresh token');

    return payload; // passed
  }
}
// async validateRefreshToken(userId: number, token: string) {
//   const user = await this.findById(userId);
//   if (!user || !user.refresh_token_hash) return false;

//   return await bcrypt.compare(token, user.refresh_token_hash);
// }