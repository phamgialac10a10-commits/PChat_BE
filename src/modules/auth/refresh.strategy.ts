import { Injectable, UnauthorizedException } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { ConfigModule, ConfigService } from "@nestjs/config";


@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  constructor(private config: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.get<string>('JWT_REFRESH_SECRET'),
      passReqToCallback: true,
    } as any);
  }

  async validate(req: any, payload: any){
    const refreshToken = req.get('authorization')?.replace('Bearer', '').trim();


    if(!refreshToken) {
        throw new UnauthorizedException('Refresh token missing');
    }

    return {
        payload,
        refreshToken,
    }
  }
}