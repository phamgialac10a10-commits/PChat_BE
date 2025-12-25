import { Injectable, UnauthorizedException } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { ConfigService } from "@nestjs/config";
import { UserService } from "../user/user.service";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(private config: ConfigService, private userService: UserService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: config.get<string>('JWT_SECRET'),
      passReqToCallback: true,
    } as any);
  }

  async validate(req: any, payload: any) {
    // const token = req.headers['authorization']?.replace('Bearer ', '');

    // if(!token) {
    //   throw new UnauthorizedException('Missing access token');
    // }

    const user = await this.userService.findById(payload.sub);

    if(!user) {
        throw new UnauthorizedException('User no longer exists');
    }

    // if(!user.token.access_token || user.token.access_token !== token) {
    //   throw new UnauthorizedException('Access token is invalid');
    // }

    // if(user.token.access_expires_at && new Date() > user.token.access_expires_at) {
    //   throw new UnauthorizedException('Access token expired');
    // }

    return payload;
  }

}