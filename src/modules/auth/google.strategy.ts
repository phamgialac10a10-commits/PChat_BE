import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { Strategy, VerifyCallback } from "passport-google-oauth20";
import { ConfigModule, ConfigService } from "@nestjs/config";

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google'){
    constructor(){
        super({
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback',
            scope: ['email', 'profile'],
        } as any);
    }

    async validate(
        accessToken: string,
        refreshToken: string,
        profile: string,
        done: VerifyCallback,
    ): Promise<any>{
        try {
            // console.log(profile);
    
            const { id, displayName, name, emails, photos, provider }: any = profile;
            const user = {
                google_id: id,
                displayName: displayName,
                provider: provider,
                email: emails[0].value || null,
                firstName: name.givenName || '',
                lastName: name.familyName || '',
                picture: photos[0].value || null,
                accessToken,
            };
            done(null, user);
        } catch(err){
            done(err, false);
        }
    }
}