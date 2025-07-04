import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { ConfigService } from '@nestjs/config';
import { AuthService } from '../services/auth.service';
import { GoogleProfile } from '../interfaces/auth.interface';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    private authService: AuthService,
    private configService: ConfigService,
  ) {
    super({
      clientID: configService.get<string>('GOOGLE_CLIENT_ID'),
      clientSecret: configService.get<string>('GOOGLE_CLIENT_SECRET'),
      callbackURL: configService.get<string>('GOOGLE_CALLBACK_URL'),
      scope: ['email', 'profile'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<any> {
    const { id, name, emails, photos } = profile;

    const googleProfile: GoogleProfile = {
      id,
      displayName: name.givenName + ' ' + name.familyName,
      name: {
        familyName: name.familyName,
        givenName: name.givenName,
      },
      emails: emails.map((email: any) => ({
        value: email.value,
        verified: email.verified,
      })),
      photos: photos.map((photo: any) => ({
        value: photo.value,
      })),
      provider: 'google',
    };

    try {
      const result = await this.authService.googleAuth(googleProfile);
      done(null, result);
    } catch (error) {
      done(error, null);
    }
  }
}
