import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { AuthService } from '../services/auth.service';
import { JwtPayload } from '../interfaces/auth.interface';
import { User } from '../../db/schema';
import { UserRole, Permission } from '../types/roles.types';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private authService: AuthService,
    private configService: ConfigService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        ExtractJwt.fromAuthHeaderAsBearerToken(),
        (request: Request) => {
          return request?.cookies?.access_token;
        },
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET') || 'your-secret-key',
    });
  }

  async validate(payload: JwtPayload & { role: UserRole; permissions: Permission[] }): Promise<User> {
    const user = await this.authService.validateUser(payload);

    if (!user) {
      throw new UnauthorizedException('Invalid or expired token');
    }

    // Attach role and permissions to the user object for use in guards
    (user as any).role = payload.role;
    (user as any).permissions = payload.permissions;

    return user;
  }
}
