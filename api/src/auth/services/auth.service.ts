import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  BadRequestException,
  Inject,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { eq, and } from 'drizzle-orm';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { Response } from 'express';

import { Database } from '../../db/database';
import { DATABASE_TOKEN } from '../../db/database.module';
import { users, sessions, refreshTokens, User } from '../../db/schema';
import { RegisterDto, LoginDto, AuthResponseDto } from '../dto/auth.dto';
import { JwtPayload, GoogleProfile } from '../interfaces/auth.interface';
import { UserRole, ROLE_PERMISSIONS, Permission } from '../types/roles.types';

@Injectable()
export class AuthService {
  constructor(
    @Inject(DATABASE_TOKEN) private db: Database,
    private jwtService: JwtService,
  ) {}

  async register(
    registerDto: RegisterDto,
    userAgent?: string,
    ipAddress?: string,
    res?: Response,
  ): Promise<AuthResponseDto> {
    const { name, email, password } = registerDto;

    // Check if user already exists
    const existingUser = await this.db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (existingUser.length > 0) {
      throw new ConflictException('User with this email already exists');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user with default role
    const newUsers = await this.db
      .insert(users)
      .values({
        name,
        email,
        password: hashedPassword,
        provider: 'local',
        role: UserRole.USER,
        permissions: JSON.stringify([]),
        isEmailVerified: false,
        isActive: true,
      })
      .returning();

    const user = newUsers[0];

    // Create session and tokens
    return this.createSessionAndTokens(user, userAgent, ipAddress, res);
  }

  async login(
    loginDto: LoginDto,
    userAgent?: string,
    ipAddress?: string,
    res?: Response,
  ): Promise<AuthResponseDto> {
    const { email, password } = loginDto;

    // Find user
    const userResult = await this.db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (userResult.length === 0) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const user = userResult[0];

    // Check if user is active
    if (!user.isActive) {
      throw new UnauthorizedException('Account is deactivated');
    }

    // Check if user has a password (OAuth users might not)
    if (!user.password) {
      throw new UnauthorizedException('Please use OAuth to login');
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    return this.createSessionAndTokens(user, userAgent, ipAddress, res);
  }

  async refreshToken(
    refreshTokenString: string,
    userAgent?: string,
    ipAddress?: string,
    res?: Response,
  ): Promise<AuthResponseDto> {
    // Find refresh token
    const tokenResult = await this.db
      .select({
        refreshToken: refreshTokens,
        user: users,
      })
      .from(refreshTokens)
      .innerJoin(users, eq(refreshTokens.userId, users.id))
      .where(
        and(
          eq(refreshTokens.token, refreshTokenString),
          eq(refreshTokens.isRevoked, false),
        ),
      )
      .limit(1);

    if (tokenResult.length === 0) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const { refreshToken, user } = tokenResult[0];

    // Check if user is active
    if (!user.isActive) {
      throw new UnauthorizedException('Account is deactivated');
    }

    // Check if token is expired
    if (new Date() > refreshToken.expiresAt!) {
      throw new UnauthorizedException('Refresh token expired');
    }

    // Revoke old refresh token
    await this.db
      .update(refreshTokens)
      .set({ isRevoked: true })
      .where(eq(refreshTokens.id, refreshToken.id));

    // Create new session and tokens
    return this.createSessionAndTokens(user, userAgent, ipAddress, res);
  }

  async logout(userId: number, sessionToken?: string): Promise<void> {
    if (sessionToken) {
      // Logout specific session
      await this.db
        .update(sessions)
        .set({ isActive: false })
        .where(
          and(
            eq(sessions.userId, userId),
            eq(sessions.sessionToken, sessionToken),
          ),
        );
    } else {
      // Logout all sessions
      await this.db
        .update(sessions)
        .set({ isActive: false })
        .where(eq(sessions.userId, userId));
    }

    // Revoke all refresh tokens for user
    await this.db
      .update(refreshTokens)
      .set({ isRevoked: true })
      .where(eq(refreshTokens.userId, userId));
  }

  async validateUser(payload: JwtPayload): Promise<User | null> {
    const sessionResult = await this.db
      .select({
        user: users,
        session: sessions,
      })
      .from(sessions)
      .innerJoin(users, eq(sessions.userId, users.id))
      .where(
        and(
          eq(sessions.id, payload.sessionId),
          eq(sessions.isActive, true),
          eq(users.id, payload.sub),
        ),
      )
      .limit(1);

    if (sessionResult.length === 0) {
      return null;
    }

    const { user, session } = sessionResult[0];

    // Check if session is expired
    if (new Date() > session.expiresAt!) {
      return null;
    }

    // Update last accessed time
    await this.db
      .update(sessions)
      .set({ lastAccessedAt: new Date() })
      .where(eq(sessions.id, session.id));

    return user;
  }

  async googleAuth(
    profile: GoogleProfile,
    userAgent?: string,
    ipAddress?: string,
  ): Promise<AuthResponseDto> {
    let user: User;

    // Check if user exists with Google ID
    const existingUserResult = await this.db
      .select()
      .from(users)
      .where(eq(users.googleId, profile.id))
      .limit(1);

    if (existingUserResult.length > 0) {
      user = existingUserResult[0];
    } else {
      // Check if user exists with same email
      const emailUserResult = await this.db
        .select()
        .from(users)
        .where(eq(users.email, profile.emails[0].value))
        .limit(1);

      if (emailUserResult.length > 0) {
        // Link existing account with Google
        const updatedUsers = await this.db
          .update(users)
          .set({
            googleId: profile.id,
            avatar: profile.photos[0]?.value,
            isEmailVerified: true,
          })
          .where(eq(users.id, emailUserResult[0].id))
          .returning();
        user = updatedUsers[0];
      } else {
        // Create new user
        const newUsers = await this.db
          .insert(users)
          .values({
            name: profile.displayName,
            email: profile.emails[0].value,
            googleId: profile.id,
            avatar: profile.photos[0]?.value,
            provider: 'google',
            isEmailVerified: true,
          })
          .returning();
        user = newUsers[0];
      }
    }

    return this.createSessionAndTokens(user, userAgent, ipAddress);
  }

  private async createSessionAndTokens(
    user: User,
    userAgent?: string,
    ipAddress?: string,
    res?: Response,
  ): Promise<AuthResponseDto> {
    // Create session
    const sessionToken = uuidv4();
    const sessionExpiresAt = new Date();
    sessionExpiresAt.setDate(sessionExpiresAt.getDate() + 7); // 7 days

    const newSessions = await this.db
      .insert(sessions)
      .values({
        userId: user.id,
        sessionToken,
        userAgent,
        ipAddress,
        expiresAt: sessionExpiresAt,
      })
      .returning();

    const session = newSessions[0];

    // Create JWT payload with role and permissions
    const userRole = user.role as UserRole;
    const rolePermissions = ROLE_PERMISSIONS[userRole] || [];
    const customPermissions: Permission[] = user.permissions
      ? JSON.parse(user.permissions)
      : [];
    const allPermissions = [...rolePermissions, ...customPermissions];

    const payload: JwtPayload & { role: UserRole; permissions: Permission[] } = {
      sub: user.id,
      email: user.email,
      sessionId: session.id,
      role: userRole,
      permissions: allPermissions,
    };

    // Generate tokens
    const accessToken = this.jwtService.sign(payload, { expiresIn: '15m' });

    const refreshTokenString = uuidv4();
    const refreshTokenExpiresAt = new Date();
    refreshTokenExpiresAt.setDate(refreshTokenExpiresAt.getDate() + 30); // 30 days

    await this.db.insert(refreshTokens).values({
      userId: user.id,
      token: refreshTokenString,
      expiresAt: refreshTokenExpiresAt,
    });

    // Set cookies if response object is available
    if (res) {
      this.setAuthCookies(res, accessToken, refreshTokenString);
    }

    return {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        avatar: user.avatar || undefined,
        provider: user.provider || 'local',
        role: userRole,
        permissions: allPermissions,
        isEmailVerified: user.isEmailVerified || false,
        isActive: user.isActive || true,
      },
      accessToken,
      refreshToken: refreshTokenString,
      expiresIn: 15 * 60, // 15 minutes in seconds
    };
  }

  async getUserSessions(userId: number) {
    return this.db
      .select({
        id: sessions.id,
        sessionToken: sessions.sessionToken,
        userAgent: sessions.userAgent,
        ipAddress: sessions.ipAddress,
        isActive: sessions.isActive,
        createdAt: sessions.createdAt,
        lastAccessedAt: sessions.lastAccessedAt,
        expiresAt: sessions.expiresAt,
      })
      .from(sessions)
      .where(eq(sessions.userId, userId))
      .orderBy(sessions.lastAccessedAt);
  }

  async revokeSession(userId: number, sessionId: number): Promise<void> {
    await this.db
      .update(sessions)
      .set({ isActive: false })
      .where(and(eq(sessions.userId, userId), eq(sessions.id, sessionId)));
  }

  private setAuthCookies(res: Response, accessToken: string, refreshToken: string): void {
    // Set access token cookie (15 minutes)
    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    // Set refresh token cookie (30 days)
    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    });
  }

  clearAuthCookies(res: Response): void {
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
  }

  async updateUserRole(userId: number, role: UserRole, permissions?: Permission[]): Promise<User> {
    const permissionsJson = permissions ? JSON.stringify(permissions) : JSON.stringify([]);
    
    const updatedUsers = await this.db
      .update(users)
      .set({
        role,
        permissions: permissionsJson,
        updatedAt: new Date(),
      })
      .where(eq(users.id, userId))
      .returning();

    if (updatedUsers.length === 0) {
      throw new UnauthorizedException('User not found');
    }

    return updatedUsers[0];
  }

  async deactivateUser(userId: number): Promise<void> {
    await this.db
      .update(users)
      .set({
        isActive: false,
        updatedAt: new Date(),
      })
      .where(eq(users.id, userId));

    // Revoke all user sessions and tokens
    await this.logout(userId);
  }

  async activateUser(userId: number): Promise<void> {
    await this.db
      .update(users)
      .set({
        isActive: true,
        updatedAt: new Date(),
      })
      .where(eq(users.id, userId));
  }
}
