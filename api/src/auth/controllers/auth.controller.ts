import {
  Controller,
  Post,
  Get,
  Delete,
  Body,
  UseGuards,
  Req,
  Res,
  Param,
  ParseIntPipe,
  HttpCode,
  HttpStatus,
  Headers,
  Put,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiBody,
  ApiParam,
  ApiHeader,
  ApiOkResponse,
  ApiCreatedResponse,
  ApiUnauthorizedResponse,
  ApiBadRequestResponse,
  ApiNotFoundResponse,
  ApiForbiddenResponse,
} from '@nestjs/swagger';
import { Request, Response } from 'express';
import { AuthService } from '../services/auth.service';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { GoogleAuthGuard } from '../guards/google-auth.guard';
import { Public } from '../decorators/public.decorator';
import { CurrentUser } from '../decorators/current-user.decorator';
import {
  RegisterDto,
  LoginDto,
  RefreshTokenDto,
  AuthResponseDto,
  UserResponseDto,
  SessionDto,
  MessageResponseDto,
  UserManagementDto,
  UpdateUserRoleDto,
} from '../dto/auth.dto';
import { User } from '../../db/schema';
import { RolesGuard } from '../guards/roles.guard';
import { Roles } from '../decorators/roles.decorator';
import { UserRole } from '../types/roles.types';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Register a new user',
    description: 'Create a new user account with email and password',
  })
  @ApiCreatedResponse({
    description: 'User successfully registered',
    type: AuthResponseDto,
  })
  @ApiBadRequestResponse({
    description: 'Invalid input data or email already exists',
    schema: {
      example: {
        statusCode: 400,
        message: [
          'email must be an email',
          'password must be longer than or equal to 6 characters',
        ],
        error: 'Bad Request',
      },
    },
  })
  @ApiBody({ type: RegisterDto })
  async register(
    @Body() registerDto: RegisterDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthResponseDto> {
    const userAgent = req.get('User-Agent');
    const ipAddress = req.ip || req.connection.remoteAddress;

    return this.authService.register(registerDto, userAgent, ipAddress, res);
  }

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Login user',
    description: 'Authenticate user with email and password',
  })
  @ApiOkResponse({
    description: 'User successfully logged in',
    type: AuthResponseDto,
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid credentials',
    schema: {
      example: {
        statusCode: 401,
        message: 'Invalid credentials',
        error: 'Unauthorized',
      },
    },
  })
  @ApiBody({ type: LoginDto })
  async login(
    @Body() loginDto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthResponseDto> {
    const userAgent = req.get('User-Agent');
    const ipAddress = req.ip || req.connection.remoteAddress;

    return this.authService.login(loginDto, userAgent, ipAddress, res);
  }

  @Public()
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Refresh access token',
    description: 'Get a new access token using refresh token from cookies or request body',
  })
  @ApiOkResponse({
    description: 'New access token generated',
    type: AuthResponseDto,
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid or expired refresh token',
    schema: {
      example: {
        statusCode: 401,
        message: 'Invalid refresh token',
        error: 'Unauthorized',
      },
    },
  })
  @ApiBody({ type: RefreshTokenDto, required: false })
  async refreshToken(
    @Body() refreshTokenDto: RefreshTokenDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthResponseDto> {
    const userAgent = req.get('User-Agent');
    const ipAddress = req.ip || req.connection.remoteAddress;

    // Try to get refresh token from cookies first, then from body
    const refreshToken = req.cookies?.refresh_token || refreshTokenDto?.refreshToken;

    if (!refreshToken) {
      throw new Error('Refresh token not provided in cookies or request body');
    }

    return this.authService.refreshToken(
      refreshToken,
      userAgent,
      ipAddress,
      res,
    );
  }

  @Public()
  @Post('refresh-cookie')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Refresh access token using cookies only',
    description: 'Get a new access token using refresh token from cookies only',
  })
  @ApiOkResponse({
    description: 'New access token generated',
    type: AuthResponseDto,
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid or expired refresh token, or no refresh token in cookies',
    schema: {
      example: {
        statusCode: 401,
        message: 'No refresh token found in cookies',
        error: 'Unauthorized',
      },
    },
  })
  async refreshTokenFromCookie(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthResponseDto> {
    const userAgent = req.get('User-Agent');
    const ipAddress = req.ip || req.connection.remoteAddress;

    // Get refresh token from cookies only
    const refreshToken = req.cookies?.refresh_token;

    if (!refreshToken) {
      throw new Error('No refresh token found in cookies');
    }

    return this.authService.refreshToken(
      refreshToken,
      userAgent,
      ipAddress,
      res,
    );
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: 'Logout user',
    description:
      'Logout user and revoke all active sessions and refresh tokens',
  })
  @ApiOkResponse({
    description: 'User successfully logged out',
    type: MessageResponseDto,
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid or missing authentication token',
  })
  async logout(
    @CurrentUser() user: User,
    @Headers('authorization') authHeader?: string,
    @Res({ passthrough: true }) res?: Response,
  ): Promise<{ message: string }> {
    // Extract session token from JWT if available
    let sessionToken: string | undefined;

    if (authHeader) {
      try {
        // You could decode the JWT to get session info, but for simplicity
        // we'll just logout all sessions for now
        await this.authService.logout(user.id);
      } catch (error) {
        await this.authService.logout(user.id);
      }
    } else {
      await this.authService.logout(user.id);
    }

    // Clear authentication cookies
    if (res) {
      this.authService.clearAuthCookies(res);
    }

    return { message: 'Logged out successfully' };
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: 'Get current user profile',
    description:
      'Get the profile information of the currently authenticated user',
  })
  @ApiOkResponse({
    description: 'User profile retrieved successfully',
    type: UserResponseDto,
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid or missing authentication token',
  })
  async getProfile(@CurrentUser() user: User) {
    return {
      id: user.id,
      name: user.name,
      email: user.email,
      avatar: user.avatar,
      provider: user.provider,
      isEmailVerified: user.isEmailVerified,
      createdAt: user.createdAt,
    };
  }

  @UseGuards(JwtAuthGuard)
  @Get('sessions')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: 'Get user sessions',
    description: 'Get all active sessions for the current user',
  })
  @ApiOkResponse({
    description: 'User sessions retrieved successfully',
    type: [SessionDto],
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid or missing authentication token',
  })
  async getSessions(@CurrentUser() user: User) {
    return this.authService.getUserSessions(user.id);
  }

  @UseGuards(JwtAuthGuard)
  @Delete('sessions/:sessionId')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: 'Revoke session',
    description: 'Revoke a specific session by ID',
  })
  @ApiParam({
    name: 'sessionId',
    description: 'Session ID to revoke',
    type: 'integer',
    example: 1,
  })
  @ApiOkResponse({
    description: 'Session revoked successfully',
    type: MessageResponseDto,
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid or missing authentication token',
  })
  @ApiNotFoundResponse({
    description: 'Session not found',
  })
  async revokeSession(
    @CurrentUser() user: User,
    @Param('sessionId', ParseIntPipe) sessionId: number,
  ): Promise<{ message: string }> {
    await this.authService.revokeSession(user.id, sessionId);
    return { message: 'Session revoked successfully' };
  }

  // Google OAuth routes
  @Public()
  @Get('google')
  @UseGuards(GoogleAuthGuard)
  @ApiOperation({
    summary: 'Initiate Google OAuth',
    description: 'Redirect to Google OAuth authorization page',
  })
  @ApiResponse({
    status: 302,
    description: 'Redirect to Google OAuth',
  })
  async googleAuth() {
    // This route will redirect to Google
  }

  @Public()
  @Get('google/callback')
  @UseGuards(GoogleAuthGuard)
  @ApiOperation({
    summary: 'Google OAuth callback',
    description:
      'Handle Google OAuth callback and return authentication tokens',
  })
  @ApiOkResponse({
    description: 'Google OAuth successful',
    type: AuthResponseDto,
  })
  @ApiBadRequestResponse({
    description: 'Google OAuth failed',
  })
  async googleAuthCallback(@Req() req: any, @Res() res: Response) {
    const authResponse: AuthResponseDto = req.user;

    // In a real app, you might redirect to your frontend with tokens
    // For now, we'll just return the auth response
    res.json(authResponse);
  }

  // Alternative Google OAuth endpoint that returns JSON instead of redirect
  @Public()
  @Post('google/authenticate')
  @ApiOperation({
    summary: 'Google OAuth authenticate (Not implemented)',
    description: 'Alternative Google OAuth flow - not yet implemented',
  })
  @ApiBadRequestResponse({
    description: 'Not implemented - use /auth/google flow instead',
  })
  async googleAuthenticate(
    @Body('accessToken') accessToken: string,
    @Req() req: Request,
  ) {
    // Implement Google token verification
    return { message: 'Google authentication endpoint' };
  }

  // Admin endpoints for user management
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  @Get('users')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: 'Get all users (Admin only)',
    description: 'Retrieve a list of all users in the system',
  })
  @ApiOkResponse({
    description: 'Users retrieved successfully',
    type: [UserManagementDto],
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions',
  })
  async getAllUsers(): Promise<UserManagementDto[]> {
    // Implementation would get all users from the database
    return [];
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  @Put('users/:id/role')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: 'Update user role (Admin only)',
    description: 'Update the role and permissions of a specific user',
  })
  @ApiParam({
    name: 'id',
    description: 'User ID',
    type: 'number',
  })
  @ApiOkResponse({
    description: 'User role updated successfully',
    type: MessageResponseDto,
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions',
  })
  async updateUserRole(
    @Param('id', ParseIntPipe) userId: number,
    @Body() updateRoleDto: UpdateUserRoleDto,
    @CurrentUser() currentUser: User,
  ): Promise<MessageResponseDto> {
    // Prevent admin from changing their own role
    if (userId === currentUser.id) {
      throw new Error('Cannot change your own role');
    }

    await this.authService.updateUserRole(
      userId,
      updateRoleDto.role,
      updateRoleDto.permissions,
    );

    return { message: 'User role updated successfully' };
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  @Delete('users/:id/deactivate')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: 'Deactivate user (Admin only)',
    description: 'Deactivate a user account',
  })
  @ApiParam({
    name: 'id',
    description: 'User ID',
    type: 'number',
  })
  @ApiOkResponse({
    description: 'User deactivated successfully',
    type: MessageResponseDto,
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions',
  })
  async deactivateUser(
    @Param('id', ParseIntPipe) userId: number,
    @CurrentUser() currentUser: User,
  ): Promise<MessageResponseDto> {
    // Prevent admin from deactivating their own account
    if (userId === currentUser.id) {
      throw new Error('Cannot deactivate your own account');
    }

    await this.authService.deactivateUser(userId);
    return { message: 'User deactivated successfully' };
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  @Post('users/:id/activate')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: 'Activate user (Admin only)',
    description: 'Activate a deactivated user account',
  })
  @ApiParam({
    name: 'id',
    description: 'User ID',
    type: 'number',
  })
  @ApiOkResponse({
    description: 'User activated successfully',
    type: MessageResponseDto,
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions',
  })
  async activateUser(
    @Param('id', ParseIntPipe) userId: number,
  ): Promise<MessageResponseDto> {
    await this.authService.activateUser(userId);
    return { message: 'User activated successfully' };
  }
}
