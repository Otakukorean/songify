import { IsEmail, IsString, MinLength, IsOptional } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { UserRole, Permission } from '../types/roles.types';

export class RegisterDto {
  @ApiProperty({
    description: 'User full name',
    example: 'John Doe',
    minLength: 2,
  })
  @IsString()
  @MinLength(2)
  name: string;

  @ApiProperty({
    description: 'User email address',
    example: 'john.doe@example.com',
    format: 'email',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    description: 'User password',
    example: 'password123',
    minLength: 6,
  })
  @IsString()
  @MinLength(6)
  password: string;
}

export class LoginDto {
  @ApiProperty({
    description: 'User email address',
    example: 'john.doe@example.com',
    format: 'email',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    description: 'User password',
    example: 'password123',
  })
  @IsString()
  password: string;
}

export class RefreshTokenDto {
  @ApiProperty({
    description: 'Refresh token received from login/register',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @IsString()
  refreshToken: string;
}

export class UserResponseDto {
  @ApiProperty({ description: 'User ID', example: 1 })
  id: number;

  @ApiProperty({ description: 'User full name', example: 'John Doe' })
  name: string;

  @ApiProperty({ description: 'User email', example: 'john.doe@example.com' })
  email: string;

  @ApiPropertyOptional({
    description: 'User avatar URL',
    example: 'https://example.com/avatar.jpg',
  })
  avatar?: string;

  @ApiProperty({
    description: 'Authentication provider',
    example: 'local',
    enum: ['local', 'google'],
  })
  provider: string;

  @ApiProperty({
    description: 'User role',
    example: 'user',
    enum: UserRole,
  })
  role: UserRole;

  @ApiProperty({
    description: 'User permissions',
    example: ['read:own_profile', 'update:own_profile'],
    isArray: true,
    enum: Permission,
  })
  permissions: Permission[];

  @ApiProperty({ description: 'Email verification status', example: false })
  isEmailVerified: boolean;

  @ApiProperty({ description: 'Account active status', example: true })
  isActive: boolean;

  @ApiPropertyOptional({
    description: 'Account creation date',
    example: '2024-01-01T00:00:00.000Z',
  })
  createdAt?: Date;
}

export class AuthResponseDto {
  @ApiProperty({ description: 'User information', type: UserResponseDto })
  user: UserResponseDto;

  @ApiProperty({
    description: 'JWT access token (15 minutes expiration)',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  accessToken: string;

  @ApiProperty({
    description: 'Refresh token (30 days expiration)',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  refreshToken: string;

  @ApiProperty({
    description: 'Access token expiration time in seconds',
    example: 900,
  })
  expiresIn: number;
}

export class SessionDto {
  @ApiProperty({ description: 'Session ID', example: 1 })
  id: number;

  @ApiProperty({
    description: 'Session token',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  sessionToken: string;

  @ApiPropertyOptional({
    description: 'User agent string',
    example: 'Mozilla/5.0...',
  })
  userAgent?: string;

  @ApiPropertyOptional({ description: 'IP address', example: '192.168.1.1' })
  ipAddress?: string;

  @ApiProperty({ description: 'Session active status', example: true })
  isActive: boolean;

  @ApiProperty({
    description: 'Session creation date',
    example: '2024-01-01T00:00:00.000Z',
  })
  createdAt: Date;

  @ApiProperty({
    description: 'Last access date',
    example: '2024-01-01T00:00:00.000Z',
  })
  lastAccessedAt: Date;

  @ApiProperty({
    description: 'Session expiration date',
    example: '2024-01-08T00:00:00.000Z',
  })
  expiresAt: Date;
}

export class MessageResponseDto {
  @ApiProperty({
    description: 'Response message',
    example: 'Operation completed successfully',
  })
  message: string;
}

export class GoogleAuthDto {
  @ApiProperty({
    description: 'Google OAuth authorization code',
    example: '4/0AX4XfWi...',
  })
  @IsString()
  code: string;

  @ApiPropertyOptional({
    description: 'OAuth state parameter',
    example: 'random-state-string',
  })
  @IsOptional()
  @IsString()
  state?: string;
}

export class UpdateProfileDto {
  @ApiPropertyOptional({
    description: 'Updated user name',
    example: 'John Smith',
    minLength: 2,
  })
  @IsOptional()
  @IsString()
  @MinLength(2)
  name?: string;
}

export class UpdateUserRoleDto {
  @ApiProperty({
    description: 'New user role',
    example: 'moderator',
    enum: UserRole,
  })
  role: UserRole;

  @ApiPropertyOptional({
    description: 'Custom permissions (optional)',
    example: ['read:all_users', 'moderate:content'],
    isArray: true,
    enum: Permission,
  })
  @IsOptional()
  permissions?: Permission[];
}

export class UserManagementDto {
  @ApiProperty({ description: 'User ID', example: 1 })
  id: number;

  @ApiProperty({ description: 'User full name', example: 'John Doe' })
  name: string;

  @ApiProperty({ description: 'User email', example: 'john.doe@example.com' })
  email: string;

  @ApiProperty({
    description: 'User role',
    example: 'user',
    enum: UserRole,
  })
  role: UserRole;

  @ApiProperty({
    description: 'User permissions',
    example: ['read:own_profile', 'update:own_profile'],
    isArray: true,
    enum: Permission,
  })
  permissions: Permission[];

  @ApiProperty({ description: 'Account active status', example: true })
  isActive: boolean;

  @ApiProperty({ description: 'Email verification status', example: false })
  isEmailVerified: boolean;

  @ApiProperty({
    description: 'Authentication provider',
    example: 'local',
    enum: ['local', 'google'],
  })
  provider: string;

  @ApiProperty({
    description: 'Account creation date',
    example: '2024-01-01T00:00:00.000Z',
  })
  createdAt: Date;
}
