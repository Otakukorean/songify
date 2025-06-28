import {
  Controller,
  Get,
  Put,
  Delete,
  Param,
  Body,
  ParseIntPipe,
  NotFoundException,
  UseGuards,
  ForbiddenException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiBearerAuth,
  ApiOkResponse,
  ApiNotFoundResponse,
  ApiForbiddenResponse,
  ApiUnauthorizedResponse,
  ApiParam,
  ApiBody,
} from '@nestjs/swagger';
import { UsersService } from './users.service';
import { User } from '../db/schema';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import {
  UserResponseDto,
  UpdateProfileDto,
  MessageResponseDto,
} from '../auth/dto/auth.dto';

@ApiTags('Users')
@Controller('users')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth('JWT-auth')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get()
  @ApiOperation({
    summary: 'Get all users',
    description: 'Retrieve a list of all registered users',
  })
  @ApiOkResponse({
    description: 'Users retrieved successfully',
    type: [UserResponseDto],
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid or missing authentication token',
  })
  async findAll() {
    return this.usersService.findAll();
  }

  @Get('me')
  @ApiOperation({
    summary: 'Get my profile',
    description: 'Get the current user profile information',
  })
  @ApiOkResponse({
    description: 'User profile retrieved successfully',
    type: UserResponseDto,
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid or missing authentication token',
  })
  async getMyProfile(@CurrentUser() user: User) {
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

  @Get(':id')
  @ApiOperation({
    summary: 'Get user by ID',
    description: 'Retrieve a specific user by their ID',
  })
  @ApiParam({
    name: 'id',
    description: 'User ID',
    type: 'integer',
    example: 1,
  })
  @ApiOkResponse({
    description: 'User found successfully',
    type: UserResponseDto,
  })
  @ApiNotFoundResponse({
    description: 'User not found',
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid or missing authentication token',
  })
  async findById(@Param('id', ParseIntPipe) id: number) {
    const user = await this.usersService.findById(id);
    if (!user) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }
    return user;
  }

  @Put('me')
  @ApiOperation({
    summary: 'Update my profile',
    description: 'Update the current user profile information',
  })
  @ApiBody({ type: UpdateProfileDto })
  @ApiOkResponse({
    description: 'Profile updated successfully',
    type: UserResponseDto,
  })
  @ApiNotFoundResponse({
    description: 'User not found',
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid or missing authentication token',
  })
  async updateMyProfile(
    @CurrentUser() user: User,
    @Body() userData: UpdateProfileDto,
  ) {
    const updatedUser = await this.usersService.update(user.id, userData);
    if (!updatedUser) {
      throw new NotFoundException('User not found');
    }
    return updatedUser;
  }

  @Put(':id')
  @ApiOperation({
    summary: 'Update user by ID',
    description: 'Update a user profile (only own profile allowed)',
  })
  @ApiParam({
    name: 'id',
    description: 'User ID',
    type: 'integer',
    example: 1,
  })
  @ApiBody({ type: UpdateProfileDto })
  @ApiOkResponse({
    description: 'User updated successfully',
    type: UserResponseDto,
  })
  @ApiNotFoundResponse({
    description: 'User not found',
  })
  @ApiForbiddenResponse({
    description: 'You can only update your own profile',
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid or missing authentication token',
  })
  async update(
    @CurrentUser() currentUser: User,
    @Param('id', ParseIntPipe) id: number,
    @Body() userData: UpdateProfileDto,
  ) {
    // Only allow users to update their own profile or admin users
    if (currentUser.id !== id) {
      throw new ForbiddenException('You can only update your own profile');
    }

    const user = await this.usersService.update(id, userData);
    if (!user) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }
    return user;
  }

  @Delete(':id')
  @ApiOperation({
    summary: 'Delete user by ID',
    description: 'Delete a user account (only own account allowed)',
  })
  @ApiParam({
    name: 'id',
    description: 'User ID',
    type: 'integer',
    example: 1,
  })
  @ApiOkResponse({
    description: 'User deleted successfully',
    type: MessageResponseDto,
  })
  @ApiNotFoundResponse({
    description: 'User not found',
  })
  @ApiForbiddenResponse({
    description: 'You can only delete your own account',
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid or missing authentication token',
  })
  async delete(
    @CurrentUser() currentUser: User,
    @Param('id', ParseIntPipe) id: number,
  ) {
    // Only allow users to delete their own account or admin users
    if (currentUser.id !== id) {
      throw new ForbiddenException('You can only delete your own account');
    }

    const deleted = await this.usersService.delete(id);
    if (!deleted) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }
    return { message: 'User deleted successfully' };
  }
}
