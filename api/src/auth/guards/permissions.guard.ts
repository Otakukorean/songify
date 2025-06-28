import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PERMISSIONS_KEY } from '../decorators/permissions.decorator';
import { Permission, ROLE_PERMISSIONS, UserRole } from '../types/roles.types';
import { User } from '../../db/schema';

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredPermissions = this.reflector.getAllAndOverride<Permission[]>(
      PERMISSIONS_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!requiredPermissions) {
      return true;
    }

    const { user }: { user: User } = context.switchToHttp().getRequest();
    
    if (!user || !user.isActive) {
      return false;
    }

    // Get user permissions from role
    const userRole = user.role as UserRole;
    const rolePermissions = ROLE_PERMISSIONS[userRole] || [];
    
    // Parse custom permissions from user (if any)
    let customPermissions: Permission[] = [];
    try {
      customPermissions = user.permissions ? JSON.parse(user.permissions) : [];
    } catch (error) {
      customPermissions = [];
    }

    // Combine role permissions with custom permissions
    const allUserPermissions = [...rolePermissions, ...customPermissions];

    // Check if user has all required permissions
    return requiredPermissions.every((permission) =>
      allUserPermissions.includes(permission),
    );
  }
} 