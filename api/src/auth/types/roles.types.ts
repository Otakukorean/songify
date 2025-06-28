export enum UserRole {
  USER = 'user',
  MODERATOR = 'moderator',
  ADMIN = 'admin',
}

export enum Permission {
  // User permissions
  READ_OWN_PROFILE = 'read:own_profile',
  UPDATE_OWN_PROFILE = 'update:own_profile',
  DELETE_OWN_ACCOUNT = 'delete:own_account',
  
  // Moderator permissions
  READ_ALL_USERS = 'read:all_users',
  UPDATE_USER_PROFILE = 'update:user_profile',
  MODERATE_CONTENT = 'moderate:content',
  
  // Admin permissions
  DELETE_ANY_USER = 'delete:any_user',
  MANAGE_ROLES = 'manage:roles',
  MANAGE_PERMISSIONS = 'manage:permissions',
  VIEW_ANALYTICS = 'view:analytics',
  SYSTEM_ADMIN = 'system:admin',
}

export const ROLE_PERMISSIONS: Record<UserRole, Permission[]> = {
  [UserRole.USER]: [
    Permission.READ_OWN_PROFILE,
    Permission.UPDATE_OWN_PROFILE,
    Permission.DELETE_OWN_ACCOUNT,
  ],
  [UserRole.MODERATOR]: [
    Permission.READ_OWN_PROFILE,
    Permission.UPDATE_OWN_PROFILE,
    Permission.DELETE_OWN_ACCOUNT,
    Permission.READ_ALL_USERS,
    Permission.UPDATE_USER_PROFILE,
    Permission.MODERATE_CONTENT,
  ],
  [UserRole.ADMIN]: [
    Permission.READ_OWN_PROFILE,
    Permission.UPDATE_OWN_PROFILE,
    Permission.DELETE_OWN_ACCOUNT,
    Permission.READ_ALL_USERS,
    Permission.UPDATE_USER_PROFILE,
    Permission.MODERATE_CONTENT,
    Permission.DELETE_ANY_USER,
    Permission.MANAGE_ROLES,
    Permission.MANAGE_PERMISSIONS,
    Permission.VIEW_ANALYTICS,
    Permission.SYSTEM_ADMIN,
  ],
};

export interface UserWithRole {
  id: number;
  name: string;
  email: string;
  role: UserRole;
  permissions: Permission[];
  isActive: boolean;
  isEmailVerified: boolean;
} 