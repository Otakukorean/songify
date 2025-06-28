import { SetMetadata } from '@nestjs/common';
import { Permission } from '../types/roles.types';

export const PERMISSIONS_KEY = 'permissions';
export const RequirePermissions = (...permissions: Permission[]) =>
  SetMetadata(PERMISSIONS_KEY, permissions); 