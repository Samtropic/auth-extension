import { SetMetadata } from '@nestjs/common';
import { PermissionType } from '../permissions.type';

export const PERMISSIONS_KEY = 'roles';
export const Permissions = (...permissions: PermissionType[]) =>
  SetMetadata(PERMISSIONS_KEY, permissions);
