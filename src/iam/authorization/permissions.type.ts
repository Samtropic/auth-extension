import { CoffesPermission } from '../../coffees/coffees.permission';

export const Permission = {
  ...CoffesPermission,
};

export type PermissionType = CoffesPermission; // | ...other permision enums
