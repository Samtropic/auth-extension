import { PassportSerializer } from '@nestjs/passport';
import { User } from '../../../../users/entities/user.entity';
import { ActiveUserData } from '../../../../iam/interfaces/active-user-data.interface';

export class UserSerializer extends PassportSerializer {
  serializeUser(user: User, done: (err: Error, user: ActiveUserData) => void) {
    done(null, {
      sub: user.id,
      email: user.email,
      role: user.role,
      permissions: user.permissions,
    });
  }

  /**
   * Here we just pass the ActiveUserData payload instead of getting the user entity
   * through the user repository because it's called for every request and may cause
   * performance issue.
   * @param payload
   * @param done
   */
  deserializeUser(
    payload: ActiveUserData,
    done: (err: Error, user: ActiveUserData) => void,
  ) {
    done(null, payload);
  }
}
