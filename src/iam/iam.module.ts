import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '../users/entities/user.entity';
import { AuthenticationController } from './authentication/authentication.controller';
import { AuthenticationService } from './authentication/authentication.service';
import { AuthenticationGuard } from './authentication/guards/authentication/authentication.guard';
import jwtConfig from './config/jwt.config';
import { BcryptService } from './hashing/bcrypt.service';
import { HashingService } from './hashing/hashing.service';
import { AccessTokenGuard } from './authentication/guards/access-token/access-token.guard';
import { RefreshTokenIdsStorage } from './authentication/refresh-token-ids.storage/refresh-token-ids.storage';
import { RolesGuard } from './authorization/guards/roles/roles.guard';
import { PermissionsGuard } from './authorization/guards/permissions/permissions.guard';
import { PolicyHandlerStorage } from './authorization/policies/policy-handlers.storage';
import { FrameworkContributorPolicyHandler } from './authorization/policies/framework-contributor.policy';
import { PoliciesGuard } from './authorization/guards/policies/policies.guard';
import { ApiKeysService } from './authentication/api-keys.service';
import { ApiKey } from '../users/api-keys/entities/api-key.entity/api-key.entity';
import { ApiKeyGuard } from './authentication/guards/api-key/api-key.guard';
import { GoogleAuthService } from './authentication/social/google-auth.service';
import { GoogleAuthController } from './authentication/social/google-auth.controller';
import { OtpAuthService } from './authentication/otp-auth.service';
import { SessionAuthService } from './authentication/session-auth.service';
import { SessionAuthController } from './authentication/session-auth.controller';
import * as session from 'express-session';
import * as passport from 'passport';
import { UserSerializer } from './authentication/serializers/user-serializer/user-serializer';
import RedisStore from 'connect-redis';
import Redis from 'ioredis';
@Module({
  imports: [
    TypeOrmModule.forFeature([User, ApiKey]),
    JwtModule.registerAsync(jwtConfig.asProvider()),
    ConfigModule.forFeature(jwtConfig),
  ],
  providers: [
    {
      provide: HashingService,
      useClass: BcryptService,
    },
    {
      provide: APP_GUARD,
      useClass: AuthenticationGuard,
    },
    {
      provide: APP_GUARD,
      useClass: PoliciesGuard, //PermissionsGuard, // RolesGuard,
    },
    AccessTokenGuard,
    ApiKeyGuard,
    AuthenticationService,
    RefreshTokenIdsStorage,
    PolicyHandlerStorage,
    FrameworkContributorPolicyHandler,
    ApiKeysService,
    GoogleAuthService,
    OtpAuthService,
    SessionAuthService,
    UserSerializer,
  ],
  controllers: [
    AuthenticationController,
    GoogleAuthController,
    SessionAuthController,
  ],
  exports: [],
})
export class IamModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    const redisClient = new Redis(6379, 'localhost');
    let redisStore = new RedisStore({
      client: redisClient,
      prefix: 'myapp:',
    });
    consumer
      .apply(
        session({
          store: redisStore,
          secret: process.env.SESSION_SECRET,
          resave: false,
          saveUninitialized: false,
          cookie: {
            sameSite: true,
            httpOnly: true,
          },
        }),
        passport.initialize(),
        passport.session(),
      )
      .forRoutes('*');
  }
}
