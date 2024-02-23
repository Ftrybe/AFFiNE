import { Module } from '@nestjs/common';

import { FeatureModule } from '../features';
import { UsersModule } from '../users';
import { AuthController } from './controller';
import { AuthResolver } from './resolver';
import { AuthService } from './service';
import { SessionService } from './session';
import { AuthSessionController } from './session.controller';

@Module({
  imports: [FeatureModule, UsersModule],
  providers: [AuthService, AuthResolver, SessionService],
  exports: [AuthService, SessionService],
  controllers: [AuthController, AuthSessionController],
})
export class AuthModule {}

export * from './guard';
export { TokenType } from './resolver';
export { AuthService };
