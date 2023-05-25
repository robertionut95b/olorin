import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { PasswordService } from './password.service';
import { GqlAuthGuard } from './guards/gql-auth.guard';
import { AuthService } from './auth.service';
import { AuthResolver } from './auth.resolver';
import { JwtStrategy } from './strategies/jwt.strategy';
import { SecurityConfig } from 'src/common/configs/config.interface';
import { GithubStrategy } from './strategies/github.strategy';
import { GithubOauthController } from './github-oauth.controller';
import { GithubOauthGuard } from './guards/github.guard';
import { JwtRefreshTokenStrategy } from './strategies/jwtRefresh.strategy';
import { UserLoginListener } from './listeners/userLogin.listener';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      useFactory: async (configService: ConfigService) => {
        const securityConfig = configService.get<SecurityConfig>('security');
        return {
          secret: configService.get<string>('JWT_ACCESS_SECRET'),
          signOptions: {
            expiresIn: securityConfig.expiresIn,
          },
        };
      },
      inject: [ConfigService],
    }),
  ],
  providers: [
    AuthService,
    AuthResolver,
    JwtStrategy,
    JwtRefreshTokenStrategy,
    GithubStrategy,
    GqlAuthGuard,
    GithubOauthGuard,
    PasswordService,
    UserLoginListener,
  ],
  controllers: [GithubOauthController],
  exports: [GqlAuthGuard],
})
export class AuthModule {}
