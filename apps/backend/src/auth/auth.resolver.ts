import {
  Resolver,
  Mutation,
  Args,
  Parent,
  ResolveField,
} from '@nestjs/graphql';
import { AuthService } from './auth.service';
import { Auth } from './models/auth.model';
import { Token } from './models/token.model';
import { LoginInput } from './dto/login.input';
import { SignupInput } from './dto/signup.input';
import { RefreshTokenInput } from './dto/refresh-token.input';
import { User } from 'src/users/models/user.model';
import { Req, UseGuards } from '@nestjs/common';
import { GqlJwtRefreshGuard } from './guards/gql-jwtRefresh.guard';
import { LogoutResponse } from './models/logout.model';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { UserLoginEvent } from './events/userLogin.payload';
import { Request } from 'express';
import { extractAgentIpFromRequest } from 'src/common/http/requestInterceptor';
import { RequestEntityGql } from 'src/common/decorators/request.decorator';

@Resolver(() => Auth)
export class AuthResolver {
  constructor(
    private readonly auth: AuthService,
    private eventEmitter: EventEmitter2
  ) {}

  @Mutation(() => Auth)
  async signup(@Args('data') data: SignupInput) {
    data.email = data.email.toLowerCase();
    const { accessToken, refreshToken } = await this.auth.createUser(data);
    return {
      accessToken,
      refreshToken,
    };
  }

  @Mutation(() => Auth)
  async login(
    @Args('data') { email, password }: LoginInput,
    @RequestEntityGql() request: Request
  ) {
    const { accessToken, refreshToken, id } = await this.auth.login(
      email.toLowerCase(),
      password
    );

    // emit device registration
    const { agent, ip } = extractAgentIpFromRequest(request);
    this.eventEmitter.emit('user.login', new UserLoginEvent(id, agent, ip));

    return {
      accessToken,
      refreshToken,
    };
  }

  @UseGuards(GqlJwtRefreshGuard)
  @Mutation(() => LogoutResponse)
  async logout(@Args() { token }: RefreshTokenInput): Promise<LogoutResponse> {
    await this.auth.logout(token);
    return {
      message: 'Successfully logged out',
    };
  }

  @UseGuards(GqlJwtRefreshGuard)
  @Mutation(() => Token)
  async refreshToken(@Args() { token }: RefreshTokenInput) {
    return this.auth.refreshToken(token);
  }

  @ResolveField('user', () => User)
  async user(@Parent() auth: Auth) {
    return await this.auth.getUserFromToken(auth.accessToken);
  }
}
