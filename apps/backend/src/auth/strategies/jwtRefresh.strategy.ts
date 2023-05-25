import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { AuthService } from '../auth.service';
import { RefreshJwtDto } from '../dto/refreshJwt.dto';
import { RefreshTokenInput } from '../dto/refresh-token.input';
import { extractAgentIpFromRequest } from 'src/common/http/requestInterceptor';

/**
 * Extracts the jwt from a graphql request body
 * @param req Http Request
 */
const gqlBodyExtractor = (req: Request) => {
  const body = req.body as {
    query: string;
    variables: RefreshTokenInput;
  };
  return body.variables.token;
};

@Injectable()
export class JwtRefreshTokenStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh-token'
) {
  constructor(configService: ConfigService, private authService: AuthService) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        gqlBodyExtractor,
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
      secretOrKey: configService.get('JWT_REFRESH_SECRET'),
      passReqToCallback: true,
    });
  }

  async validate(request: Request, payload: RefreshJwtDto) {
    const { tokenId } = payload;
    const { ip } = extractAgentIpFromRequest(request);
    return this.authService.getUserIfRefreshTokenIsValid(tokenId, ip);
  }
}
