import { PrismaService } from 'nestjs-prisma';
import { Prisma, User } from '@prisma/client';
import {
  Injectable,
  NotFoundException,
  BadRequestException,
  ConflictException,
  UnauthorizedException,
  InternalServerErrorException,
  ForbiddenException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PasswordService } from './password.service';
import { SignupInput } from './dto/signup.input';
import { Token } from './models/token.model';
import { SecurityConfig } from 'src/common/configs/config.interface';
import { OauthSignupInput } from './dto/oauthSignup.input';
import { JwtDto } from './dto/jwt.dto';
import { RefreshJwtDto } from './dto/refreshJwt.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
    private readonly passwordService: PasswordService,
    private readonly configService: ConfigService
  ) {}

  async createUser(payload: SignupInput | OauthSignupInput): Promise<Token> {
    const hashedPassword = await this.passwordService.hashPassword(
      payload.password
    );

    try {
      const user = await this.prisma.user.create({
        data: {
          ...payload,
          password: hashedPassword,
          role: 'USER',
        },
      });

      return this.generateTokens({
        userId: user.id,
      });
    } catch (e) {
      if (
        e instanceof Prisma.PrismaClientKnownRequestError &&
        e.code === 'P2002'
      ) {
        throw new ConflictException(`Email ${payload.email} already used.`);
      }
      throw new Error(e);
    }
  }

  async login(email: string, password: string): Promise<Token & User> {
    const user = await this.prisma.user.findUnique({ where: { email } });

    if (!user) {
      throw new NotFoundException(`No user found for email: ${email}`);
    }

    const passwordValid = await this.passwordService.validatePassword(
      password,
      user.password
    );

    if (!passwordValid) {
      throw new BadRequestException('Invalid password');
    }

    const { accessToken, refreshToken } = await this.generateTokens({
      userId: user.id,
    });

    return {
      ...user,
      accessToken,
      refreshToken,
    };
  }

  validateUser(userId: string): Promise<User> {
    return this.prisma.user.findUnique({ where: { id: userId } });
  }

  getUserFromToken(token: string): Promise<User> {
    const id = this.jwtService.decode(token)['userId'];
    return this.prisma.user.findUnique({ where: { id } });
  }

  async generateTokens(payload: { userId: string }): Promise<Token> {
    const accessToken = this.generateAccessToken(payload);
    const refreshToken = await this.generateRefreshToken(payload);
    return {
      accessToken,
      refreshToken: refreshToken.token,
    };
  }

  private generateAccessToken(payload: { userId: string }): string {
    return this.jwtService.sign(payload);
  }

  private async generateRefreshToken(payload: { userId: string }) {
    const securityConfig = this.configService.get<SecurityConfig>('security');
    const tokenId = crypto.randomUUID();
    const token = this.jwtService.sign(
      { ...payload, tokenId },
      {
        secret: this.configService.get('JWT_REFRESH_SECRET'),
        expiresIn: securityConfig.refreshIn,
      }
    );
    const { exp } = this.validateRefreshToken(token);
    const tokenEntity = await this.prisma.refreshToken.create({
      data: {
        id: tokenId,
        refreshToken: this.passwordService.hashPasswordSync(token),
        userId: payload.userId,
        reuseCount: 0,
        exp: new Date(exp * 1000),
      },
    });
    return {
      entity: tokenEntity,
      token,
    };
  }

  refreshToken(token: string) {
    try {
      const { userId } = this.validateRefreshToken(token);
      return this.generateTokens({
        userId,
      });
    } catch (e) {
      throw new UnauthorizedException();
    }
  }

  async getUserIfRefreshTokenIsValid(refreshTokenId: string, ip?: string) {
    try {
      const foundToken = await this.prisma.refreshToken.findUnique({
        where: {
          id: refreshTokenId,
        },
        include: {
          User: {
            include: {
              devices: true,
            },
          },
        },
      });

      if (foundToken == null) {
        //refresh token is valid but the id is not in database
        throw new UnauthorizedException();
      }

      if (foundToken.reuseCount > 0) {
        // token reuse, invalidate and delete all refresh tokens
        await this.prisma.refreshToken.deleteMany({
          where: {
            userId: foundToken.User.id,
          },
        });
        throw new UnauthorizedException();
      }

      if (ip) {
        // check if the token is reused from another address by comparing request's ip with registered devices on login
        const devices = foundToken.User.devices ?? [];
        const isIpInDevices = devices.some((d) => d.ip === ip);
        if (!isIpInDevices) {
          // token reuse from another address, invalidate all refresh tokens
          await this.prisma.refreshToken.deleteMany({
            where: {
              userId: foundToken.User.id,
            },
          });
          throw new UnauthorizedException();
        }
      }

      // increment reuse counter
      await this.prisma.refreshToken.update({
        where: {
          id: refreshTokenId,
        },
        data: {
          reuseCount: foundToken.reuseCount + 1,
        },
      });

      return foundToken.User;
    } catch (e) {
      throw new UnauthorizedException();
    }
  }

  async logout(refreshToken: string) {
    const { tokenId } = this.validateRefreshToken(refreshToken);
    if (tokenId) {
      await this.prisma.refreshToken.delete({
        where: {
          id: tokenId,
        },
      });
    }
  }

  validateRefreshToken(token: string) {
    try {
      return this.jwtService.verify<RefreshJwtDto>(token, {
        secret: this.configService.get('JWT_REFRESH_SECRET'),
      });
    } catch (e) {
      throw new UnauthorizedException();
    }
  }
}
