import { Controller, Get, Req, Res, UseGuards } from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { GithubOauthGuard } from './guards/github.guard';
import { User } from '@prisma/client';

@Controller('auth/github')
export class GithubOauthController {
  constructor(private authService: AuthService) {}

  @Get()
  @UseGuards(GithubOauthGuard)
  async githubAuth() {
    // pass
  }

  @Get('callback')
  @UseGuards(GithubOauthGuard)
  async githubAuthCallback(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ) {
    const user = req.user as User;

    const { accessToken, refreshToken } = await this.authService.generateTokens(
      {
        userId: user.id,
      }
    );
    return { accessToken, refreshToken };
  }
}
