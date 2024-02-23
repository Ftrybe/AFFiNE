import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Header,
  Post,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { omit } from 'lodash-es';

import { PaymentRequiredException, URLHelper } from '../../fundamentals';
import { UsersService } from '../users';
import { Public } from './guard';
import { AuthService } from './service';
import { parseAuthUserSeqNum, SessionService } from './session';

interface SignInCredential {
  email: string;
  password?: string;
}

@Controller('/auth')
export class AuthController {
  constructor(
    private readonly url: URLHelper,
    private readonly auth: AuthService,
    private readonly user: UsersService,
    private readonly session: SessionService
  ) {}

  @Public()
  @Post('/sign-in')
  @Header('content-type', 'application/json')
  async signIn(
    @Req() req: Request,
    @Res() res: Response,
    @Body() credential: SignInCredential,
    @Query('redirect_uri') redirectUri = this.url.home
  ) {
    const canSignIn = await this.auth.canSignIn(credential.email);
    if (!canSignIn) {
      throw new PaymentRequiredException(
        `You don't have early access permission\nVisit https://community.affine.pro/c/insider-general/ for more information`
      );
    }

    if (credential.password) {
      const session = await this.session.signIn(
        credential.email,
        credential.password,
        req.cookies[this.session.sessionCookieName]
      );

      res.cookie(this.session.sessionCookieName, session.sessionId, {
        expires: session.expiresAt ?? void 0, // expiredAt is `string | null`
        ...this.session.cookieOptions,
      });

      const user = await this.user.findUserById(session.userId);

      res.send(omit(user, 'password'));
    } else {
      // send email magic link
      const user = await this.user.findOrCreateUser(credential.email);
      await this.auth.sendSignInEmail(user, redirectUri);
      res.send({
        email: credential.email,
      });
    }
  }

  @Get('/sign-out')
  async signOut(
    @Req() req: Request,
    @Res() res: Response,
    @Query('redirect_uri') redirectUri?: string
  ) {
    const session = await this.session.signOut(
      req.cookies[this.session.sessionCookieName],
      parseAuthUserSeqNum(req.headers[this.session.authUserSeqCookieName])
    );

    if (session) {
      res.cookie(this.session.sessionCookieName, session.id, {
        expires: session.expiresAt ?? void 0, // expiredAt is `string | null`
        ...this.session.cookieOptions,
      });
    } else {
      res.clearCookie(this.session.sessionCookieName);
    }

    if (redirectUri) {
      return this.url.safeRedirect(res, redirectUri);
    } else {
      return res.send(null);
    }
  }

  @Public()
  @Get('/challenge')
  async challenge() {
    return this.session.createChallengeToken();
  }

  @Public()
  @Get('/magic-link')
  async magicLinkSignIn(
    @Req() req: Request,
    @Res() res: Response,
    @Query('token') token?: string,
    @Query('redirect_uri') redirectUri = this.url.home
  ) {
    if (!token) {
      throw new BadRequestException('Invalid Sign-in mail Token');
    }

    const user = await this.auth.verifyMagicLinkToken(token);

    if (!user) {
      throw new BadRequestException('Invalid Sign-in mail Token');
    }

    const session = await this.session.createSession(
      user,
      req.cookies[this.session.sessionCookieName]
    );

    res.cookie(this.session.sessionCookieName, session.sessionId, {
      expires: session.expiresAt ?? void 0,
      ...this.session.cookieOptions,
    });

    return this.url.safeRedirect(res, redirectUri);
  }
}
