import {
  BadRequestException,
  Injectable,
  NestMiddleware,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService, TokenExpiredError } from '@nestjs/jwt';
import { NextFunction, Request, Response } from 'express';
import { envVariableKeys } from 'src/common/const/env.const';
import { JwtPayload } from '../strategy/jwt.strategy';

@Injectable()
export class BearerTokenMiddleware implements NestMiddleware {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}
  async use(req: Request, res: Response, next: NextFunction) {
    /// Bearer $token
    const authHeader = req.headers['authorization'];

    if (!authHeader) {
      next();
      return;
    }

    try {
      const token = this.validateBearerToken(authHeader);

      const decoded: JwtPayload = this.jwtService.decode(token);
      if (!decoded || typeof decoded !== 'object' || !('type' in decoded)) {
        throw new UnauthorizedException('유효하지 않은 토큰입니다!');
      }
      const decodedPayload = decoded;

      if (
        decodedPayload.type !== 'refresh' &&
        decodedPayload.type !== 'access'
      ) {
        throw new UnauthorizedException('잘못된 토큰입니다.');
      }

      const secretKey =
        decodedPayload.type === 'refresh'
          ? envVariableKeys.refreshTokenSecret
          : envVariableKeys.accessTokenSecret;

      const payload: JwtPayload = await this.jwtService.verifyAsync(token, {
        secret: this.configService.get<string>(secretKey),
      });

      req.user = payload;
      next();
    } catch (e) {
      if (e instanceof TokenExpiredError) {
        throw new UnauthorizedException('토큰이 만료되었습니다!');
      }

      //throw new UnauthorizedException('토큰이 만료되었습니다!');
      /// Guard 에서 토큰검증을 했기 때문에 여기서는 next() 로 넘겨주는 것으로 변경(PUblic() 인 경우 토큰 검증 안하도록)
      next();
    }
  }

  validateBearerToken(rawToken: string) {
    const bearerSplit = rawToken.split(' ');

    if (bearerSplit.length !== 2) {
      throw new BadRequestException('토큰 포맷이 잘못됐습니다!');
    }

    const [bearer, token] = bearerSplit;

    if (bearer.toLowerCase() != 'bearer') {
      throw new BadRequestException('토큰 포맷이 잘못됐습니다!');
    }

    return token;
  }
}
