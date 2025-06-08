import {
  Controller,
  Get,
  Headers,
  Post,
  Request,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
//import { AuthGuard } from '@nestjs/passport';
import { LocalAuthGuard } from './strategy/local.strategy';
import { RequestWithUser } from 'src/common/interfaces/request-with-user.interface';
import { JwtAuthGuard } from './strategy/jwt.strategy';
import { Public } from './decorator/public.decorator';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('register')
  /// authorization: Basic $token
  registerUser(@Headers('authorization') token: string) {
    return this.authService.register(token);
  }

  @Public()
  @Post('login')
  /// authorization: Basic $token
  loginUser(@Headers('authorization') token: string) {
    return this.authService.login(token);
  }

  //@Post('token/access')
  // async rotateAccessToken(@Headers('authorization') token: string) {
  //   const payload = await this.authService.parseBearerToken(token, true);
  //   return {
  //     accessToken: await this.authService.issueToken(
  //       { id: payload.sub, role: payload.role },
  //       false,
  //     ),
  //   };
  // }

  /// bearer token middleware 사용한 경우
  @Post('token/access')
  async rotateAccessToken(@Request() req: RequestWithUser) {
    return {
      accessToken: await this.authService.issueToken(req.user, false),
    };
  }

  //@UseGuards(AuthGuard('codefactory'))
  @UseGuards(LocalAuthGuard)
  @Post('login/passport')
  async loginUserPassport(@Request() req: RequestWithUser) {
    return {
      refreshToken: await this.authService.issueToken(req.user, true),
      accessToken: await this.authService.issueToken(req.user, false),
    };
  }

  @UseGuards(JwtAuthGuard)
  @Get('private')
  private(@Request() req: RequestWithUser) {
    return req.user;
  }
}
