import { Injectable } from '@nestjs/common';
import { AuthGuard, PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AuthService } from '../auth.service';
import { User } from 'src/user/entities/user.entity';

export class LocalAuthGuard extends AuthGuard('codefactory') {}

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy, 'codefactory') {
  constructor(private readonly authService: AuthService) {
    super({
      usernameField: 'email',
    });
  }

  /**
   * LocalStrategy
   *
   * validate: username, password
   *
   * return -> Request();
   */
  async validate(email: string, password: string): Promise<User> {
    const user = await this.authService.authenticate(email, password);
    return user;
  }
}
