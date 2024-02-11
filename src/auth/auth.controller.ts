import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthSignInDto, AuthSignUpDto } from './dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}
  @Post('/signup')
  signUp(@Body() body: AuthSignUpDto) {
    return this.authService.signUp(body);
  }

  @Post('/signin')
  signIn(@Body() body: AuthSignInDto) {
    return this.authService.signIn(body);
  }
}
