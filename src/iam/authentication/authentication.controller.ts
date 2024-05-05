import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { AuthenticationService } from './authentication.service';
import { SignUpDto } from './dto/sign-up.dto';
import { SignInDto } from './dto/sign-in.dto';
import { Auth } from './decorators/auth.decorator';
import { AuthType } from './enums/auth-type.enum';
import { RefreshTokenDto } from './dto/refresh-token.dto';
// import { Response } from 'express';

@Auth(AuthType.None)
@Controller('authentication')
export class AuthenticationController {
  constructor(private readonly authenticationService: AuthenticationService) {}

  @Post('sign-up')
  signUp(@Body() signUpDto: SignUpDto) {
    return this.authenticationService.signUp(signUpDto);
  }

  /* TODO: This method is preferable for security reasons,
   *  set a cookie instead of returning token in body
   */
  //   @HttpCode(HttpStatus.OK)
  //   @Post('sign-in')
  //   async signIn(
  //     @Res({ passthrough: true }) response: Response,
  //     @Body() signInDto: SignInDto,
  //   ) {
  //     const accessToken = await this.authenticationService.signIn(signInDto);
  //     response.cookie('accessToken', accessToken, {
  //       secure: true,
  //       httpOnly: true,
  //       sameSite: true,
  //     });
  //   }

  @HttpCode(HttpStatus.OK)
  @Post('sign-in')
  signIn(@Body() signInDto: SignInDto) {
    return this.authenticationService.signIn(signInDto);
  }

  @HttpCode(HttpStatus.OK)
  @Post('refresh-tokens')
  refreshTokens(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.authenticationService.refreshTokens(refreshTokenDto);
  }
}
