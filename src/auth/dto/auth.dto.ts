import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class AuthSignUpDto {
  @IsEmail()
  email: string;
  @IsString()
  @IsNotEmpty()
  password: string;
}

export class AuthSignInDto {
  @IsEmail()
  email: string;
  @IsString()
  @IsNotEmpty()
  password: string;
}
