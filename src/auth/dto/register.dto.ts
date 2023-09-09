import { IsEmail, IsString, MinLength } from 'class-validator';

export class RegisterDto {
  @IsEmail()
  readonly email: string;

  @IsString()
  readonly name: string;

  @MinLength(6)
  readonly password: string;
}
