import { IsEmail, IsMobilePhone, IsString, Length } from 'class-validator';
import { ConfirmPassword } from 'src/common/decorators/password.decorator';

export class SignupDto {
  @IsString()
  first_name: string;

  @IsString()
  last_name: string;

  @IsMobilePhone('fa-IR', {}, { message: 'your phone number is incorrect' })
  mobile: string;

  @IsString()
  @IsEmail({ host_whitelist: ['gmail.com', 'yahoo.com'] }, { message: 'your email format is incorrect' })
  email: string;

  @IsString()
  @Length(6, 20, { message: 'your password is incorrect' })
  password: string;

  @IsString()
  @ConfirmPassword('password')
  confirm_password: string;
}

export class LoginDto {
  @IsString()
  @IsEmail({ host_whitelist: ['gmail.com', 'yahoo.com'] }, { message: 'your email format is incorrect' })
  email: string;

  @IsString()
  @Length(6, 20, { message: 'your password is incorrect' })
  password: string;
}
