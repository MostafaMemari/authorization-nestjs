import { BadRequestException, ConflictException, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { UserEntity } from '../user/entities/user.entity';
import { Repository } from 'typeorm';
import { OtpEntity } from '../user/entities/otp.entity';
import { CheckOtpDto, SendOtpDto } from './dto/otp.dto';
import { randomInt } from 'crypto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { TokensPayLoad } from './types/payload';
import { LoginDto, SignupDto } from './dto/basic.dto';
import { compareSync, genSaltSync, hashSync } from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(UserEntity) private userRepository: Repository<UserEntity>,
    @InjectRepository(OtpEntity) private otpRepository: Repository<OtpEntity>,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async sendOtp(otpDto: SendOtpDto) {
    const { mobile } = otpDto;
    let user = await this.userRepository.findOneBy({ mobile });

    if (!user) {
      user = this.userRepository.create({ mobile });
      user = await this.userRepository.save(user);
    }
    await this.createOtpForUser(user);
    return { message: 'send code successfully' };
  }
  async checkOtp(otpDto: CheckOtpDto) {
    const { code, mobile } = otpDto;

    const user = await this.userRepository.findOne({ where: { mobile }, relations: { otp: true } });

    const dateNow = new Date();
    if (!user || !user?.otp) throw new UnauthorizedException('Not Found Account');

    const otp = user?.otp;

    if (otp?.code !== code) throw new UnauthorizedException('otp code is incorrect');
    if (otp.expires_in < dateNow) throw new UnauthorizedException('otp code is expired');
    if (!user.mobile_verify) await this.userRepository.update({ id: user.id }, { mobile_verify: true });

    const { accessToken, refreshToken } = this.makeTokensForUser({ id: user.id, mobile });

    return { accessToken, refreshToken, message: 'You logged-in successfully' };
  }
  async signup(signupDto: SignupDto) {
    const { first_name, last_name, email, password, confirm_password, mobile } = signupDto;
    await this.checkEmail(email);
    await this.checkMobile(mobile);

    const user = await this.userRepository.create({
      first_name,
      last_name,
      mobile,
      email,
      password: this.hashPassword(password),
      mobile_verify: false,
    });
    await this.userRepository.save(user);
    return {
      message: 'user signup successfully',
    };
  }
  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;
    const user = await this.userRepository.findOneBy({ email });

    if (!user) throw new UnauthorizedException('username or password is incorrect');

    if (!compareSync(password, user.password))
      throw new UnauthorizedException('username or password is incorrect');

    const { accessToken, refreshToken } = this.makeTokensForUser({ mobile: user.mobile, id: user.id });

    return {
      accessToken,
      refreshToken,
      message: 'you logged-in successfully',
    };
  }

  async checkEmail(email: string) {
    const user = await this.userRepository.findOneBy({ email });
    if (user) throw new ConflictException('email is already exist');
  }
  async checkMobile(mobile: string) {
    const user = await this.userRepository.findOneBy({ mobile });
    if (user) throw new ConflictException('mobile is already exist');
  }

  async createOtpForUser(user: UserEntity) {
    const code = randomInt(10000, 99999).toString();

    const expiresIn = new Date(new Date().getTime() + 1000 * 60 * 2);
    let otp = await this.otpRepository.findOneBy({ userId: user.id });
    if (otp) {
      if (otp.expires_in > new Date()) throw new BadRequestException('otp code not expired');
      otp.code = code;
      otp.expires_in = expiresIn;
    } else {
      otp = this.otpRepository.create({
        code,
        expires_in: expiresIn,
        userId: user.id,
      });
    }
    otp = await this.otpRepository.save(otp);
    user.otpId = otp.id;
    await this.userRepository.save(user);
  }
  makeTokensForUser(payload: TokensPayLoad) {
    const accessToken = this.jwtService.sign(payload, {
      secret: this.configService.get('Jwt.accessTokenSecret'),
      expiresIn: '30d',
    });
    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get('Jwt.refreshTokenSecret'),
      expiresIn: '1y',
    });

    return {
      accessToken,
      refreshToken,
    };
  }

  async validateAccessToken(token: string) {
    try {
      const payload = this.jwtService.verify<TokensPayLoad>(token, {
        secret: this.configService.get('Jwt.accessTokenSecret'),
      });
      if (typeof payload === 'object' && payload?.id) {
        const user = await this.userRepository.findOneBy({ id: payload.id });
        if (!user) {
          throw new UnauthorizedException('login on your account');
        }
        return user;
      }
      throw new UnauthorizedException('login on your account');
    } catch (error) {
      throw new UnauthorizedException('login on your account');
    }
  }

  hashPassword(password: string) {
    const salt = genSaltSync(10);
    return hashSync(password, salt);
  }
}
