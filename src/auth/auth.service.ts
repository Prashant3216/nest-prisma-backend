import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthSignInDto, AuthSignUpDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable({})
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}
  async signIn(body: AuthSignInDto) {
    //find the user
    const user = await this.prisma.user.findUnique({
      where: {
        email: body.email,
      },
    });
    if (!user) {
      throw new ForbiddenException('Credentials Incorrect');
    }
    // check the password

    const pwMatch = await argon.verify(user.hash, body.password);

    if (!pwMatch) {
      throw new ForbiddenException('Password Incorrect');
    }

    return { access_token: await this.signedToken(user.id, user.email) };
  }
  async signUp(body: AuthSignUpDto) {
    //generate the hash password
    const hash = await argon.hash(body.password);
    try {
      //save the user in the data base
      const user = await this.prisma.user.create({
        data: {
          email: body.email,
          hash,
        },
        select: {
          email: true,
          id: true,
        },
      });
      //return the user details

      return { access_token: await this.signedToken(user.id, user.email) };
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('credentials are already taken');
        }
      }
    }
  }

  signedToken(userId: number, email: string): Promise<string> {
    const payload = {
      sub: userId,
      email,
    };
    const jwtSecret = this.configService.get('JWT_SECRET');

    return this.jwtService.signAsync(payload, {
      secret: jwtSecret,
      expiresIn: '15m',
    });
  }
}
