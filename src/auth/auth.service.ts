import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthSignInDto, AuthSignUpDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable({})
export class AuthService {
  constructor(private prisma: PrismaService) {}
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
    delete user.hash;
    return user;
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

      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('credentials are already taken');
        }
      }
    }
  }
}
