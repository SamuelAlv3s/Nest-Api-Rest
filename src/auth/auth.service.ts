import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';

@Injectable()
export class AuthService {
  constructor(private prismaService: PrismaService) {}

  async signup(dto: AuthDto) {
    const { email, password } = dto;
    const hashedPassword = await argon.hash(password);
    const user = await this.prismaService.user.create({
      data: {
        email,
        hash: hashedPassword,
      },
      // select: {
      //   id: true,
      //   email: true,
      //   createdAt: true,
      // },
    });

    delete user.hash;
    return user;
  }

  signin() {}
}
