import { Injectable } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import { UserLoginEvent } from '../events/userLogin.payload';
import { PrismaService } from 'nestjs-prisma';

@Injectable()
export class UserLoginListener {
  constructor(private readonly prisma: PrismaService) {}

  @OnEvent('user.login', { async: true, promisify: true })
  async handleOrderCreatedEvent(event: UserLoginEvent) {
    const user = await this.prisma.user.findUniqueOrThrow({
      where: {
        id: event.userId,
      },
    });

    if (user) {
      // register device login
      await this.prisma.device.upsert({
        create: {
          agent: event.agent,
          ip: event.ip,
          userId: user.id,
        },
        update: {
          lastLogin: new Date(),
        },
        where: {
          ip: event.ip,
        },
      });
    }
  }
}
