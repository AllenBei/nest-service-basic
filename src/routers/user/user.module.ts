import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';

import { User } from '@app/entities';
import { UserService } from './user.service';
import { AuthModule } from '@app/shared/auth';
import { RedisModule } from '@app/shared/redis';
import { UserController } from './user.controller';

@Module({
    imports: [TypeOrmModule.forFeature([User]), AuthModule, RedisModule],

    controllers: [UserController],

    providers: [UserService],
})
export class UserModule {}
