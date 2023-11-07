import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

import { TimeEntityBase } from './lib/time-entity-base';
import { USER_STATUS, USER_ADMIN } from '@app/routers/user/user.constant';

@Entity()
export class User extends TimeEntityBase {
    @PrimaryGeneratedColumn('increment', { comment: 'user id' })
    id: number;

    @Column('varchar', { nullable: false, length: 100, comment: 'unionid，微信 ID' })
    unionid: string;

    @Column('varchar', { nullable: true, length: 100, comment: 'baid，万代 ID' })
    baid: string;

    @Column('varchar', { unique: true, length: 30, nullable: false, comment: 'username' })
    username: string;

    @Column('varchar', { nullable: true, length: 80, comment: 'password' })
    password: string | null;

    @Column('varchar', { nullable: true, length: 100, comment: 'email' })
    email: string;

    @Column('tinyint', { unsigned: true, nullable: false, default: USER_STATUS.NORMAL, comment: 'status' })
    status: USER_STATUS;

    @Column('varchar', { nullable: true, length: 200, comment: 'avatar' })
    avatar: string;

    @Column('tinyint', { nullable: false, default:0, comment: 'gender' })
    gender: number;

    @Column('tinyint', { unsigned: true, nullable: false, default: USER_ADMIN.NORMAL, comment: 'admin' })
    admin: USER_ADMIN;
}
