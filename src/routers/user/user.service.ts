// import * as bcrypt from 'bcrypt';
// import * as svgCaptcha from 'svg-captcha';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Repository, DataSource } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';

import { UserLoginDto } from './user.dto';
import { AuthService } from '@app/shared/auth';
import { RedisService } from '@app/shared/redis';
import { FailException } from '@app/exceptions/fail.exception';
import { ERROR_CODE } from '@app/constants/error-code.constant';
import { Access, RoleAccess, User, UserRole } from '@app/entities';
import { ACCESS_TYPE } from '@app/routers/manage/access-manage/access-manage.constant';
import { USER_STATUS, USER_ADMIN } from './user.constant';
import { userLoginCachePrefix, } from './user.helper';
import { IUserInfo, IUserLoginResponse, IUserInfoAccess } from './user.interface';
import { RESPONSE_DEFAULT_TEXT } from '@app/constants/http.constant';

@Injectable()
export class UserService {
    public constructor(
        private redisService: RedisService,
        private configService: ConfigService,
        // private emailerService: EmailerService,
        private authService: AuthService,
        private readonly dataSource: DataSource,
        @InjectRepository(User) private readonly userRepository: Repository<User>,
    ) { }


    /**
     * 注册用户
     * @param unionId
     * @param openId
     * @param phone
     * @param baid
     * @param password
     */
    public async registerUser(unionid: string): Promise<void> {
        // const emailHandle = userRegisterEmailPrefix(USER_EMAIL_TYPE.REGISTER, email);
        // //验证注册时邮箱验证码的正确性
        // const emailCode = await this.redisService.get<string>(emailHandle);

        // if (!emailCode || emailCode !== code) throw new FailException(ERROR_CODE.USER.USER_EMAIL_CODE_ERROR);

        // 查询unionid存在的用户
        const currentUser = await this.userRepository.findOneBy({ unionid });

        // 如果用户名或者邮箱已经存在
        if (currentUser) throw new FailException(ERROR_CODE.USER.USER_UNION_ID_EXISTS, { messgae: RESPONSE_DEFAULT_TEXT.ACCOUNT_EXISTS });

        //因小程序自带权限鉴定功能，unionId 为处理后的数据。所以早期为 null，后续salt 可用于的密码。
        // const salt = this.configService.get('app.userPwdSalt') || '';
        // const unionidHash = await bcrypt.hash(unionid, salt);

        const user = this.userRepository.create({
            username: `用户${unionid}`,
            password: null,
            unionid,
        });

        await this.userRepository.save(user);
        // 删除掉指定的验证缓存
        // await this.redisService.delete(emailHandle);
    }

    // /**
    //  * 修改用户密码
    //  * @param email
    //  * @param password
    //  * @param code
    //  */
    // public async modifyUserPassword(email: string, password: string, code: string): Promise<void> {
    //     // 获取缓存中存储的code
    //     const storeCode = await this.redisService.get<string>(userRegisterEmailPrefix(USER_EMAIL_TYPE.PASSWORD_RESET, email));

    //     if (!storeCode || storeCode !== code) throw new FailException(ERROR_CODE.USER.USER_EMAIL_CODE_ERROR);

    //     const targetUser = await this.userRepository.findOneBy({ email });
    //     if (!targetUser) throw new FailException(ERROR_CODE.USER.USER_NOT_EXISTS);

    //     const salt = this.configService.get('app.userPwdSalt') || '';
    //     targetUser.password = await bcrypt.hash(password, salt);

    //     await this.userRepository.save(targetUser);
    //     // 修改密码后，需要用户重新登录
    //     await this.redisService.delete(userLoginCachePrefix(targetUser.id, email));
    // }

    // /**
    //  * 创建验证码
    //  * @param hash 刷新时需要把原来的hash传过来
    //  * @param width
    //  * @param height
    //  * @param size
    //  * @param fontSize
    //  * @param background
    //  * @returns
    //  */
    // public async createCaptcha(
    //     hash: string,
    //     width: number,
    //     height: number,
    //     size: number,
    //     fontSize: number,
    //     background: string,
    // ): Promise<IUserCaptchaResponse> {
    //     const { text, data } = svgCaptcha.create({
    //         size,
    //         fontSize,
    //         width,
    //         height,
    //         background,
    //     });

    //     const captchaId = hash && (await this.redisService.exists(userLoginCaptchaPrefix(hash))) ? hash : nanoid();

    //     await this.redisService.set(userLoginCaptchaPrefix(captchaId), text.toLocaleLowerCase(), USER_CAPTCHA_EXPIRE);

    //     const dataSvgImg = `data:image/svg+xml;base64,${Buffer.from(data).toString('base64')}`;

    //     return {
    //         hashId: captchaId,
    //         captcha: dataSvgImg,
    //     };
    // }

    /**
     * 用户登录
     * @param loginInfo
     * @returns
     */
    public async login(loginInfo: UserLoginDto): Promise<IUserLoginResponse> {
        const { unionid } = loginInfo;

        // 比对登录验证码
        // const captchaKey = userLoginCaptchaPrefix(hashId);
        // const storeLoginCaptcha = await this.redisService.get<string>(captchaKey);
        // if (!storeLoginCaptcha || storeLoginCaptcha !== code) throw new FailException(ERROR_CODE.USER.USER_CAPTCHA_ERROR);

        // 查询用户以及相关的角色
        // const subQuery = this.dataSource
        //     .createQueryBuilder(UserRole, 'ur')
        //     .select(['ur.userId AS userId', 'GROUP_CONCAT(ur.role) AS roles'])
        //     .groupBy('ur.userId')
        //     .getQuery();

        // const salt = this.configService.get('app.userPwdSalt') || '';
        // const unionidHash = await bcrypt.hash(unionid, salt);
        // const validatePassword = await bcrypt.compare(currentUser.unionid, unionidHash);

        // 如果用户不存在或者密码错误，则不允许进行登录
        // if (!currentUser || !validatePassword)

        const currentUser = await this.userRepository
            .createQueryBuilder('user')
            .select([
                'user.id AS id',
                'user.unionid AS unionid',
                'user.username AS username',
                'user.status AS status',
                // 'user.admin AS admin',
                // 'ur.roles AS roles',
            ])
            // .leftJoin(`(${subQuery})`, 'ur', 'ur.userId=user.id')
            .where('user.unionid=:unionid', { unionid })
            .getRawOne();

        if (!currentUser)
            throw new FailException(ERROR_CODE.USER.USER_LOGIN_ERROR);

        const { id, username, status } = currentUser;

        // 如果用户的状态不正常，那么也不允许正常登录

        if (status !== USER_STATUS.NORMAL) throw new FailException(ERROR_CODE.USER.USER_STATUS_FORBIDDEN);

        // 返回服务端的token
        const token = this.authService.genToken({ id, username, unionid });

        // 如果不配置，那么则不设置过期时间
        const expireTime = this.configService.get<number>('app.loginExpiresIn');

        // 需要把相关的信息存入到redis数据库中, 并且设置过期时间
        await this.redisService.set(
            userLoginCachePrefix(unionid),
            {
                id,
                username,
                unionid,
                token,
                // admin,
                // roleIds: roles ? roles.split(',').map((item: string) => Number(item)) : [],
            },
            expireTime,
        );

        // 删除已验证的验证码
        // await this.redisService.delete(captchaKey);

        return {
            token,
        };
    }

    /**
     * 用户登出
     * @param id
     * @param unionid
     */
    public async logout(unionid: string): Promise<void> {
        const redisHandle = userLoginCachePrefix(unionid);

        await this.redisService.delete(redisHandle);
    }

    /**
     * 查询用户自身信息
     * @param userId
     * @returns
     */
    public async queryUserProfile(userId: number): Promise<Omit<IUserInfo, 'status'>> {
        const userProfile = await this.userRepository.findOne({
            select: ['id', 'unionid', 'baid', 'username', 'email', 'avatar', 'gender', 'admin'],
            where: { id: userId },
        });

        if (!userProfile) throw new FailException(ERROR_CODE.USER.USER_PROFILE_ERROR);

        // let access: IUserInfoAccess[];

        // // 如果是管理员权限
        // if (userProfile.admin === USER_ADMIN.ADMIN) {
        //     access = await this.dataSource
        //         .createQueryBuilder(Access, 'access')
        //         .select(['access.name AS name', 'access.routerName AS routerName', 'access.routerUrl AS routerUrl'])
        //         .where('access.type=:type', { type: ACCESS_TYPE.MENU })
        //         .getRawMany();
        // } else {
        //     const subQuery = this.dataSource
        //         .createQueryBuilder(UserRole, 'userRole')
        //         .select('userRole.role AS id')
        //         .where('userRole.userId=:userId')
        //         .getQuery();

        //     access = await this.dataSource
        //         .createQueryBuilder(RoleAccess, 'roleAccess')
        //         .select(['access.name AS name', 'access.routerName AS routerName', 'access.routerUrl AS routerUrl'])
        //         .leftJoin(Access, 'access', 'roleAccess.access=access.id')
        //         .where(`access.type=:type AND roleAccess.roleId IN (${subQuery})`)
        //         .setParameters({ userId, type: ACCESS_TYPE.MENU })
        //         .getRawMany();
        // }

        const { id, unionid, baid, username, avatar, gender } = userProfile

        return {
            id, unionid, baid, username, avatar, gender
            // access
        };
    }
}
