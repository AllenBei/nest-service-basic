import { Body, Controller, Inject, Post, Get, Query, Put } from '@nestjs/common';

import { IPayLoad } from '@app/shared/auth';
import { UserService } from './user.service';
import { User } from '@app/decorators/user.decorator';
import { UseLoginAccessInterface, UsePublicInterface } from '@app/decorators/public.decorator';
import { RegisterUserDto, UserLoginDto } from './user.dto';

@Controller('user')
export class UserController {

    constructor(private readonly userService: UserService) { }


    // 注册接口，无需进行登录验证
    @UsePublicInterface()
    @Post('register')
    public async registerUser(@Body() registerInfo: RegisterUserDto) {
        const { unionid } = registerInfo;

        await this.userService.registerUser(unionid);
    }

    // 修改密码
    // @UsePublicInterface()
    // @Put('password-reset')
    // public async modifyUserPassword(@Body() modifyInfo: ModifyUserPwdDto) {
    //     const { password, email } = modifyInfo;

    //     await this.userService.modifyUserPassword(email, password);
    // }

    // 登录验证码
    // @UsePublicInterface()
    // @Get('captcha')
    // public loginCaptcha(@Query() captchaInfo: CaptchaInfoDto) {
    //     const { hashId, w, h, s, fs, bg } = captchaInfo;

    //     return this.userService.createCaptcha(hashId, w, h, s, fs, bg);
    // }

    // 用户登录接口
    @UsePublicInterface()
    @Post('login')
    public userLogin(@Body() loginInfo: UserLoginDto) {
        return this.userService.login(loginInfo);
    }

    // 用户登出
    @UseLoginAccessInterface()
    @Post('logout')
    public async userLogout(@User() userInfo: IPayLoad) {
        const { unionid } = userInfo;

        await this.userService.logout(unionid);
    }

    // 查询用户自身信息
    @UseLoginAccessInterface()
    @Get('profile')
    public userProfile(@User() userInfo: IPayLoad) {
        const { id } = userInfo;

        return this.userService.queryUserProfile(id);
    }
}
