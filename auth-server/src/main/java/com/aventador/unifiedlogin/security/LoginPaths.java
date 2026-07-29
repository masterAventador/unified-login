package com.aventador.unifiedlogin.security;

/** 登录相关的固定路径，供安全配置、限流过滤器与登录页控制器共用，避免同一路径散落多处各写一份。 */
public final class LoginPaths {

    public static final String LOGIN = "/login";

    /** 账号被锁定时的跳转目标，登录页据此渲染锁定提示。 */
    public static final String LOCKED_REDIRECT = LOGIN + "?locked";

    private LoginPaths() {
    }
}
