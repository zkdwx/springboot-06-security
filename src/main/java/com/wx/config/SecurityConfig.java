package com.wx.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //链式编程

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //首页所有人可以访问，功能只有对应有权限的人才能访问
        //请求授权的规则
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");
        http.formLogin();
        http.logout().logoutSuccessUrl("/");
        //开启记住我功能
        http.rememberMe();
    }

    //认证
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("wx1").password(new BCryptPasswordEncoder().encode("111")).roles("vip1")
                .and()
                .withUser("wx2").password(new BCryptPasswordEncoder().encode("222")).roles("vip2")
                .and()
                .withUser("wx3").password(new BCryptPasswordEncoder().encode("333")).roles("vip3");
    }
}
