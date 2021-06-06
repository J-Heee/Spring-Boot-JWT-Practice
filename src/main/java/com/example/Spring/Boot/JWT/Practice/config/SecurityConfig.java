package com.example.Spring.Boot.JWT.Practice.config;

import com.example.Spring.Boot.JWT.Practice.jwt.JwtAccessDeniedHandler;
import com.example.Spring.Boot.JWT.Practice.jwt.JwtAuthenticationEntryPoint;
import com.example.Spring.Boot.JWT.Practice.jwt.JwtSecurityConfig;
import com.example.Spring.Boot.JWT.Practice.jwt.TokenProvider;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


@EnableWebSecurity    //기본적인 Web 보안을 활성화 하겠다는 의미
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;


    //TokenProvider, JwtAuthenticationEntryPoint, JwtAccessDeniedHandler 주입받음
    public SecurityConfig(
            TokenProvider tokenProvider,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler
    ) {
        this.tokenProvider = tokenProvider;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }


    //Password Encode는 BCryptPasswordEncoder() 사용
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring()
                .antMatchers(
                        "/h2-console/**"
                        ,"/favicon.ico"
                );
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                //token 방식을 사용하기 때문에 csrf 설정 disable
                .csrf().disable()

                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                //h2-console 위한 설정 추가
                .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                //세션을 사용하지 않기 때문에 STATELESS로 설정
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .authorizeRequests()    //HttpServletRequest를 사용하는 요청들에 대한 접근제한을 설정
                .antMatchers("/api/hello").permitAll()    // 관련 요청은 인증(Token)없이 접근 허용
                .antMatchers("/api/authenticate").permitAll()
                .antMatchers("/api/signup").permitAll()

                .anyRequest().authenticated()    //나머지 요청들은 모두 인증되어야 함

                .and()
                .apply(new JwtSecurityConfig(tokenProvider));    //JwtFilter를 addFilterBefore 메소드로 등록했던 JwtSecurityConfig 클래스 적용
    }
}