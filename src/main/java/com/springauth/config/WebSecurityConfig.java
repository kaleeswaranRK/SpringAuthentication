package com.springauth.config;

//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//
//
//    @EnableWebSecurity
//    public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
//
//        @Override
//        protected void configure(HttpSecurity http) throws Exception {
//            http.authorizeRequests()
//                .anyRequest().authenticated()
//                .and()
//                .httpBasic();
//        }
//
//        @Override
//        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//            auth.inMemoryAuthentication()
//                .withUser("user")
//                .password("{noop}password") // Spring Security 5 requires specifying the password encoder explicitly. {noop} denotes plain text encoding.
//                .roles("USER");
//        }
//    }




