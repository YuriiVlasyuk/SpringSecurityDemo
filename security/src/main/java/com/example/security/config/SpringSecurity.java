package com.example.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.sql.DataSource;

public class SpringSecurity extends WebSecurityConfigurerAdapter
{
    @Autowired
    private DataSource ds;

    @Autowired
    public void configureAMBuilder(AuthenticationManagerBuilder auth) throws Exception
    {
        auth.jdbcAuthentication().dataSource(ds)
                .authoritiesByUsernameQuery("select username, role from usr where username=?")
                .usersByUsernameQuery("select username,userpassword, 1 from usr where username=?");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        http.httpBasic().and().authorizeRequests().anyRequest().authenticated();
        http.csrf().disable();
    }

    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }

}