package com.example.common;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.web.csrf.CsrfFilter;

@Configuration
@EnableWebMvcSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
    	CsrfTokenResponseHeaderBindingFilter csrfFilter = csrfTokenResponseHeaderBindingFilter();

        http
        	.addFilterAfter(csrfFilter, CsrfFilter.class)
        	.headers()
	.cacheControl()
	.xssProtection()
	.and()
            .authorizeRequests()
            .antMatchers("/")
            .permitAll()
            .anyRequest().authenticated()
            .and()
            .formLogin()
            .loginPage("/login.html")
            .permitAll()
            .and()
            .logout()
            .permitAll();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .inMemoryAuthentication()
                .withUser("u").password("p").roles("USER");
    }

    @Bean
    public CsrfTokenResponseHeaderBindingFilter csrfTokenResponseHeaderBindingFilter() {
    	return new CsrfTokenResponseHeaderBindingFilter();
    }
}