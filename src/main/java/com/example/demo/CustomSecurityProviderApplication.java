package com.example.demo;

import java.security.Principal;
import java.util.Collections;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class CustomSecurityProviderApplication {

	public static void main(String[] args) {
		SpringApplication.run(CustomSecurityProviderApplication.class, args);
	}

}

@RestController
class GreetinRestController {
	@GetMapping("/greeting")
	public String greet(Principal p) {
		return " Hello " + p.getName() + " !!!.";
	}

}

@Configuration
@EnableWebSecurity
class CustomSecurityConfigure extends WebSecurityConfigurerAdapter {

	private final CustomAuthenticatonProvider customProvider;

	public CustomSecurityConfigure(CustomAuthenticatonProvider customProvider) {
		this.customProvider = customProvider;
	}

	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(this.customProvider);
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.httpBasic().and().authorizeRequests().anyRequest().authenticated();

	}
}

@Component
class CustomAuthenticatonProvider implements AuthenticationProvider {

	private boolean isValid(String user, String pass) {
		if (user.equals("akash") && pass.equals("password")) {
			return true;
		}
		return false;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String ua = authentication.getName();
		String ps = authentication.getCredentials().toString();
		if (isValid(ua, ps)) {
			return new UsernamePasswordAuthenticationToken(ua,
					ps,
					Collections.singletonList(new SimpleGrantedAuthority("USER")));
		}
		throw new BadCredentialsException("Not Albe to login..!!");
	}

	@Override
	public boolean supports(Class<?> authentication) {

		return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
