package com.authentication.jwt.config

import com.authentication.jwt.filter.JwtRequestFilter
import com.authentication.jwt.service.CustomUserDetailsService
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

/**
 * Spring security configuration
 */
@Configuration
@EnableWebSecurity
class SecurityConfig(
        val customUserDetailsService: CustomUserDetailsService,
        val jwtRequestFilter: JwtRequestFilter
) : WebSecurityConfigurerAdapter() {

    /**
     * Indicates that we'll use CustomUserDetailsService to validate user existence.
     * @see CustomUserDetailsService
     */
    override fun configure(auth: AuthenticationManagerBuilder) {
        auth.userDetailsService(customUserDetailsService)
    }

    /**
     * This used to be a default bean but it doesn't exists any more, so for that reason we have to declare it.
     * Will allow us to call the bean to validate the existence of a user.
     */
    @Bean
    override fun authenticationManager(): AuthenticationManager {
        return super.authenticationManager()
    }

    /**
     * This PasswordEncoder is provided for legacy and testing purposes only and is not considered secure.
     * A password encoder that does nothing. Useful for testing where working with plain text passwords may be preferred.
     */
    @Bean
    fun passwordEncoder(): PasswordEncoder = NoOpPasswordEncoder.getInstance()

    /**
     * - We allow not authorized requests over "/authenticate" due to it allows us to authenticate and obtain the token.
     * - The rest of the endpoints required authentication.
     * - Session managements is stateless due to with JWT security approach we don't wanna have any sessions,
     * will validate each request header seeking for a valid token.
     * - Before filter allow us to add a middleware in which we can validate token information per request and
     * add it as part of the spring security context.
     * @see JwtRequestFilter
     */
    override fun configure(http: HttpSecurity) {
        http.csrf().disable()
                .authorizeRequests().antMatchers("/authenticate")
                .permitAll().anyRequest().authenticated().and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter::class.java)
    }

}