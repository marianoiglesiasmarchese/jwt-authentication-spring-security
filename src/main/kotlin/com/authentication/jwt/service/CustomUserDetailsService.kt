package com.authentication.jwt.service

import com.authentication.jwt.model.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.stereotype.Service
import java.util.*

/**
 * This service will be called by spring security when we call authenticationManager.authenticate() from /authenticate endpoint
 */
@Service
class CustomUserDetailsService: UserDetailsService {

    /**
     * This represents a fetch over the db seeking for the user that matches with the username
     */
    override fun loadUserByUsername(username: String): UserDetails {
        return User(
            id = UUID.randomUUID(),
            password = "pass",
            email = "",
            avatar = "",
            authorities = listOf(),
            username = username
        )
    }

}