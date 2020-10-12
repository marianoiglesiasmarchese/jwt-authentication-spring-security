package com.authentication.jwt.model

import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import java.util.*

class User(
    val id: UUID,
    val email: String,
    val avatar: String,
    username: String,
    password: String,
    authorities: List<SimpleGrantedAuthority>
) : User(username, password, authorities)
