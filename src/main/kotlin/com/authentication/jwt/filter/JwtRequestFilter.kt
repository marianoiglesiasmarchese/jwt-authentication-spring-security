package com.authentication.jwt.filter

import com.authentication.jwt.model.User
import com.authentication.jwt.service.CustomUserDetailsService
import com.authentication.jwt.util.JwtUtil
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * Middleware that allow us to validate token information and set the spring security context.
 * This actions allow us to preserve user information downstream steps.
 */
@Component
class JwtRequestFilter(
        private val jwtUtil: JwtUtil,
        val customUserDetailsService: CustomUserDetailsService
): OncePerRequestFilter() {

    /**
     * Checks token's validity and whether it belongs to a valid user or not.
     * Additionally, it sets the spring security context.
     */
    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        val authorizationHeader = request.getHeader("Authorization")
        var userName : String? = null
        var jwt : String? = null
        authorizationHeader?.startsWith("Bearer ").let {
            if (it == true){
                jwt = authorizationHeader.substring(7)
                userName = jwtUtil.extractUsername(jwt)
            }
        }
        if(userName != null && SecurityContextHolder.getContext().authentication == null ){
            val user = customUserDetailsService.loadUserByUsername(userName!!) as User
            if (jwtUtil.validateToken(jwt!!, user)){
                val authenticationToken = UsernamePasswordAuthenticationToken(user, null, user.authorities)
                authenticationToken.details = WebAuthenticationDetailsSource().buildDetails(request)
                SecurityContextHolder.getContext().authentication = authenticationToken
            }
        }
        chain.doFilter(request,response)
    }

}