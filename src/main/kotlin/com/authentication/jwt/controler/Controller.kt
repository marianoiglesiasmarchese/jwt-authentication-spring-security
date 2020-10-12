package com.authentication.jwt.controler

import com.authentication.jwt.model.User
import com.authentication.jwt.service.CustomUserDetailsService
import com.authentication.jwt.util.JwtUtil
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

@RestController
class Controller(
	val jwtUtil: JwtUtil,
	val authenticationManager: AuthenticationManager,
	val customUserDetailsService: CustomUserDetailsService
) {

	/**
	 * Secured endpoint, we won't be able to reach it unless we were authenticated before.
	 * @param user, allow us to work with the information of the authenticated user.
	 */
	@GetMapping("/")
	fun helloWorld(@AuthenticationPrincipal user: User): String {
		println(user)
		return "hello world"
	}

	/**
	 * Endpoint without spring security protection which allow us to obtain the authentication token
	 */
	@PostMapping("/authenticate")
	fun authenticate(@RequestBody authRequest: AuthRequest): Map<String, String> {
		try {
			authenticationManager.authenticate(
					UsernamePasswordAuthenticationToken(
							authRequest.username,
							authRequest.password
					)
			)
		} catch (e: BadCredentialsException){
			throw Exception("Incorrect username or password", e)
		}
		val user = customUserDetailsService.loadUserByUsername(authRequest.username)
		return jwtUtil.generateToken(user as User)
	}

}

class AuthRequest(val username: String, val password: String)
