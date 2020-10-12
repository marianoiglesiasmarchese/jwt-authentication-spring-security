package com.authentication.jwt.util

import com.authentication.jwt.model.User
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.util.*

@Component
class JwtUtil {

    @Value("\${jwt.secret}")
    private lateinit var secretKey: String

    /**
     * Returns all the claims within the token payload
     */
    fun extractAllClaims(token: String): Claims {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).body
    }

    /**
     * Allow us to extract claims individually
     */
    fun <T> extractClaim(token: String?, claimsResolver: (Claims?) -> T): T {
        val claims = extractAllClaims(token!!)
        return claimsResolver.invoke(claims)
    }

    fun extractUsername(token: String?): String {
        return extractClaim(token) { obj: Claims? -> obj!!.subject }
    }

    fun extractExpiration(token: String?): Date {
        return extractClaim(token) { obj: Claims? -> obj!!.expiration }
    }

    fun isTokenExpired(token: String) = extractExpiration(token).before(Date())

    /**
     * Loads the payload of the token.
     *
     * Within the payload, there are a number of keys with values.
     * These keys are called “claims” and the JWT specification has seven of these specified as “registered” claims.
     * You can find more details about them here:
     * @see <a href="https://tools.ietf.org/html/rfc7519#section-4.1">rfc 7519 - claims</a>
     * The claims detailed above represents the claims that are reserved both in the key that is used and the expected type.
     * When building a JWT, you can put in any custom claims you wish.
     */
    fun generateToken(user: User): Map<String, String> {
        val claims = hashMapOf<String, Object>()
        return mapOf("jwt" to createToken(claims, user.username))
    }

    /**
     * This method creates the token with expiration date and signed with a secret key
     *
     * @param claims, the JWT claims to be set as the JWT body.
     * @param subject,the JWT subject value or null to remove the property from the Claims map.
     *
     */
    fun createToken(claims: Map<String, Object>, subject: String): String {
        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(Date(System.currentTimeMillis()))
            .setExpiration(Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)) // Expiration date of 10 hours
            .signWith(SignatureAlgorithm.HS256, secretKey).compact()
    }

    /**
     * Allow us to validate if the token hasn't expired and if the information included as part of the token actually belongs to the user
     */
    fun validateToken(token: String, user: User): Boolean {
        val userName = extractUsername(token)
        return userName == user.username && isTokenExpired(token).not()
    }

}