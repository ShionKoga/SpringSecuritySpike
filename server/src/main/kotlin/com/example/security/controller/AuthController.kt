package com.example.security.controller

import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jwt.*
import org.springframework.security.provisioning.JdbcUserDetailsManager
import org.springframework.web.bind.annotation.*
import java.time.Instant
import java.time.temporal.ChronoUnit

@RestController
@RequestMapping("/api/auth")
class AuthController(
    private val userDetailsService: UserDetailsService,
    private val authenticationManager: AuthenticationManager,
    private val jwtEncoder: JwtEncoder,
    private val passwordEncoder: PasswordEncoder,
) {
    @PostMapping("/signup")
    fun signup(
        @RequestBody request: LoginSignupRequest,
        httpRequest: HttpServletRequest,
        httpResponse: HttpServletResponse,
    ) {
        val jdbcUserDetailsManager = userDetailsService as? JdbcUserDetailsManager ?: return
        val encodedPassword = passwordEncoder.encode(request.password)
        val user = User.builder()
            .username(request.username)
            .password(encodedPassword)
            .roles("USER")
            .build()
        jdbcUserDetailsManager.createUser(user)
        val authentication = UsernamePasswordAuthenticationToken.authenticated(user, "", user.authorities)
        SecurityContextHolder.getContext().authentication = authentication
        httpRequest.saveSecurityContextIntoSession(SecurityContextHolder.getContext())
        val token = createToken(user)
        httpResponse.addTokenCookie(token)
    }

    @PostMapping("/login")
    fun login(
        @RequestBody request: LoginSignupRequest,
        httpRequest: HttpServletRequest,
        httpResponse: HttpServletResponse,
    ) {
        val authenticationRequest = UsernamePasswordAuthenticationToken.unauthenticated(request.username, request.password)
        val authentication = authenticationManager.authenticate(authenticationRequest)
        SecurityContextHolder.getContext().authentication = authentication
        httpRequest.saveSecurityContextIntoSession(SecurityContextHolder.getContext())
        val user = authentication.principal as UserDetails
        val token = createToken(user)
        httpResponse.addTokenCookie(token)
    }

    private fun createToken(user: UserDetails): String {
        val jwsHeader = JwsHeader.with { "HS256" }.build()
        val claims = JwtClaimsSet.builder()
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plus(30L, ChronoUnit.DAYS))
            .subject(user.username)
            .build()
        return jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims)).tokenValue
    }

    private fun HttpServletRequest.saveSecurityContextIntoSession(context: SecurityContext) {
        this.getSession(true).setAttribute("SPRING_SECURITY_CONTEXT", context)
    }

    private fun HttpServletResponse.addTokenCookie(token: String) {
        val cookie = Cookie("SECURITY_SAMPLE_ACCESS_TOKEN", token)
        cookie.maxAge = 3600
        cookie.path = "/api"
        cookie.isHttpOnly = true
        this.addCookie(cookie)
    }

    @GetMapping("/user")
    fun getMe(authentication: Authentication): UserDetails {
        val jwt = authentication.principal as Jwt
        val userDetails = userDetailsService.loadUserByUsername(jwt.subject)
        return userDetails
    }

    @GetMapping("/logout")
    fun logout(httpRequest: HttpServletRequest, httpResponse: HttpServletResponse) {
        val session = httpRequest.getSession(false)
        session?.invalidate()

        SecurityContextHolder.clearContext()

        val cookie = Cookie("SECURITY_SAMPLE_ACCESS_TOKEN", "")
        cookie.maxAge = 0
        cookie.value = null
        cookie.path = "/api"
        cookie.isHttpOnly = true
        httpResponse.addCookie(cookie)
    }
}

data class LoginSignupRequest(val username: String, val password: String)