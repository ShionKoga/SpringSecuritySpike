package com.example.security.controller

import com.example.security.repository.OAuthTokenRepository
import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jwt.*
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken
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
    private val tokenRepository: OAuthTokenRepository,
    @Value("\${spring.security.google.redirect-uri}") private val redirectUri: String,
    @Value("\${spring.security.google.login-success-uri}") private val loginSuccessUri: String,
) {
    @PostMapping("/signup")
    fun signup(
        @RequestBody request: LoginSignupRequest,
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
        val token = createToken(user)
        httpResponse.addTokenCookie(token)
    }

    @PostMapping("/login")
    fun login(
        @RequestBody request: LoginSignupRequest,
        httpResponse: HttpServletResponse,
    ) {
        val authenticationRequest = UsernamePasswordAuthenticationToken.unauthenticated(request.username, request.password)
        val authentication = authenticationManager.authenticate(authenticationRequest)
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
        return userDetailsService.loadUserByUsername(jwt.subject)
    }

    @GetMapping("/logout")
    fun logout(httpRequest: HttpServletRequest, httpResponse: HttpServletResponse) {
        SecurityContextHolder.clearContext()

        val cookie = Cookie("SECURITY_SAMPLE_ACCESS_TOKEN", "")
        cookie.maxAge = 0
        cookie.value = null
        cookie.path = "/api"
        cookie.isHttpOnly = true
        httpResponse.addCookie(cookie)
    }

    @GetMapping("/login/google")
    fun loginWithGoogle(httpRequest: HttpServletRequest, httpResponse: HttpServletResponse) {
        return httpResponse.sendRedirect(
            "https://accounts.google.com/o/oauth2/v2/auth" +
                    "?client_id=695126314073-58kj03td09di1plk0v8ru4f38jinvkg5.apps.googleusercontent.com" +
                    "&redirect_uri=${redirectUri}" +
                    "&response_type=code" +
                    "&scope=openid%20email%20&profile"
        )
    }

    @GetMapping("/code/google")
    fun exchangeCodeAndAccessToken(@RequestParam code: String, httpResponse: HttpServletResponse) {
        val token = tokenRepository.getTokenByCode(code).idToken
        val bearerTokenAuthenticationToken = BearerTokenAuthenticationToken(token)
        val bearerTokenAuthentication = authenticationManager.authenticate(bearerTokenAuthenticationToken)
        val jwt = bearerTokenAuthentication.principal as Jwt
        try {
            val userDetails = userDetailsService.loadUserByUsername(jwt.claims["email"] as String)
            this.login(LoginSignupRequest(userDetails.username, ""), httpResponse)
        } catch (e: UsernameNotFoundException) {
            this.signup(LoginSignupRequest(jwt.claims["email"] as String, ""), httpResponse)
        }
        return httpResponse.sendRedirect(loginSuccessUri)
    }
}

data class LoginSignupRequest(val username: String, val password: String)
