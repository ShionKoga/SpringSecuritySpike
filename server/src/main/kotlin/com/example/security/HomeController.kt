package com.example.security

import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.JdbcUserDetailsManager
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@Controller
class HomeController {
    @RequestMapping("/")
    fun index(): String {
        return "index.html"
    }
}

@RestController
@RequestMapping("/api/auth")
class AuthController(
    private val userDetailsService: UserDetailsService,
    private val authenticationManager: AuthenticationManager,
) {
    @PostMapping("/signup")
    fun signup(
        @RequestBody request: LoginSignupRequest,
        httpRequest: HttpServletRequest,
        httpResponse: HttpServletResponse,
    ) {
        val jdbcUserDetailsManager = userDetailsService as? JdbcUserDetailsManager ?: return
        val user = User.builder()
            .username(request.username)
            .password(request.password)
            .roles("USER")
            .build()
        jdbcUserDetailsManager.createUser(user)
        val authentication = UsernamePasswordAuthenticationToken.authenticated(user, "", user.authorities)
        SecurityContextHolder.getContext().authentication = authentication
        httpRequest.saveSecurityContextIntoSession(SecurityContextHolder.getContext())
        httpResponse.addSessionCookie(httpRequest.session.id)
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
        httpResponse.addSessionCookie(httpRequest.session.id)
    }

    private fun HttpServletRequest.saveSecurityContextIntoSession(context: SecurityContext) {
        this.getSession(true).setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext())
    }

    private fun HttpServletResponse.addSessionCookie(sessionId: String) {
        val cookie = Cookie("JSESSIONID", sessionId)
        cookie.path = "/"
        this.addCookie(cookie)
    }

    @GetMapping("/user")
    fun getMe(authentication: Authentication): User {
        return authentication.principal as User
    }

    @GetMapping("/logout")
    fun logout(httpRequest: HttpServletRequest, httpResponse: HttpServletResponse) {
        val session = httpRequest.getSession(false)
        session?.invalidate()

        SecurityContextHolder.clearContext()

        val cookie = Cookie("JSESSIONID", "")
        cookie.path = "/"
        cookie.maxAge = 0
        httpResponse.addCookie(cookie)
    }
}

data class LoginSignupRequest(val username: String, val password: String)