package com.example.security

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
@RequestMapping("/user")
class UserController(
    private val userDetailsService: UserDetailsService,
) {
    @PostMapping("/signup")
    fun signup(@RequestBody request: SignupRequest) {
        val jdbcUserDetailsManager = userDetailsService as? JdbcUserDetailsManager ?: return
        val user = User.builder()
            .username(request.username)
            .password(request.password)
            .roles("ADMIN")
            .build()
        jdbcUserDetailsManager.createUser(user)
    }

    @GetMapping("/hoge")
    fun hoge(): String {
        return "hoge"
    }
}

data class SignupRequest(val username: String, val password: String)