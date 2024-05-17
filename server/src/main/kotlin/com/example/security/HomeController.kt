package com.example.security

import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
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
class AuthController {
    @GetMapping("/user")
    fun getMe(authentication: Authentication): User {
        val oidcUser = authentication.principal as OidcUser
        return User(oidcUser.attributes["name"] as String, "", mutableListOf(SimpleGrantedAuthority("ROLE_USER")))
    }
}
