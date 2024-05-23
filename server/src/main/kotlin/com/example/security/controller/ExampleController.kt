package com.example.security.controller

import org.springframework.security.core.Authentication
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/example")
class ExampleController(private val service: ExampleService) {
    @GetMapping("/hello")
    fun hello(authentication: Authentication): String {
        return service.getGreeting(authentication.name)
    }

    @GetMapping("/hoge")
    fun hoge(): String {
        return "hoge"
    }
}

interface ExampleService {
    fun getGreeting(username: String): String
}

@Service
class DefaultExampleService: ExampleService {
    override fun getGreeting(username: String): String {
        return "Hello, $username!"
    }
}