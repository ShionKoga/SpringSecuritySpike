package com.example.security.config

import com.nimbusds.jose.jwk.source.ImmutableSecret
import com.nimbusds.jose.proc.SecurityContext
import jakarta.servlet.http.HttpServletRequest
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.jwt.*
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver
import javax.crypto.spec.SecretKeySpec

@Configuration
class JwtAuthenticationConfig(
    @Value("\${spring.security.key}")
    private val jwtKey: String,
) {
    private val secretKey = SecretKeySpec(jwtKey.toByteArray(), "HmacSHA256")

    @Bean(name = ["defaultJwtDecoder"])
    fun defaultJwtDecoder(): JwtDecoder {
        return NimbusJwtDecoder.withSecretKey(secretKey).build()
    }

    @Bean(name = ["googleJwtDecoder"])
    fun googleJwtDecoder(): JwtDecoder {
        return NimbusJwtDecoder
            .withJwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
            .build()
    }

    @Bean(name = ["appleJwtDecoder"])
    fun appleJwtDecoder(): JwtDecoder {
        return NimbusJwtDecoder
            .withJwkSetUri("https://appleid.apple.com/auth/keys")
            .build()
    }

    @Bean
    fun jwtEncoder(): JwtEncoder {
        val secret = ImmutableSecret<SecurityContext>(secretKey)
        return NimbusJwtEncoder(secret)
    }

    @Bean
    fun bearerTokenResolver(): BearerTokenResolver {
        return CustomBearerTokenResolver()
    }
}

class CustomBearerTokenResolver: BearerTokenResolver {
    override fun resolve(request: HttpServletRequest): String? {
        if (!request.requestURI.contains("/api")) return null
        val permittedUrls = listOf(
            "/api/auth/signup",
            "/api/auth/login",
            "/api/auth/login/google",
            "/api/auth/login/apple",
            "/api/auth/code/google",
            "/api/auth/code/apple",
        )
        if (permittedUrls.contains(request.requestURI)) return null
        val cookie = request.cookies?.find { it.name == "SECURITY_SAMPLE_ACCESS_TOKEN" }
        return cookie?.value
    }
}