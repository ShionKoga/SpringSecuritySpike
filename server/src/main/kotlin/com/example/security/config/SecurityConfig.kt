package com.example.security.config
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider
import org.springframework.security.web.SecurityFilterChain


@Configuration
@EnableWebSecurity
class SecurityConfig(
    @Qualifier("defaultJwtDecoder") private val defaultJwtDecoder: JwtDecoder,
    @Qualifier("googleJwtDecoder") private val googleJwtDecoder: JwtDecoder,
) {
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests {
                it.requestMatchers(
                    "/api/auth/signup",
                    "/api/auth/login",
                    "/api/auth/login/google",
                    "/api/auth/code/google",
                ).permitAll()
                it.anyRequest().authenticated()
            }
            .csrf { it.disable() }
            .oauth2ResourceServer {
                it.jwt{ jwt -> jwt.decoder(defaultJwtDecoder) }
            }
        return http.build()
    }

    @Bean
    fun authenticationManager(
        userDetailsService: UserDetailsService,
        passwordEncoder: PasswordEncoder,
    ): AuthenticationManager {
        val daoAuthenticationProvider = DaoAuthenticationProvider()
        daoAuthenticationProvider.setUserDetailsService(userDetailsService)
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder)

        val defaultJwtAuthenticationProvider = JwtAuthenticationProvider(defaultJwtDecoder)
        val googleJwtAuthenticationProvider = JwtAuthenticationProvider(googleJwtDecoder)

        return ProviderManager(
            daoAuthenticationProvider,
            defaultJwtAuthenticationProvider,
            googleJwtAuthenticationProvider,
        )
    }
}