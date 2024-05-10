package com.example.security

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.DelegatingPasswordEncoder
import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain


@Configuration
@EnableWebSecurity
class SecurityConfig {
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests {
                it.anyRequest().authenticated()
            }
            .formLogin {}
//            .httpBasic {}
//            .addFilterBefore(HogeFilter(), UsernamePasswordAuthenticationFilter::class.java)
        return http.build()
    }

    @Bean
    fun userDetailsService(): UserDetailsService {
        val user1 = User.builder()
            .username("user1")
            .password("{bcrypt}$2a$10\$ofhSMQ38QHWK3aCOZvAK.eneoaAnSHAFc0M48ud7Xyig3H8KUwUOm")
            .roles("USER")
            .build()
        val user2 = User.builder()
            .username("user2")
            .password("{noop}password")
            .roles("USER")
            .build()
        println("user.password========================")
        println(user1.password)
        println(user2.password)
        return InMemoryUserDetailsManager(user1, user2)
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        val idForEncode = "bcrypt"
        val encoders: MutableMap<String, PasswordEncoder> = mutableMapOf()
        encoders[idForEncode] = BCryptPasswordEncoder(16)
        encoders["argon2"] = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()
        encoders["pbkdf2"] = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8()
        encoders["noop"] = NoOpPasswordEncoder.getInstance()
        return DelegatingPasswordEncoder(idForEncode, encoders)
    }
}

//class HogeFilter: OncePerRequestFilter() {
//    override fun doFilterInternal(
//        request: HttpServletRequest,
//        response: HttpServletResponse,
//        filterChain: FilterChain
//    ) {
//        println("${request.requestURL}===========================HOGE FILTER=====================================")
//        filterChain.doFilter(request, response)
//    }
//}