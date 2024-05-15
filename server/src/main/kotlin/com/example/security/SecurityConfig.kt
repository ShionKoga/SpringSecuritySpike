package com.example.security
import jakarta.persistence.*
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.datasource.DriverManagerDataSource
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.DelegatingPasswordEncoder
import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder
import org.springframework.security.provisioning.JdbcUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import javax.sql.DataSource


@Configuration
@EnableWebSecurity
class SecurityConfig {
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests {
                it.requestMatchers(
                    "/api/auth/signup",
                    "/api/auth/login",
                ).permitAll()
                it.anyRequest().authenticated()
            }
            .csrf { it.disable() }
            .sessionManagement {
                it.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            }
            .securityContext {
                it.securityContextRepository(HttpSessionSecurityContextRepository())
            }
        return http.build()
    }

    @Bean
    fun authenticationManager(
        userDetailsService: UserDetailsService,
        passwordEncoder: PasswordEncoder,
    ): AuthenticationManager {
        val authenticationProvider = DaoAuthenticationProvider()
        authenticationProvider.setUserDetailsService(userDetailsService)
        authenticationProvider.setPasswordEncoder(passwordEncoder)
        return ProviderManager(authenticationProvider)
    }

    @Bean
    fun userDetailsService(dataSource: DataSource): UserDetailsService {
        return JdbcUserDetailsManager(dataSource)
    }

    @Value("\${spring.datasource.url}")
    private lateinit var datasourceUrl: String

    @Value("\${spring.datasource.username}")
    private lateinit var datasourceUsername: String

    @Value("\${spring.datasource.password}")
    private lateinit var datasourcePassword: String

    @Value("\${spring.datasource.driver-class-name}")
    private lateinit var datasourceDriverClassName: String

    @Bean
    fun dataSource(): DataSource {
        val dataSource = DriverManagerDataSource()
        dataSource.setDriverClassName(datasourceDriverClassName)
        dataSource.url = datasourceUrl
        dataSource.username = datasourceUsername
        dataSource.password = datasourcePassword
        return dataSource
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        val idForEncode = "bcrypt"
        val encoders: MutableMap<String, PasswordEncoder> = mutableMapOf()
        encoders[idForEncode] = BCryptPasswordEncoder()
        encoders["argon2"] = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()
        encoders["pbkdf2"] = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8()
        encoders["noop"] = NoOpPasswordEncoder.getInstance()
        return DelegatingPasswordEncoder(idForEncode, encoders)
    }
}

@Entity
@Table(name = "users")
data class MyUser(
    @Id
    @Column(name = "username", nullable = false, length = 50)
    private var username: String,

    @Column(name = "password", nullable = false, length = 500)
    private var password: String,

    @Column(name = "enabled", nullable = false)
    private var enabled: Boolean,

    @OneToMany(mappedBy = "username", fetch = FetchType.EAGER, cascade = [CascadeType.ALL], orphanRemoval = true)
    var authorities: MutableList<Authority> = mutableListOf()
): UserDetails {
    override fun getAuthorities(): Collection<GrantedAuthority> = authorities
    override fun getPassword(): String = password
    override fun getUsername(): String = username
    override fun isAccountNonExpired(): Boolean = true
    override fun isAccountNonLocked(): Boolean = true
    override fun isCredentialsNonExpired(): Boolean = true
    override fun isEnabled(): Boolean = enabled
}

@Entity
@Table(name = "authorities")
@IdClass(AuthorityId::class)
data class Authority(
    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "username", nullable = false)
    var username: MyUser,

    @Id
    @Column(name = "authority", nullable = false, length = 50)
    val authorityString: String
): GrantedAuthority {
    override fun getAuthority(): String = authorityString
}

data class AuthorityId(
    var username: String? = null,
    var authorityString: String? = null
) : java.io.Serializable