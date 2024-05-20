package com.example.security.entity

import jakarta.persistence.*
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

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