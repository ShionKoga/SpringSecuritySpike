package com.example.security.repository

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.springframework.beans.factory.annotation.Value
import org.springframework.core.io.ClassPathResource
import org.springframework.http.MediaType
import org.springframework.http.RequestEntity
import org.springframework.stereotype.Repository
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.client.RestTemplate
import java.security.KeyFactory
import java.security.interfaces.ECPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*

interface OAuthTokenRepository {
    fun getTokenByCode(code: String): TokenResponse
}

interface TokenResponse {
    val accessToken: String
    val tokenType: String
    val expiresIn: Int
    val idToken: String
}

@Serializable
data class GoogleTokenResponse(
    @SerialName("access_token")
    override val accessToken: String,

    @SerialName("token_type")
    override val tokenType: String,

    @SerialName("expires_in")
    override val expiresIn: Int,

    @SerialName("scope")
    val scope: String,

    @SerialName("id_token")
    override val idToken: String,
): TokenResponse

@Serializable
data class AppleTokenResponse(
    @SerialName("access_token")
    override val accessToken: String,

    @SerialName("token_type")
    override val tokenType: String,

    @SerialName("expires_in")
    override val expiresIn: Int,

    @SerialName("refresh_token")
    val refreshToken: String,

    @SerialName("id_token")
    override val idToken: String,
): TokenResponse

@Repository
class GoogleOAuthTokenRepository(
    @Value("\${spring.security.google.client-id}")
    private val clientId: String,
    @Value("\${spring.security.google.client-secret}")
    private val clientSecret: String,
    @Value("\${spring.security.google.redirect-uri}")
    private val redirectUri: String
) : OAuthTokenRepository {
    override fun getTokenByCode(code: String): TokenResponse {
        val body = """
            {
                "code": "$code",
                "client_id": "$clientId",
                "client_secret": "$clientSecret",
                "redirect_uri": "$redirectUri",
                "grant_type": "authorization_code",
                "access_type": "offline"
            }
        """.trimIndent()
        return try {
            getToken(body)
        } catch (e: Exception) {
            throw Exception("Error getting token", e)
        }
    }

    private fun getToken(body: String): TokenResponse {
        val request = RequestEntity
            .post("https://www.googleapis.com/oauth2/v4/token")
            .contentType(MediaType.APPLICATION_JSON)
            .body(body)
        val restTemplate = RestTemplate()
        val response = restTemplate.exchange(request, String::class.java)
        val responseBody = response.body!!
        return Json.decodeFromString<GoogleTokenResponse>(responseBody)
    }
}

@Repository
class AppleOAuthTokenRepository(
    @Value("\${spring.security.apple.client-id}")
    val clientId: String,
): OAuthTokenRepository {
    override fun getTokenByCode(code: String): TokenResponse {
        val map = LinkedMultiValueMap<String, String>()
        map.add("client_id", clientId)
        map.add("client_secret", generateAppleClientSecret())
        map.add("code", code)
        map.add("grant_type", "authorization_code")
        val request = RequestEntity
            .post("https://appleid.apple.com/auth/token")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .body(map)
        val restTemplate = RestTemplate()
        val response = restTemplate.exchange(request, String::class.java)
        val responseBody = response.body!!
        return Json.decodeFromString<AppleTokenResponse>(responseBody)
    }

    private fun generateAppleClientSecret(): String {
        val privateKey = loadPrivateKey("AppleAuthKey.p8")

        val algorithm = Algorithm.ECDSA256(null, privateKey)
        return JWT.create()
            .withIssuer("575NKNQV6Z")
            .withAudience("https://appleid.apple.com")
            .withSubject(clientId)
            .withExpiresAt(Date(System.currentTimeMillis() + 3600000)) // 1 hour
            .withKeyId("RK3GDD5HZB")
            .sign(algorithm)
    }

    private fun loadPrivateKey(path: String): ECPrivateKey {
        val resource = ClassPathResource(path)
        val keyBytes = resource.inputStream.readAllBytes()
        val keyPem = String(keyBytes)
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace("\\s+".toRegex(), "")
        val decodedKey = Base64.getDecoder().decode(keyPem)
        val keySpec = PKCS8EncodedKeySpec(decodedKey)
        val keyFactory = KeyFactory.getInstance("EC")
        return keyFactory.generatePrivate(keySpec) as ECPrivateKey
    }
}