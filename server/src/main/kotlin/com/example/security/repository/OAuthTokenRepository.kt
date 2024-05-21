package com.example.security.repository

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.MediaType
import org.springframework.http.RequestEntity
import org.springframework.stereotype.Repository
import org.springframework.web.client.RestTemplate

interface OAuthTokenRepository {
    fun getTokenByCode(code: String): TokenResponse
}

@Serializable
data class TokenResponse(
    @SerialName("access_token")
    val accessToken: String,

    @SerialName("token_type")
    val tokenType: String,

    @SerialName("expires_in")
    val expiresIn: Int,

    @SerialName("scope")
    val scope: String,

    @SerialName("id_token")
    val idToken: String,
)

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
        return Json.decodeFromString(responseBody)
    }
}