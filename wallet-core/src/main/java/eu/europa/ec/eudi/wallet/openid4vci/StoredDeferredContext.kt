package eu.europa.ec.eudi.wallet.openid4vci

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

@Serializable
internal data class StoredDeferredContext(
    // --- 1. Configuration URIs ---
    val credentialIssuerId: String,
    val deferredEndpoint: String,
    val tokenEndpoint: String,
    val authorizationServerId: String, // Was missing in my previous snippet
    val challengeEndpoint: String? = null,

    // --- 2. Client Identity & Keys (Ordered) ---
    val clientId: String,
    // The STRICTLY ORDERED list of keys used for the credentials
    val popKeyAliases: List<String>,
    val dPoPKeyAlias: String? = null,
    val clientAttestationPopKeyId: String? = null,
    val clientAttestationJwt: String? = null, // Store if you need to reuse the exact JWT

    // --- 3. Transaction State ---
    val transactionId: String,
    val accessToken: String,
    val accessTokenType: String = "DPoP", // "DPoP" or "Bearer"
    val refreshToken: String? = null,

    // --- 4. Encryption Specs (Optional) ---
    // Storing as generic JSON strings/elements to keep this class simple
    // If you don't use encryption, these will be null.
    val requestEncryptionKeyJwk: String? = null,
    val requestEncryptionMethod: String? = null,
    val responseEncryptionMethod: String? = null
)