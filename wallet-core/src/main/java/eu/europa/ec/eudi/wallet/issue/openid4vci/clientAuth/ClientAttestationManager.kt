/*
 * Copyright (c) 2025 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package eu.europa.ec.eudi.wallet.issue.openid4vci.clientAuth

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.ClientAttestationJWT
import eu.europa.ec.eudi.openid4vci.ClientAttestationPoPJWTSpec
import eu.europa.ec.eudi.openid4vci.Signer
import eu.europa.ec.eudi.wallet.logging.Logger
import org.multipaz.crypto.Algorithm
import org.multipaz.securearea.SecureArea
import java.security.MessageDigest

/**
 * Internal manager that orchestrates the attestation-based authentication flow.
 *
 * This manager coordinates the complete attestation lifecycle:
 * 1. Creates or reuses a key in the SecureArea, bound to the CredentialIssuerId
 * 2. Calls the consumer's [ClientAttestationJwtProvider] to obtain the attestation JWT
 * 3. Creates a [Signer] for proof-of-possession token signing
 *
 * ## Key Lifecycle and Persistence
 * Keys are persisted in the SecureArea and bound to the CredentialIssuerId using a deterministic
 * alias. This ensures the same key is reused across issuance sessions for the same issuer,
 * eliminating the need to obtain new attestation JWTs for every issuance request.
 *
 * ## Error Handling
 * If the attestation flow fails, the key is intentionally not deleted. This allows for retry
 * attempts and maintains the key-issuer binding for future operations.
 *
 * @property config The client attestation configuration containing the JWT provider and settings
 * @property credentialIssuerId The credential issuer identifier used to generate a stable key alias
 * @property clientAttestationPOPJwsAlgs List of supported PoP JWS algorithms from issuer metadata
 * @property secureArea The secure area for key storage and cryptographic operations
 * @property logger Optional logger for debugging and monitoring
 */
internal class ClientAttestationManager(
    private val config: ClientAttestationConfig,
    private val credentialIssuerId: String,
    private val clientAttestationPOPJwsAlgs: List<Algorithm>?,
    private val secureArea: SecureArea,
    private val logger: Logger?,
) {

    /**
     * Executes the full attestation flow and returns the components needed for OpenID4VCI.
     *
     * This method orchestrates the complete attestation process:
     * 1. Generates a deterministic key alias based on the CredentialIssuerId
     * 2. Checks if an attestation key already exists for this issuer
     * 3. Creates a new key if needed, or reuses the existing one
     * 4. Obtains the attestation JWT from the provider
     * 5. Creates a PoP signer for subsequent credential requests
     *
     * @return [Result] containing [AttestationResult] with the attestation JWT, PoP spec, and key alias,
     *         or an error if any step fails
     */
    suspend fun executeAttestationFlow(): Result<AttestationResult> = runCatching {
        // Step 1: Generate deterministic key alias bound to CredentialIssuerId
        val keyAlias = generateKeyAlias(credentialIssuerId)

        logger?.log(
            Logger.Record(
                level = Logger.Companion.LEVEL_DEBUG,
                message = "Using attestation key alias: $keyAlias for issuer: $credentialIssuerId"
            )
        )

        // Step 2: Check if key already exists, create if not
        val keyExists = try {
            secureArea.getKeyInfo(keyAlias)
            true
        } catch (e: Exception) {
            false
        }

        if (!keyExists) {
            logger?.log(
                Logger.Record(
                    level = Logger.Companion.LEVEL_DEBUG,
                    message = "Creating new attestation key with alias: $keyAlias"
                )
            )

            val createKeySettings = config.createKeySettingsBuilder.build(
                clientAttestationPOPJWSAlgs = clientAttestationPOPJwsAlgs,
            )

            secureArea.createKey(keyAlias, createKeySettings)

            logger?.log(
                Logger.Record(
                    level = Logger.Companion.LEVEL_DEBUG,
                    message = "Attestation key created successfully"
                )
            )
        } else {
            logger?.log(
                Logger.Record(
                    level = Logger.Companion.LEVEL_DEBUG,
                    message = "Reusing existing attestation key"
                )
            )
        }

        // Step 3: Get public key and convert to JWK
        val keyInfo = secureArea.getKeyInfo(keyAlias)

        logger?.log(
            Logger.Record(
                level = Logger.Companion.LEVEL_DEBUG,
                message = "Requesting attestation JWT from provider"
            )
        )

        // Step 4: Call consumer's provider to get attestation JWT
        val attestationJwt = config.jwtProvider
            .getAttestationJwt(keyInfo)
            .getOrThrow()

        logger?.log(
            Logger.Record(
                level = Logger.Companion.LEVEL_DEBUG,
                message = "Attestation JWT received successfully"
            )
        )

        // Step 5: Parse and validate JWT
        val parsedJwt = SignedJWT.parse(attestationJwt)
        val clientAttestationJWT = ClientAttestationJWT(jwt = parsedJwt)

        // Step 6: Create the PoP signer
        val popSigner: Signer<JWK> = SecureAreaAttestationSigner(
            secureArea = secureArea,
            keyAlias = keyAlias,
            unlockKey = config.unlockKey,
            logger = logger
        )

        val popSpec = ClientAttestationPoPJWTSpec(popSigner)

        AttestationResult(
            attestationJWT = clientAttestationJWT,
            popSpec = popSpec,
            keyAlias = keyAlias
        )
    }.onFailure { error ->
        logger?.log(
            Logger.Record(
                level = Logger.Companion.LEVEL_ERROR,
                message = "Attestation flow failed",
                thrown = error
            )
        )
        // Note: Key is not deleted on failure - it remains bound to the CredentialIssuerId for retry
    }

    /**
     * Generates a deterministic key alias based on the CredentialIssuerId.
     *
     * This ensures the same key is reused for the same issuer across sessions. The alias is
     * generated by:
     * 1. Creating a SHA-256 hash of the issuer ID
     * 2. Converting the hash to hex format
     * 3. Truncating to 16 characters for a compact, URL-safe identifier
     * 4. Prefixing with "client-attestation-" for namespace clarity
     *
     * @param credentialIssuerId The credential issuer identifier to hash
     * @return A deterministic, stable key alias for the given issuer
     */
    private fun generateKeyAlias(credentialIssuerId: String): String {
        // Create a hash of the issuer ID to get a stable, URL-safe identifier
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(credentialIssuerId.toByteArray())
        val hashHex = hashBytes.joinToString("") { "%02x".format(it) }.take(16)
        return "client-attestation-$hashHex"
    }

    /**
     * Result of the attestation flow containing all components needed for OpenID4VCI.
     *
     * @property attestationJWT The attestation JWT obtained from the wallet provider backend
     * @property popSpec The proof-of-possession JWT specification with the signer
     * @property keyAlias The alias of the attestation key in the secure area
     */
    data class AttestationResult(
        val attestationJWT: ClientAttestationJWT,
        val popSpec: ClientAttestationPoPJWTSpec,
        val keyAlias: String,
    )
}

