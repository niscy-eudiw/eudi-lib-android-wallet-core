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

import org.multipaz.securearea.KeyInfo

/**
 * Provider that handles communication with wallet provider backend to obtain attestation JWT.
 *
 * This functional interface defines the contract for obtaining attestation JWTs during the
 * OpenID4VCI client attestation flow. Implementors communicate with their wallet provider
 * backend service to exchange public key information for a signed attestation JWT.
 *
 * ## Key Lifecycle
 * The attestation key is persisted and bound to the CredentialIssuerId. The same key will be
 * reused for subsequent issuance requests from the same issuer, so the provider should handle
 * both initial key attestation and potential key reuse scenarios.
 *
 * ## Implementation Responsibilities
 * 1. Receive the [KeyInfo] containing the public key and key metadata
 * 2. Extract and format the public key (typically as JWK)
 * 3. Send the public key to your wallet provider backend endpoint
 * 4. Receive and validate the attestation JWT from the wallet provider
 * 5. Return the JWT wrapped in a [Result]
 *
 * ## Example Implementation
 * ```kotlin
 * val provider = ClientAttestationJwtProvider { keyInfo, challenge ->
 *     try {
 *         // Extract public key in JWK format
 *         val publicKeyJwk = keyInfo.publicKey.toJwk().toString()
 *
 *         // Call your backend service
 *         val response = httpClient.post("https://wallet-provider.example.com/attestation") {
 *             setBody(AttestationRequest(
 *                 publicKey = publicKeyJwk,
 *                 challenge = challenge
 *             ))
 *         }
 *
 *         Result.success(response.body<AttestationResponse>().jwt)
 *     } catch (e: Exception) {
 *         Result.failure(e)
 *     }
 * }
 * ```
 *
 * @see [ClientAttestationConfig] for configuring attestation-based authentication
 * @see [KeyInfo] for key information structure
 */
fun interface ClientAttestationJwtProvider {
    /**
     * Obtains an attestation JWT from the wallet provider backend.
     *
     * This method is called by the library during the attestation flow. Implementors should:
     * 1. Extract the public key from [keyInfo] (e.g., `keyInfo.publicKey.toJwk().toString()`)
     * 2. Send it to their wallet provider backend
     * 3. Receive the attestation JWT from the wallet provider
     * 4. Return it wrapped in a [Result]
     *
     * The attestation JWT received from the wallet provider should be a signed JWT that proves
     * the authenticity of the client and binds it to the public key.
     *
     * @param keyInfo The key information including the public key to send to wallet provider.
     *                Access the public key via `keyInfo.publicKey` and convert to JWK format.
     * @return [Result] containing the attestation JWT string received from the wallet provider
     *         on success, or an exception on failure.
     */
    suspend fun getAttestationJwt(keyInfo: KeyInfo): Result<String>
}

