/*
 * Copyright (c) 2024-2025 European Commission
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

package eu.europa.ec.eudi.wallet.issue.openid4vci

import eu.europa.ec.eudi.openid4vci.AuthorizedRequest
import eu.europa.ec.eudi.openid4vci.IssuanceRequestPayload
import eu.europa.ec.eudi.openid4vci.Issuer
import eu.europa.ec.eudi.openid4vci.KeyAttestationJWT
import eu.europa.ec.eudi.openid4vci.ProofTypeMeta
import eu.europa.ec.eudi.openid4vci.ProofSpecification
import eu.europa.ec.eudi.openid4vci.SubmissionOutcome
import eu.europa.ec.eudi.wallet.document.UnsignedDocument
import eu.europa.ec.eudi.wallet.document.credential.ProofOfPossessionSigner
import eu.europa.ec.eudi.wallet.provider.WalletAttestationsProvider
import kotlinx.coroutines.runBlocking
import org.multipaz.securearea.KeyUnlockData

internal class SubmitRequest(
    val config: OpenId4VciManager.Config,
    val walletAttestationsProvider: WalletAttestationsProvider?,
    val issuer: Issuer,
    authorizedRequest: AuthorizedRequest,
) {
    var authorizedRequest: AuthorizedRequest = authorizedRequest
        private set

    suspend fun request(offeredDocuments: Map<UnsignedDocument, Offer.OfferedDocument>): Response {
        return Response(offeredDocuments.mapValues { (unsignedDocument, offeredDocument) ->
            try {
                val (keyAliases, outcome) = submitRequest(unsignedDocument, offeredDocument)
                ResponseResult(
                    keyAliases = keyAliases,
                    outcome = Result.success(outcome)
                )
            } catch (e: Throwable) {
                ResponseResult(emptyList(), Result.failure(e))
            }
        })
    }

    private suspend fun submitRequest(
        unsignedDocument: UnsignedDocument,
        offeredDocument: Offer.OfferedDocument,
        keyUnlockData: Map<KeyAlias, KeyUnlockData?>? = null,
    ): ResponseResult<SubmissionOutcome> {
        val payload =
            IssuanceRequestPayload.ConfigurationBased(offeredDocument.configurationIdentifier)
        val signers = unsignedDocument.getPoPSigners()

        val (updatedAuthorizedRequest, outcome) = when (config.clientAuthenticationType) {
            is OpenId4VciManager.ClientAuthenticationType.None -> {
                requestWithNoAuthentication(
                    payload,
                    signers,
                    unsignedDocument,
                    offeredDocument,
                    keyUnlockData
                )
            }

            is OpenId4VciManager.ClientAuthenticationType.AttestationBased -> {
                requestWithAttestationBasedAuth(
                    payload,
                    signers,
                    unsignedDocument,
                    offeredDocument,
                    keyUnlockData
                )
            }
        }

        this.authorizedRequest = updatedAuthorizedRequest
        return ResponseResult(
            keyAliases = signers.map { it.keyAlias },
            outcome = outcome
        )
    }

    private suspend fun requestWithNoAuthentication(
        payload: IssuanceRequestPayload,
        signers: List<ProofOfPossessionSigner>,
        unsignedDocument: UnsignedDocument,
        offeredDocument: Offer.OfferedDocument,
        keyUnlockData: Map<KeyAlias, KeyUnlockData?>?,
    ): Pair<AuthorizedRequest, SubmissionOutcome> {
        val jwtProofType = offeredDocument.configuration.proofTypesSupported.values
            .filterIsInstance<ProofTypeMeta.Jwt>()
            .firstOrNull()

        // If JWT proof with attestation is possible and provider is available
        if (jwtProofType != null && walletAttestationsProvider != null) {
            return authorizedRequest.requestWithJwtProofWithKeyAttestation(
                payload, signers, keyUnlockData,
                unlockResume = { updatedKeyUnlockData ->
                    submitRequest(unsignedDocument, offeredDocument, updatedKeyUnlockData)
                }
            )
        }

        // Fall back to NoProof if issuer doesn't require JWT proofs
        if (jwtProofType == null) {
            return with(issuer) {
                authorizedRequest.request(payload, ProofSpecification.NoProof)
            }.getOrThrow()
        }

        throw IllegalStateException(
            "Issuer requires key attestation proof but no WalletAttestationsProvider is available"
        )
    }

    private suspend fun requestWithAttestationBasedAuth(
        payload: IssuanceRequestPayload,
        signers: List<ProofOfPossessionSigner>,
        unsignedDocument: UnsignedDocument,
        offeredDocument: Offer.OfferedDocument,
        keyUnlockData: Map<KeyAlias, KeyUnlockData?>?,
    ): Pair<AuthorizedRequest, SubmissionOutcome> {

        val attestationProofType =
            offeredDocument.configuration.proofTypesSupported.values.filterIsInstance<ProofTypeMeta.Attestation>()
                .firstOrNull()
        if (attestationProofType != null) {
            return requestWithAttestationProof(payload, signers)
        }

        val jwtProofType =
            offeredDocument.configuration.proofTypesSupported.values.filterIsInstance<ProofTypeMeta.Jwt>()
                .firstOrNull()

        if (jwtProofType != null) {
            return authorizedRequest.requestWithJwtProofWithKeyAttestation(
                payload, signers, keyUnlockData,
                unlockResume = { updatedKeyUnlockData ->
                    submitRequest(unsignedDocument, offeredDocument, updatedKeyUnlockData)
                }
            )
        }

        throw IllegalStateException("No supported proof type found in the credential configuration")
    }

    private suspend fun requestWithAttestationProof(
        payload: IssuanceRequestPayload,
        signers: List<ProofOfPossessionSigner>,
    ): Pair<AuthorizedRequest, SubmissionOutcome> {
        val walletAttestationsProvider = checkNotNull(walletAttestationsProvider) {
            "WalletAttestationsProvider is required for attestation based client authentication"
        }
        val proofsSpecification = ProofSpecification.AttestationProof { nonce, _ ->
            walletAttestationsProvider.getKeyAttestation(
                signers.map { it.getKeyInfo() },
                nonce
            )
                .map { KeyAttestationJWT(it) }
                .getOrThrow()
        }
        return authorizedRequest.requestWithAttestationProof(payload, proofsSpecification)
    }

    class Response(map: Map<UnsignedDocument, ResponseResult<Result<SubmissionOutcome>>>) :
        Map<UnsignedDocument, ResponseResult<Result<SubmissionOutcome>>> by map

    data class ResponseResult<T>(
        val keyAliases: List<String>,
        val outcome: T,
    )

    private suspend fun AuthorizedRequest.requestWithAttestationProof(
        payload: IssuanceRequestPayload,
        proofsSpecification: ProofSpecification.AttestationProof,
    ): Pair<AuthorizedRequest, SubmissionOutcome> {
        return with(issuer) {
            request(payload, proofsSpecification)
        }.getOrThrow()
    }

    private suspend fun AuthorizedRequest.requestWithJwtProofWithKeyAttestation(
        payload: IssuanceRequestPayload,
        signers: List<ProofOfPossessionSigner>,
        keyUnlockData: Map<String, KeyUnlockData?>?,
        unlockResume: suspend (Map<String, KeyUnlockData?>) -> ResponseResult<SubmissionOutcome>,
    ): Pair<AuthorizedRequest, SubmissionOutcome> {
        val walletAttestationsProvider = checkNotNull(walletAttestationsProvider) {
            "WalletAttestationsProvider is required for attestation based client authentication"
        }
        var proofSigner: KeyAttestationSigner? = null
        val proofsSpecification = ProofSpecification.JwtProof(
            proofSignerProvider = { nonce, _ ->
                val factory = KeyAttestationSigner.Factory(
                    signers, walletAttestationsProvider, keyUnlockData
                )
                factory(nonce).getOrThrow().also { proofSigner = it }
            }
        )
        try {
            return with(issuer) { request(payload, proofsSpecification) }.getOrThrow()
        } catch (e: Throwable) {

            val isUserAuthRequired = proofSigner?.keyLockedException != null
            if (isUserAuthRequired) {
                val keysAndSecureAreas = mapOf(
                    proofSigner.signer.let { it.keyAlias to it.secureArea }
                )
                throw UserAuthRequiredException(
                    signingAlgorithm = proofSigner.signer.getKeyInfo().algorithm,
                    keysAndSecureAreas = keysAndSecureAreas,
                    resume = { keyUnlockData ->
                        unlockResume(keyUnlockData)
                    },
                    cause = e
                )
            } else {
                throw e
            }
        }

    }

}
