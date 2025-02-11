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

package eu.europa.ec.eudi.wallet.transfer.openId4vp

import com.android.identity.crypto.Algorithm
import com.android.identity.securearea.KeyUnlockData
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.jca.JCAContext
import com.nimbusds.jose.jwk.AsymmetricJWK
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import eu.europa.ec.eudi.iso18013.transfer.response.DisclosedDocument
import eu.europa.ec.eudi.iso18013.transfer.response.DisclosedDocuments
import eu.europa.ec.eudi.iso18013.transfer.response.RequestProcessor
import eu.europa.ec.eudi.iso18013.transfer.response.RequestedDocuments
import eu.europa.ec.eudi.iso18013.transfer.response.ResponseResult
import eu.europa.ec.eudi.iso18013.transfer.response.device.DeviceResponse
import eu.europa.ec.eudi.iso18013.transfer.response.device.ProcessedDeviceRequest
import eu.europa.ec.eudi.openid4vp.Consensus
import eu.europa.ec.eudi.openid4vp.PresentationQuery
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject
import eu.europa.ec.eudi.openid4vp.VerifiablePresentation
import eu.europa.ec.eudi.openid4vp.VerifierId
import eu.europa.ec.eudi.openid4vp.VpContent
import eu.europa.ec.eudi.prex.DescriptorMap
import eu.europa.ec.eudi.prex.Id
import eu.europa.ec.eudi.prex.InputDescriptorId
import eu.europa.ec.eudi.prex.JsonPath
import eu.europa.ec.eudi.prex.PresentationSubmission
import eu.europa.ec.eudi.sdjwt.DefaultSdJwtOps
import eu.europa.ec.eudi.sdjwt.DefaultSdJwtOps.present
import eu.europa.ec.eudi.sdjwt.DefaultSdJwtOps.serialize
import eu.europa.ec.eudi.sdjwt.DefaultSdJwtOps.serializeWithKeyBinding
import eu.europa.ec.eudi.sdjwt.JwtAndClaims
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps.kbJwtIssuer
import eu.europa.ec.eudi.sdjwt.SdJwt
import eu.europa.ec.eudi.sdjwt.vc.ClaimPath
import eu.europa.ec.eudi.sdjwt.vc.ClaimPathElement
import eu.europa.ec.eudi.wallet.document.DocumentId
import eu.europa.ec.eudi.wallet.document.DocumentManager
import eu.europa.ec.eudi.wallet.document.IssuedDocument
import eu.europa.ec.eudi.wallet.document.format.MsoMdocFormat
import eu.europa.ec.eudi.wallet.document.format.SdJwtVcFormat
import eu.europa.ec.eudi.wallet.internal.OpenId4VpUtils.getSessionTranscriptBytes
import eu.europa.ec.eudi.wallet.issue.openid4vci.toJoseEncoded
import kotlinx.coroutines.runBlocking
import java.util.Base64
import java.util.Date
import java.util.UUID
import kotlin.collections.component1
import kotlin.collections.component2

class ProcessedMsoMdocOpenId4VpRequest(
    private val processedDeviceRequest: ProcessedDeviceRequest,
    private val resolvedRequestObject: ResolvedRequestObject,
    val msoMdocNonce: String,
) : RequestProcessor.ProcessedRequest.Success(processedDeviceRequest.requestedDocuments) {
    override fun generateResponse(
        disclosedDocuments: DisclosedDocuments,
        signatureAlgorithm: Algorithm?,
    ): ResponseResult {
        return try {
            require(resolvedRequestObject is ResolvedRequestObject.OpenId4VPAuthorization)
            val presentationQuery = resolvedRequestObject.presentationQuery
            require(presentationQuery is PresentationQuery.ByPresentationDefinition) {
                "Currently only PresentationDefinition is supported"
            }

            val presentationDefinition = presentationQuery.value

            val deviceResponse = processedDeviceRequest.generateResponse(
                disclosedDocuments,
                signatureAlgorithm
            ).getOrThrow() as DeviceResponse

            val vpContent = VpContent.PresentationExchange(
                verifiablePresentations = listOf(
                    VerifiablePresentation.Generic(
                        Base64.getUrlEncoder().withoutPadding()
                            .encodeToString(deviceResponse.deviceResponseBytes)
                    )
                ),
                presentationSubmission = PresentationSubmission(
                    id = Id(UUID.randomUUID().toString()),
                    definitionId = presentationDefinition.id,
                    descriptorMaps = presentationDefinition.inputDescriptors.map { inputDescriptor ->
                        DescriptorMap(
                            id = inputDescriptor.id,
                            format = FORMAT_MSO_MDOC,
                            path = JsonPath.Companion.jsonPath("$")!!
                        )
                    }
                )
            )
            val consensus = Consensus.PositiveConsensus.VPTokenConsensus(vpContent)

            ResponseResult.Success(
                OpenId4VpResponse.DeviceResponse(
                    resolvedRequestObject = resolvedRequestObject,
                    consensus = consensus,
                    msoMdocNonce = msoMdocNonce,
                    responseBytes = deviceResponse.deviceResponseBytes
                )
            )
        } catch (e: Throwable) {
            ResponseResult.Failure(e)
        }
    }
}

class ProcessedGenericOpenId4VpRequest(
    private val documentManager: DocumentManager,
    private val resolvedRequestObject: ResolvedRequestObject,
    private val inputDescriptorMap: Map<InputDescriptorId, List<DocumentId>>,
    requestedDocuments: RequestedDocuments,
    val msoMdocNonce: String,
) : RequestProcessor.ProcessedRequest.Success(requestedDocuments) {
    override fun generateResponse(
        disclosedDocuments: DisclosedDocuments,
        signatureAlgorithm: Algorithm?,
    ): ResponseResult {
        return try {
            require(resolvedRequestObject is ResolvedRequestObject.OpenId4VPAuthorization)
            val presentationQuery = resolvedRequestObject.presentationQuery
            require(presentationQuery is PresentationQuery.ByPresentationDefinition) {
                "Currently only PresentationDefinition is supported"
            }

            val presentationDefinition = presentationQuery.value

            val verifiablePresentations = disclosedDocuments.map { disclosedDocument ->
                val document =
                    documentManager.getValidIssuedDocumentById(disclosedDocument.documentId)
                document.id to when (document.format) {
                    is SdJwtVcFormat -> presentSdJwtVc(
                        document = document,
                        disclosedDocument = disclosedDocument,
                        signatureAlgorithm = signatureAlgorithm ?: Algorithm.ES256,
                    )

                    is MsoMdocFormat -> presentMsoMdoc(
                        sessionTranscript = resolvedRequestObject
                            .getSessionTranscriptBytes(msoMdocNonce),
                        disclosedDocument = disclosedDocument,
                        requestedDocuments = requestedDocuments,
                        signatureAlgorithm = signatureAlgorithm ?: Algorithm.ES256
                    )
                }
            }.toList()

            val descriptorMaps = constructDescriptorsMap(verifiablePresentations)

            val presentationSubmission = PresentationSubmission(
                id = Id(UUID.randomUUID().toString()),
                definitionId = presentationDefinition.id,
                descriptorMaps = descriptorMaps,
            )
            val vpContent = VpContent.PresentationExchange(
                verifiablePresentations = verifiablePresentations.map { it.second }.toList(),
                presentationSubmission = presentationSubmission,
            )
            val consensus = Consensus.PositiveConsensus.VPTokenConsensus(vpContent)

            ResponseResult.Success(
                OpenId4VpResponse.GenericResponse(
                    resolvedRequestObject = resolvedRequestObject,
                    consensus = consensus,
                    msoMdocNonce = msoMdocNonce,
                    response = verifiablePresentations
                        .map { it.second }
                        .map { it.toString() }
                        .toList()
                )
            )
        } catch (e: Throwable) {
            ResponseResult.Failure(e)
        }
    }

    private fun presentMsoMdoc(
        disclosedDocument: DisclosedDocument,
        requestedDocuments: RequestedDocuments,
        sessionTranscript: ByteArray,
        signatureAlgorithm: Algorithm,
    ): VerifiablePresentation.Generic {
        val deviceResponse = ProcessedDeviceRequest(
            documentManager = documentManager,
            sessionTranscript = sessionTranscript,
            requestedDocuments = RequestedDocuments(requestedDocuments.filter { it.documentId == disclosedDocument.documentId })
        ).generateResponse(
            disclosedDocuments = DisclosedDocuments(disclosedDocument),
            signatureAlgorithm = signatureAlgorithm
        ).getOrThrow() as DeviceResponse

        return VerifiablePresentation.Generic(
            Base64
                .getUrlEncoder()
                .withoutPadding()
                .encodeToString(deviceResponse.deviceResponseBytes)
        )
    }

    private fun presentSdJwtVc(
        document: IssuedDocument,
        disclosedDocument: DisclosedDocument,
        signatureAlgorithm: Algorithm,
    ): VerifiablePresentation.Generic {
        val issuedSdJwt = DefaultSdJwtOps
            .unverifiedIssuanceFrom(String(document.issuerProvidedData))
            .getOrThrow()

        return VerifiablePresentation.Generic(
            issuedSdJwt.present(disclosedDocument.disclosedItems.map { disclosedItem ->
                require(disclosedItem is SdJwtVcItem)
                ClaimPath(disclosedItem.path.map {
                    ClaimPathElement.Claim(it)
                })
            }.toSet())?.let { presentation ->
                // check if cnf is present and present with key binding
                if (null != issuedSdJwt.jwt.second["cnf"]) {
                    presentation.presentWithKeyBinding(
                        signatureAlgorithm = signatureAlgorithm,
                        document = document,
                        keyUnlockData = disclosedDocument.keyUnlockData,
                        clientId = resolvedRequestObject.client.id,
                        nonce = resolvedRequestObject.nonce,
                        issueDate = Date()
                    )
                } else presentation.serialize()
            } ?: throw IllegalArgumentException("Failed to create SD JWT VC presentation")
        )
    }


    private fun SdJwt<JwtAndClaims>.presentWithKeyBinding(
        document: IssuedDocument,
        keyUnlockData: KeyUnlockData?,
        clientId: VerifierId,
        nonce: String,
        signatureAlgorithm: Algorithm,
        issueDate: Date,
    ): String {
        return runBlocking {
            val algorithm = JWSAlgorithm.parse((signatureAlgorithm).jwseAlgorithmIdentifier)
            val buildKbJwt = kbJwtIssuer(
                signer = object : JWSSigner {
                    override fun getJCAContext(): JCAContext = JCAContext()
                    override fun supportedJWSAlgorithms(): Set<JWSAlgorithm> = setOf(algorithm)
                    override fun sign(header: JWSHeader, signingInput: ByteArray): Base64URL {
                        val signature =
                            document.sign(signingInput, signatureAlgorithm, keyUnlockData)
                                .getOrThrow()
                        return Base64URL.encode(signature.toJoseEncoded(algorithm))
                    }
                },
                signAlgorithm = algorithm,
                publicKey = JWK.parseFromPEMEncodedObjects(document.keyInfo.publicKey.toPem()) as AsymmetricJWK
            ) {
                audience(clientId.originalClientId)
                claim("nonce", nonce)
                issueTime(issueDate)
            }
            serializeWithKeyBinding(buildKbJwt).getOrThrow()
        }
    }

    private fun constructDescriptorsMap(
        verifiablePresentations: List<Pair<DocumentId, VerifiablePresentation.Generic>>,
    ): List<DescriptorMap> {

        return inputDescriptorMap.flatMap { (inputDescriptorId, documentIds) ->
            verifiablePresentations.mapIndexed { index, (documentId, _) ->
                documentIds.takeIf { it.contains(documentId) }
                    ?.let {
                        DescriptorMap(
                            id = inputDescriptorId,
                            format = when (documentManager.getValidIssuedDocumentById(documentId).format) {
                                is MsoMdocFormat -> FORMAT_MSO_MDOC
                                is SdJwtVcFormat -> FORMAT_SD_JWT_VC
                            },
                            path = JsonPath.jsonPath(if (verifiablePresentations.size > 1) "$[$index]" else "$")
                                ?: throw IllegalStateException("Failed to create JsonPath")
                        )
                    }
            }
        }.filterNotNull()
    }
}

