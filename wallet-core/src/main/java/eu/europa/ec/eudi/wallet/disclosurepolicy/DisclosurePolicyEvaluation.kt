/*
 * Copyright (c) 2026 European Commission
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
package eu.europa.ec.eudi.wallet.disclosurepolicy

import eu.europa.ec.eudi.iso18013.transfer.response.RequestProcessor.ProcessedRequest
import eu.europa.ec.eudi.wallet.disclosurepolicy.DisclosurePolicyResult.CannotEvaluate
import eu.europa.ec.eudi.wallet.disclosurepolicy.DisclosurePolicyResult.CannotEvaluate.Reason
import eu.europa.ec.eudi.wallet.disclosurepolicy.DisclosurePolicyResult.NoPolicy
import eu.europa.ec.eudi.wallet.disclosurepolicy.DisclosurePolicyResult.NotSatisfied
import eu.europa.ec.eudi.wallet.disclosurepolicy.DisclosurePolicyResult.Satisfied
import eu.europa.ec.eudi.wallet.disclosurepolicy.EmbeddedDisclosurePolicy.PolicyType
import eu.europa.ec.eudi.wallet.document.Document
import eu.europa.ec.eudi.wallet.document.format.SdJwtVcFormat
import eu.europa.ec.eudi.wallet.registration.RegistrationCertificate
import eu.europa.ec.eudi.wallet.registration.RegistrationCertificateResult
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import org.bouncycastle.asn1.x500.X500Name
import org.multipaz.crypto.javaX509Certificates
import org.multipaz.request.JsonRequestedClaim
import org.multipaz.request.MdocRequestedClaim
import org.multipaz.request.RequestedClaim
import java.security.cert.X509Certificate

/**
 * The result of evaluating the embedded disclosure policy of a document for a presentation
 * request. The result informs the user; the user decides whether to present the document.
 */
sealed interface DisclosurePolicyResult {

    /** The document has no embedded disclosure policy, or its policy sets no restriction. */
    data object NoPolicy : DisclosurePolicyResult

    /** The relying party meets the policy. */
    data object Satisfied : DisclosurePolicyResult

    /**
     * The relying party does not meet the policy.
     *
     * @property policyUri the URI that identifies the policy
     * @property laymanUri the address of a page that explains the policy to the user, if the issuer
     * published one
     */
    data class NotSatisfied(
        val policyUri: String,
        val laymanUri: String? = null,
    ) : DisclosurePolicyResult

    /**
     * The policy could not be evaluated.
     *
     * @property reason the reason the policy could not be evaluated
     * @property policyUri the URI that identifies the policy, or `null` when it could not be read
     * @property laymanUri the address of a page that explains the policy to the user, or `null` when
     * the issuer did not publish one or the policy could not be read
     */
    data class CannotEvaluate(
        val reason: Reason,
        val policyUri: String? = null,
        val laymanUri: String? = null,
    ) : DisclosurePolicyResult {

        /** The reasons a policy cannot be evaluated. */
        enum class Reason {
            /** The policy does not follow the expected JSON form. */
            MALFORMED_POLICY,

            /** The policy lists access certificate subjects and the relying party has no trusted access certificate with an identifier. */
            RELYING_PARTY_NOT_IDENTIFIED,

            /**
             * The policy lists services of registered relying parties or certificate subjects, and the
             * relying party has no verified registration certificate, or its signer chain is not available.
             */
            REGISTRATION_CERTIFICATE_NOT_VERIFIED,
        }
    }
}

/**
 * The result of evaluating the embedded disclosure policy of a document, for the document and for
 * each claim about to be presented.
 *
 * @property documentResult the result of the policy of the document
 * @property claimResults for each claim passed to [evaluateDisclosurePolicy], the result that applies
 * to it: the result of its own policy, when the policy of the document sets one for it, or else
 * [documentResult]
 */
data class DisclosurePolicyEvaluation(
    val documentResult: DisclosurePolicyResult,
    val claimResults: Map<RequestedClaim, DisclosurePolicyResult> = emptyMap(),
)

/**
 * Evaluates the embedded disclosure policy of this document for a presentation request.
 *
 * @param request the processed presentation request
 * @param claims the claims of this document about to be presented, as in the presentment selection
 * @return the results to show to the user before the user approves the presentation
 */
fun Document.evaluateDisclosurePolicy(
    request: ProcessedRequest.Success,
    claims: Collection<RequestedClaim> = emptyList(),
): DisclosurePolicyEvaluation =
    evaluateDisclosurePolicy(
        policyJson = issuerMetadata?.embeddedDisclosurePolicy,
        relyingPartyIdentifier = request.trustedRelyingPartyIdentifier(),
        verifiedRegistration = request.wrpRegistration as? RegistrationCertificateResult.Verified,
        claims = claims,
        vct = (format as? SdJwtVcFormat)?.vct,
    )

/**
 * Evaluates an embedded disclosure policy.
 *
 * @param policyJson the policy as stored with the document, or `null` when there is none
 * @param relyingPartyIdentifier the identifier in the trusted access certificate of the relying party
 * @param verifiedRegistration the verified registration certificate of the relying party, or `null`
 * when there is none
 * @param claims the claims about to be presented
 * @param vct the vct of the document, for an SD-JWT VC
 */
internal fun evaluateDisclosurePolicy(
    policyJson: JsonElement?,
    relyingPartyIdentifier: String?,
    verifiedRegistration: RegistrationCertificateResult.Verified?,
    claims: Collection<RequestedClaim> = emptyList(),
    vct: String? = null,
): DisclosurePolicyEvaluation {
    if (policyJson == null) return DisclosurePolicyEvaluation(NoPolicy, claims.associateWith { NoPolicy })
    val policy = (policyJson as? JsonObject)?.let { EmbeddedDisclosurePolicy.fromJson(it) }
        ?: return CannotEvaluate(Reason.MALFORMED_POLICY).let { DisclosurePolicyEvaluation(it, claims.associateWith { _ -> it }) }
    val evaluate = { type: PolicyType -> policy.evaluate(type, relyingPartyIdentifier, verifiedRegistration) }
    val documentResult = evaluate(policy.type)
    return DisclosurePolicyEvaluation(
        documentResult = documentResult,
        claimResults = claims.associateWith { claim ->
            policy.claimPolicyOf(claim, vct)?.let { evaluate(it.type) } ?: documentResult
        },
    )
}

private fun EmbeddedDisclosurePolicy.evaluate(
    type: PolicyType,
    relyingPartyIdentifier: String?,
    verifiedRegistration: RegistrationCertificateResult.Verified?,
): DisclosurePolicyResult = when (type) {
    PolicyType.None -> NoPolicy
    is PolicyType.AuthorizedRelyingParties ->
        evaluateAuthorizedRelyingParties(this, type, relyingPartyIdentifier, verifiedRegistration?.registration)

    is PolicyType.AuthorizedCertificateSubjects ->
        evaluateAuthorizedCertificateSubjects(this, type, verifiedRegistration?.signerChain.orEmpty())
}

/**
 * Finds the claim policy that applies to [claim], or `null` when there is none, so that the policy
 * of the document applies.
 *
 * - ISO/IEC 18013-5: the claim policy whose namespace and attribute identifier are those of [claim].
 * - SD-JWT VC: among the claim policies for [vct], those whose attribute identifier, split at `.`,
 *   is the claim path of [claim] or its beginning; the one with the most segments wins. For
 *   example, a policy for `address` applies to `address.street_address`, unless there is also one
 *   for `address.street_address`.
 */
private fun EmbeddedDisclosurePolicy.claimPolicyOf(
    claim: RequestedClaim,
    vct: String?,
): EmbeddedDisclosurePolicy.ClaimPolicy? = when (claim) {
    is MdocRequestedClaim ->
        claimPolicies.firstOrNull {
            it.namespaceOrVct == claim.namespaceName && it.attributeIdentifier == claim.dataElementName
        }

    is JsonRequestedClaim -> {
        val claimPath = claim.claimPath
            .takeWhile { (it as? JsonPrimitive)?.isString == true }
            .map { it.jsonPrimitive.content }
        claimPolicies
            .filter { it.namespaceOrVct == vct }
            .map { it to it.attributeIdentifier.split('.') }
            .filter { (_, policyPath) -> claimPath.take(policyPath.size) == policyPath }
            .maxByOrNull { (_, policyPath) -> policyPath.size }
            ?.first
    }
}

/**
 * The policy is met when one of its subjects is the subject of a certificate in the chain that
 * signed the verified registration certificate, the root included. The root is not always part of
 * the chain that the relying party presents, so its subject is taken as the issuer of the last
 * certificate of the chain, which the trust validation of the chain has linked to it.
 */
private fun evaluateAuthorizedCertificateSubjects(
    policy: EmbeddedDisclosurePolicy,
    type: PolicyType.AuthorizedCertificateSubjects,
    registrationSignerChain: List<X509Certificate>,
): DisclosurePolicyResult {
    val chainNames = runCatching {
        registrationSignerChain.map { X500Name.getInstance(it.subjectX500Principal.encoded) } +
            X500Name.getInstance(registrationSignerChain.last().issuerX500Principal.encoded)
    }.getOrNull() ?: return policy.cannotEvaluate(Reason.REGISTRATION_CERTIFICATE_NOT_VERIFIED)
    val matched = type.subjectDns.any { subjectDn ->
        val authorized = policyDistinguishedName(subjectDn) ?: return@any false
        chainNames.any { authorized == it }
    }
    return if (matched) Satisfied else policy.notSatisfied()
}

/**
 * A service of a registered relying party is matched by the identifier (`sub`) of its verified
 * registration certificate, which names the relying party itself also when an intermediary presents
 * the request. An access certificate subject is matched by the identifier in the trusted access
 * certificate; a subject without an identifier matches no relying party.
 */
private fun evaluateAuthorizedRelyingParties(
    policy: EmbeddedDisclosurePolicy,
    type: PolicyType.AuthorizedRelyingParties,
    relyingPartyIdentifier: String?,
    verifiedRegistration: RegistrationCertificate?,
): DisclosurePolicyResult {
    val wrpIdentifiers = verifiedRegistration?.identifiers.orEmpty().map { it.value }
    val matched = type.relyingParties.any { relyingParty ->
        when (relyingParty) {
            // The service identifier is not compared: Technical Specification 5 registers it with the Registrar,
            // but no certificate that the relying party presents carries it.
            is AuthorizedRelyingParty.WrpService -> relyingParty.wrpIdentifier in wrpIdentifiers
            is AuthorizedRelyingParty.AccessCertificateSubject ->
                relyingPartyIdentifier != null && relyingParty.relyingPartyIdentifier() == relyingPartyIdentifier
        }
    }
    if (matched) return Satisfied
    if (verifiedRegistration == null && type.relyingParties.any { it is AuthorizedRelyingParty.WrpService }) {
        return policy.cannotEvaluate(Reason.REGISTRATION_CERTIFICATE_NOT_VERIFIED)
    }
    if (relyingPartyIdentifier == null && type.relyingParties.any { it is AuthorizedRelyingParty.AccessCertificateSubject }) {
        return policy.cannotEvaluate(Reason.RELYING_PARTY_NOT_IDENTIFIED)
    }
    return policy.notSatisfied()
}

private fun EmbeddedDisclosurePolicy.notSatisfied(): NotSatisfied = NotSatisfied(policyUri, laymanUri)

private fun EmbeddedDisclosurePolicy.cannotEvaluate(reason: Reason): CannotEvaluate =
    CannotEvaluate(reason, policyUri, laymanUri)

/**
 * Returns the identifier in the access certificate of the relying party, when the request has a
 * single requester identity and its certificate chain is trusted.
 */
private fun ProcessedRequest.Success.trustedRelyingPartyIdentifier(): String? {
    if (trustMetadata == null) return null
    val identity = requester.requesterIdentities.singleOrNull() ?: return null
    val accessCertificate = identity.certChain.javaX509Certificates.firstOrNull() ?: return null
    return runCatching { X500Name.getInstance(accessCertificate.subjectX500Principal.encoded) }
        .getOrNull()
        ?.relyingPartyIdentifier()
}
