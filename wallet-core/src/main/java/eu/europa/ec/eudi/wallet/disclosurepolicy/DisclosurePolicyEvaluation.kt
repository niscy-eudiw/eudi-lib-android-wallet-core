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

            /**
             * The relying party is not authenticated: its access certificate is not trusted, or has no
             * identifier, while the policy needs it.
             */
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
 * @property documentResult the result for presenting the document: the least favourable of
 * [claimResults], or the result of the policy of the document when no claims are passed
 * @property claimResults for each claim passed to [evaluateDisclosurePolicy], the least favourable
 * result of the policies that apply to it. A claim policy applies to the claim it is set for, to the
 * claims inside it that have no claim policy of their own, and to the claims that contain it, since
 * presenting a claim presents the claims inside it. When no claim policy applies to a claim, the
 * policy of the document applies to it.
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
        relyingPartyAuthenticated = request.trustMetadata != null,
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
 * @param relyingPartyAuthenticated whether the access certificate of the relying party is trusted;
 * the registration certificate is used only when it is, since it is bound to the access certificate
 * by its identifier only
 */
internal fun evaluateDisclosurePolicy(
    policyJson: JsonElement?,
    relyingPartyIdentifier: SubjectIdentifier?,
    verifiedRegistration: RegistrationCertificateResult.Verified?,
    claims: Collection<RequestedClaim> = emptyList(),
    vct: String? = null,
    relyingPartyAuthenticated: Boolean = true,
): DisclosurePolicyEvaluation {
    if (policyJson == null) return DisclosurePolicyEvaluation(NoPolicy, claims.associateWith { NoPolicy })
    val policy = (policyJson as? JsonObject)?.let { EmbeddedDisclosurePolicy.fromJson(it) }
        ?: return CannotEvaluate(Reason.MALFORMED_POLICY).let { DisclosurePolicyEvaluation(it, claims.associateWith { _ -> it }) }
    val relyingParty = RelyingParty(
        identifier = relyingPartyIdentifier,
        registration = verifiedRegistration?.takeIf { relyingPartyAuthenticated },
        noRegistrationReason = if (verifiedRegistration != null) Reason.RELYING_PARTY_NOT_IDENTIFIED
        else Reason.REGISTRATION_CERTIFICATE_NOT_VERIFIED,
    )
    val evaluate = { type: PolicyType -> policy.evaluate(type, relyingParty) }
    val policyResult = evaluate(policy.type)
    val claimResults = claims.associateWith { claim -> policy.claimResult(claim, vct, policyResult, evaluate) }
    return DisclosurePolicyEvaluation(
        documentResult = claimResults.values.maxByOrNull { it.severity } ?: policyResult,
        claimResults = claimResults,
    )
}

/**
 * What a presentation request tells about the relying party.
 *
 * @property identifier the identifier in its trusted access certificate
 * @property registration its verified registration certificate, when its access certificate is trusted
 * @property noRegistrationReason the reason to report when the policy needs [registration] and there
 * is none
 */
private class RelyingParty(
    val identifier: SubjectIdentifier?,
    val registration: RegistrationCertificateResult.Verified?,
    val noRegistrationReason: Reason,
)

private fun EmbeddedDisclosurePolicy.evaluate(type: PolicyType, relyingParty: RelyingParty): DisclosurePolicyResult =
    when (type) {
        PolicyType.None -> NoPolicy
        is PolicyType.AuthorizedRelyingParties -> evaluateAuthorizedRelyingParties(this, type, relyingParty)
        is PolicyType.AuthorizedCertificateSubjects -> evaluateAuthorizedCertificateSubjects(this, type, relyingParty)
    }

/**
 * The least favourable result of the policies that apply to [claim].
 *
 * - ISO/IEC 18013-5: the claim policy whose namespace and attribute identifier are those of [claim]
 *   applies to it, or else the policy of the document, whose result is [policyResult].
 * - SD-JWT VC: the path of a claim policy for [vct] is its attribute identifier split at `.`, and the
 *   path of [claim] is its claim path without array elements. The claim policy whose path is the
 *   path of [claim], or else the longest beginning of it, applies to the claim: a policy for
 *   `address` applies to `address.street_address`. When there is none, the policy of the document
 *   applies. Presenting a claim presents the claims inside it, so the claim policies whose path
 *   continues the path of [claim] apply to it too: a policy for `address.street_address` applies to
 *   `address`.
 */
private fun EmbeddedDisclosurePolicy.claimResult(
    claim: RequestedClaim,
    vct: String?,
    policyResult: DisclosurePolicyResult,
    evaluate: (PolicyType) -> DisclosurePolicyResult,
): DisclosurePolicyResult = when (claim) {
    is MdocRequestedClaim ->
        claimPolicies
            .firstOrNull { it.namespaceOrVct == claim.namespaceName && it.attributeIdentifier == claim.dataElementName }
            ?.let { evaluate(it.type) }
            ?: policyResult

    is JsonRequestedClaim -> {
        val claimPath = claim.claimPath
            .filter { (it as? JsonPrimitive)?.isString == true }
            .map { it.jsonPrimitive.content }
        val policies = claimPolicies
            .filter { it.namespaceOrVct == vct }
            .map { it to it.attributeIdentifier.split('.') }
        val ownResult = policies
            .filter { (_, policyPath) -> claimPath.take(policyPath.size) == policyPath }
            .maxByOrNull { (_, policyPath) -> policyPath.size }
            ?.let { (claimPolicy, _) -> evaluate(claimPolicy.type) }
            ?: policyResult
        val nestedResults = policies
            .filter { (_, policyPath) -> policyPath.size > claimPath.size && policyPath.take(claimPath.size) == claimPath }
            .map { (claimPolicy, _) -> evaluate(claimPolicy.type) }
        (nestedResults + ownResult).maxBy { it.severity }
    }
}

/** How unfavourable a result is to presenting: not satisfied, then not evaluated, satisfied and no policy. */
private val DisclosurePolicyResult.severity: Int
    get() = when (this) {
        NoPolicy -> 0
        Satisfied -> 1
        is CannotEvaluate -> 2
        is NotSatisfied -> 3
    }

/**
 * The policy is met when one of its subjects is the subject of a certificate in the chain that
 * signed the verified registration certificate, the root included. Only the part of the chain in
 * which each certificate is signed by the next one counts: certificates after it were not part of
 * the validated path. The root is not always part of the chain that the relying party presents, so
 * its subject is taken as the issuer of the last certificate of that part, which the trust
 * validation of the chain has linked to it.
 */
private fun evaluateAuthorizedCertificateSubjects(
    policy: EmbeddedDisclosurePolicy,
    type: PolicyType.AuthorizedCertificateSubjects,
    relyingParty: RelyingParty,
): DisclosurePolicyResult {
    val registration = relyingParty.registration ?: return policy.cannotEvaluate(relyingParty.noRegistrationReason)
    val signedChain = registration.signerChain.signedPrefix()
    val chainNames = runCatching {
        signedChain.map { X500Name.getInstance(it.subjectX500Principal.encoded) } +
            X500Name.getInstance(signedChain.last().issuerX500Principal.encoded)
    }.getOrNull() ?: return policy.cannotEvaluate(Reason.REGISTRATION_CERTIFICATE_NOT_VERIFIED)
    val matched = type.subjectDns.any { subjectDn ->
        val authorized = policyDistinguishedName(subjectDn) ?: return@any false
        chainNames.any { authorized == it }
    }
    return if (matched) Satisfied else policy.notSatisfied()
}

/**
 * The beginning of this chain in which each certificate is signed by the next one, and names it as
 * its issuer.
 */
private fun List<X509Certificate>.signedPrefix(): List<X509Certificate> {
    val signed = take(1).toMutableList()
    for (next in drop(1)) {
        val previous = signed.last()
        val signedByNext = previous.issuerX500Principal == next.subjectX500Principal &&
            runCatching { previous.verify(next.publicKey) }.isSuccess
        if (!signedByNext) break
        signed += next
    }
    return signed
}

/**
 * A service of a registered relying party is matched by the identifier (`sub`) of its verified
 * registration certificate, which names the relying party itself also when an intermediary presents
 * the request. An access certificate subject is matched by the type and the value of the identifier
 * in the trusted access certificate; a subject without an identifier matches no relying party. When
 * an intermediary presents the request, the access certificate is the intermediary's, so access
 * certificate subjects are not matched.
 */
private fun evaluateAuthorizedRelyingParties(
    policy: EmbeddedDisclosurePolicy,
    type: PolicyType.AuthorizedRelyingParties,
    relyingParty: RelyingParty,
): DisclosurePolicyResult {
    val registration = relyingParty.registration?.registration
    val wrpIdentifiers = registration?.identifiers.orEmpty().map { it.value }
    val accessCertificateIdentifier = relyingParty.identifier?.takeIf { registration?.intermediary == null }
    val matched = type.relyingParties.any { authorized ->
        when (authorized) {
            // The service identifier is not compared: Technical Specification 5 registers it with the Registrar,
            // but no certificate that the relying party presents carries it.
            is AuthorizedRelyingParty.WrpService -> authorized.wrpIdentifier in wrpIdentifiers
            is AuthorizedRelyingParty.AccessCertificateSubject ->
                accessCertificateIdentifier != null && authorized.relyingPartyIdentifier() == accessCertificateIdentifier
        }
    }
    if (matched) return Satisfied
    if (registration == null && type.relyingParties.any { it is AuthorizedRelyingParty.WrpService }) {
        return policy.cannotEvaluate(relyingParty.noRegistrationReason)
    }
    if (relyingParty.identifier == null && type.relyingParties.any { it is AuthorizedRelyingParty.AccessCertificateSubject }) {
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
private fun ProcessedRequest.Success.trustedRelyingPartyIdentifier(): SubjectIdentifier? {
    if (trustMetadata == null) return null
    val identity = requester.requesterIdentities.singleOrNull() ?: return null
    val accessCertificate = identity.certChain.javaX509Certificates.firstOrNull() ?: return null
    return runCatching { X500Name.getInstance(accessCertificate.subjectX500Principal.encoded) }
        .getOrNull()
        ?.relyingPartyIdentifier()
}
