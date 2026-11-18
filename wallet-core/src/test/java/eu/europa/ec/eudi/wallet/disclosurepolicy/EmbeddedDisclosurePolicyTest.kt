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
import eu.europa.ec.eudi.iso18013.transfer.response.ResponseResult
import eu.europa.ec.eudi.iso18013.transfer.response.WrpRegistrationInfo
import eu.europa.ec.eudi.wallet.disclosurepolicy.DisclosurePolicyResult.CannotEvaluate
import eu.europa.ec.eudi.wallet.disclosurepolicy.DisclosurePolicyResult.CannotEvaluate.Reason
import eu.europa.ec.eudi.wallet.disclosurepolicy.DisclosurePolicyResult.NoPolicy
import eu.europa.ec.eudi.wallet.disclosurepolicy.DisclosurePolicyResult.NotSatisfied
import eu.europa.ec.eudi.wallet.disclosurepolicy.DisclosurePolicyResult.Satisfied
import eu.europa.ec.eudi.wallet.document.Document
import eu.europa.ec.eudi.wallet.document.metadata.IssuerMetadata
import eu.europa.ec.eudi.wallet.registration.Intermediary
import eu.europa.ec.eudi.wallet.registration.RegistrationCertificate
import eu.europa.ec.eudi.wallet.registration.RegistrationCertificateResult
import eu.europa.ec.eudi.wallet.registration.RegistrationFailureReason
import eu.europa.ec.eudi.wallet.registration.RegistrationIdentifier
import io.mockk.every
import io.mockk.mockk
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Assert.assertEquals
import org.junit.Test
import org.multipaz.crypto.X509CertChain
import org.multipaz.crypto.fromJavaX509Certificates
import org.multipaz.presentment.CredentialSelection
import org.multipaz.request.OpenID4VPRequesterIdentity
import org.multipaz.request.Requester
import org.multipaz.securearea.KeyUnlockData
import org.multipaz.trustmanagement.TrustMetadata
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Date

class EmbeddedDisclosurePolicyTest {

    @Test
    fun `a document without a policy has no restriction`() {
        assertEquals(NoPolicy, evaluateDisclosurePolicy(null, "LEIXG-1", null))
    }

    @Test
    fun `a none policy sets no restriction`() {
        assertEquals(NoPolicy, evaluate("""{"policy_uri": "$POLICY_URI", "policy": "none"}"""))
    }

    @Test
    fun `a policy that is not a JSON object is malformed`() {
        val result = evaluateDisclosurePolicy(JsonPrimitive(POLICY_URI), "LEIXG-1", null)

        assertEquals(CannotEvaluate(Reason.MALFORMED_POLICY), result)
    }

    @Test
    fun `a policy without a policy uri is malformed`() {
        val result = evaluate("""{"policy": "none"}""")

        assertEquals(CannotEvaluate(Reason.MALFORMED_POLICY), result)
    }

    @Test
    fun `a policy string other than none is malformed`() {
        val result = evaluate("""{"policy_uri": "$POLICY_URI", "policy": "all"}""")

        assertEquals(CannotEvaluate(Reason.MALFORMED_POLICY), result)
    }

    @Test
    fun `a rule with more than one member is malformed`() {
        val result = evaluate(
            """
            {
              "policy_uri": "$POLICY_URI",
              "policy": {
                "authorized_rp_ids": ["LEIXG-1, Service 1"],
                "authorized_cert_subject_DNs": ["CN=Registrar, C=EU"]
              }
            }
            """
        )

        assertEquals(CannotEvaluate(Reason.MALFORMED_POLICY), result)
    }

    @Test
    fun `an unknown rule makes the policy malformed`() {
        val result = evaluate("""{"policy_uri": "$POLICY_URI", "policy": {"authorized_purposes": []}}""")

        assertEquals(CannotEvaluate(Reason.MALFORMED_POLICY), result)
    }

    @Test
    fun `a certificate of the registration signer chain satisfies the policy`() {
        assertEquals(Satisfied, evaluateWithSignerChain(authorizedCertificateSubjects(INTERMEDIATE_CA)))
    }

    @Test
    fun `the root of the registration signer chain satisfies the policy also when the chain does not include it`() {
        assertEquals(Satisfied, evaluateWithSignerChain(authorizedCertificateSubjects(ROOT_CA)))
    }

    @Test
    fun `certificate subjects are compared regardless of case, spacing and reversed attribute order`() {
        val result = evaluateWithSignerChain(authorizedCertificateSubjects("c=nl,  o=ministerie bzk, cn=registrar ca"))

        assertEquals(Satisfied, result)
    }

    @Test
    fun `a registration signer chain without an authorized subject does not satisfy the policy`() {
        val result = evaluateWithSignerChain(authorizedCertificateSubjects("CN=Other Registrar CA, O=Other, C=BE"))

        assertEquals(NotSatisfied::class, result::class)
    }

    @Test
    fun `certificate subjects cannot be checked without a verified registration certificate`() {
        val result = evaluateDisclosurePolicy(policyJson(authorizedCertificateSubjects(ROOT_CA)), "LEIXG-1", null)

        assertEquals(Reason.REGISTRATION_CERTIFICATE_NOT_VERIFIED, (result as CannotEvaluate).reason)
    }

    @Test
    fun `certificate subjects cannot be checked without the registration signer chain`() {
        val result = evaluateDisclosurePolicy(
            policyJson(authorizedCertificateSubjects(ROOT_CA)),
            "LEIXG-1",
            RegistrationCertificateResult.Verified(registration("LEIXG-1")),
        )

        assertEquals(Reason.REGISTRATION_CERTIFICATE_NOT_VERIFIED, (result as CannotEvaluate).reason)
    }

    @Test
    fun `a certificate subject without attribute types makes the policy malformed`() {
        val result = evaluateWithSignerChain(
            authorizedCertificateSubjects("Autoriteit Uitgifte Registratiecertificaten, Ministerie BZK, NTRNL-12345678, NL")
        )

        assertEquals(CannotEvaluate(Reason.MALFORMED_POLICY), result)
    }

    @Test
    fun `the registration signer chain in the request is used`() {
        val document = documentWithPolicy(authorizedCertificateSubjects(ROOT_CA))

        val result = document.evaluateDisclosurePolicy(
            request(
                listOf(certificate(BCStyle.ORGANIZATION_IDENTIFIER, "LEIXG-1")),
                registration = RegistrationCertificateResult.Verified(
                    registration("LEIXG-1"),
                    signerChain = registrationSignerChain,
                ),
            )
        )

        assertEquals(Satisfied, result)
    }

    @Test
    fun `extensions are ignored`() {
        val result = evaluate(
            """
            {
              "policy_uri": "$POLICY_URI",
              "policy": "none",
              "extensions": {"specific_attribute_policies": {"org.iso.18013.5.1, portrait": {"authorized_rp_ids": []}}}
            }
            """
        )

        assertEquals(NoPolicy, result)
    }

    @Test
    fun `a registered relying party in the verified registration certificate satisfies the policy`() {
        val result = evaluate(authorizedRelyingParties("LEIXG-1, Service 1"), registration = registration("LEIXG-1"))

        assertEquals(Satisfied, result)
    }

    @Test
    fun `the service identifier is not compared`() {
        val result = evaluate(authorizedRelyingParties("LEIXG-1, Other service"), registration = registration("LEIXG-1"))

        assertEquals(Satisfied, result)
    }

    @Test
    fun `a relying party that matches no entry does not satisfy the policy`() {
        val result = evaluate(
            authorizedRelyingParties("LEIXG-2, Service 1", "ORGID=LEIXG-3"),
            identifier = "LEIXG-1",
            registration = registration("LEIXG-1"),
        )

        assertEquals(NotSatisfied(policyUri = POLICY_URI, laymanUri = LAYMAN_URI), result)
    }

    @Test
    fun `an intermediary is not the registered relying party`() {
        val registration = registration("LEIXG-1").copy(intermediary = Intermediary(identifier = "LEIXG-9"))

        assertEquals(
            NotSatisfied::class,
            evaluate(authorizedRelyingParties("LEIXG-9, Service 1"), "LEIXG-9", registration)::class,
        )
        assertEquals(Satisfied, evaluate(authorizedRelyingParties("LEIXG-1, Service 1"), "LEIXG-9", registration))
    }

    @Test
    fun `entries are trimmed and empty or duplicate entries are ignored`() {
        val policy = authorizedRelyingParties(" LEIXG-1 ,  Service 1 ", "", "LEIXG-1, Service 1")

        assertEquals(
            listOf(AuthorizedRelyingParty.WrpService("LEIXG-1", "Service 1")),
            (EmbeddedDisclosurePolicy.fromJson(policyJson(policy))?.type
                as EmbeddedDisclosurePolicy.PolicyType.AuthorizedRelyingParties).relyingParties,
        )
    }

    @Test
    fun `an entry without a service identifier makes the policy malformed`() {
        val result = evaluate(authorizedRelyingParties("LEIXG-1"), registration = registration("LEIXG-1"))

        assertEquals(CannotEvaluate(Reason.MALFORMED_POLICY), result)
    }

    @Test
    fun `registered relying parties cannot be checked without a verified registration certificate`() {
        val document = documentWithPolicy(authorizedRelyingParties("LEIXG-1, Service 1"))

        val result = document.evaluateDisclosurePolicy(
            request(
                listOf(certificate(BCStyle.ORGANIZATION_IDENTIFIER, "LEIXG-1")),
                registration = RegistrationCertificateResult.Failed(
                    reason = RegistrationFailureReason.EXPIRED,
                    registration = registration("LEIXG-1"),
                ),
            )
        )

        assertEquals(Reason.REGISTRATION_CERTIFICATE_NOT_VERIFIED, (result as CannotEvaluate).reason)
    }

    @Test
    fun `a matching subject is enough without a registration certificate`() {
        val policy = authorizedRelyingParties("LEIXG-2, Service 1", "ORGID=LEIXG-1, O=Shop SA, C=GR")

        assertEquals(Satisfied, evaluate(policy, identifier = "LEIXG-1", registration = null))
    }

    @Test
    fun `a subject without an identifier matches no relying party`() {
        val result = evaluate(authorizedRelyingParties("CN=Shop, O=Shop SA, C=GR"))

        assertEquals(NotSatisfied::class, result::class)
    }

    @Test
    fun `a subject with two serial numbers matches no relying party`() {
        // OpenSSL prints the surname as SN, which a policy reads as the serial number.
        val result = evaluate(
            authorizedRelyingParties("CN=Jo Doe, SN=Doe, GN=Jo, serialNumber=TINGR-123, C=GR"),
            identifier = "TINGR-123",
        )

        assertEquals(NotSatisfied::class, result::class)
    }

    @Test
    fun `SN in a policy is the serial number of a natural person`() {
        val document = documentWithPolicy(
            authorizedRelyingParties("CN=Jo Doe, GN=Jo, surname=Doe, SN=TINGR-123, C=GR")
        )

        val result = document.evaluateDisclosurePolicy(
            request(listOf(certificate(BCStyle.SERIALNUMBER, "TINGR-123")))
        )

        assertEquals(Satisfied, result)
    }

    @Test
    fun `an untrusted access certificate does not identify the relying party`() {
        val document = documentWithPolicy(authorizedRelyingParties("ORGID=LEIXG-1"))

        val result = document.evaluateDisclosurePolicy(
            request(listOf(certificate(BCStyle.ORGANIZATION_IDENTIFIER, "LEIXG-1")), trusted = false)
        )

        assertEquals(Reason.RELYING_PARTY_NOT_IDENTIFIED, (result as CannotEvaluate).reason)
    }

    @Test
    fun `several requester identities do not identify the relying party`() {
        val document = documentWithPolicy(authorizedRelyingParties("ORGID=LEIXG-1"))

        val result = document.evaluateDisclosurePolicy(
            request(
                listOf(
                    certificate(BCStyle.ORGANIZATION_IDENTIFIER, "LEIXG-1"),
                    certificate(BCStyle.ORGANIZATION_IDENTIFIER, "LEIXG-2"),
                )
            )
        )

        assertEquals(Reason.RELYING_PARTY_NOT_IDENTIFIED, (result as CannotEvaluate).reason)
    }

    @Test
    fun `a verified registration certificate in the request satisfies the policy`() {
        val document = documentWithPolicy(authorizedRelyingParties("LEIXG-1, Service 1"))

        val result = document.evaluateDisclosurePolicy(
            request(
                listOf(certificate(BCStyle.ORGANIZATION_IDENTIFIER, "LEIXG-1")),
                registration = RegistrationCertificateResult.Verified(registration("LEIXG-1")),
            )
        )

        assertEquals(Satisfied, result)
    }
}

private const val POLICY_URI = "https://issuer.example.com/edp/v1"
private const val LAYMAN_URI = "https://issuer.example.com/edp"

private fun authorizedRelyingParties(vararg entries: String): String =
    """
    {
      "policy_uri": "$POLICY_URI",
      "policy": {"authorized_rp_ids": [${entries.joinToString { "\"$it\"" }}]},
      "layman_uri": "$LAYMAN_URI"
    }
    """

private fun registration(wrpIdentifier: String): RegistrationCertificate =
    RegistrationCertificate(identifiers = listOf(RegistrationIdentifier(wrpIdentifier)))

private fun policyJson(policy: String): JsonObject = Json.parseToJsonElement(policy).jsonObject

private fun evaluate(
    policy: String,
    identifier: String? = "LEIXG-1",
    registration: RegistrationCertificate? = null,
): DisclosurePolicyResult =
    evaluateDisclosurePolicy(policyJson(policy), identifier, registration?.let { RegistrationCertificateResult.Verified(it) })

private const val ROOT_CA = "CN=Registrar Root CA, O=Ministerie BZK, C=NL"
private const val INTERMEDIATE_CA = "CN=Registrar CA, O=Ministerie BZK, C=NL"

private fun authorizedCertificateSubjects(vararg subjectDns: String): String =
    """
    {
      "policy_uri": "$POLICY_URI",
      "policy": {"authorized_cert_subject_DNs": [${subjectDns.joinToString { "\"$it\"" }}]}
    }
    """

/**
 * The chain that signed a registration certificate, signer first: a signer certificate issued by an
 * intermediate CA, issued by a root CA that the chain does not include.
 */
private val registrationSignerChain: List<X509Certificate> by lazy {
    val root = ecKeyPair()
    val intermediate = ecKeyPair()
    val signer = ecKeyPair()
    listOf(
        issuedCertificate("CN=Registrar Signer, O=Ministerie BZK, C=NL", signer, INTERMEDIATE_CA, intermediate),
        issuedCertificate(INTERMEDIATE_CA, intermediate, ROOT_CA, root),
    )
}

private fun evaluateWithSignerChain(policy: String): DisclosurePolicyResult =
    evaluateDisclosurePolicy(
        policyJson(policy),
        "LEIXG-1",
        RegistrationCertificateResult.Verified(registration("LEIXG-1"), signerChain = registrationSignerChain),
    )

private fun ecKeyPair(): KeyPair =
    KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

private fun issuedCertificate(
    subject: String,
    subjectKeyPair: KeyPair,
    issuer: String,
    issuerKeyPair: KeyPair,
): X509Certificate {
    val now = Instant.now()
    val builder = JcaX509v3CertificateBuilder(
        X500Name(issuer),
        BigInteger(64, SecureRandom()),
        Date.from(now.minusSeconds(3600)),
        Date.from(now.plusSeconds(86400)),
        X500Name(subject),
        subjectKeyPair.public,
    )
    val signer = JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeyPair.private)
    return JcaX509CertificateConverter().getCertificate(builder.build(signer))
}

private fun documentWithPolicy(policy: String): Document = mockk {
    every { issuerMetadata } returns IssuerMetadata(
        documentConfigurationIdentifier = "employee_card",
        display = emptyList(),
        claims = null,
        credentialIssuerIdentifier = "https://issuer.example.com",
        issuerDisplay = null,
        embeddedDisclosurePolicy = policyJson(policy),
    )
}

private fun request(
    accessCertificates: List<X509Certificate>,
    trusted: Boolean = true,
    registration: WrpRegistrationInfo? = null,
): ProcessedRequest.Success = object : ProcessedRequest.Success(
    presentmentData = mockk(),
    requester = Requester(
        requesterIdentities = accessCertificates.map {
            OpenID4VPRequesterIdentity(X509CertChain.fromJavaX509Certificates(listOf(it)), "verifier.example.com")
        }
    ),
    trustMetadata = if (trusted) TrustMetadata() else null,
    wrpRegistration = registration,
) {
    override suspend fun generateResponse(
        selection: CredentialSelection,
        keyUnlockData: Map<String, KeyUnlockData>,
    ): ResponseResult = error("not used")
}

private fun certificate(identifierType: ASN1ObjectIdentifier, identifier: String): X509Certificate {
    val subject = X500NameBuilder(BCStyle.INSTANCE)
        .addRDN(BCStyle.CN, "Test Relying Party")
        .addRDN(identifierType, identifier)
        .build()
    val keyPair = KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair()
    val now = Instant.now()
    val builder = JcaX509v3CertificateBuilder(
        subject,
        BigInteger(64, SecureRandom()),
        Date.from(now.minusSeconds(3600)),
        Date.from(now.plusSeconds(86400)),
        subject,
        keyPair.public,
    )
    val signer = JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.private)
    return JcaX509CertificateConverter().getCertificate(builder.build(signer))
}
