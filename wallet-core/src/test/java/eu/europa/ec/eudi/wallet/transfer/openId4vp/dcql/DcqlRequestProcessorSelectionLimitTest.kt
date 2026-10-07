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
package eu.europa.ec.eudi.wallet.transfer.openId4vp.dcql

import eu.europa.ec.eudi.iso18013.transfer.response.ReaderAuthPolicy
import eu.europa.ec.eudi.iso18013.transfer.response.RequestProcessor
import eu.europa.ec.eudi.openid4vp.Client
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject
import eu.europa.ec.eudi.openid4vp.dcql.ClaimPath
import eu.europa.ec.eudi.openid4vp.dcql.ClaimPathElement
import eu.europa.ec.eudi.openid4vp.dcql.ClaimsQuery
import eu.europa.ec.eudi.openid4vp.dcql.CredentialQuery
import eu.europa.ec.eudi.openid4vp.dcql.CredentialQueryIds
import eu.europa.ec.eudi.openid4vp.dcql.CredentialSetQuery
import eu.europa.ec.eudi.openid4vp.dcql.CredentialSets
import eu.europa.ec.eudi.openid4vp.dcql.Credentials
import eu.europa.ec.eudi.openid4vp.dcql.DCQL
import eu.europa.ec.eudi.openid4vp.dcql.DCQLMetaSdJwtVcExtensions
import eu.europa.ec.eudi.openid4vp.dcql.QueryId
import eu.europa.ec.eudi.wallet.document.DocumentManager
import eu.europa.ec.eudi.wallet.document.IssuedDocument
import eu.europa.ec.eudi.wallet.document.format.DocumentFormat
import eu.europa.ec.eudi.wallet.document.format.SdJwtVcFormat
import eu.europa.ec.eudi.wallet.transfer.openId4vp.OpenId4VpReaderTrust
import eu.europa.ec.eudi.wallet.transfer.openId4vp.OpenId4VpRequest
import eu.europa.ec.eudi.wallet.transfer.openId4vp.OpenId4VpRequestException
import eu.europa.ec.eudi.wallet.transfer.openId4vp.ReaderTrustResult
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Test
import org.multipaz.claim.JsonClaim
import org.multipaz.credential.SecureAreaBoundCredential
import java.net.URI
import kotlin.test.assertFalse
import kotlin.test.assertIs

private const val PID_VCT = "urn:eudi:pid:1"

/**
 * Tests for the limit on the selections a DCQL request allows. Every credential query asks for a
 * PID. With one PID in the wallet, an optional credential set with k options allows k + 1 choices
 * and the request allows the product of the choices of its sets.
 */
class DcqlRequestProcessorSelectionLimitTest {

    @Test
    fun `a request that allows as many selections as the limit is processed`(): Unit = runBlocking {
        // 2 × 2 × 2 × 5 × 5 × 5 = 1000 selections
        val request = requestWithOptionalSets(optionsPerSet = listOf(1, 1, 1, 4, 4, 4))

        val processed = buildProcessor().process(request)

        assertIs<ProcessedDcqlRequest>(processed)
    }

    /**
     * The failure is not an [OpenId4VpRequestException], so no error response is sent to the
     * verifier: whether a request goes over the limit depends on the credentials in the wallet.
     */
    @Test
    fun `a request that allows more selections than the limit fails without an error for the verifier`(): Unit =
        runBlocking {
            // 2^10 = 1024 selections
            val request = requestWithOptionalSets(optionsPerSet = List(10) { 1 })

            val processed = buildProcessor().process(request)

            val failure = assertIs<RequestProcessor.ProcessedRequest.Failure>(processed)
            assertFalse(failure.error is OpenId4VpRequestException)
        }

    /** A query with `multiple = true` is one choice however many credentials match it. */
    @Test
    fun `queries with multiple are counted as one choice each`(): Unit = runBlocking {
        // 2 credentials for each of 10 queries: 2^10 = 1024 selections without `multiple`, 1 with it
        val queries = List(10) { index ->
            pidQuery(QueryId("pid_$index"), multiple = true)
        }
        val request = request(DCQL(credentials = Credentials(queries), credentialSets = null))

        val processed = buildProcessor(pidCount = 2).process(request)

        assertIs<ProcessedDcqlRequest>(processed)
    }

    /** Builds a request with one optional credential set per entry, with that many options. */
    private fun requestWithOptionalSets(optionsPerSet: List<Int>): OpenId4VpRequest {
        val idsPerSet = optionsPerSet.mapIndexed { set, options ->
            List(options) { option -> QueryId("pid_${set}_$option") }
        }
        val dcql = DCQL(
            credentials = Credentials(idsPerSet.flatten().map { id -> pidQuery(id) }),
            credentialSets = CredentialSets(
                idsPerSet.map { ids ->
                    CredentialSetQuery(options = ids.map { CredentialQueryIds(listOf(it)) }, required = false)
                },
            ),
        )
        return request(dcql)
    }

    /** Builds a query for the `given_name` of a PID. */
    private fun pidQuery(id: QueryId, multiple: Boolean? = null): CredentialQuery =
        CredentialQuery.sdJwtVc(
            id = id,
            sdJwtVcMeta = DCQLMetaSdJwtVcExtensions(vctValues = listOf(PID_VCT)),
            multiple = multiple,
            requireCryptographicHolderBinding = false,
            claims = listOf(
                ClaimsQuery.sdJwtVc(path = ClaimPath(listOf(ClaimPathElement.Claim("given_name")))),
            ),
        )

    private fun request(dcql: DCQL): OpenId4VpRequest {
        val resolved = mockk<ResolvedRequestObject> {
            every { query } returns dcql
            every { transactionData } returns null
            every { client } returns Client.RedirectUri(URI.create("https://verifier.example"))
        }
        return mockk { every { resolvedRequestObject } returns resolved }
    }

    /** Builds a processor over a wallet that holds [pidCount] PIDs with a `given_name` claim. */
    private fun buildProcessor(pidCount: Int = 1): DcqlRequestProcessor {
        val issuedDocs = List(pidCount) {
            val credential = mockk<SecureAreaBoundCredential> {
                coEvery { getClaims(documentTypeRepository = null) } returns listOf(
                    JsonClaim(
                        displayName = "given_name",
                        attribute = null,
                        vct = PID_VCT,
                        claimPath = JsonArray(listOf(JsonPrimitive("given_name"))),
                        value = JsonPrimitive("Alice"),
                    ),
                )
            }
            mockk<IssuedDocument> {
                every { format } returns SdJwtVcFormat(PID_VCT) as DocumentFormat
                coEvery { findCredential(now = any()) } returns credential
            }
        }
        val documentManager = mockk<DocumentManager> {
            every { getDocuments(predicate = any()) } returns issuedDocs
            every { getDocuments(predicate = null) } returns issuedDocs
        }
        val trust = mockk<OpenId4VpReaderTrust> {
            every { result } returns ReaderTrustResult.Pending
            every { readerTrustStore } returns null
            every { readerTrustStore = any() } returns Unit
        }
        return DcqlRequestProcessor(documentManager, trust, ReaderAuthPolicy.DoNotEnforce)
    }
}
