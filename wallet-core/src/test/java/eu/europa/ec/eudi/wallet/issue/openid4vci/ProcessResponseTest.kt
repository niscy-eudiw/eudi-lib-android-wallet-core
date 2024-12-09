/*
 * Copyright (c) 2024 European Commission
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

import com.android.identity.crypto.Algorithm
import com.android.identity.securearea.KeyUnlockData
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError
import eu.europa.ec.eudi.openid4vci.SubmissionOutcome
import eu.europa.ec.eudi.wallet.document.DocumentId
import eu.europa.ec.eudi.wallet.document.DocumentManager
import eu.europa.ec.eudi.wallet.document.UnsignedDocument
import eu.europa.ec.eudi.wallet.document.format.MsoMdocFormat
import eu.europa.ec.eudi.wallet.logging.Logger
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlin.test.Test

class ProcessResponseTest {

    @Test
    fun `process triggers DocumentRequiresUserAuth and resumes with keyUnlockData`() = runTest {
        val documentId = "document-id"
        val documentManager: DocumentManager = mockk {
            every { deleteDocumentById(documentId) } returns mockk()
        }
        val deferredContextCreator = mockk<DeferredContextCreator> {}
        val issuedDocumentIds = mutableListOf<DocumentId>()
        val logger = Logger { println(it) }
        val keyUnlockDataMock: KeyUnlockData = mockk()

        val listener = OpenId4VciManager.OnResult<IssueEvent> { event ->
            CoroutineScope(Dispatchers.Default).launch {
                when (event) {
                    is IssueEvent.DocumentRequiresUserAuth -> {
                        event.resume(keyUnlockDataMock)
                    }

                    else -> {}
                }
            }
        }

        val unsignedDocument: UnsignedDocument = mockk {
            every { id } returns documentId
            every { name } returns "document-name"
            every { format } returns MsoMdocFormat(docType = "doc-type")
        }
        val outcome: SubmissionOutcome.Failed =
            SubmissionOutcome.Failed(error = CredentialIssuanceError.UnsupportedCredentialFormat())
        val outcomeResult: Result<SubmissionOutcome> = Result.failure(
            UserAuthRequiredException(
                signingAlgorithm = Algorithm.ES256,
                resume = { _ -> outcome },
                cause = null
            )
        )

        val processResponse = ProcessResponse(
            documentManager,
            deferredContextCreator,
            listener,
            issuedDocumentIds,
            logger
        )

        processResponse.process(unsignedDocument, outcomeResult)
    }
}