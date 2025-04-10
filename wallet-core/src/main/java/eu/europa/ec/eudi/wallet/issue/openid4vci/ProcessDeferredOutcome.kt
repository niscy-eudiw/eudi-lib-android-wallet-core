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

import eu.europa.ec.eudi.openid4vci.Credential
import eu.europa.ec.eudi.openid4vci.DeferredCredentialQueryOutcome
import eu.europa.ec.eudi.openid4vci.DeferredIssuanceContext
import eu.europa.ec.eudi.wallet.document.DeferredDocument
import eu.europa.ec.eudi.wallet.document.Document
import eu.europa.ec.eudi.wallet.document.DocumentManager
import eu.europa.ec.eudi.wallet.document.IssuedDocument
import eu.europa.ec.eudi.wallet.document.Outcome
import eu.europa.ec.eudi.wallet.internal.d
import eu.europa.ec.eudi.wallet.issue.openid4vci.OpenId4VciManager.Companion.TAG
import eu.europa.ec.eudi.wallet.logging.Logger
import org.bouncycastle.util.encoders.Hex
import java.util.Base64

internal class ProcessDeferredOutcome(
    val documentManager: DocumentManager,
    val callback: OpenId4VciManager.OnResult<DeferredIssueResult>,
    val deferredIssuanceContext: DeferredIssuanceContext?,
    val logger: Logger? = null,
) {

    fun process(deferredDocument: DeferredDocument, outcome: DeferredCredentialQueryOutcome) {
        try {
            when (outcome) {
                is DeferredCredentialQueryOutcome.Errored -> {
                    callback(
                        DeferredIssueResult.DocumentFailed(
                            deferredDocument,
                            cause = IllegalStateException(outcome.error)
                        )
                    )
                }

                is DeferredCredentialQueryOutcome.IssuancePending -> {
                    deferredIssuanceContext?.let { ctx ->
                        documentManager.storeDeferredDocument(deferredDocument, ctx.toByteArray())
                            .notifyListener(deferredDocument)
                    } ?: callback(
                        DeferredIssueResult.DocumentNotReady(deferredDocument)
                    )
                }

                is DeferredCredentialQueryOutcome.Issued -> when (val credential =
                    outcome.credentials.first().credential) {
                    is Credential.Json -> TODO("Not supported yet")
                    is Credential.Str -> {
                        val cborBytes = Base64.getUrlDecoder().decode(credential.value)
                        logger?.d(TAG, "CBOR bytes: ${Hex.toHexString(cborBytes)}")
                        documentManager.storeIssuedDocument(deferredDocument, cborBytes)
                            .notifyListener(deferredDocument)
                    }
                }
            }
        } catch (e: Throwable) {
            callback(DeferredIssueResult.DocumentFailed(deferredDocument, e))
        }
    }


    private fun Outcome<Document>.notifyListener(
        deferredDocument: DeferredDocument,
    ) = this.kotlinResult.onSuccess { document ->
        when (document) {
            is DeferredDocument -> callback(DeferredIssueResult.DocumentNotReady(document))
            is IssuedDocument -> callback(DeferredIssueResult.DocumentIssued(document))
            else -> callback(
                DeferredIssueResult.DocumentFailed(
                    document, IllegalStateException(
                        "Unexpected document state"
                    )
                )
            )
        }
    }.onFailure { throwable ->
        documentManager.deleteDocumentById(deferredDocument.id)
        callback(
            DeferredIssueResult.DocumentFailed(
                deferredDocument,
                cause = throwable
            )
        )
    }
}