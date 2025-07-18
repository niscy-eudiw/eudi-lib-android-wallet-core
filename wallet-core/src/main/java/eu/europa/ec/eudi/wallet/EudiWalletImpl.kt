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

package eu.europa.ec.eudi.wallet

import android.content.Context
import eu.europa.ec.eudi.iso18013.transfer.TransferManager
import eu.europa.ec.eudi.iso18013.transfer.readerauth.ReaderTrustStore
import eu.europa.ec.eudi.iso18013.transfer.readerauth.ReaderTrustStoreAware
import eu.europa.ec.eudi.wallet.document.DocumentManager
import eu.europa.ec.eudi.wallet.document.sample.SampleDocumentManager
import eu.europa.ec.eudi.wallet.document.sample.SampleDocumentManagerImpl
import eu.europa.ec.eudi.wallet.internal.getCertificate
import eu.europa.ec.eudi.wallet.issue.openid4vci.OpenId4VciManager
import eu.europa.ec.eudi.wallet.logging.Logger
import eu.europa.ec.eudi.wallet.presentation.PresentationManager
import eu.europa.ec.eudi.wallet.statium.DocumentStatusResolver
import eu.europa.ec.eudi.wallet.transactionLogging.TransactionLogger
import io.ktor.client.HttpClient
import java.security.cert.X509Certificate

/**
 * Implementation of [EudiWallet]
 * @property context the android context
 * @property config the wallet configuration
 * @property documentManager the document manager
 * @property presentationManager the presentation manager
 * @property transferManager the transfer manager
 * @property documentStatusResolver the document status resolver
 * @property transactionLogger the transaction logger
 * @property ktorHttpClientFactory the ktor http client factory for use in the OpenId4VciManager and OpenId4VpManager
 * @property logger the logger
 */
class EudiWalletImpl internal constructor(
    val context: Context,
    override val config: EudiWalletConfig,
    override val documentManager: DocumentManager,
    override val presentationManager: PresentationManager,
    override val transferManager: TransferManager,
    override val logger: Logger,
    override val documentStatusResolver: DocumentStatusResolver,
    val transactionLogger: TransactionLogger?,
    val ktorHttpClientFactory: (() -> HttpClient)?
) : EudiWallet, DocumentManager, PresentationManager by presentationManager,
    SampleDocumentManager by SampleDocumentManagerImpl(documentManager),
    DocumentStatusResolver by documentStatusResolver {

    override fun setReaderTrustStore(readerTrustStore: ReaderTrustStore) = apply {
        (this as PresentationManager).readerTrustStore = readerTrustStore
        if (transferManager is ReaderTrustStoreAware) {
            transferManager.readerTrustStore = readerTrustStore
        }
    }

    override fun setTrustedReaderCertificates(trustedReaderCertificates: List<X509Certificate>) =
        setReaderTrustStore(ReaderTrustStore.getDefault(trustedReaderCertificates))

    override fun setTrustedReaderCertificates(vararg rawRes: Int) =
        setReaderTrustStore(ReaderTrustStore.getDefault(rawRes.map { context.getCertificate(it) }))

    /**
     * Creates an instance of [OpenId4VciManager] for interacting with the OpenID for Verifiable Credential Issuance protocol.
     *
     * The configuration can be provided in two ways:
     * 1. As a parameter to this method
     * 2. From the wallet's [EudiWalletConfig.openId4VciConfig]
     *
     * @param config Optional configuration for the OpenId4VciManager. If null, the configuration from [EudiWalletConfig.openId4VciConfig]
     *               will be used. If both are null, an [IllegalStateException] is thrown.
     * @param ktorHttpClientFactory Optional HTTP client factory to use for network requests. If null, the wallet's
     *                            configured HTTP client factory will be used.
     * @return An instance of [OpenId4VciManager] configured with the provided or default settings
     * @throws IllegalStateException If neither a config parameter is provided nor a configuration exists in [EudiWalletConfig]
     */
    override fun createOpenId4VciManager(
        config: OpenId4VciManager.Config?,
        ktorHttpClientFactory: (() -> HttpClient)?,
    ): OpenId4VciManager {
        val config = config ?: this.config.openId4VciConfig ?: throw IllegalStateException(
            "OpenId4Vci configuration is missing. Please provide a config parameter or configure it in EudiWalletConfig."
        )

        val httpClientFactory = ktorHttpClientFactory ?: this.ktorHttpClientFactory

        return OpenId4VciManager(context) {
            documentManager(this@EudiWalletImpl)
            config(config)
            logger(this@EudiWalletImpl.logger)
            if (httpClientFactory != null) {
                ktorHttpClientFactory(httpClientFactory)
            }
        }
    }
}
