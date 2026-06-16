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

package eu.europa.ec.eudi.wallet.document

import org.multipaz.securearea.CreateKeySettings

/**
 * Interface that defines the required creationSettings when creating a document with
 * [DocumentManager.createDocument]. Implementors of [DocumentManager] may
 * introduce custom requirements for creating a document.
 *
 * @see [CreateDocumentSettingsImpl] implementation
 */
interface CreateDocumentSettings {

    /**
     * Identifier for the secure area where document keys will be stored.
     * This should match an existing secure area in the system.
     */
    val secureAreaIdentifier: String

    /**
     * Configuration settings for key creation within the secure area.
     * These settings define properties such as key algorithms, key sizes,
     * and any other parameters required by the underlying secure area implementation.
     */
    val createKeySettings: CreateKeySettings

    /**
     * Specifies the number of credentials to create for this document.
     * Multiple credentials can be used for load balancing or redundancy purposes.
     * Must be greater than 0.
     */
    val numberOfCredentials: Int

    /**
     * Defines the policy for credential usage and lifecycle management.
     * Controls whether credentials are used once and deleted or rotated through multiple uses.
     *
     * @see CredentialPolicy
     */
    val credentialPolicy: CredentialPolicy

    companion object {
        /**
         * Create a new instance of [CreateDocumentSettings] for [DocumentManagerImpl.createDocument]
         * that uses the [org.multipaz.securearea.SecureArea].
         *
         * @param secureAreaIdentifier The identifier from [org.multipaz.securearea.SecureArea]
         * where the document's keys should be stored
         * @param createKeySettings The [CreateKeySettings] implementation that accompanies the provided
         * [org.multipaz.securearea.SecureArea]
         * @param numberOfCredentials The number of credentials to create for this document.
         * Must be greater than 0. Defaults to 1 if not specified.
         * @param credentialPolicy The policy determining how credentials are managed after use.
         * Defaults to [CredentialPolicy.RotatingBatch] if not specified.
         * @return A new instance of [CreateDocumentSettings]
         * @throws IllegalArgumentException if numberOfCredentials is not greater than 0
         */
        operator fun invoke(
            secureAreaIdentifier: String,
            createKeySettings: CreateKeySettings,
            numberOfCredentials: Int = 1,
            credentialPolicy: CredentialPolicy = CredentialPolicy.RotatingBatch()
        ): CreateDocumentSettings {
            require(numberOfCredentials > 0) {
                "Number of credentials must be greater than 0"
            }
            return CreateDocumentSettingsImpl(
                secureAreaIdentifier = secureAreaIdentifier,
                createKeySettings = createKeySettings,
                numberOfCredentials = numberOfCredentials,
                credentialPolicy = credentialPolicy,
            )
        }
    }

    sealed interface CredentialPolicy {

        /**
         * Method A (Once-only / ETSI TS 119 472-3): Each credential instance is used exactly
         * once, then deleted. Credentials are typically issued in batches (batch size is captured
         * by [CreateDocumentSettings.numberOfCredentials]).
         *
         * Consumption behavior: credential is deleted after a single use.
         *
         * When [reissueTriggerUnused] is non-null, the issuer has advertised a reuse policy and
         * reissuance should be triggered when the number of remaining unused credential instances
         * is at or below this threshold. When null, no issuer reuse policy is in effect and the
         * application controls reissuance independently.
         *
         * @property reissueTriggerUnused reissuance threshold, or null if no issuer policy.
         * @see RotatingBatch for a policy that allows credential reuse
         */
        data class OnceOnly(
            val reissueTriggerUnused: Int? = null,
        ) : CredentialPolicy

        /**
         * Method B (Limited-time / ETSI TS 119 472-3): A single credential instance is presented
         * multiple times until its validity period expires. No batch issuance.
         *
         * Consumption behavior: credential persists and its usage count is incremented.
         *
         * @property reissueTriggerLifetimeLeft reissuance should be triggered when the
         *           remaining credential lifetime is at or below this duration.
         */
        data class LimitedTime(
            val reissueTriggerLifetimeLeft: kotlin.time.Duration,
        ) : CredentialPolicy

        /**
         * Method C (Rotating-batch / ETSI TS 119 472-3): Credentials are issued in a batch and
         * presented in random order per relying party. After all credentials in the batch have
         * been presented once, they are reshuffled.
         *
         * Consumption behavior: credential usage count is incremented.
         * Full random selection and reshuffle semantics are planned for a future release.
         *
         * When [reissueTriggerLifetimeLeft] is non-null, the issuer has advertised a reuse policy
         * and reissuance should be triggered when the remaining credential lifetime is at or below
         * this duration. When null, no issuer reuse policy is in effect and the application
         * controls reissuance independently.
         *
         * @property reissueTriggerLifetimeLeft reissuance threshold, or null if no issuer policy.
         * @see OnceOnly for a stricter policy that deletes credentials after use
         */
        data class RotatingBatch(
            val reissueTriggerLifetimeLeft: kotlin.time.Duration? = null,
        ) : CredentialPolicy

        /**
         * Method D (Per-Relying-Party / ETSI TS 119 472-3): Credentials are issued in a batch.
         * A different credential instance is assigned to each relying party, and the same
         * credential is consistently used for repeat visits to the same relying party.
         *
         * Consumption behavior: credential usage count is incremented.
         * Full RP-to-credential mapping is planned for a future release.
         *
         * @property reissueTriggerLifetimeLeft reissuance should be triggered when the
         *           remaining credential lifetime is at or below this duration.
         * @property reissueTriggerUnused reissuance should be triggered when the number of
         *           remaining unassigned credential instances is at or below this threshold.
         */
        data class PerRelyingParty(
            val reissueTriggerLifetimeLeft: kotlin.time.Duration,
            val reissueTriggerUnused: Int,
        ) : CredentialPolicy

        companion object
    }
}