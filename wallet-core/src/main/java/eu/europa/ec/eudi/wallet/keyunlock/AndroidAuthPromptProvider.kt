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

package eu.europa.ec.eudi.wallet.keyunlock

import androidx.biometric.BiometricManager.Authenticators
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import org.multipaz.securearea.AndroidKeystoreKeyUnlockData
import org.multipaz.securearea.AndroidKeystoreSecureArea
import org.multipaz.securearea.KeyLockedException
import org.multipaz.securearea.KeyUnlockData
import org.multipaz.securearea.KeyUnlockDataProvider
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.UnlockReason
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.resume

/**
 * A [KeyUnlockDataProvider] implementation that shows Android's authentication prompt
 * when a key needs to be unlocked for signing operations.
 *
 * This provider supports both biometric (fingerprint, face) AND device credential
 * (PIN, pattern, password) authentication methods.
 *
 * This provider:
 * 1. Creates [AndroidKeystoreKeyUnlockData] for the locked key
 * 2. Shows an authentication prompt with the CryptoObject
 * 3. Returns the authenticated KeyUnlockData on success
 * 4. Throws [KeyLockedException] on failure/cancellation
 *
 * @property activityProvider Function that returns the current FragmentActivity
 * @property defaultTitle Default title for the authentication prompt
 * @property defaultSubtitle Default subtitle for the authentication prompt
 * @property mainThreadDispatcher Dispatcher provider for main thread operations (injectable for testing)
 */
internal class AndroidAuthPromptProvider(
    private val activityProvider: () -> FragmentActivity?,
    private val defaultTitle: String = "Authentication Required",
    private val defaultSubtitle: String = "Authenticate to continue",
    internal val mainThreadDispatcher: MainThreadDispatcher = DefaultMainThreadDispatcher()
) : KeyUnlockDataProvider {

    override val key: CoroutineContext.Key<KeyUnlockDataProvider>
        get() = KeyUnlockDataProvider.Key

    override suspend fun getKeyUnlockData(
        secureArea: SecureArea,
        alias: String,
        unlockReason: UnlockReason
    ): KeyUnlockData {
        val activity = activityProvider()
            ?: throw KeyLockedException("No activity available for authentication prompt")

        // Ensure we're working with Android Keystore
        val androidSecureArea = secureArea as? AndroidKeystoreSecureArea
            ?: throw KeyLockedException("SecureArea is not AndroidKeystoreSecureArea")

        // Create unlock data for the key
        val unlockData = AndroidKeystoreKeyUnlockData(androidSecureArea, alias)

        // Get CryptoObject for signing
        val cryptoObject = try {
            unlockData.getCryptoObjectForSigning()
        } catch (e: Exception) {
            throw KeyLockedException("Failed to get CryptoObject: ${e.message}")
        }

        // Determine prompt text from UnlockReason
        val (title, subtitle) = when (unlockReason) {
            is UnlockReason.HumanReadable -> unlockReason.title to unlockReason.subtitle
            else -> defaultTitle to defaultSubtitle
        }

        // Show authentication prompt and wait for result
        val authenticated = showAuthPrompt(
            activity = activity,
            cryptoObject = cryptoObject,
            title = title,
            subtitle = subtitle
        )

        if (!authenticated) {
            throw KeyLockedException("User cancelled authentication")
        }

        return unlockData
    }

    /**
     * Shows an authentication prompt and suspends until the user authenticates or cancels.
     *
     * BiometricPrompt must be created and authenticate() must be called on the main thread.
     * We use withContext(mainThreadDispatcher.dispatcher) to ensure this requirement is met.
     *
     * @param activity The FragmentActivity to show the prompt in
     * @param cryptoObject The CryptoObject to authenticate with
     * @param title The title to display
     * @param subtitle The subtitle to display
     * @return true if authentication succeeded, false if cancelled/failed
     */
    private suspend fun showAuthPrompt(
        activity: FragmentActivity,
        cryptoObject: BiometricPrompt.CryptoObject?,
        title: String,
        subtitle: String
    ): Boolean = withContext(mainThreadDispatcher.dispatcher) {
        suspendCancellableCoroutine { continuation ->
            val executor = ContextCompat.getMainExecutor(activity)

            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (continuation.isActive) {
                        continuation.resume(true)
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (continuation.isActive) {
                        continuation.resume(false)
                    }
                }

                override fun onAuthenticationFailed() {
                    // Don't resume here - let user retry
                    // Only resume on success or error (which includes too many failures)
                }
            }

            val biometricPrompt = BiometricPrompt(activity, executor, callback)

            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle(subtitle)
                // Allow both biometric (fingerprint, face) and device credential (PIN, pattern, password)
                .setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL)
                .setConfirmationRequired(false)
                .build()

            // Authenticate with CryptoObject if available
            if (cryptoObject != null) {
                biometricPrompt.authenticate(promptInfo, cryptoObject)
            } else {
                biometricPrompt.authenticate(promptInfo)
            }

            // Cancel the prompt if the coroutine is cancelled
            continuation.invokeOnCancellation {
                biometricPrompt.cancelAuthentication()
            }
        }
    }
}
