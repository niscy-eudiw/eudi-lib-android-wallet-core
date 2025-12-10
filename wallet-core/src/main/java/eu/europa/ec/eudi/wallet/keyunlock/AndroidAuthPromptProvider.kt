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

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.CancellableContinuation
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
 * Provides Android biometric/credential authentication for key unlock operations.
 *
 * Handles device capability detection to ensure proper authenticator selection:
 * - BIOMETRIC_STRONG (Class 3) for crypto operations on capable devices
 * - DEVICE_CREDENTIAL fallback when strong biometrics unavailable
 *
 * @property activityProvider Returns the current FragmentActivity for prompt display
 * @property defaultTitle Default prompt title
 * @property defaultSubtitle Default prompt subtitle
 * @property mainThreadDispatcher Dispatcher for main thread operations (injectable for testing)
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
        val activity = requireActivity()
        val androidSecureArea = requireAndroidKeystore(secureArea)
        val unlockData = AndroidKeystoreKeyUnlockData(androidSecureArea, alias)
        val cryptoObject = getCryptoObject(unlockData)
        val (title, subtitle) = extractPromptText(unlockReason)

        val authenticated = showAuthPrompt(activity, cryptoObject, title, subtitle)
        if (!authenticated) {
            throw KeyLockedException("User cancelled authentication")
        }

        return unlockData
    }

    private fun requireActivity(): FragmentActivity =
        activityProvider() ?: throw KeyLockedException("No activity available for authentication prompt")

    private fun requireAndroidKeystore(secureArea: SecureArea): AndroidKeystoreSecureArea =
        secureArea as? AndroidKeystoreSecureArea
            ?: throw KeyLockedException("SecureArea is not AndroidKeystoreSecureArea")

    private suspend fun getCryptoObject(unlockData: AndroidKeystoreKeyUnlockData): BiometricPrompt.CryptoObject? =
        try {
            unlockData.getCryptoObjectForSigning()
        } catch (e: Exception) {
            throw KeyLockedException("Failed to get CryptoObject: ${e.message}")
        }

    private fun extractPromptText(unlockReason: UnlockReason): Pair<String, String> =
        when (unlockReason) {
            is UnlockReason.HumanReadable -> unlockReason.title to unlockReason.subtitle
            else -> defaultTitle to defaultSubtitle
        }

    private suspend fun showAuthPrompt(
        activity: FragmentActivity,
        cryptoObject: BiometricPrompt.CryptoObject?,
        title: String,
        subtitle: String
    ): Boolean = withContext(mainThreadDispatcher.dispatcher) {
        suspendCancellableCoroutine { continuation ->
            val biometricPrompt = createBiometricPrompt(activity, continuation)
            val authConfig = resolveAuthConfig(activity, cryptoObject)
            val promptInfo = buildPromptInfo(title, subtitle, authConfig.authenticators)

            executeAuthentication(biometricPrompt, promptInfo, authConfig.cryptoObject)
            continuation.invokeOnCancellation { biometricPrompt.cancelAuthentication() }
        }
    }

    private fun createBiometricPrompt(
        activity: FragmentActivity,
        continuation: CancellableContinuation<Boolean>
    ): BiometricPrompt {
        val executor = ContextCompat.getMainExecutor(activity)
        val callback = AuthenticationCallback(continuation)
        return BiometricPrompt(activity, executor, callback)
    }

    /**
     * Resolves authentication configuration based on device capabilities.
     *
     * CryptoObject requires BIOMETRIC_STRONG (Class 3). On devices without it,
     * falls back to DEVICE_CREDENTIAL which supports crypto operations.
     */
    private fun resolveAuthConfig(
        activity: FragmentActivity,
        cryptoObject: BiometricPrompt.CryptoObject?
    ): AuthConfig {
        if (cryptoObject == null) {
            return AuthConfig(
                authenticators = Authenticators.BIOMETRIC_WEAK or Authenticators.DEVICE_CREDENTIAL,
                cryptoObject = null
            )
        }

        val hasStrongBiometric = hasStrongBiometricSupport(activity)
        return if (hasStrongBiometric) {
            AuthConfig(
                authenticators = Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL,
                cryptoObject = cryptoObject
            )
        } else {
            AuthConfig(
                authenticators = Authenticators.DEVICE_CREDENTIAL,
                cryptoObject = cryptoObject
            )
        }
    }

    private fun hasStrongBiometricSupport(activity: FragmentActivity): Boolean =
        BiometricManager.from(activity)
            .canAuthenticate(Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    private fun buildPromptInfo(
        title: String,
        subtitle: String,
        authenticators: Int
    ): BiometricPrompt.PromptInfo =
        BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(authenticators)
            .setConfirmationRequired(false)
            .build()

    private fun executeAuthentication(
        prompt: BiometricPrompt,
        promptInfo: BiometricPrompt.PromptInfo,
        cryptoObject: BiometricPrompt.CryptoObject?
    ) {
        if (cryptoObject != null) {
            prompt.authenticate(promptInfo, cryptoObject)
        } else {
            prompt.authenticate(promptInfo)
        }
    }

    private data class AuthConfig(
        val authenticators: Int,
        val cryptoObject: BiometricPrompt.CryptoObject?
    )

    private class AuthenticationCallback(
        private val continuation: CancellableContinuation<Boolean>
    ) : BiometricPrompt.AuthenticationCallback() {

        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            if (continuation.isActive) continuation.resume(true)
        }

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            if (continuation.isActive) continuation.resume(false)
        }

        override fun onAuthenticationFailed() {
            // Allow retry - only complete on success or terminal error
        }
    }
}
