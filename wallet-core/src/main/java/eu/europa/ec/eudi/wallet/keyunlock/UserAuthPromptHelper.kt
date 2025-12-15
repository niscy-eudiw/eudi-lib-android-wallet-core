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

import android.app.Activity
import android.app.Application
import android.os.Bundle
import androidx.fragment.app.FragmentActivity
import org.multipaz.context.initializeApplication
import org.multipaz.securearea.KeyUnlockDataProvider
import java.lang.ref.WeakReference

/**
 * Authentication prompt bridge for multipaz key unlock operations.
 *
 * This bridge handles:
 * - Multipaz application context initialization
 * - Activity lifecycle tracking for authentication prompts
 * - Providing [KeyUnlockDataProvider] for signing operations
 *
 * Supports both biometric (fingerprint, face) AND device credential
 * (PIN, pattern, password) authentication methods.
 *
 * ## Usage
 *
 * ### Option 1: Use defaults (simplest)
 * ```kotlin
 * class MyApp : Application() {
 *     override fun onCreate() {
 *         super.onCreate()
 *         UserAuthPromptHelper.initialize(this)
 *     }
 * }
 * ```
 *
 * ### Option 2: Custom messages
 * ```kotlin
 * UserAuthPromptHelper.initialize(
 *     application = this,
 *     title = "Verify your identity",
 *     subtitle = "Use fingerprint or PIN to sign"
 * )
 * ```
 *
 * ### Option 3: Custom provider (full control)
 * ```kotlin
 * UserAuthPromptHelper.initialize(this)
 * UserAuthPromptHelper.setCustomProvider(object : KeyUnlockDataProvider {
 *     override suspend fun getKeyUnlockData(...): KeyUnlockData {
 *         // Your custom UI and logic
 *     }
 * })
 * ```
 *
 * The dispatcher is used internally by wallet-core for all signing operations.
 * You typically don't need to use it directly.
 */
object UserAuthPromptHelper {

    @Volatile
    private var currentActivityRef: WeakReference<FragmentActivity>? = null
    private var promptTitle: String = "Authentication Required"
    private var promptSubtitle: String = "Authenticate to continue"
    private var initialized: Boolean = false
    private var customProvider: KeyUnlockDataProvider? = null

    private val activityLifecycleCallbacks = object : Application.ActivityLifecycleCallbacks {
        override fun onActivityResumed(activity: Activity) {
            (activity as? FragmentActivity)?.let {
                currentActivityRef = WeakReference(it)
            }
        }

        override fun onActivityPaused(activity: Activity) {
            if (currentActivityRef?.get() == activity) {
                currentActivityRef = null
            }
        }

        override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {}
        override fun onActivityStarted(activity: Activity) {}
        override fun onActivityStopped(activity: Activity) {}
        override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
        override fun onActivityDestroyed(activity: Activity) {}
    }

    /**
     * Initialize the authentication prompt bridge.
     *
     * Call this once at app startup in Application.onCreate().
     * This will:
     * - Initialize multipaz application context
     * - Register activity lifecycle callbacks for tracking foreground activity
     *
     * @param application The application instance
     * @param title Default title for authentication prompt (optional)
     * @param subtitle Default subtitle for authentication prompt (optional)
     */
    @JvmStatic
    @JvmOverloads
    fun initialize(
        application: Application,
        title: String = "Authentication Required",
        subtitle: String = "Authenticate to continue"
    ) {
        if (initialized) return

        // Initialize multipaz application context
        initializeApplication(application)

        // Register lifecycle callbacks to track foreground activity
        application.registerActivityLifecycleCallbacks(activityLifecycleCallbacks)

        this.promptTitle = title
        this.promptSubtitle = subtitle
        this.initialized = true
    }

    /**
     * Set a custom [KeyUnlockDataProvider] for full control over authentication UI.
     *
     * When set, this provider will be used instead of the default [AndroidAuthPromptProvider].
     * Use this if you need:
     * - Custom UI (e.g., Compose-based dialog)
     * - Custom authentication flow
     * - Additional logic before/after authentication
     *
     * @param provider Custom provider implementation, or null to use default
     */
    @JvmStatic
    fun setCustomProvider(provider: KeyUnlockDataProvider?) {
        customProvider = provider
    }

    /**
     * Returns whether the bridge has been initialized.
     */
    @JvmStatic
    fun isInitialized(): Boolean = initialized

    /**
     * Get the current foreground activity.
     */
    @JvmStatic
    fun getCurrentActivity(): FragmentActivity? = currentActivityRef?.get()

    /**
     * The [KeyUnlockDataProvider] dispatcher to add to coroutine context.
     *
     * Returns the custom provider if set via [setCustomProvider], otherwise
     * returns the default [AndroidAuthPromptProvider] which shows a system
     * BiometricPrompt dialog.
     *
     * When added to a coroutine context, this dispatcher will automatically
     * show an authentication prompt (biometric or PIN/pattern/password) when
     * a key needs to be unlocked for signing operations.
     *
     * @throws IllegalStateException if [initialize] was not called
     */
    @JvmStatic
    val dispatcher: KeyUnlockDataProvider
        get() {
            if (!initialized) {
                throw IllegalStateException(
                    "UserAuthPromptHelper not initialized. Call UserAuthPromptHelper.initialize(application) first."
                )
            }
            // Return custom provider if set, otherwise default
            return customProvider ?: AndroidAuthPromptProvider(
                activityProvider = { currentActivityRef?.get() },
                defaultTitle = promptTitle,
                defaultSubtitle = promptSubtitle
            )
        }

    /**
     * Reset the bridge (mainly for testing purposes).
     */
    @JvmStatic
    fun reset() {
        currentActivityRef = null
        promptTitle = "Authentication Required"
        promptSubtitle = "Authenticate to continue"
        customProvider = null
        initialized = false
    }
}
