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

import android.app.Application
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.multipaz.securearea.AndroidKeystoreSecureArea
import org.multipaz.securearea.KeyLockedException
import org.multipaz.securearea.KeyUnlockData
import org.multipaz.securearea.KeyUnlockDataProvider
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.UnlockReason
import org.multipaz.securearea.software.SoftwareKeyUnlockData
import org.multipaz.securearea.software.SoftwareSecureArea
import org.multipaz.storage.ephemeral.EphemeralStorage

/**
 * Instrumented tests for custom [KeyUnlockDataProvider] functionality.
 *
 * These tests verify:
 * - Custom provider can handle different SecureArea types
 * - setCustomProvider properly routes to custom implementation
 * - Provider receives correct parameters (secureArea, alias, unlockReason)
 * - Multiple SecureArea types in single provider (composite pattern)
 */
@RunWith(AndroidJUnit4::class)
class CustomProviderInstrumentedTest {

    private lateinit var application: Application

    @Before
    fun setUp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        application = context.applicationContext as Application
        MultipazAuthPrompt.reset()
    }

    @After
    fun tearDown() {
        MultipazAuthPrompt.reset()
    }

    @Test
    fun testCustomProviderReceivesCorrectParameters() = runBlocking {
        MultipazAuthPrompt.initialize(application)

        var receivedSecureArea: SecureArea? = null
        var receivedAlias: String? = null
        var receivedReason: UnlockReason? = null

        val customProvider = object : KeyUnlockDataProvider {
            override suspend fun getKeyUnlockData(
                secureArea: SecureArea,
                alias: String,
                unlockReason: UnlockReason
            ): KeyUnlockData {
                receivedSecureArea = secureArea
                receivedAlias = alias
                receivedReason = unlockReason
                throw KeyLockedException("Test - parameters captured")
            }
        }

        MultipazAuthPrompt.setCustomProvider(customProvider)

        val storage = EphemeralStorage()
        val softwareSecureArea = SoftwareSecureArea.create(storage)
        val testAlias = "test_key_alias"
        val testReason = UnlockReason.HumanReadable("Test Title", "Test Subtitle", false)

        try {
            withContext(MultipazAuthPrompt.dispatcher) {
                MultipazAuthPrompt.dispatcher.getKeyUnlockData(
                    softwareSecureArea,
                    testAlias,
                    testReason
                )
            }
            fail("Expected KeyLockedException")
        } catch (e: KeyLockedException) {
            // Expected
        }

        assertEquals(softwareSecureArea, receivedSecureArea)
        assertEquals(testAlias, receivedAlias)
        assertEquals(testReason, receivedReason)
    }

    @Test
    fun testCustomProviderCanHandleSoftwareSecureArea() = runBlocking {
        MultipazAuthPrompt.initialize(application)

        val customProvider = object : KeyUnlockDataProvider {
            override suspend fun getKeyUnlockData(
                secureArea: SecureArea,
                alias: String,
                unlockReason: UnlockReason
            ): KeyUnlockData {
                return when (secureArea) {
                    is SoftwareSecureArea -> SoftwareKeyUnlockData("test_passphrase")
                    else -> throw KeyLockedException("Unsupported SecureArea: ${secureArea::class.simpleName}")
                }
            }
        }

        MultipazAuthPrompt.setCustomProvider(customProvider)

        val storage = EphemeralStorage()
        val softwareSecureArea = SoftwareSecureArea.create(storage)

        val unlockData = MultipazAuthPrompt.dispatcher.getKeyUnlockData(
            softwareSecureArea,
            "test_alias",
            UnlockReason.Unspecified
        )

        assertNotNull(unlockData)
        assertTrue(unlockData is SoftwareKeyUnlockData)
    }

    @Test
    fun testCompositeProviderHandlesMultipleSecureAreaTypes() = runBlocking {
        MultipazAuthPrompt.initialize(application)

        var softwareSecureAreaHandled = false
        var androidKeystoreDetected = false

        val compositeProvider = object : KeyUnlockDataProvider {
            override suspend fun getKeyUnlockData(
                secureArea: SecureArea,
                alias: String,
                unlockReason: UnlockReason
            ): KeyUnlockData {
                return when (secureArea) {
                    is SoftwareSecureArea -> {
                        softwareSecureAreaHandled = true
                        SoftwareKeyUnlockData("passphrase")
                    }
                    is AndroidKeystoreSecureArea -> {
                        androidKeystoreDetected = true
                        throw KeyLockedException("AndroidKeystore requires biometric - test only")
                    }
                    else -> throw KeyLockedException("Unsupported: ${secureArea::class.simpleName}")
                }
            }
        }

        MultipazAuthPrompt.setCustomProvider(compositeProvider)

        // Test SoftwareSecureArea path
        val storage = EphemeralStorage()
        val softwareSecureArea = SoftwareSecureArea.create(storage)

        val unlockData = MultipazAuthPrompt.dispatcher.getKeyUnlockData(
            softwareSecureArea,
            "software_key",
            UnlockReason.Unspecified
        )

        assertTrue(softwareSecureAreaHandled)
        assertNotNull(unlockData)

        // Test AndroidKeystoreSecureArea path
        val androidSecureArea = AndroidKeystoreSecureArea.create(storage)

        try {
            MultipazAuthPrompt.dispatcher.getKeyUnlockData(
                androidSecureArea,
                "android_key",
                UnlockReason.Unspecified
            )
            fail("Expected KeyLockedException")
        } catch (e: KeyLockedException) {
            // Expected
        }

        assertTrue(androidKeystoreDetected)
    }

    @Test
    fun testCustomProviderWithHumanReadableReason() = runBlocking {
        MultipazAuthPrompt.initialize(application)

        var capturedTitle: String? = null
        var capturedSubtitle: String? = null

        val customProvider = object : KeyUnlockDataProvider {
            override suspend fun getKeyUnlockData(
                secureArea: SecureArea,
                alias: String,
                unlockReason: UnlockReason
            ): KeyUnlockData {
                if (unlockReason is UnlockReason.HumanReadable) {
                    capturedTitle = unlockReason.title
                    capturedSubtitle = unlockReason.subtitle
                }
                return SoftwareKeyUnlockData("passphrase")
            }
        }

        MultipazAuthPrompt.setCustomProvider(customProvider)

        val storage = EphemeralStorage()
        val softwareSecureArea = SoftwareSecureArea.create(storage)
        val reason = UnlockReason.HumanReadable(
            title = "Sign Document",
            subtitle = "Authenticate to sign your mDL",
            requireConfirmation = true
        )

        MultipazAuthPrompt.dispatcher.getKeyUnlockData(
            softwareSecureArea,
            "key",
            reason
        )

        assertEquals("Sign Document", capturedTitle)
        assertEquals("Authenticate to sign your mDL", capturedSubtitle)
    }

    @Test
    fun testDefaultProviderThrowsForNonAndroidKeystore() = runBlocking {
        MultipazAuthPrompt.initialize(application)
        // Don't set custom provider - use default AndroidAuthPromptProvider

        val storage = EphemeralStorage()
        val softwareSecureArea = SoftwareSecureArea.create(storage)

        try {
            MultipazAuthPrompt.dispatcher.getKeyUnlockData(
                softwareSecureArea,
                "test_key",
                UnlockReason.Unspecified
            )
            fail("Expected KeyLockedException")
        } catch (e: KeyLockedException) {
            // Default provider only supports AndroidKeystoreSecureArea
            assertTrue(e.message!!.contains("AndroidKeystoreSecureArea"))
        }
    }

    @Test
    fun testProviderInCoroutineContext() = runBlocking {
        MultipazAuthPrompt.initialize(application)

        var providerFoundInContext = false

        val customProvider = object : KeyUnlockDataProvider {
            override suspend fun getKeyUnlockData(
                secureArea: SecureArea,
                alias: String,
                unlockReason: UnlockReason
            ): KeyUnlockData {
                providerFoundInContext = true
                return SoftwareKeyUnlockData("pass")
            }
        }

        MultipazAuthPrompt.setCustomProvider(customProvider)

        val storage = EphemeralStorage()
        val softwareSecureArea = SoftwareSecureArea.create(storage)

        // Use withContext to add provider to coroutine context
        withContext(MultipazAuthPrompt.dispatcher) {
            // The provider should be accessible from context
            val provider = coroutineContext[KeyUnlockDataProvider.Key]
            assertNotNull(provider)

            provider!!.getKeyUnlockData(
                softwareSecureArea,
                "key",
                UnlockReason.Unspecified
            )
        }

        assertTrue(providerFoundInContext)
    }
}
