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
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.multipaz.context.initializeApplication
import org.multipaz.securearea.KeyLockedException
import org.multipaz.securearea.KeyUnlockData
import org.multipaz.securearea.KeyUnlockDataProvider
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.UnlockReason
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for [MultipazAuthPrompt].
 *
 * Tests verify:
 * - Initialization behavior
 * - Custom provider injection via setCustomProvider
 * - Dispatcher returns correct provider (custom vs default)
 * - Activity tracking
 * - Reset functionality
 */
class MultipazAuthPromptTest {

    private lateinit var mockApplication: Application

    @Before
    fun setUp() {
        // Mock the multipaz initializeApplication function
        mockkStatic(::initializeApplication)
        every { initializeApplication(any()) } returns Unit

        mockApplication = mockk(relaxed = true)
        MultipazAuthPrompt.reset()
    }

    @After
    fun tearDown() {
        MultipazAuthPrompt.reset()
        unmockkAll()
    }

    @Test
    fun `isInitialized returns false before initialization`() {
        assertFalse(MultipazAuthPrompt.isInitialized())
    }

    @Test
    fun `isInitialized returns true after initialization`() {
        MultipazAuthPrompt.initialize(mockApplication)
        assertTrue(MultipazAuthPrompt.isInitialized())
    }

    @Test
    fun `initialize is idempotent - second call does not change state`() {
        MultipazAuthPrompt.initialize(mockApplication, "Title1", "Subtitle1")
        assertTrue(MultipazAuthPrompt.isInitialized())

        // Second initialization should be ignored
        MultipazAuthPrompt.initialize(mockApplication, "Title2", "Subtitle2")
        assertTrue(MultipazAuthPrompt.isInitialized())
    }

    @Test
    fun `dispatcher throws IllegalStateException when not initialized`() {
        assertFalse(MultipazAuthPrompt.isInitialized())

        val exception = assertFailsWith<IllegalStateException> {
            MultipazAuthPrompt.dispatcher
        }

        assertTrue(exception.message!!.contains("not initialized"))
    }

    @Test
    fun `dispatcher returns default AndroidAuthPromptProvider when no custom provider set`() {
        MultipazAuthPrompt.initialize(mockApplication)

        val dispatcher = MultipazAuthPrompt.dispatcher

        assertNotNull(dispatcher)
        assertTrue(dispatcher is AndroidAuthPromptProvider)
    }

    @Test
    fun `setCustomProvider replaces default provider`() {
        MultipazAuthPrompt.initialize(mockApplication)

        val customProvider = TestKeyUnlockDataProvider()
        MultipazAuthPrompt.setCustomProvider(customProvider)

        val dispatcher = MultipazAuthPrompt.dispatcher
        assertEquals(customProvider, dispatcher)
    }

    @Test
    fun `setCustomProvider with null restores default provider`() {
        MultipazAuthPrompt.initialize(mockApplication)

        // Set custom provider
        val customProvider = TestKeyUnlockDataProvider()
        MultipazAuthPrompt.setCustomProvider(customProvider)
        assertEquals(customProvider, MultipazAuthPrompt.dispatcher)

        // Set null to restore default
        MultipazAuthPrompt.setCustomProvider(null)

        val dispatcher = MultipazAuthPrompt.dispatcher
        assertTrue(dispatcher is AndroidAuthPromptProvider)
    }

    @Test
    fun `custom provider getKeyUnlockData is called`() = runTest {
        MultipazAuthPrompt.initialize(mockApplication)

        var providerCalled = false
        val customProvider = object : KeyUnlockDataProvider {
            override suspend fun getKeyUnlockData(
                secureArea: SecureArea,
                alias: String,
                unlockReason: UnlockReason
            ): KeyUnlockData {
                providerCalled = true
                throw KeyLockedException("Test provider called")
            }
        }

        MultipazAuthPrompt.setCustomProvider(customProvider)

        val mockSecureArea: SecureArea = mockk()

        assertFailsWith<KeyLockedException> {
            MultipazAuthPrompt.dispatcher.getKeyUnlockData(
                mockSecureArea,
                "testAlias",
                UnlockReason.Unspecified
            )
        }

        assertTrue(providerCalled, "Custom provider should have been called")
    }

    @Test
    fun `getCurrentActivity returns null when no activity tracked`() {
        MultipazAuthPrompt.initialize(mockApplication)
        assertNull(MultipazAuthPrompt.getCurrentActivity())
    }

    @Test
    fun `reset clears initialization state`() {
        MultipazAuthPrompt.initialize(mockApplication)
        assertTrue(MultipazAuthPrompt.isInitialized())

        MultipazAuthPrompt.reset()

        assertFalse(MultipazAuthPrompt.isInitialized())
    }

    @Test
    fun `reset clears custom provider`() {
        MultipazAuthPrompt.initialize(mockApplication)
        MultipazAuthPrompt.setCustomProvider(TestKeyUnlockDataProvider())

        MultipazAuthPrompt.reset()
        MultipazAuthPrompt.initialize(mockApplication)

        // After reset and re-init, should use default provider
        val dispatcher = MultipazAuthPrompt.dispatcher
        assertTrue(dispatcher is AndroidAuthPromptProvider)
    }

    @Test
    fun `multiple reset calls are safe`() {
        MultipazAuthPrompt.initialize(mockApplication)

        MultipazAuthPrompt.reset()
        MultipazAuthPrompt.reset()
        MultipazAuthPrompt.reset()

        assertFalse(MultipazAuthPrompt.isInitialized())
    }

    /**
     * Test implementation of KeyUnlockDataProvider for testing purposes.
     */
    private class TestKeyUnlockDataProvider : KeyUnlockDataProvider {
        override suspend fun getKeyUnlockData(
            secureArea: SecureArea,
            alias: String,
            unlockReason: UnlockReason
        ): KeyUnlockData {
            throw KeyLockedException("Test provider")
        }
    }
}
