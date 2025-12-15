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
 * Unit tests for [UserAuthPromptHelper].
 *
 * Tests verify:
 * - Initialization behavior
 * - Custom provider injection via setCustomProvider
 * - Dispatcher returns correct provider (custom vs default)
 * - Activity tracking
 * - Reset functionality
 */
class UserAuthPromptHelperTest {

    private lateinit var mockApplication: Application

    @Before
    fun setUp() {
        // Mock the multipaz initializeApplication function
        mockkStatic(::initializeApplication)
        every { initializeApplication(any()) } returns Unit

        mockApplication = mockk(relaxed = true)
        UserAuthPromptHelper.reset()
    }

    @After
    fun tearDown() {
        UserAuthPromptHelper.reset()
        unmockkAll()
    }

    @Test
    fun `isInitialized returns false before initialization`() {
        assertFalse(UserAuthPromptHelper.isInitialized())
    }

    @Test
    fun `isInitialized returns true after initialization`() {
        UserAuthPromptHelper.initialize(mockApplication)
        assertTrue(UserAuthPromptHelper.isInitialized())
    }

    @Test
    fun `initialize is idempotent - second call does not change state`() {
        UserAuthPromptHelper.initialize(mockApplication, "Title1", "Subtitle1")
        assertTrue(UserAuthPromptHelper.isInitialized())

        // Second initialization should be ignored
        UserAuthPromptHelper.initialize(mockApplication, "Title2", "Subtitle2")
        assertTrue(UserAuthPromptHelper.isInitialized())
    }

    @Test
    fun `dispatcher throws IllegalStateException when not initialized`() {
        assertFalse(UserAuthPromptHelper.isInitialized())

        val exception = assertFailsWith<IllegalStateException> {
            UserAuthPromptHelper.dispatcher
        }

        assertTrue(exception.message!!.contains("not initialized"))
    }

    @Test
    fun `dispatcher returns default AndroidAuthPromptProvider when no custom provider set`() {
        UserAuthPromptHelper.initialize(mockApplication)

        val dispatcher = UserAuthPromptHelper.dispatcher

        assertNotNull(dispatcher)
        assertTrue(dispatcher is AndroidAuthPromptProvider)
    }

    @Test
    fun `setCustomProvider replaces default provider`() {
        UserAuthPromptHelper.initialize(mockApplication)

        val customProvider = TestKeyUnlockDataProvider()
        UserAuthPromptHelper.setCustomProvider(customProvider)

        val dispatcher = UserAuthPromptHelper.dispatcher
        assertEquals(customProvider, dispatcher)
    }

    @Test
    fun `setCustomProvider with null restores default provider`() {
        UserAuthPromptHelper.initialize(mockApplication)

        // Set custom provider
        val customProvider = TestKeyUnlockDataProvider()
        UserAuthPromptHelper.setCustomProvider(customProvider)
        assertEquals(customProvider, UserAuthPromptHelper.dispatcher)

        // Set null to restore default
        UserAuthPromptHelper.setCustomProvider(null)

        val dispatcher = UserAuthPromptHelper.dispatcher
        assertTrue(dispatcher is AndroidAuthPromptProvider)
    }

    @Test
    fun `custom provider getKeyUnlockData is called`() = runTest {
        UserAuthPromptHelper.initialize(mockApplication)

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

        UserAuthPromptHelper.setCustomProvider(customProvider)

        val mockSecureArea: SecureArea = mockk()

        assertFailsWith<KeyLockedException> {
            UserAuthPromptHelper.dispatcher.getKeyUnlockData(
                mockSecureArea,
                "testAlias",
                UnlockReason.Unspecified
            )
        }

        assertTrue(providerCalled, "Custom provider should have been called")
    }

    @Test
    fun `getCurrentActivity returns null when no activity tracked`() {
        UserAuthPromptHelper.initialize(mockApplication)
        assertNull(UserAuthPromptHelper.getCurrentActivity())
    }

    @Test
    fun `reset clears initialization state`() {
        UserAuthPromptHelper.initialize(mockApplication)
        assertTrue(UserAuthPromptHelper.isInitialized())

        UserAuthPromptHelper.reset()

        assertFalse(UserAuthPromptHelper.isInitialized())
    }

    @Test
    fun `reset clears custom provider`() {
        UserAuthPromptHelper.initialize(mockApplication)
        UserAuthPromptHelper.setCustomProvider(TestKeyUnlockDataProvider())

        UserAuthPromptHelper.reset()
        UserAuthPromptHelper.initialize(mockApplication)

        // After reset and re-init, should use default provider
        val dispatcher = UserAuthPromptHelper.dispatcher
        assertTrue(dispatcher is AndroidAuthPromptProvider)
    }

    @Test
    fun `multiple reset calls are safe`() {
        UserAuthPromptHelper.initialize(mockApplication)

        UserAuthPromptHelper.reset()
        UserAuthPromptHelper.reset()
        UserAuthPromptHelper.reset()

        assertFalse(UserAuthPromptHelper.isInitialized())
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
