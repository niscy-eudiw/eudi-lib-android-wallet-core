/*
 * Copyright (c) 2025 European Commission
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

package eu.europa.ec.eudi.wallet.issue.openid4vci.clientAuth

import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.multipaz.securearea.KeyInfo
import org.multipaz.securearea.KeyUnlockData
import org.multipaz.securearea.SecureArea

/**
 * Unit tests for [ClientAttestationConfig].
 *
 * These tests focus on data class behavior, configuration properties,
 * and the unlock key callback functionality. Tests that require actual
 * Android Keystore or file system operations are excluded from unit tests
 * as they require instrumentation testing or proper Android environment setup.
 *
 * Test coverage includes:
 * - Data class instantiation with various configurations
 * - Property immutability and correctness
 * - Equality and hash code behavior
 * - Data class copy functionality
 * - Custom unlock key callbacks
 * - Default unlock key behavior (returns null)
 */
class ClientAttestationConfigTest {

    private lateinit var mockSecureArea: SecureArea
    private lateinit var mockJwtProvider: ClientAttestationJwtProvider
    private lateinit var mockKeyUnlockData: KeyUnlockData

    @Before
    fun setUp() {
        mockSecureArea = mockk(relaxed = true)
        mockJwtProvider = mockk(relaxed = true)
        mockKeyUnlockData = mockk(relaxed = true)
    }

    @Test
    fun testClientAttestationConfigInstantiation() {
        val createKeySettingsBuilder: CreateKeySettingsBuilder = mockk(relaxed = true)

        val config = ClientAttestationConfig(
            jwtProvider = mockJwtProvider,
            secureArea = mockSecureArea,
            createKeySettingsBuilder = createKeySettingsBuilder
        )

        assertEquals(mockJwtProvider, config.jwtProvider)
        assertEquals(mockSecureArea, config.secureArea)
        assertEquals(createKeySettingsBuilder, config.createKeySettingsBuilder)
        assertNotNull(config.unlockKey)
    }

    @Test
    fun testClientAttestationConfigWithCustomUnlockKey() = runBlocking {
        val createKeySettingsBuilder: CreateKeySettingsBuilder = mockk(relaxed = true)
        val customUnlockKey: suspend (String, SecureArea) -> KeyUnlockData? = { _, _ ->
            mockKeyUnlockData
        }

        val config = ClientAttestationConfig(
            jwtProvider = mockJwtProvider,
            secureArea = mockSecureArea,
            createKeySettingsBuilder = createKeySettingsBuilder,
            unlockKey = customUnlockKey
        )

        val result = config.unlockKey("test-key", mockSecureArea)
        assertEquals(mockKeyUnlockData, result)
    }

    @Test
    fun testDefaultUnlockKeyReturnsNull() = runBlocking {
        val createKeySettingsBuilder: CreateKeySettingsBuilder = mockk(relaxed = true)

        val config = ClientAttestationConfig(
            jwtProvider = mockJwtProvider,
            secureArea = mockSecureArea,
            createKeySettingsBuilder = createKeySettingsBuilder
        )

        val result = config.unlockKey("test-key", mockSecureArea)
        assertNull(result)
    }

    @Test
    fun testClientAttestationConfigEqualityWithSameParameters() {
        val createKeySettingsBuilder: CreateKeySettingsBuilder = mockk(relaxed = true)
        val sameUnlockKey: suspend (String, SecureArea) -> KeyUnlockData? = { _, _ -> null }

        val config1 = ClientAttestationConfig(
            jwtProvider = mockJwtProvider,
            secureArea = mockSecureArea,
            createKeySettingsBuilder = createKeySettingsBuilder,
            unlockKey = sameUnlockKey
        )

        val config2 = ClientAttestationConfig(
            jwtProvider = mockJwtProvider,
            secureArea = mockSecureArea,
            createKeySettingsBuilder = createKeySettingsBuilder,
            unlockKey = sameUnlockKey
        )

        assertEquals(config1, config2)
    }

    @Test
    fun testClientAttestationConfigInequalityDifferentJwtProvider() {
        val createKeySettingsBuilder: CreateKeySettingsBuilder = mockk(relaxed = true)
        val mockJwtProvider2 = mockk<ClientAttestationJwtProvider>(relaxed = true)
        val sameUnlockKey: suspend (String, SecureArea) -> KeyUnlockData? = { _, _ -> null }

        val config1 = ClientAttestationConfig(
            jwtProvider = mockJwtProvider,
            secureArea = mockSecureArea,
            createKeySettingsBuilder = createKeySettingsBuilder,
            unlockKey = sameUnlockKey
        )

        val config2 = ClientAttestationConfig(
            jwtProvider = mockJwtProvider2,
            secureArea = mockSecureArea,
            createKeySettingsBuilder = createKeySettingsBuilder,
            unlockKey = sameUnlockKey
        )

        assertTrue(config1 != config2)
    }

    @Test
    fun testClientAttestationConfigInequalityDifferentSecureArea() {
        val createKeySettingsBuilder: CreateKeySettingsBuilder = mockk(relaxed = true)
        val mockSecureArea2 = mockk<SecureArea>(relaxed = true)
        val sameUnlockKey: suspend (String, SecureArea) -> KeyUnlockData? = { _, _ -> null }

        val config1 = ClientAttestationConfig(
            jwtProvider = mockJwtProvider,
            secureArea = mockSecureArea,
            createKeySettingsBuilder = createKeySettingsBuilder,
            unlockKey = sameUnlockKey
        )

        val config2 = ClientAttestationConfig(
            jwtProvider = mockJwtProvider,
            secureArea = mockSecureArea2,
            createKeySettingsBuilder = createKeySettingsBuilder,
            unlockKey = sameUnlockKey
        )

        assertTrue(config1 != config2)
    }

    @Test
    fun testClientAttestationConfigToString() {
        val createKeySettingsBuilder: CreateKeySettingsBuilder = mockk(relaxed = true)

        val config = ClientAttestationConfig(
            jwtProvider = mockJwtProvider,
            secureArea = mockSecureArea,
            createKeySettingsBuilder = createKeySettingsBuilder
        )

        val toString = config.toString()
        assertTrue(toString.contains("ClientAttestationConfig"))
        assertTrue(toString.contains("jwtProvider"))
        assertTrue(toString.contains("secureArea"))
    }

    @Test
    fun testClientAttestationConfigDataClassCopy() {
        val createKeySettingsBuilder: CreateKeySettingsBuilder = mockk(relaxed = true)
        val sameUnlockKey: suspend (String, SecureArea) -> KeyUnlockData? = { _, _ -> null }

        val config = ClientAttestationConfig(
            jwtProvider = mockJwtProvider,
            secureArea = mockSecureArea,
            createKeySettingsBuilder = createKeySettingsBuilder,
            unlockKey = sameUnlockKey
        )

        val mockJwtProvider2 = mockk<ClientAttestationJwtProvider>(relaxed = true)
        val copiedConfig = config.copy(jwtProvider = mockJwtProvider2)

        assertEquals(mockJwtProvider2, copiedConfig.jwtProvider)
        assertEquals(mockSecureArea, copiedConfig.secureArea)
        assertEquals(createKeySettingsBuilder, copiedConfig.createKeySettingsBuilder)
    }

    @Test
    fun testClientAttestationConfigCopyPreservesUnlockKey() = runBlocking {
        val createKeySettingsBuilder: CreateKeySettingsBuilder = mockk(relaxed = true)
        val customUnlockKey: suspend (String, SecureArea) -> KeyUnlockData? = { _, _ ->
            mockKeyUnlockData
        }

        val config = ClientAttestationConfig(
            jwtProvider = mockJwtProvider,
            secureArea = mockSecureArea,
            createKeySettingsBuilder = createKeySettingsBuilder,
            unlockKey = customUnlockKey
        )

        val mockSecureArea2 = mockk<SecureArea>(relaxed = true)
        val copiedConfig = config.copy(secureArea = mockSecureArea2)

        // Verify unlock key is preserved
        val result = copiedConfig.unlockKey("test-key", mockSecureArea)
        assertEquals(mockKeyUnlockData, result)
    }

    @Test
    fun testClientAttestationConfigHashCodeConsistency() {
        val createKeySettingsBuilder: CreateKeySettingsBuilder = mockk(relaxed = true)
        val sameUnlockKey: suspend (String, SecureArea) -> KeyUnlockData? = { _, _ -> null }

        val config1 = ClientAttestationConfig(
            jwtProvider = mockJwtProvider,
            secureArea = mockSecureArea,
            createKeySettingsBuilder = createKeySettingsBuilder,
            unlockKey = sameUnlockKey
        )

        val config2 = ClientAttestationConfig(
            jwtProvider = mockJwtProvider,
            secureArea = mockSecureArea,
            createKeySettingsBuilder = createKeySettingsBuilder,
            unlockKey = sameUnlockKey
        )

        // Equal objects must have equal hash codes
        assertEquals(config1.hashCode(), config2.hashCode())
    }

    @Test
    fun testClientAttestationConfigHashCodeWithDifferentComponents() {
        val createKeySettingsBuilder: CreateKeySettingsBuilder = mockk(relaxed = true)
        val sameUnlockKey: suspend (String, SecureArea) -> KeyUnlockData? = { _, _ -> null }

        val config1 = ClientAttestationConfig(
            jwtProvider = mockJwtProvider,
            secureArea = mockSecureArea,
            createKeySettingsBuilder = createKeySettingsBuilder,
            unlockKey = sameUnlockKey
        )

        val mockJwtProvider2 = mockk<ClientAttestationJwtProvider>(relaxed = true)
        val config2 = ClientAttestationConfig(
            jwtProvider = mockJwtProvider2,
            secureArea = mockSecureArea,
            createKeySettingsBuilder = createKeySettingsBuilder,
            unlockKey = sameUnlockKey
        )

        // Different objects may have different hash codes (not required but expected)
        // We just verify they are integers and can be called
        assertNotNull(config1.hashCode())
        assertNotNull(config2.hashCode())
    }

    @Test
    fun testUnlockKeyWithKeyAliasAndSecureArea() = runBlocking {
        val createKeySettingsBuilder: CreateKeySettingsBuilder = mockk(relaxed = true)
        val keyAlias = "my-key-alias"

        var capturedKeyAlias = ""
        var capturedSecureArea: SecureArea? = null

        val customUnlockKey: suspend (String, SecureArea) -> KeyUnlockData? = { alias, area ->
            capturedKeyAlias = alias
            capturedSecureArea = area
            mockKeyUnlockData
        }

        val config = ClientAttestationConfig(
            jwtProvider = mockJwtProvider,
            secureArea = mockSecureArea,
            createKeySettingsBuilder = createKeySettingsBuilder,
            unlockKey = customUnlockKey
        )

        val result = config.unlockKey(keyAlias, mockSecureArea)

        assertEquals(keyAlias, capturedKeyAlias)
        assertEquals(mockSecureArea, capturedSecureArea)
        assertEquals(mockKeyUnlockData, result)
    }

    @Test
    fun testCreateKeySettingsBuilderIsNotNull() {
        val createKeySettingsBuilder: CreateKeySettingsBuilder = mockk(relaxed = true)

        val config = ClientAttestationConfig(
            jwtProvider = mockJwtProvider,
            secureArea = mockSecureArea,
            createKeySettingsBuilder = createKeySettingsBuilder
        )

        assertNotNull(config.createKeySettingsBuilder)
    }

    @Test
    fun testJwtProviderIsNotNull() {
        val createKeySettingsBuilder: CreateKeySettingsBuilder = mockk(relaxed = true)

        val config = ClientAttestationConfig(
            jwtProvider = mockJwtProvider,
            secureArea = mockSecureArea,
            createKeySettingsBuilder = createKeySettingsBuilder
        )

        assertNotNull(config.jwtProvider)
    }

    @Test
    fun testSecureAreaIsNotNull() {
        val createKeySettingsBuilder: CreateKeySettingsBuilder = mockk(relaxed = true)

        val config = ClientAttestationConfig(
            jwtProvider = mockJwtProvider,
            secureArea = mockSecureArea,
            createKeySettingsBuilder = createKeySettingsBuilder
        )

        assertNotNull(config.secureArea)
    }

    @Test
    fun testMultipleConfigInstancesWithDifferentComponents() {
        val createKeySettingsBuilder1: CreateKeySettingsBuilder = mockk(relaxed = true)
        val createKeySettingsBuilder2: CreateKeySettingsBuilder = mockk(relaxed = true)
        val mockSecureArea2 = mockk<SecureArea>(relaxed = true)
        val mockJwtProvider2 = mockk<ClientAttestationJwtProvider>(relaxed = true)
        val sameUnlockKey: suspend (String, SecureArea) -> KeyUnlockData? = { _, _ -> null }

        val config1 = ClientAttestationConfig(
            jwtProvider = mockJwtProvider,
            secureArea = mockSecureArea,
            createKeySettingsBuilder = createKeySettingsBuilder1,
            unlockKey = sameUnlockKey
        )

        val config2 = ClientAttestationConfig(
            jwtProvider = mockJwtProvider2,
            secureArea = mockSecureArea2,
            createKeySettingsBuilder = createKeySettingsBuilder2,
            unlockKey = sameUnlockKey
        )

        assertTrue(config1 != config2)
        assertEquals(config1.jwtProvider, mockJwtProvider)
        assertEquals(config2.jwtProvider, mockJwtProvider2)
        assertEquals(config1.secureArea, mockSecureArea)
        assertEquals(config2.secureArea, mockSecureArea2)
    }

    @Test
    fun testUnlockKeyReturnsNullWhenNotProvided() = runBlocking {
        val createKeySettingsBuilder: CreateKeySettingsBuilder = mockk(relaxed = true)

        val config = ClientAttestationConfig(
            jwtProvider = mockJwtProvider,
            secureArea = mockSecureArea,
            createKeySettingsBuilder = createKeySettingsBuilder
            // No custom unlock key provided - should use default
        )

        val result = config.unlockKey("any-key", mockSecureArea)
        assertNull(result)
    }

    @Test
    fun testUnlockKeyWithDifferentKeyAliases() = runBlocking {
        val createKeySettingsBuilder: CreateKeySettingsBuilder = mockk(relaxed = true)
        val capturedAliases = mutableListOf<String>()

        val customUnlockKey: suspend (String, SecureArea) -> KeyUnlockData? = { alias, _ ->
            capturedAliases.add(alias)
            mockKeyUnlockData
        }

        val config = ClientAttestationConfig(
            jwtProvider = mockJwtProvider,
            secureArea = mockSecureArea,
            createKeySettingsBuilder = createKeySettingsBuilder,
            unlockKey = customUnlockKey
        )

        config.unlockKey("key-1", mockSecureArea)
        config.unlockKey("key-2", mockSecureArea)
        config.unlockKey("key-3", mockSecureArea)

        assertEquals(listOf("key-1", "key-2", "key-3"), capturedAliases)
    }

    @Test
    fun testJwtProviderFunctionality() = runBlocking {
        val createKeySettingsBuilder: CreateKeySettingsBuilder = mockk(relaxed = true)
        val mockKeyInfo = mockk<KeyInfo>(relaxed = true)

        coEvery { mockJwtProvider.getAttestationJwt(any()) } returns Result.success("test-jwt")

        val config = ClientAttestationConfig(
            jwtProvider = mockJwtProvider,
            secureArea = mockSecureArea,
            createKeySettingsBuilder = createKeySettingsBuilder
        )

        val result = config.jwtProvider.getAttestationJwt(mockKeyInfo)

        assertTrue(result.isSuccess)
        assertEquals("test-jwt", result.getOrNull())
    }

    @Test
    fun testJwtProviderErrorHandling() = runBlocking {
        val createKeySettingsBuilder: CreateKeySettingsBuilder = mockk(relaxed = true)
        val mockKeyInfo = mockk<KeyInfo>(relaxed = true)
        val testException = Exception("Test error")

        coEvery { mockJwtProvider.getAttestationJwt(any()) } returns Result.failure(testException)

        val config = ClientAttestationConfig(
            jwtProvider = mockJwtProvider,
            secureArea = mockSecureArea,
            createKeySettingsBuilder = createKeySettingsBuilder
        )

        val result = config.jwtProvider.getAttestationJwt(mockKeyInfo)

        assertTrue(result.isFailure)
        assertEquals(testException, result.exceptionOrNull())
    }
}
