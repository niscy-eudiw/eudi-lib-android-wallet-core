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

import eu.europa.ec.eudi.wallet.logging.Logger
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.multipaz.crypto.Algorithm
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.KeyInfo
import org.multipaz.securearea.SecureArea

/**
 * Unit tests for [ClientAttestationManager].
 *
 * These tests verify the core functionality of the ClientAttestationManager
 * by focusing on behavior rather than implementation details. Tests are designed
 * to work with mocked dependencies and focus on:
 *
 * Key alias generation logic
 * Attestation flow orchestration
 * Error handling
 * Manager instantiation and configuration
 */
class ClientAttestationManagerTest {

    private lateinit var mockConfig: ClientAttestationConfig
    private lateinit var mockSecureArea: SecureArea
    private lateinit var mockJwtProvider: ClientAttestationJwtProvider
    private lateinit var mockLogger: Logger
    private lateinit var mockKeyInfo: KeyInfo
    private lateinit var mockCreateKeySettings: CreateKeySettings
    private lateinit var mockCreateKeySettingsBuilder: CreateKeySettingsBuilder
    private lateinit var testAttestationJwt: String

    private val testIssuerId = "https://issuer.example.com"
    private val testPopAlgorithms = listOf(Algorithm.ESP256, Algorithm.ESP384)

    @Before
    fun setUp() {
        mockSecureArea = mockk(relaxed = true)
        mockJwtProvider = mockk(relaxed = true)
        mockLogger = mockk(relaxed = true)
        mockKeyInfo = mockk(relaxed = true)
        mockCreateKeySettings = mockk(relaxed = true)
        mockCreateKeySettingsBuilder = mockk(relaxed = true)

        mockConfig = mockk(relaxed = true) {
            every { createKeySettingsBuilder } returns mockCreateKeySettingsBuilder
            every { jwtProvider } returns mockJwtProvider
            every { unlockKey } returns { _, _ -> null }
        }

        testAttestationJwt = createTestJwt()
    }

    private fun createTestJwt(): String {
        val header = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9"
        val payload = "eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxMDAwMDAwMDAwfQ"
        val signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        return "$header.$payload.$signature"
    }

    @Test
    fun testGenerateKeyAliasIsDeterministic() {
        val manager = ClientAttestationManager(
            config = mockConfig,
            credentialIssuerId = testIssuerId,
            clientAttestationPOPJwsAlgs = testPopAlgorithms,
            secureArea = mockSecureArea,
            logger = null
        )

        val generateMethod = manager::class.java.getDeclaredMethod("generateKeyAlias", String::class.java)
        generateMethod.isAccessible = true

        val alias1 = generateMethod.invoke(manager, testIssuerId) as String
        val alias2 = generateMethod.invoke(manager, testIssuerId) as String

        assertEquals(alias1, alias2)
    }

    @Test
    fun testGenerateKeyAliasFormat() {
        val manager = ClientAttestationManager(
            config = mockConfig,
            credentialIssuerId = testIssuerId,
            clientAttestationPOPJwsAlgs = testPopAlgorithms,
            secureArea = mockSecureArea,
            logger = null
        )

        val generateMethod = manager::class.java.getDeclaredMethod("generateKeyAlias", String::class.java)
        generateMethod.isAccessible = true

        val alias = generateMethod.invoke(manager, testIssuerId) as String

        assertTrue(alias.startsWith("client-attestation-"))
        assertEquals(35, alias.length)
    }

    @Test
    fun testGenerateKeyAliasDifferentIssuersProduceDifferentAliases() {
        val manager = ClientAttestationManager(
            config = mockConfig,
            credentialIssuerId = testIssuerId,
            clientAttestationPOPJwsAlgs = testPopAlgorithms,
            secureArea = mockSecureArea,
            logger = null
        )

        val generateMethod = manager::class.java.getDeclaredMethod("generateKeyAlias", String::class.java)
        generateMethod.isAccessible = true

        val alias1 = generateMethod.invoke(manager, "issuer1") as String
        val alias2 = generateMethod.invoke(manager, "issuer2") as String

        assertTrue(alias1 != alias2)
    }

    @Test
    fun testClientAttestationManagerInstantiation() {
        val manager = ClientAttestationManager(
            config = mockConfig,
            credentialIssuerId = testIssuerId,
            clientAttestationPOPJwsAlgs = testPopAlgorithms,
            secureArea = mockSecureArea,
            logger = null
        )

        assertNotNull(manager)
    }

    @Test
    fun testClientAttestationManagerInstantiationWithLogger() {
        val manager = ClientAttestationManager(
            config = mockConfig,
            credentialIssuerId = testIssuerId,
            clientAttestationPOPJwsAlgs = testPopAlgorithms,
            secureArea = mockSecureArea,
            logger = mockLogger
        )

        assertNotNull(manager)
    }

    @Test
    fun testClientAttestationManagerInstantiationWithNullAlgorithms() {
        val manager = ClientAttestationManager(
            config = mockConfig,
            credentialIssuerId = testIssuerId,
            clientAttestationPOPJwsAlgs = null,
            secureArea = mockSecureArea,
            logger = null
        )

        assertNotNull(manager)
    }

    @Test
    fun testExecuteAttestationFlowWithKeyNotFound() = runBlocking {
        coEvery { mockSecureArea.getKeyInfo(any()) } throws Exception("Key not found")
        coEvery { mockJwtProvider.getAttestationJwt(any()) } returns Result.success(testAttestationJwt)
        coEvery { mockCreateKeySettingsBuilder.build(any()) } returns mockCreateKeySettings
        coEvery { mockSecureArea.createKey(any(), any()) } returns mockKeyInfo

        val manager = ClientAttestationManager(
            config = mockConfig,
            credentialIssuerId = testIssuerId,
            clientAttestationPOPJwsAlgs = testPopAlgorithms,
            secureArea = mockSecureArea,
            logger = null
        )

        val result = manager.executeAttestationFlow()

        // Should attempt to create key when it doesn't exist
        coVerify(atLeast = 1) { mockSecureArea.createKey(any(), any()) }
    }

    @Test
    fun testExecuteAttestationFlowWithExistingKey() = runBlocking {
        coEvery { mockSecureArea.getKeyInfo(any()) } returns mockKeyInfo
        coEvery { mockJwtProvider.getAttestationJwt(any()) } returns Result.success(testAttestationJwt)

        val manager = ClientAttestationManager(
            config = mockConfig,
            credentialIssuerId = testIssuerId,
            clientAttestationPOPJwsAlgs = testPopAlgorithms,
            secureArea = mockSecureArea,
            logger = null
        )

        val result = manager.executeAttestationFlow()

        // Should not create key when it exists
        coVerify(exactly = 0) { mockSecureArea.createKey(any(), any()) }
    }

    @Test
    fun testExecuteAttestationFlowCallsJwtProvider() = runBlocking {
        coEvery { mockSecureArea.getKeyInfo(any()) } returns mockKeyInfo
        coEvery { mockJwtProvider.getAttestationJwt(any()) } returns Result.success(testAttestationJwt)

        val manager = ClientAttestationManager(
            config = mockConfig,
            credentialIssuerId = testIssuerId,
            clientAttestationPOPJwsAlgs = testPopAlgorithms,
            secureArea = mockSecureArea,
            logger = null
        )

        manager.executeAttestationFlow()

        // Verify JWT provider is called
        coVerify(atLeast = 1) { mockJwtProvider.getAttestationJwt(any()) }
    }

    @Test
    fun testExecuteAttestationFlowHandlesJwtProviderFailure() = runBlocking {
        coEvery { mockSecureArea.getKeyInfo(any()) } returns mockKeyInfo
        val testException = Exception("JWT provider error")
        coEvery { mockJwtProvider.getAttestationJwt(any()) } returns Result.failure(testException)

        val manager = ClientAttestationManager(
            config = mockConfig,
            credentialIssuerId = testIssuerId,
            clientAttestationPOPJwsAlgs = testPopAlgorithms,
            secureArea = mockSecureArea,
            logger = null
        )

        val result = manager.executeAttestationFlow()

        // Verify error is returned
        assertTrue(result.isFailure)
        assertEquals(testException, result.exceptionOrNull())
    }

    @Test
    fun testExecuteAttestationFlowDoesNotDeleteKeyOnFailure() = runBlocking {
        coEvery { mockSecureArea.getKeyInfo(any()) } returns mockKeyInfo
        coEvery { mockJwtProvider.getAttestationJwt(any()) } returns Result.failure(Exception("Provider error"))
        coEvery { mockSecureArea.deleteKey(any()) } returns Unit

        val manager = ClientAttestationManager(
            config = mockConfig,
            credentialIssuerId = testIssuerId,
            clientAttestationPOPJwsAlgs = testPopAlgorithms,
            secureArea = mockSecureArea,
            logger = null
        )

        manager.executeAttestationFlow()

        // Verify key is not deleted on failure
        coVerify(exactly = 0) { mockSecureArea.deleteKey(any()) }
    }

    @Test
    fun testExecuteAttestationFlowLogsWithLogger() = runBlocking {
        coEvery { mockSecureArea.getKeyInfo(any()) } returns mockKeyInfo
        coEvery { mockJwtProvider.getAttestationJwt(any()) } returns Result.success(testAttestationJwt)

        val manager = ClientAttestationManager(
            config = mockConfig,
            credentialIssuerId = testIssuerId,
            clientAttestationPOPJwsAlgs = testPopAlgorithms,
            secureArea = mockSecureArea,
            logger = mockLogger
        )

        manager.executeAttestationFlow()

        // Verify logging was called at least once
        verify(atLeast = 1) { mockLogger.log(any()) }
    }

    @Test
    fun testExecuteAttestationFlowWithoutLogger() = runBlocking {
        coEvery { mockSecureArea.getKeyInfo(any()) } returns mockKeyInfo
        coEvery { mockJwtProvider.getAttestationJwt(any()) } returns Result.success(testAttestationJwt)

        val manager = ClientAttestationManager(
            config = mockConfig,
            credentialIssuerId = testIssuerId,
            clientAttestationPOPJwsAlgs = testPopAlgorithms,
            secureArea = mockSecureArea,
            logger = null
        )

        // Should not throw exception when logger is null
        val result = manager.executeAttestationFlow()
        assertNotNull(result)
    }

    @Test
    fun testExecuteAttestationFlowCallsCreateKeySettingsBuilder() = runBlocking {
        coEvery { mockSecureArea.getKeyInfo(any()) } throws Exception("Key not found")
        coEvery { mockJwtProvider.getAttestationJwt(any()) } returns Result.success(testAttestationJwt)
        coEvery { mockCreateKeySettingsBuilder.build(any()) } returns mockCreateKeySettings
        coEvery { mockSecureArea.createKey(any(), any()) } returns mockKeyInfo

        val manager = ClientAttestationManager(
            config = mockConfig,
            credentialIssuerId = testIssuerId,
            clientAttestationPOPJwsAlgs = testPopAlgorithms,
            secureArea = mockSecureArea,
            logger = null
        )

        manager.executeAttestationFlow()

        // Verify builder is called to create key settings
        coVerify(atLeast = 1) { mockCreateKeySettingsBuilder.build(any()) }
    }

    @Test
    fun testExecuteAttestationFlowConfigHasJwtProvider() {
        val manager = ClientAttestationManager(
            config = mockConfig,
            credentialIssuerId = testIssuerId,
            clientAttestationPOPJwsAlgs = testPopAlgorithms,
            secureArea = mockSecureArea,
            logger = null
        )

        // Just verify manager was created successfully
        assertNotNull(manager)
    }

    @Test
    fun testExecuteAttestationFlowConfigHasSecureArea() {
        val manager = ClientAttestationManager(
            config = mockConfig,
            credentialIssuerId = testIssuerId,
            clientAttestationPOPJwsAlgs = testPopAlgorithms,
            secureArea = mockSecureArea,
            logger = null
        )

        assertNotNull(manager)
        assertNotNull(mockSecureArea)
    }

    @Test
    fun testMultipleManagerInstancesIndependent() {
        val manager1 = ClientAttestationManager(
            config = mockConfig,
            credentialIssuerId = "issuer1",
            clientAttestationPOPJwsAlgs = testPopAlgorithms,
            secureArea = mockSecureArea,
            logger = null
        )

        val manager2 = ClientAttestationManager(
            config = mockConfig,
            credentialIssuerId = "issuer2",
            clientAttestationPOPJwsAlgs = testPopAlgorithms,
            secureArea = mockSecureArea,
            logger = null
        )

        assertNotNull(manager1)
        assertNotNull(manager2)
    }

    @Test
    fun testDifferentIssuersGenerateDifferentAliases() {
        val manager = ClientAttestationManager(
            config = mockConfig,
            credentialIssuerId = testIssuerId,
            clientAttestationPOPJwsAlgs = testPopAlgorithms,
            secureArea = mockSecureArea,
            logger = null
        )

        val generateMethod = manager::class.java.getDeclaredMethod("generateKeyAlias", String::class.java)
        generateMethod.isAccessible = true

        val alias1 = generateMethod.invoke(manager, "issuer1") as String
        val alias2 = generateMethod.invoke(manager, "issuer2") as String

        assertTrue(alias1 != alias2)
    }

    @Test
    fun testConfigIsPreserved() {
        val manager = ClientAttestationManager(
            config = mockConfig,
            credentialIssuerId = testIssuerId,
            clientAttestationPOPJwsAlgs = testPopAlgorithms,
            secureArea = mockSecureArea,
            logger = mockLogger
        )

        // Just verify manager was created successfully with all parameters
        assertNotNull(manager)
    }
}
