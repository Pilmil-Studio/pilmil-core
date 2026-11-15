package fr.pilmil.core.platform.backup

import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.zip.GZIPOutputStream
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AndroidBackupVaultTest {

    // 2 000 itérations pour une exécution ultra-rapide des tests unitaires
    private val vault = AndroidBackupVault(iterations = 2_000)
    private val passphrase = "PhraseSecrèteForte&Unique2026!".toCharArray()

    @Test
    fun testEncryptAndDecryptRoundTrip() {
        val payload = """{"app":"lunaison","version":1,"records":[{"cycle":28,"flow":"light"}]}"""
        val container = vault.encrypt(payload, passphrase)

        // Vérification de l'en-tête
        assertTrue(container.size >= AndroidBackupVault.MIN_CONTAINER_SIZE)
        val magic = container.copyOfRange(0, 6).toString(Charsets.US_ASCII)
        assertEquals("PILMIL", magic)
        assertEquals(1.toByte(), container[6])

        // Déchiffrement réussi
        val decrypted = vault.decrypt(container, passphrase)
        assertEquals(payload, decrypted)
    }

    @Test
    fun testDecryptionFailsWithWrongPassphrase() {
        val payload = """{"app":"sommelle","diaryEntries":7}"""
        val container = vault.encrypt(payload, passphrase)

        val wrongPassphrase = "MotDePasseIncorrect!".toCharArray()
        assertFailsWith<InvalidPassphraseException> {
            vault.decrypt(container, wrongPassphrase)
        }
    }

    @Test
    fun testAes256GcmCrossCompatibilityWithJavaxCrypto() {
        val salt = ByteArray(16) { (it + 1).toByte() }
        val iv = ByteArray(12) { (it + 10).toByte() }
        val pass = "MotDePasseCrossPlatform2026!".toCharArray()
        val keyCommon = Aes256Gcm.pbkdf2HmacSha256(pass.concatToString().encodeToByteArray(), salt, 2_000)

        val spec = PBEKeySpec(pass, salt, 2_000, 256)
        val keyJvm = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        assertTrue(keyCommon.contentEquals(keyJvm))

        val plaintext = "date;flow;note\n2026-11-15;Léger;Test Android <-> iOS".encodeToByteArray()
        val ctCommon = Aes256Gcm.encrypt(keyCommon, iv, plaintext)

        // Déchiffrement par javax.crypto (Android) d'un message chiffré par Aes256Gcm (iOS)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(keyJvm, "AES"), GCMParameterSpec(128, iv))
        val decryptedByJvm = cipher.doFinal(ctCommon)
        assertTrue(plaintext.contentEquals(decryptedByJvm))

        // Déchiffrement par Aes256Gcm (iOS) d'un message chiffré par javax.crypto (Android)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyJvm, "AES"), GCMParameterSpec(128, iv))
        val ctJvm = cipher.doFinal(plaintext)
        val decryptedByCommon = Aes256Gcm.decrypt(keyCommon, iv, ctJvm)
        assertTrue(plaintext.contentEquals(decryptedByCommon))
    }

    @Test
    fun testDecryptionFailsWithTamperedCiphertext() {
        val payload = """{"sensitiveHealthData":"confidential"}"""
        val container = vault.encrypt(payload, passphrase)

        // Altération d'un seul octet dans la charge utile chiffrée
        container[container.size - 5] = (container[container.size - 5].toInt() xor 0xFF).toByte()

        assertFailsWith<InvalidPassphraseException> {
            vault.decrypt(container, passphrase)
        }
    }

    @Test
    fun testDecryptionFailsWithInvalidMagic() {
        val payload = "data"
        val container = vault.encrypt(payload, passphrase)

        container[0] = 'B'.code.toByte()
        container[1] = 'A'.code.toByte()
        container[2] = 'D'.code.toByte()

        assertFailsWith<CorruptedBackupException> {
            vault.decrypt(container, passphrase)
        }
    }

    @Test
    fun testDecryptionFailsWithUnsupportedVersion() {
        val payload = "data"
        val container = vault.encrypt(payload, passphrase)

        container[6] = 99.toByte()

        assertFailsWith<CorruptedBackupException> {
            vault.decrypt(container, passphrase)
        }
    }

    @Test
    fun testDecryptionFailsWithTruncatedContainer() {
        val truncated = ByteArray(30) { 0 }
        assertFailsWith<CorruptedBackupException> {
            vault.decrypt(truncated, passphrase)
        }
    }

    @Test
    fun testEmptyPassphraseThrowsIllegalArgumentException() {
        assertFailsWith<IllegalArgumentException> {
            vault.encrypt("data", charArrayOf())
        }
        assertFailsWith<IllegalArgumentException> {
            vault.decrypt(ByteArray(60), charArrayOf())
        }
    }

    @Test
    fun testLargePayloadCompressionEfficiency() {
        // Répétition de données typiques JSON pour tester la compression GZIP
        val largePayload = (1..100).joinToString(",", prefix = "[", postfix = "]") {
            """{"id":$it,"timestamp":"2026-11-06T20:00:00Z","metric":"heart_rate_variability","value":65.4}"""
        }
        val uncompressedSize = largePayload.toByteArray(Charsets.UTF_8).size
        val container = vault.encrypt(largePayload, passphrase)

        // Le conteneur complet (en-tête + chiffré) doit être significativement plus petit que le JSON brut
        assertTrue(container.size < uncompressedSize, "Le conteneur (${container.size} octets) devrait être plus petit que le JSON brut ($uncompressedSize octets)")

        val restored = vault.decrypt(container, passphrase)
        assertEquals(largePayload, restored)
    }

    // Fabrique indépendamment un conteneur v1 (si [gzip] = false, [raw] est chiffré tel quel au lieu d'être compressé)
    private fun buildContainer(raw: ByteArray, iterations: Int, gzip: Boolean = true): ByteArray {
        val salt = ByteArray(16) { it.toByte() }
        val iv = ByteArray(12) { (it + 100).toByte() }
        val key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(PBEKeySpec(passphrase, salt, iterations, 256)).encoded
        val plain = if (gzip) {
            ByteArrayOutputStream().also { bos -> GZIPOutputStream(bos).use { it.write(raw) } }.toByteArray()
        } else raw
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        cipher.updateAAD(byteArrayOf(*AndroidBackupVault.MAGIC, AndroidBackupVault.VERSION))
        val ct = cipher.doFinal(plain)
        return ByteBuffer.allocate(AndroidBackupVault.HEADER_LENGTH + ct.size)
            .put(AndroidBackupVault.MAGIC).put(AndroidBackupVault.VERSION).put(salt)
            .putInt(iterations).put(iv).put(ct).array()
    }

    @Test
    fun testHeaderTruncatedJustBelowMinimum() {
        val container = vault.encrypt("data", passphrase)
        assertFailsWith<CorruptedBackupException> {
            vault.decrypt(container.copyOf(AndroidBackupVault.MIN_CONTAINER_SIZE - 1), passphrase)
        }
    }

    @Test
    fun testIterationsOutOfBounds() {
        for (bad in listOf(0, 999, 2_000_001, -1)) {
            val container = vault.encrypt("data", passphrase)
            ByteBuffer.wrap(container).putInt(23, bad)
            assertFailsWith<CorruptedBackupException>("itérations = $bad") {
                vault.decrypt(container, passphrase)
            }
        }
    }

    @Test
    fun testTamperedHeaderFieldsAreRejected() {
        // Sel, itérations (valides) et IV altérés : l'authentification échoue
        for (index in listOf(7, 26, 27)) {
            val container = vault.encrypt("data", passphrase)
            container[index] = (container[index].toInt() xor 0x01).toByte()
            assertFailsWith<InvalidPassphraseException>("octet $index") {
                vault.decrypt(container, passphrase)
            }
        }
    }

    @Test
    fun testInvalidGzipPayloadIsCorrupted() {
        val container = buildContainer("pas du gzip".toByteArray(), iterations = 2_000, gzip = false)
        assertFailsWith<CorruptedBackupException> {
            vault.decrypt(container, passphrase)
        }
    }

    @Test
    fun testOversizedDecompressedPayloadIsRejected() {
        val limited = AndroidBackupVault(iterations = 2_000, maxDecompressedSize = 1024)
        val container = buildContainer(ByteArray(4 * 1024), iterations = 2_000)
        assertFailsWith<CorruptedBackupException> {
            limited.decrypt(container, passphrase)
        }
    }

    @Test
    fun testEmptyPayloadRoundTrip() {
        assertEquals("", vault.decrypt(vault.encrypt("", passphrase), passphrase))
    }

    @Test
    fun testDecryptsLegacyContainerAt100kIterations() {
        val payload = """{"legacy":true}"""
        val container = buildContainer(payload.toByteArray(), iterations = 100_000)
        // Le coffre courant lit les itérations dans l'en-tête, quelle que soit sa valeur par défaut
        assertEquals(payload, AndroidBackupVault().decrypt(container, passphrase))
    }

    @Test
    fun testDefaultIterationsAreStoredInHeader() {
        val container = AndroidBackupVault().encrypt("data", passphrase)
        assertEquals(AndroidBackupVault.DEFAULT_ITERATIONS, ByteBuffer.wrap(container).getInt(23))
    }

    @Test
    fun testSamePayloadProducesDistinctContainers() {
        val payload = """{"app":"fredonne","notes":["C4","D4","E4"]}"""
        val first = vault.encrypt(payload, passphrase)
        val second = vault.encrypt(payload, passphrase)

        assertFalse(first.contentEquals(second), "Deux chiffrements doivent générer sel et IV distincts")
        assertEquals(payload, vault.decrypt(first, passphrase))
        assertEquals(payload, vault.decrypt(second, passphrase))
    }

    @Test
    fun testInjectedSecureRandomDeterminesSaltAndIv() {
        val fixedSalt = ByteArray(AndroidBackupVault.SALT_LENGTH) { (it + 1).toByte() }
        val fixedIv = ByteArray(AndroidBackupVault.IV_LENGTH) { (it + 50).toByte() }
        val deterministicRandom = object : SecureRandom() {
            private var callCount = 0
            override fun nextBytes(bytes: ByteArray) {
                val source = if (callCount == 0) fixedSalt else fixedIv
                callCount++
                source.copyInto(bytes)
            }
        }

        val deterministicVault = AndroidBackupVault(iterations = 2_000, secureRandom = deterministicRandom)
        val container = deterministicVault.encrypt("payload", passphrase)

        assertContentEquals(fixedSalt, container.copyOfRange(7, 23))
        assertContentEquals(fixedIv, container.copyOfRange(27, 39))
        assertEquals("payload", deterministicVault.decrypt(container, passphrase))
    }

    @Test
    fun testPassphraseCharArrayIsNotMutated() {
        val original = "MotDePasse#2026".toCharArray()
        val workingCopy = original.copyOf()

        val container = vault.encrypt("secret", workingCopy)
        assertContentEquals(original, workingCopy, "encrypt ne doit pas altérer le tableau passé par l'appelant")

        val restored = vault.decrypt(container, workingCopy)
        assertEquals("secret", restored)
        assertContentEquals(original, workingCopy, "decrypt ne doit pas altérer le tableau passé par l'appelant")
    }

    @Test
    fun testUnicodePayloadAndPassphraseRoundTrip() {
        val unicodePassphrase = "Été-2026-\u65E5\u672C\u8A9E-\uD83C\uDF31".toCharArray()
        val unicodePayload = "Ligne 1 : éàùçœæ\nLigne 2 : \u4E2D\u6587\nLigne 3 : \uD83C\uDF3F"

        val container = vault.encrypt(unicodePayload, unicodePassphrase)
        assertEquals(unicodePayload, vault.decrypt(container, unicodePassphrase))
    }

    @Test
    fun testIterationsBoundaryValuesAreAccepted() {
        val payload = """{"boundary":"iterations"}"""

        val minContainer = buildContainer(payload.toByteArray(), iterations = AndroidBackupVault.MIN_ITERATIONS)
        assertEquals(payload, vault.decrypt(minContainer, passphrase))

        val maxContainer = buildContainer(payload.toByteArray(), iterations = AndroidBackupVault.MAX_ITERATIONS)
        assertEquals(payload, vault.decrypt(maxContainer, passphrase))
    }

    @Test
    fun testDecompressedSizeBoundaryExactAndPlusOne() {
        val limit = 1024
        val limited = AndroidBackupVault(iterations = 2_000, maxDecompressedSize = limit)

        val exactContainer = buildContainer(ByteArray(limit) { 'A'.code.toByte() }, iterations = 2_000)
        assertEquals("A".repeat(limit), limited.decrypt(exactContainer, passphrase))

        val overByOneContainer = buildContainer(ByteArray(limit + 1) { 'A'.code.toByte() }, iterations = 2_000)
        assertFailsWith<CorruptedBackupException> {
            limited.decrypt(overByOneContainer, passphrase)
        }
    }

    @Test
    fun testMultiChunkPayloadRoundTrip() {
        // Charge utile > CHUNK_SIZE (8 KiB) avec entropie variée pour exercer plusieurs itérations de lecture GZIP
        val multiChunkPayload = (0 until 1500).joinToString("\n") { index ->
            "entry-$index-${(index * 7919) % 10000}"
        }
        assertTrue(multiChunkPayload.toByteArray(Charsets.UTF_8).size > AndroidBackupVault.CHUNK_SIZE * 2)

        val container = vault.encrypt(multiChunkPayload, passphrase)
        assertEquals(multiChunkPayload, vault.decrypt(container, passphrase))
    }

    @Test
    fun testEmptyAndMinimumSizeContainersFailAppropriately() {
        assertFailsWith<CorruptedBackupException> {
            vault.decrypt(ByteArray(0), passphrase)
        }

        // Conteneur exactement de taille MIN_CONTAINER_SIZE avec en-tête valide mais tag aléatoire
        val minSizedInvalid = ByteArray(AndroidBackupVault.MIN_CONTAINER_SIZE)
        ByteBuffer.wrap(minSizedInvalid)
            .put(AndroidBackupVault.MAGIC)
            .put(AndroidBackupVault.VERSION)
            .put(ByteArray(AndroidBackupVault.SALT_LENGTH))
            .putInt(2_000)
            .put(ByteArray(AndroidBackupVault.IV_LENGTH))
        assertFailsWith<InvalidPassphraseException> {
            vault.decrypt(minSizedInvalid, passphrase)
        }
    }

    @Test
    fun testTruncatedOrExtendedCiphertextFails() {
        val container = vault.encrypt("data", passphrase)

        assertFailsWith<InvalidPassphraseException> {
            vault.decrypt(container.copyOf(container.size - 1), passphrase)
        }
        assertFailsWith<InvalidPassphraseException> {
            vault.decrypt(container + byteArrayOf(0x00), passphrase)
        }
    }

    @Test
    fun testTamperedAuthTagLastByteFails() {
        val container = vault.encrypt("data", passphrase)
        container[container.lastIndex] = (container[container.lastIndex].toInt() xor 0x01).toByte()

        assertFailsWith<InvalidPassphraseException> {
            vault.decrypt(container, passphrase)
        }
    }
}
