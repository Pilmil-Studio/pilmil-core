package fr.pilmil.core.platform.backup

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Vecteurs de test du format `.pilmil` v1 au niveau de la primitive partagée [Aes256Gcm]
 * (la même sur Android et iOS pour PBKDF2 et AES-GCM). Le conteneur complet est testé
 * côté Android dans `AndroidBackupVaultV1VectorsTest`.
 */
class PilmilV1FormatTest {

    private val container = PilmilV1Vector.container()
    private val magicAndVersion = "PILMIL".encodeToByteArray() + byteArrayOf(1)

    private fun key(): ByteArray = PilmilV1Vector.hexToBytes(PilmilV1Vector.KEY_HEX)

    private fun iv(): ByteArray =
        container.copyOfRange(PilmilV1Vector.IV_OFFSET, PilmilV1Vector.IV_OFFSET + PilmilV1Vector.IV_LENGTH)

    private fun body(): ByteArray = container.copyOfRange(PilmilV1Vector.HEADER_LENGTH, container.size)

    @Test
    fun fixedVectorHeaderLayoutIsFrozen() {
        assertEquals(PilmilV1Vector.HEADER_LENGTH + 58 + PilmilV1Vector.TAG_LENGTH, container.size)
        assertContentEquals("PILMIL".encodeToByteArray(), container.copyOfRange(0, PilmilV1Vector.MAGIC_LENGTH))
        assertEquals(1, container[PilmilV1Vector.VERSION_OFFSET].toInt())
        val salt = container.copyOfRange(PilmilV1Vector.SALT_OFFSET, PilmilV1Vector.SALT_OFFSET + PilmilV1Vector.SALT_LENGTH)
        assertContentEquals(ByteArray(16) { (0xA0 + it).toByte() }, salt)
        val iterations = container.copyOfRange(PilmilV1Vector.ITERATIONS_OFFSET, PilmilV1Vector.IV_OFFSET)
        assertContentEquals(byteArrayOf(0, 0, 0x03, 0xE8.toByte()), iterations)
        assertContentEquals(ByteArray(12) { (0xC0 + it).toByte() }, iv())
    }

    @Test
    fun pbkdf2ReproducesFixedKey() {
        val salt = container.copyOfRange(PilmilV1Vector.SALT_OFFSET, PilmilV1Vector.SALT_OFFSET + PilmilV1Vector.SALT_LENGTH)
        val derived = Aes256Gcm.pbkdf2HmacSha256(
            PilmilV1Vector.PASSPHRASE.encodeToByteArray(),
            salt,
            PilmilV1Vector.ITERATIONS,
        )
        assertContentEquals(key(), derived)
    }

    @Test
    fun fixedVectorDecryptsWithHeaderAsAad() {
        val gzip = Aes256Gcm.decrypt(key(), iv(), body(), magicAndVersion)
        assertEquals(58, gzip.size)
        // Signature GZIP (RFC 1952) : le contenu déchiffré est bien le flux compressé attendu.
        assertEquals(0x1F, gzip[0].toInt() and 0xFF)
        assertEquals(0x8B, gzip[1].toInt() and 0xFF)
    }

    @Test
    fun fixedVectorRejectedWithoutOrWithWrongAad() {
        assertFailsWith<InvalidPassphraseException> { Aes256Gcm.decrypt(key(), iv(), body()) }
        val otherVersion = "PILMIL".encodeToByteArray() + byteArrayOf(2)
        assertFailsWith<InvalidPassphraseException> { Aes256Gcm.decrypt(key(), iv(), body(), otherVersion) }
    }

    @Test
    fun wrongKeyFailsWithTypedError() {
        val wrongKey = Aes256Gcm.pbkdf2HmacSha256(
            "phrase-fausse".encodeToByteArray(),
            container.copyOfRange(PilmilV1Vector.SALT_OFFSET, PilmilV1Vector.SALT_OFFSET + PilmilV1Vector.SALT_LENGTH),
            PilmilV1Vector.ITERATIONS,
        )
        assertFailsWith<InvalidPassphraseException> { Aes256Gcm.decrypt(wrongKey, iv(), body(), magicAndVersion) }
    }

    @Test
    fun everyModifiedByteOfCiphertextAndTagFails() {
        val original = body()
        for (i in original.indices) {
            val modified = original.copyOf()
            modified[i] = (modified[i].toInt() xor 0x01).toByte()
            assertFailsWith<InvalidPassphraseException>("octet $i modifié") {
                Aes256Gcm.decrypt(key(), iv(), modified, magicAndVersion)
            }
        }
    }

    @Test
    fun modifiedIvFails() {
        val modifiedIv = iv().also { it[0] = (it[0].toInt() xor 0x01).toByte() }
        assertFailsWith<InvalidPassphraseException> { Aes256Gcm.decrypt(key(), modifiedIv, body(), magicAndVersion) }
    }

    @Test
    fun bodyShorterThanTagIsCorruptedNotACrash() {
        for (length in 0 until PilmilV1Vector.TAG_LENGTH) {
            assertFailsWith<CorruptedBackupException>("longueur $length") {
                Aes256Gcm.decrypt(key(), iv(), body().copyOf(length), magicAndVersion)
            }
        }
    }

    @Test
    fun bodyTruncatedAnywhereFailsWithTypedError() {
        val original = body()
        for (length in PilmilV1Vector.TAG_LENGTH until original.size) {
            assertFailsWith<InvalidPassphraseException>("longueur $length") {
                Aes256Gcm.decrypt(key(), iv(), original.copyOf(length), magicAndVersion)
            }
        }
    }
}
