package fr.pilmil.core.platform.backup

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class Aes256GcmTest {

    @Test
    fun pbkdf2DerivesDeterministic32ByteKey() {
        val salt = ByteArray(16) { it.toByte() }
        val password = "secret-passphrase".encodeToByteArray()

        val key1 = Aes256Gcm.pbkdf2HmacSha256(password, salt, iterations = 1_000)
        val key2 = Aes256Gcm.pbkdf2HmacSha256(password, salt, iterations = 1_000)
        val otherKey = Aes256Gcm.pbkdf2HmacSha256("other-passphrase".encodeToByteArray(), salt, iterations = 1_000)

        assertEquals(32, key1.size)
        assertContentEquals(key1, key2)
        assertFalse(key1.contentEquals(otherKey))
    }

    @Test
    fun encryptAndDecryptRoundTrip() {
        val key = ByteArray(32) { (it * 7 + 3).toByte() }
        val iv = ByteArray(12) { (it + 1).toByte() }
        val plaintext = "Données confidentielles Pilmil — UTF-8 ✓".encodeToByteArray()

        val ciphertext = Aes256Gcm.encrypt(key, iv, plaintext)
        val decrypted = Aes256Gcm.decrypt(key, iv, ciphertext)

        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun decryptWithWrongKeyFails() {
        val key = ByteArray(32) { 1 }
        val wrongKey = ByteArray(32) { 2 }
        val iv = ByteArray(12) { 9 }
        val ciphertext = Aes256Gcm.encrypt(key, iv, "hello".encodeToByteArray())

        assertFailsWith<Throwable> {
            Aes256Gcm.decrypt(wrongKey, iv, ciphertext)
        }
    }

    @Test
    fun decryptTamperedCiphertextFails() {
        val key = ByteArray(32) { 5 }
        val iv = ByteArray(12) { 4 }
        val ciphertext = Aes256Gcm.encrypt(key, iv, "hello world".encodeToByteArray())
        ciphertext[0] = (ciphertext[0].toInt() xor 0xFF).toByte()

        assertFailsWith<Throwable> {
            Aes256Gcm.decrypt(key, iv, ciphertext)
        }
    }
}
