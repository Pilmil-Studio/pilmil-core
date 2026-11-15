package fr.pilmil.core.platform.backup

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class IosBackupVaultTest {

    @Test
    fun encryptAndDecryptRoundTrip() {
        val vault = IosBackupVault(iterations = 2_000)
        val payload = """{"version":8,"notes":"accentuées éàü"}"""
        val passphrase = "phrase-secrete-test".toCharArray()

        val encrypted = vault.encrypt(payload, passphrase)
        val decrypted = vault.decrypt(encrypted, passphrase)

        assertEquals(payload, decrypted)
    }

    @Test
    fun wrongPassphraseThrowsInvalidPassphraseException() {
        val vault = IosBackupVault(iterations = 2_000)
        val encrypted = vault.encrypt("secret", "bonne-phrase".toCharArray())

        assertFailsWith<InvalidPassphraseException> {
            vault.decrypt(encrypted, "mauvaise-phrase".toCharArray())
        }
    }

    @Test
    fun tamperedPayloadThrowsBackupException() {
        val vault = IosBackupVault(iterations = 2_000)
        val passphrase = "bonne-phrase".toCharArray()
        val encrypted = vault.encrypt("secret", passphrase)
        encrypted[encrypted.lastIndex] = (encrypted.last().toInt() xor 0x01).toByte()

        assertFailsWith<BackupException> {
            vault.decrypt(encrypted, passphrase)
        }
    }
}
