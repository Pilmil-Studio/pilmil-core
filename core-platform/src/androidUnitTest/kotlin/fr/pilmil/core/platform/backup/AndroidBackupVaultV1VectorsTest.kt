package fr.pilmil.core.platform.backup

import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Vecteurs de test du conteneur `.pilmil` v1 : phrase secrète fausse, conteneurs tronqués,
 * octets modifiés, et vecteur fixe dont les octets sont écrits en dur ([PilmilV1Vector]).
 * Le format est implémenté par plateforme (pas en `commonMain`) : ces tests passent donc
 * par [AndroidBackupVault].
 */
class AndroidBackupVaultV1VectorsTest {

    private val vault = AndroidBackupVault()
    private val passphrase = PilmilV1Vector.PASSPHRASE.toCharArray()
    private val container = PilmilV1Vector.container()

    private fun modified(index: Int): ByteArray =
        container.copyOf().also { it[index] = (it[index].toInt() xor 0x01).toByte() }

    @Test
    fun fixedVectorDecryptsToKnownText() {
        assertEquals(PilmilV1Vector.PLAINTEXT, vault.decrypt(container, passphrase))
    }

    @Test
    fun fixedVectorDecryptsWhateverTheConfiguredIterations() {
        // Le nombre d'itérations lu dans l'en-tête prime sur celui du constructeur.
        assertEquals(PilmilV1Vector.PLAINTEXT, AndroidBackupVault(iterations = 600_000).decrypt(container, passphrase))
    }

    @Test
    fun wrongPassphraseFailsWithTypedError() {
        assertFailsWith<InvalidPassphraseException> { vault.decrypt(container, "phrase-fausse".toCharArray()) }
        // Même longueur, un seul caractère différent.
        assertFailsWith<InvalidPassphraseException> { vault.decrypt(container, "phrase-de-test-v2".toCharArray()) }
    }

    @Test
    fun containerTruncatedInHeaderIsCorrupted() {
        val cuts = listOf(
            0, // vide
            3, // dans la signature
            PilmilV1Vector.VERSION_OFFSET, // avant la version
            PilmilV1Vector.VERSION_OFFSET + 1, // avant le sel
            PilmilV1Vector.SALT_OFFSET + 8, // au milieu du sel
            PilmilV1Vector.ITERATIONS_OFFSET + 2, // au milieu du nombre d'itérations
            PilmilV1Vector.IV_OFFSET + 6, // au milieu de l'IV
            PilmilV1Vector.HEADER_LENGTH - 1, // un octet avant la fin de l'en-tête
            PilmilV1Vector.HEADER_LENGTH, // en-tête seul
            PilmilV1Vector.HEADER_LENGTH + PilmilV1Vector.TAG_LENGTH - 1, // un octet sous le minimum
        )
        for (cut in cuts) {
            assertFailsWith<CorruptedBackupException>("coupé à $cut") {
                vault.decrypt(container.copyOf(cut), passphrase)
            }
        }
    }

    @Test
    fun containerTruncatedInCiphertextOrWithoutTagFails() {
        val withoutTag = container.size - PilmilV1Vector.TAG_LENGTH
        val cuts = listOf(
            PilmilV1Vector.HEADER_LENGTH + PilmilV1Vector.TAG_LENGTH, // minimum accepté, chiffré vide
            PilmilV1Vector.HEADER_LENGTH + 30, // au milieu du chiffré
            withoutTag, // chiffré entier, sans étiquette GCM
            container.size - 8, // moitié d'étiquette
            container.size - 1, // dernier octet manquant
        )
        for (cut in cuts) {
            assertFailsWith<InvalidPassphraseException>("coupé à $cut") {
                vault.decrypt(container.copyOf(cut), passphrase)
            }
        }
    }

    @Test
    fun everyPrefixFailsWithTypedErrorNeverAnythingElse() {
        for (cut in 0 until container.size) {
            val error = assertFailsWith<BackupException>("coupé à $cut") {
                vault.decrypt(container.copyOf(cut), passphrase)
            }
            assertTrue(
                error is CorruptedBackupException || error is InvalidPassphraseException,
                "coupé à $cut : ${error::class.simpleName}",
            )
        }
    }

    @Test
    fun appendedByteFails() {
        assertFailsWith<InvalidPassphraseException> { vault.decrypt(container + byteArrayOf(0), passphrase) }
    }

    @Test
    fun modifiedCiphertextByteFails() {
        assertFailsWith<InvalidPassphraseException> { vault.decrypt(modified(PilmilV1Vector.HEADER_LENGTH), passphrase) }
        assertFailsWith<InvalidPassphraseException> { vault.decrypt(modified(PilmilV1Vector.HEADER_LENGTH + 30), passphrase) }
    }

    @Test
    fun modifiedTagByteFails() {
        assertFailsWith<InvalidPassphraseException> {
            vault.decrypt(modified(container.size - PilmilV1Vector.TAG_LENGTH), passphrase)
        }
        assertFailsWith<InvalidPassphraseException> { vault.decrypt(modified(container.size - 1), passphrase) }
    }

    @Test
    fun modifiedHeaderBytesFail() {
        // Signature et version : conteneur rejeté comme corrompu.
        assertFailsWith<CorruptedBackupException> { vault.decrypt(modified(0), passphrase) }
        assertFailsWith<CorruptedBackupException> { vault.decrypt(modified(PilmilV1Vector.VERSION_OFFSET), passphrase) }
        // Sel, IV et itérations valides mais différents : la clé ou le nonce ne correspond plus.
        assertFailsWith<InvalidPassphraseException> { vault.decrypt(modified(PilmilV1Vector.SALT_OFFSET), passphrase) }
        assertFailsWith<InvalidPassphraseException> { vault.decrypt(modified(PilmilV1Vector.IV_OFFSET), passphrase) }
        assertFailsWith<InvalidPassphraseException> {
            vault.decrypt(modified(PilmilV1Vector.IV_OFFSET - 1), passphrase) // 1 000 -> 1 001 itérations
        }
        // Itérations hors bornes : rejetées avant toute dérivation.
        assertFailsWith<CorruptedBackupException> { vault.decrypt(modified(PilmilV1Vector.ITERATIONS_OFFSET), passphrase) }
    }

    @Test
    fun everySingleBitModificationFailsWithTypedError() {
        for (index in container.indices) {
            assertFailsWith<BackupException>("octet $index modifié") {
                vault.decrypt(modified(index), passphrase)
            }
        }
    }
}
