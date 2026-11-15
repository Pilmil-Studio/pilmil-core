package fr.pilmil.core.platform.backup

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class BackupExceptionTest {

    @Test
    fun backupExceptionPreservesMessageAndCause() {
        val cause = IllegalStateException("root")
        val ex = BackupException("erreur de sauvegarde", cause)

        assertEquals("erreur de sauvegarde", ex.message)
        assertSame(cause, ex.cause)

        val noCause = BackupException("sans cause")
        assertEquals("sans cause", noCause.message)
        assertNull(noCause.cause)
    }

    @Test
    fun corruptedBackupExceptionExtendsBackupException() {
        val cause = RuntimeException("io")
        val ex: Throwable = CorruptedBackupException("conteneur invalide", cause)

        assertTrue(ex is BackupException)
        assertEquals("conteneur invalide", ex.message)
        assertSame(cause, ex.cause)
    }

    @Test
    fun invalidPassphraseExceptionHasDefaultMessageAndExtendsBackupException() {
        val defaultEx: Throwable = InvalidPassphraseException()
        assertTrue(defaultEx is BackupException)
        assertEquals("Mot de passe incorrect ou données altérées", defaultEx.message)
        assertNull(defaultEx.cause)

        val cause = SecurityException("tag mismatch")
        val customEx = InvalidPassphraseException("clé erronée", cause)
        assertEquals("clé erronée", customEx.message)
        assertSame(cause, customEx.cause)
    }
}
