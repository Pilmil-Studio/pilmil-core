package fr.pilmil.core.platform.backup

/**
 * Vecteur de test figé du format `.pilmil` v1.
 *
 * Conteneur produit une fois par [AndroidBackupVault] avec des paramètres fabriqués
 * (sel `A0..AF`, IV `C0..CB`, 1 000 itérations). Les octets sont écrits en dur : toute
 * modification du format (en-tête, KDF, AAD, chiffrement) doit casser les tests qui l'utilisent.
 * Aucune donnée réelle.
 */
internal object PilmilV1Vector {
    const val PASSPHRASE = "phrase-de-test-v1"
    const val PLAINTEXT = "Vecteur de test pilmil v1 : été 2026"
    const val ITERATIONS = 1_000

    /** Clé AES-256 dérivée de [PASSPHRASE] et du sel du vecteur (PBKDF2-HMAC-SHA256, [ITERATIONS]). */
    const val KEY_HEX = "7a2f2031f9a145729eeed27c393f8dcf63a201b6c700ac4ad902f197dc74f586"

    private const val CONTAINER_HEX =
        "50494c4d494c01a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000003e8c0c1c2c3c4" +
            "c5c6c7c8c9cacbaa42239ff06c9a172af905f6a2b8f7273e65cda8fac153ec53" +
            "d4735adc90c07d76d76fbcc0e92e99f34e9aeb4511cd013a0ecebcc20bbf35ac" +
            "fbf3b54a72e888a4ade2f49f7f6c8c9192"

    const val MAGIC_LENGTH = 6
    const val VERSION_OFFSET = 6
    const val SALT_OFFSET = 7
    const val SALT_LENGTH = 16
    const val ITERATIONS_OFFSET = 23
    const val IV_OFFSET = 27
    const val IV_LENGTH = 12
    const val HEADER_LENGTH = 39
    const val TAG_LENGTH = 16

    /** Conteneur complet : en-tête (39 octets), GZIP chiffré (58 octets), tag GCM (16 octets). */
    fun container(): ByteArray = hexToBytes(CONTAINER_HEX)

    fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { hex.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
}
