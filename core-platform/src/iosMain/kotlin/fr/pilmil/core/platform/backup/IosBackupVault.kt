@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package fr.pilmil.core.platform.backup

import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import platform.Security.SecRandomCopyBytes
import platform.Security.errSecSuccess
import platform.Security.kSecRandomDefault
import platform.zlib.Z_DEFAULT_COMPRESSION
import platform.zlib.Z_DEFAULT_STRATEGY
import platform.zlib.Z_DEFLATED
import platform.zlib.Z_FINISH
import platform.zlib.Z_NO_FLUSH
import platform.zlib.Z_OK
import platform.zlib.Z_STREAM_END
import platform.zlib.deflate
import platform.zlib.deflateEnd
import platform.zlib.deflateInit2_
import platform.zlib.inflate
import platform.zlib.inflateEnd
import platform.zlib.inflateInit2_
import platform.zlib.z_stream
import platform.zlib.zlibVersion

/**
 * Implémentation iOS du conteneur de sauvegarde chiffrée `.pilmil` v1,
 * binaire-compatible avec [AndroidBackupVault] (GZIP + PBKDF2-HMAC-SHA256 + AES-256-GCM).
 */
class IosBackupVault(
    private val iterations: Int = DEFAULT_ITERATIONS,
    private val maxDecompressedSize: Int = MAX_DECOMPRESSED_SIZE,
) : BackupVault {

    companion object {
        val MAGIC: ByteArray = "PILMIL".encodeToByteArray()
        const val VERSION: Byte = 1
        const val DEFAULT_ITERATIONS: Int = 600_000
        const val SALT_LENGTH: Int = 16
        const val IV_LENGTH: Int = 12
        const val HEADER_LENGTH: Int = 6 + 1 + SALT_LENGTH + 4 + IV_LENGTH
        const val MAX_DECOMPRESSED_SIZE: Int = 50 * 1024 * 1024
        const val MIN_ITERATIONS: Int = 1_000
        const val MAX_ITERATIONS: Int = 2_000_000
    }

    init {
        require(iterations in MIN_ITERATIONS..MAX_ITERATIONS) {
            "Le nombre d'itérations PBKDF2 doit être compris entre $MIN_ITERATIONS et $MAX_ITERATIONS"
        }
    }

    override fun encrypt(payloadUtf8: String, passphrase: CharArray): ByteArray {
        require(passphrase.isNotEmpty()) { "La phrase secrète ne peut pas être vide" }

        val compressed = gzipCompress(payloadUtf8.encodeToByteArray())
        val salt = randomBytes(SALT_LENGTH)
        val iv = randomBytes(IV_LENGTH)
        val key = Aes256Gcm.pbkdf2HmacSha256(passphrase.concatToString().encodeToByteArray(), salt, iterations)

        val ciphertext = Aes256Gcm.encrypt(key, iv, compressed)
        val out = ByteArray(HEADER_LENGTH + ciphertext.size)
        var pos = 0
        MAGIC.copyInto(out, pos); pos += MAGIC.size
        out[pos++] = VERSION
        salt.copyInto(out, pos); pos += SALT_LENGTH
        out[pos++] = (iterations ushr 24).toByte()
        out[pos++] = (iterations ushr 16).toByte()
        out[pos++] = (iterations ushr 8).toByte()
        out[pos++] = iterations.toByte()
        iv.copyInto(out, pos); pos += IV_LENGTH
        ciphertext.copyInto(out, pos)
        return out
    }

    override fun decrypt(container: ByteArray, passphrase: CharArray): String {
        require(passphrase.isNotEmpty()) { "La phrase secrète ne peut pas être vide" }
        if (container.size < HEADER_LENGTH + Aes256Gcm.TAG_BYTES) {
            throw CorruptedBackupException("Fichier de sauvegarde trop court ou tronqué")
        }
        for (i in MAGIC.indices) {
            if (container[i] != MAGIC[i]) {
                throw CorruptedBackupException("Signature magique PILMIL invalide")
            }
        }
        val version = container[MAGIC.size]
        if (version != VERSION) {
            throw CorruptedBackupException("Version de sauvegarde non supportée : $version")
        }

        var pos = MAGIC.size + 1
        val salt = container.copyOfRange(pos, pos + SALT_LENGTH); pos += SALT_LENGTH
        val iters = ((container[pos].toInt() and 0xFF) shl 24) or
            ((container[pos + 1].toInt() and 0xFF) shl 16) or
            ((container[pos + 2].toInt() and 0xFF) shl 8) or
            (container[pos + 3].toInt() and 0xFF)
        pos += 4
        if (iters !in MIN_ITERATIONS..MAX_ITERATIONS) {
            throw CorruptedBackupException("Nombre d'itérations PBKDF2 invalide : $iters")
        }
        val iv = container.copyOfRange(pos, pos + IV_LENGTH); pos += IV_LENGTH
        val ciphertext = container.copyOfRange(pos, container.size)

        val key = Aes256Gcm.pbkdf2HmacSha256(passphrase.concatToString().encodeToByteArray(), salt, iters)
        val compressed = Aes256Gcm.decrypt(key, iv, ciphertext)
        val plain = gzipDecompress(compressed, maxDecompressedSize)
        return plain.decodeToString()
    }

    private fun randomBytes(size: Int): ByteArray {
        val out = ByteArray(size)
        out.usePinned { pinned ->
            val status = SecRandomCopyBytes(kSecRandomDefault, size.toULong(), pinned.addressOf(0))
            check(status == errSecSuccess) { "SecRandomCopyBytes failed: $status" }
        }
        return out
    }

    private fun gzipCompress(input: ByteArray): ByteArray = memScoped {
        val stream = alloc<z_stream>()
        val initRes = deflateInit2_(
            strm = stream.ptr,
            level = Z_DEFAULT_COMPRESSION,
            method = Z_DEFLATED,
            windowBits = 15 + 16, // format GZIP
            memLevel = 8,
            strategy = Z_DEFAULT_STRATEGY,
            version = zlibVersion()?.toString(),
            stream_size = kotlinx.cinterop.sizeOf<z_stream>().toInt(),
        )
        if (initRes != Z_OK) throw BackupException("Échec initialisation GZIP ($initRes)")

        val outChunks = mutableListOf<ByteArray>()
        val chunk = ByteArray(8192)
        try {
            input.usePinned { inPinned ->
                if (input.isNotEmpty()) {
                    stream.next_in = inPinned.addressOf(0).reinterpret()
                    stream.avail_in = input.size.toUInt()
                } else {
                    stream.next_in = null
                    stream.avail_in = 0u
                }
                do {
                    chunk.usePinned { outPinned ->
                        stream.next_out = outPinned.addressOf(0).reinterpret()
                        stream.avail_out = chunk.size.toUInt()
                        val res = deflate(stream.ptr, Z_FINISH)
                        if (res != Z_OK && res != Z_STREAM_END) {
                            throw BackupException("Échec compression GZIP ($res)")
                        }
                        val written = chunk.size - stream.avail_out.toInt()
                        if (written > 0) {
                            outChunks += chunk.copyOf(written)
                        }
                    }
                } while (stream.avail_out == 0u)
            }
        } finally {
            deflateEnd(stream.ptr)
        }
        val total = outChunks.sumOf { it.size }
        val result = ByteArray(total)
        var offset = 0
        for (c in outChunks) {
            c.copyInto(result, offset)
            offset += c.size
        }
        result
    }

    private fun gzipDecompress(input: ByteArray, maxSize: Int): ByteArray = memScoped {
        val stream = alloc<z_stream>()
        val initRes = inflateInit2_(
            strm = stream.ptr,
            windowBits = 15 + 16, // format GZIP
            version = zlibVersion()?.toString(),
            stream_size = kotlinx.cinterop.sizeOf<z_stream>().toInt(),
        )
        if (initRes != Z_OK) throw CorruptedBackupException("Échec initialisation décompression GZIP")

        val outChunks = mutableListOf<ByteArray>()
        var totalOut = 0
        val chunk = ByteArray(8192)
        try {
            input.usePinned { inPinned ->
                stream.next_in = inPinned.addressOf(0).reinterpret()
                stream.avail_in = input.size.toUInt()
                do {
                    chunk.usePinned { outPinned ->
                        stream.next_out = outPinned.addressOf(0).reinterpret()
                        stream.avail_out = chunk.size.toUInt()
                        val res = inflate(stream.ptr, Z_NO_FLUSH)
                        if (res != Z_OK && res != Z_STREAM_END) {
                            throw CorruptedBackupException("Flux GZIP corrompu ($res)")
                        }
                        val written = chunk.size - stream.avail_out.toInt()
                        if (written > 0) {
                            totalOut += written
                            if (totalOut > maxSize) {
                                throw CorruptedBackupException("Sauvegarde trop volumineuse après décompression")
                            }
                            outChunks += chunk.copyOf(written)
                        }
                        if (res == Z_STREAM_END) break
                    }
                } while (stream.avail_out == 0u || stream.avail_in > 0u)
            }
        } finally {
            inflateEnd(stream.ptr)
        }
        val result = ByteArray(totalOut)
        var offset = 0
        for (c in outChunks) {
            c.copyInto(result, offset)
            offset += c.size
        }
        result
    }
}
