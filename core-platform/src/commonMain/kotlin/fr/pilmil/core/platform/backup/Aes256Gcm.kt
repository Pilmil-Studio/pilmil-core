package fr.pilmil.core.platform.backup

/**
 * Implémentation Kotlin pur multiplateforme de AES-256-GCM (NIST FIPS 197 + SP 800-38D)
 * et PBKDF2-HMAC-SHA256 (RFC 2898) pour assurer la compatibilité binaire bit-à-bit
 * des coffres `.pilmil` v1 entre Android et iOS.
 */
internal object Aes256Gcm {

    const val KEY_BYTES = 32
    const val IV_BYTES = 12
    const val TAG_BYTES = 16

    fun encrypt(key: ByteArray, iv: ByteArray, plaintext: ByteArray, aad: ByteArray = ByteArray(0)): ByteArray {
        require(key.size == KEY_BYTES) { "Clé AES-256 invalide (${key.size} octets)" }
        require(iv.size == IV_BYTES) { "IV GCM invalide (${iv.size} octets)" }

        val roundKeys = expandKey256(key)
        val h = encryptBlock(roundKeys, ByteArray(16))

        // J0 = IV || 0x00000001
        val j0 = ByteArray(16)
        iv.copyInto(j0, 0, 0, IV_BYTES)
        j0[15] = 1

        val counter = j0.copyOf()
        inc32(counter)
        val ciphertext = gctr(roundKeys, counter, plaintext)

        val tagInput = ghash(h, aad, ciphertext)
        val tag = gctr(roundKeys, j0, tagInput)

        val out = ByteArray(ciphertext.size + TAG_BYTES)
        ciphertext.copyInto(out, 0)
        tag.copyInto(out, ciphertext.size)
        return out
    }

    fun decrypt(key: ByteArray, iv: ByteArray, ciphertextAndTag: ByteArray, aad: ByteArray = ByteArray(0)): ByteArray {
        require(key.size == KEY_BYTES) { "Clé AES-256 invalide (${key.size} octets)" }
        require(iv.size == IV_BYTES) { "IV GCM invalide (${iv.size} octets)" }
        if (ciphertextAndTag.size < TAG_BYTES) {
            throw CorruptedBackupException("Conteneur chiffré trop court")
        }

        val ctLen = ciphertextAndTag.size - TAG_BYTES
        val ciphertext = ciphertextAndTag.copyOfRange(0, ctLen)
        val providedTag = ciphertextAndTag.copyOfRange(ctLen, ciphertextAndTag.size)

        val roundKeys = expandKey256(key)
        val h = encryptBlock(roundKeys, ByteArray(16))

        val j0 = ByteArray(16)
        iv.copyInto(j0, 0, 0, IV_BYTES)
        j0[15] = 1

        val expectedTag = gctr(roundKeys, j0, ghash(h, aad, ciphertext))
        if (!constantTimeEquals(providedTag, expectedTag)) {
            throw InvalidPassphraseException()
        }

        val counter = j0.copyOf()
        inc32(counter)
        return gctr(roundKeys, counter, ciphertext)
    }

    fun pbkdf2HmacSha256(password: ByteArray, salt: ByteArray, iterations: Int, keyLengthBytes: Int = KEY_BYTES): ByteArray {
        val blockCount = (keyLengthBytes + 31) / 32
        val out = ByteArray(blockCount * 32)
        for (blockIndex in 1..blockCount) {
            val u1Input = ByteArray(salt.size + 4)
            salt.copyInto(u1Input)
            u1Input[salt.size] = (blockIndex ushr 24).toByte()
            u1Input[salt.size + 1] = (blockIndex ushr 16).toByte()
            u1Input[salt.size + 2] = (blockIndex ushr 8).toByte()
            u1Input[salt.size + 3] = blockIndex.toByte()

            var u = hmacSha256(password, u1Input)
            val t = u.copyOf()
            repeat(iterations - 1) {
                u = hmacSha256(password, u)
                for (i in t.indices) {
                    t[i] = (t[i].toInt() xor u[i].toInt()).toByte()
                }
            }
            t.copyInto(out, destinationOffset = (blockIndex - 1) * 32)
        }
        return out.copyOf(keyLengthBytes)
    }

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) {
            diff = diff or ((a[i].toInt() xor b[i].toInt()) and 0xFF)
        }
        return diff == 0
    }

    private fun gctr(roundKeys: IntArray, initialCounter: ByteArray, input: ByteArray): ByteArray {
        if (input.isEmpty()) return ByteArray(0)
        val out = ByteArray(input.size)
        val cb = initialCounter.copyOf()
        var offset = 0
        while (offset < input.size) {
            val keystream = encryptBlock(roundKeys, cb)
            val chunk = minOf(16, input.size - offset)
            for (i in 0 until chunk) {
                out[offset + i] = (input[offset + i].toInt() xor keystream[i].toInt()).toByte()
            }
            offset += chunk
            inc32(cb)
        }
        return out
    }

    private fun inc32(block: ByteArray) {
        for (i in 15 downTo 12) {
            val v = (block[i].toInt() and 0xFF) + 1
            block[i] = v.toByte()
            if ((v and 0x100) == 0) break
        }
    }

    private fun ghash(h: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        val y = ByteArray(16)
        fun processPadded(data: ByteArray) {
            var offset = 0
            while (offset < data.size) {
                val len = minOf(16, data.size - offset)
                for (i in 0 until len) {
                    y[i] = (y[i].toInt() xor data[offset + i].toInt()).toByte()
                }
                gf128Mul(y, h)
                offset += 16
            }
        }
        processPadded(aad)
        processPadded(ciphertext)

        val lenBlock = ByteArray(16)
        val aadBits = aad.size.toLong() * 8L
        val ctBits = ciphertext.size.toLong() * 8L
        for (i in 0 until 8) {
            lenBlock[i] = ((aadBits ushr (56 - 8 * i)) and 0xFFL).toByte()
            lenBlock[8 + i] = ((ctBits ushr (56 - 8 * i)) and 0xFFL).toByte()
        }
        for (i in 0 until 16) {
            y[i] = (y[i].toInt() xor lenBlock[i].toInt()).toByte()
        }
        gf128Mul(y, h)
        return y
    }

    private fun gf128Mul(x: ByteArray, y: ByteArray) {
        val z = ByteArray(16)
        val v = y.copyOf()
        for (i in 0 until 128) {
            val bit = ((x[i ushr 3].toInt() ushr (7 - (i and 7))) and 1) != 0
            if (bit) {
                for (j in 0 until 16) z[j] = (z[j].toInt() xor v[j].toInt()).toByte()
            }
            val lsb = (v[15].toInt() and 1) != 0
            for (j in 15 downTo 1) {
                v[j] = (((v[j].toInt() and 0xFF) ushr 1) or ((v[j - 1].toInt() and 1) shl 7)).toByte()
            }
            v[0] = ((v[0].toInt() and 0xFF) ushr 1).toByte()
            if (lsb) {
                v[0] = (v[0].toInt() xor 0xE1).toByte()
            }
        }
        z.copyInto(x)
    }

    // --- AES-256 (FIPS 197) ---

    private fun expandKey256(key: ByteArray): IntArray {
        val w = IntArray(60)
        for (i in 0 until 8) {
            w[i] = ((key[4 * i].toInt() and 0xFF) shl 24) or
                ((key[4 * i + 1].toInt() and 0xFF) shl 16) or
                ((key[4 * i + 2].toInt() and 0xFF) shl 8) or
                (key[4 * i + 3].toInt() and 0xFF)
        }
        for (i in 8 until 60) {
            var temp = w[i - 1]
            if (i % 8 == 0) {
                temp = subWord(rotWord(temp)) xor (RCON[i / 8] shl 24)
            } else if (i % 8 == 4) {
                temp = subWord(temp)
            }
            w[i] = w[i - 8] xor temp
        }
        return w
    }

    private fun rotWord(w: Int): Int = (w shl 8) or (w ushr 24)

    private fun subWord(w: Int): Int =
        (SBOX[(w ushr 24) and 0xFF] shl 24) or
            (SBOX[(w ushr 16) and 0xFF] shl 16) or
            (SBOX[(w ushr 8) and 0xFF] shl 8) or
            SBOX[w and 0xFF]

    private fun encryptBlock(roundKeys: IntArray, input: ByteArray): ByteArray {
        val s = ByteArray(16)
        input.copyInto(s)
        addRoundKey(s, roundKeys, 0)
        for (round in 1 until 14) {
            subBytes(s)
            shiftRows(s)
            mixColumns(s)
            addRoundKey(s, roundKeys, round * 4)
        }
        subBytes(s)
        shiftRows(s)
        addRoundKey(s, roundKeys, 14 * 4)
        return s
    }

    private fun addRoundKey(s: ByteArray, w: IntArray, offset: Int) {
        for (c in 0 until 4) {
            val k = w[offset + c]
            s[4 * c] = (s[4 * c].toInt() xor ((k ushr 24) and 0xFF)).toByte()
            s[4 * c + 1] = (s[4 * c + 1].toInt() xor ((k ushr 16) and 0xFF)).toByte()
            s[4 * c + 2] = (s[4 * c + 2].toInt() xor ((k ushr 8) and 0xFF)).toByte()
            s[4 * c + 3] = (s[4 * c + 3].toInt() xor (k and 0xFF)).toByte()
        }
    }

    private fun subBytes(s: ByteArray) {
        for (i in 0 until 16) s[i] = SBOX[s[i].toInt() and 0xFF].toByte()
    }

    private fun shiftRows(s: ByteArray) {
        val t1 = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t1
        val t2 = s[2]; val t6 = s[6]; s[2] = s[10]; s[6] = s[14]; s[10] = t2; s[14] = t6
        val t15 = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t15
    }

    private fun mixColumns(s: ByteArray) {
        for (c in 0 until 4) {
            val i = 4 * c
            val a0 = s[i].toInt() and 0xFF
            val a1 = s[i + 1].toInt() and 0xFF
            val a2 = s[i + 2].toInt() and 0xFF
            val a3 = s[i + 3].toInt() and 0xFF
            s[i] = (gf2(a0) xor gf3(a1) xor a2 xor a3).toByte()
            s[i + 1] = (a0 xor gf2(a1) xor gf3(a2) xor a3).toByte()
            s[i + 2] = (a0 xor a1 xor gf2(a2) xor gf3(a3)).toByte()
            s[i + 3] = (gf3(a0) xor a1 xor a2 xor gf2(a3)).toByte()
        }
    }

    private fun gf2(x: Int): Int {
        val shifted = x shl 1
        return if ((x and 0x80) != 0) (shifted xor 0x1B) and 0xFF else shifted and 0xFF
    }

    private fun gf3(x: Int): Int = gf2(x) xor x

    // --- HMAC-SHA256 & SHA-256 ---

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val blockSize = 64
        val normalizedKey = if (key.size > blockSize) sha256(key) else key
        val kPad = ByteArray(blockSize)
        normalizedKey.copyInto(kPad)

        val iPad = ByteArray(blockSize + data.size)
        val oPad = ByteArray(blockSize + 32)
        for (i in 0 until blockSize) {
            val k = kPad[i].toInt() and 0xFF
            iPad[i] = (k xor 0x36).toByte()
            oPad[i] = (k xor 0x5C).toByte()
        }
        data.copyInto(iPad, destinationOffset = blockSize)
        val inner = sha256(iPad)
        inner.copyInto(oPad, destinationOffset = blockSize)
        return sha256(oPad)
    }

    private fun sha256(input: ByteArray): ByteArray {
        val bitLen = input.size.toLong() * 8L
        val padLen = ((56 - (input.size + 1) % 64) + 64) % 64
        val padded = ByteArray(input.size + 1 + padLen + 8)
        input.copyInto(padded)
        padded[input.size] = 0x80.toByte()
        for (i in 0 until 8) {
            padded[padded.size - 8 + i] = ((bitLen ushr (56 - 8 * i)) and 0xFFL).toByte()
        }

        val h = SHA256_IV.copyOf()
        val w = IntArray(64)
        var offset = 0
        while (offset < padded.size) {
            for (i in 0 until 16) {
                val j = offset + 4 * i
                w[i] = ((padded[j].toInt() and 0xFF) shl 24) or
                    ((padded[j + 1].toInt() and 0xFF) shl 16) or
                    ((padded[j + 2].toInt() and 0xFF) shl 8) or
                    (padded[j + 3].toInt() and 0xFF)
            }
            for (i in 16 until 64) {
                val s0 = w[i - 15].rotateRight(7) xor w[i - 15].rotateRight(18) xor (w[i - 15] ushr 3)
                val s1 = w[i - 2].rotateRight(17) xor w[i - 2].rotateRight(19) xor (w[i - 2] ushr 10)
                w[i] = w[i - 16] + s0 + w[i - 7] + s1
            }

            var a = h[0]; var b = h[1]; var c = h[2]; var d = h[3]
            var e = h[4]; var f = h[5]; var g = h[6]; var hh = h[7]
            for (i in 0 until 64) {
                val s1 = e.rotateRight(6) xor e.rotateRight(11) xor e.rotateRight(25)
                val ch = (e and f) xor (e.inv() and g)
                val temp1 = hh + s1 + ch + SHA256_K[i] + w[i]
                val s0 = a.rotateRight(2) xor a.rotateRight(13) xor a.rotateRight(22)
                val maj = (a and b) xor (a and c) xor (b and c)
                val temp2 = s0 + maj
                hh = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2
            }
            h[0] += a; h[1] += b; h[2] += c; h[3] += d
            h[4] += e; h[5] += f; h[6] += g; h[7] += hh
            offset += 64
        }

        val out = ByteArray(32)
        for (i in 0 until 8) {
            val v = h[i]
            out[4 * i] = (v ushr 24).toByte()
            out[4 * i + 1] = (v ushr 16).toByte()
            out[4 * i + 2] = (v ushr 8).toByte()
            out[4 * i + 3] = v.toByte()
        }
        return out
    }

    private val RCON = intArrayOf(0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40)

    private val SBOX = intArrayOf(
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    )

    private val SHA256_IV = intArrayOf(
        0x6a09e667, 0xbb67ae85.toInt(), 0x3c6ef372, 0xa54ff53a.toInt(),
        0x510e527f, 0x9b05688c.toInt(), 0x1f83d9ab, 0x5be0cd19,
    )

    private val SHA256_K = intArrayOf(
        0x428a2f98, 0x71374491, 0xb5c0fbcf.toInt(), 0xe9b5dba5.toInt(),
        0x3956c25b, 0x59f111f1, 0x923f82a4.toInt(), 0xab1c5ed5.toInt(),
        0xd807aa98.toInt(), 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe.toInt(), 0x9bdc06a7.toInt(), 0xc19bf174.toInt(),
        0xe49b69c1.toInt(), 0xefbe4786.toInt(), 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152.toInt(), 0xa831c66d.toInt(), 0xb00327c8.toInt(), 0xbf597fc7.toInt(),
        0xc6e00bf3.toInt(), 0xd5a79147.toInt(), 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e.toInt(), 0x92722c85.toInt(),
        0xa2bfe8a1.toInt(), 0xa81a664b.toInt(), 0xc24b8b70.toInt(), 0xc76c51a3.toInt(),
        0xd192e819.toInt(), 0xd6990624.toInt(), 0xf40e3585.toInt(), 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814.toInt(), 0x8cc70208.toInt(),
        0x90befffa.toInt(), 0xa4506ceb.toInt(), 0xbef9a3f7.toInt(), 0xc67178f2.toInt(),
    )
}
