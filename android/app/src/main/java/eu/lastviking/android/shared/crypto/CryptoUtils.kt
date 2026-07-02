package eu.lastviking.android.shared.crypto

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Security
import java.security.spec.ECGenParameterSpec
import java.util.UUID

import java.security.KeyFactory
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec

import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.digests.SHA256Digest
import javax.crypto.KeyAgreement
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom

object CryptoUtils {
    private val bcProvider = BouncyCastleProvider()
    private val secureRandom = SecureRandom()

    init {
        Security.removeProvider("BC")
        Security.addProvider(bcProvider)
    }

    fun generateRandomBytes(size: Int): ByteArray {
        val bytes = ByteArray(size)
        secureRandom.nextBytes(bytes)
        return bytes
    }

    fun deriveX25519SharedSecret(privateKey: java.security.PrivateKey, publicKeyBytes: ByteArray): ByteArray {
        val agreement = KeyAgreement.getInstance("X25519", bcProvider)
        agreement.init(privateKey)
        
        val kf = KeyFactory.getInstance("X25519", bcProvider)
        // Note: publicKeyBytes is the raw 32 bytes public key. 
        // BC expects X509EncodedKeySpec for X509 formatted keys, but let's see how we extract it.
        // Actually, for X25519 raw bytes we might need a custom spec or use BC's internal types if raw isn't supported via standard JCA easily.
        // PROTOCOL.md: "x25519_public_key" is raw 32-byte.
        
        // Convert raw 32 bytes to X509EncodedKeySpec for X25519
        // 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00 is the X509 header for X25519
        val header = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00)
        val x509Bytes = header + publicKeyBytes
        val pubKey = kf.generatePublic(java.security.spec.X509EncodedKeySpec(x509Bytes))
        
        agreement.doPhase(pubKey, true)
        return agreement.generateSecret()
    }

    fun hkdfSha256(secret: ByteArray, info: String, length: Int): ByteArray {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(secret, null, info.toByteArray()))
        val okm = ByteArray(length)
        hkdf.generateBytes(okm, 0, length)
        return okm
    }

    fun aesGcmEncrypt(key: ByteArray, plaintext: ByteArray, nonce: ByteArray): Pair<ByteArray, ByteArray> {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), spec)
        val result = cipher.doFinal(plaintext)
        val ciphertext = result.sliceArray(0 until result.size - 16)
        val tag = result.sliceArray(result.size - 16 until result.size)
        return Pair(ciphertext, tag)
    }

    fun aesGcmDecrypt(key: ByteArray, ciphertext: ByteArray, nonce: ByteArray, tag: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), spec)
        return cipher.doFinal(ciphertext + tag)
    }

    fun loadX509Certificate(data: ByteArray): X509Certificate {
        val cf = CertificateFactory.getInstance("X.509")
        return cf.generateCertificate(data.inputStream()) as X509Certificate
    }

    fun loadPrivateKey(data: ByteArray, algorithm: String): java.security.PrivateKey {
        if (data.isEmpty()) throw java.security.spec.InvalidKeySpecException("Private key data is empty")
        val spec = PKCS8EncodedKeySpec(data)
        
        // On Android, "EC" usually works with the default provider (Conscrypt).
        // If it fails or we specifically need BC (e.g. for X25519/XDH on older versions), we try BC.
        val providers = mutableListOf<java.security.Provider?>()
        providers.add(null) // Default provider
        providers.add(bcProvider)
        
        val algorithms = if (algorithm == "EC") listOf("EC", "ECDSA") else listOf(algorithm)
        
        var lastError: Exception? = null
        for (provider in providers) {
            for (algo in algorithms) {
                try {
                    val kf = if (provider != null) KeyFactory.getInstance(algo, provider) else KeyFactory.getInstance(algo)
                    return kf.generatePrivate(spec)
                } catch (e: Exception) {
                    lastError = e
                }
            }
        }
        throw lastError ?: java.security.spec.InvalidKeySpecException("Failed to load $algorithm private key")
    }

    fun generateP256KeyPair(): KeyPair {
        // Try system provider first (Conscrypt), then fall back to BC
        return try {
            val kpg = KeyPairGenerator.getInstance("EC")
            kpg.initialize(ECGenParameterSpec("secp256r1"))
            kpg.generateKeyPair()
        } catch (e: Exception) {
            val kpg = KeyPairGenerator.getInstance("EC", bcProvider)
            kpg.initialize(ECGenParameterSpec("secp256r1"))
            kpg.generateKeyPair()
        }
    }

    fun generateX25519KeyPair(): KeyPair {
        // Try "X25519" (modern), then "XDH" (BC/older), then try without provider
        return try {
            KeyPairGenerator.getInstance("X25519", bcProvider)
        } catch (e: Exception) {
            try {
                KeyPairGenerator.getInstance("XDH", bcProvider)
            } catch (e2: Exception) {
                KeyPairGenerator.getInstance("X25519")
            }
        } .generateKeyPair()
    }

    fun generateCsr(keyPair: KeyPair, commonName: String): ByteArray {
        val signer = JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider(bcProvider)
            .build(keyPair.private)
        val builder = JcaPKCS10CertificationRequestBuilder(
            X500Name("CN=$commonName"),
            keyPair.public
        )
        return builder.build(signer).encoded
    }

    fun sha256(data: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(data)
    }

    fun toHex(data: ByteArray): String {
        return data.joinToString("") { "%02x".format(it) }
    }

    fun generatePeerId(): String {
        val now = System.currentTimeMillis()
        val random = java.security.SecureRandom()

        // 48 bits of timestamp
        var msb = (now and 0xFFFFFFFFFFFFL) shl 16
        // 4 bits of version (7)
        msb = msb or (0x7L shl 12)
        // 12 bits of randomness
        msb = msb or (random.nextLong() and 0x0FFFL)

        // 2 bits of variant (2)
        var lsb = (0x2L shl 62)
        // 62 bits of randomness
        lsb = lsb or (random.nextLong() and 0x3FFFFFFFFFFFFFFFL)

        return UUID(msb, lsb).toString().lowercase()
    }
}
