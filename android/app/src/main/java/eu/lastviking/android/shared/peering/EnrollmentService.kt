package eu.lastviking.android.shared.peering

import android.util.Log
import com.google.protobuf.ByteString
import eu.lastviking.android.shared.crypto.CryptoUtils
import eu.lastviking.android.shared.data.EnrollmentInfo
import eu.lastviking.shared.proto.SharedProto
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import java.util.UUID

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class EnrollmentService {

    suspend fun enroll(
        host: String,
        port: Int,
        userFingerprint: String,
        requestedName: String,
        onVerificationCodeGenerated: (String) -> Unit
    ): Result<EnrollmentInfo> = withContext(Dispatchers.IO) {
        try {
            val tlsKeyPair = CryptoUtils.generateP256KeyPair()
            val x25519KeyPair = CryptoUtils.generateX25519KeyPair()
            val csr = CryptoUtils.generateCsr(tlsKeyPair, requestedName)
            val verificationCode = CryptoUtils.toHex(CryptoUtils.sha256(csr)).take(8)
            
            withContext(Dispatchers.Main) {
                onVerificationCodeGenerated(verificationCode)
            }
            
            val x25519PublicBytes = x25519KeyPair.public.encoded

            // Create a TrustManager that captures the server certificate
            var serverCert: X509Certificate? = null
            val trustManager = object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                    serverCert = chain?.get(0)
                }
                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            }

            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, arrayOf<TrustManager>(trustManager), null)

            val socket = Socket()
            socket.connect(InetSocketAddress(host, port), 5000)
            val sslSocket = sslContext.socketFactory.createSocket(socket, host, port, true) as SSLSocket
            sslSocket.startHandshake()

            val cert = serverCert ?: throw Exception("No server certificate presented")
            val certFingerprint = CryptoUtils.toHex(CryptoUtils.sha256(cert.encoded))
            
            if (!certFingerprint.startsWith(userFingerprint.lowercase())) {
                 throw Exception("Fingerprint mismatch. Server: $certFingerprint")
            }

            val inputStream = DataInputStream(sslSocket.inputStream)
            val outputStream = DataOutputStream(sslSocket.outputStream)

            val uuid = CryptoUtils.generatePeerId()
            val peerId = SharedProto.PeerId.newBuilder().setUuid(uuid).build()
            val identity = SharedProto.PeerIdentity.newBuilder()
                .setPeerId(peerId)
                .setName(requestedName)
                .setPlatform(SharedProto.Platform.PLATFORM_ANDROID)
                .build()

            val request = SharedProto.EnrollmentRequest.newBuilder()
                .setRequestedIdentity(identity)
                .setCertificateRequest(ByteString.copyFrom(csr))
                .setVerificationCode(verificationCode)
                .setX25519PublicKey(ByteString.copyFrom(x25519PublicBytes.takeLast(32).toByteArray()))
                .build()

            val envelope = SharedProto.Envelope.newBuilder()
                .setProtocolVersion(1)
                .setMessageId(UUID.randomUUID().toString())
                .setEnrollmentRequest(request)
                .build()

            val serialized = envelope.toByteArray()
            outputStream.writeInt(serialized.size)
            outputStream.write(serialized)
            outputStream.flush()

            val responseSize = inputStream.readInt()
            val responseBytes = ByteArray(responseSize)
            inputStream.readFully(responseBytes)

            val responseEnvelope = SharedProto.Envelope.parseFrom(responseBytes)
            if (responseEnvelope.hasEnrollmentDecision()) {
                val decision = responseEnvelope.enrollmentDecision
                if (decision.approved) {
                    Result.success(EnrollmentInfo(
                        peerId = uuid,
                        name = requestedName,
                        tlsPrivateKey = tlsKeyPair.private.encoded,
                        x25519PrivateKey = x25519KeyPair.private.encoded,
                        signedCertificate = decision.signedCertificate.toByteArray(),
                        caCertificate = decision.trustedAgentCaCertificate.toByteArray(),
                        peerList = decision.peerList,
                        trustedAgentHost = host
                    ))
                } else {
                    Result.failure(Exception("Enrollment rejected: ${decision.message}"))
                }
            } else {
                Result.failure(Exception("Invalid response from server"))
            }
        } catch (e: Exception) {
            Log.e("EnrollmentService", "Enrollment failed", e)
            Result.failure(e)
        }
    }
}
