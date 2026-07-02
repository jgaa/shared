package eu.lastviking.android.shared.peering

import android.util.Log
import eu.lastviking.android.shared.crypto.CryptoUtils
import eu.lastviking.shared.proto.SharedProto
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableSharedFlow
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.Socket
import java.util.*
import javax.net.ssl.SSLSocket

class PeerConnection(
    var peerId: String,
    val isInitiator: Boolean,
    private val socket: SSLSocket,
    private val scope: CoroutineScope,
    private val onMessageReceived: suspend (PeerConnection, SharedProto.Envelope) -> Unit,
    private val onDisconnected: (PeerConnection) -> Unit
) {
    private val inputStream = DataInputStream(socket.inputStream)
    private val outputStream = DataOutputStream(socket.outputStream)
    private var active = true

    init {
        scope.launch(Dispatchers.IO) {
            try {
                Log.i("PeerConnection", "Connection established with $peerId")
                while (active) {
                    val size = inputStream.readInt()
                    val bytes = ByteArray(size)
                    inputStream.readFully(bytes)
                    val envelope = SharedProto.Envelope.parseFrom(bytes)
                    Log.d("PeerConnection", "Received message from $peerId: ${envelope.bodyCase}")
                    onMessageReceived(this@PeerConnection, envelope)
                }
            } catch (e: Exception) {
                Log.i("PeerConnection", "Connection to $peerId closed: ${e.message}")
            } finally {
                disconnect()
            }
        }
    }

    suspend fun send(envelope: SharedProto.Envelope) = withContext(Dispatchers.IO) {
        try {
            Log.d("PeerConnection", "Sending message to $peerId: ${envelope.bodyCase}")
            val bytes = envelope.toByteArray()
            outputStream.writeInt(bytes.size)
            outputStream.write(bytes)
            outputStream.flush()
        } catch (e: Exception) {
            Log.w("PeerConnection", "Failed to send message to $peerId: ${e.message}")
            disconnect()
        }
    }

    fun disconnect() {
        if (!active) return
        active = false
        try {
            socket.close()
        } catch (e: Exception) {}
        onDisconnected(this)
    }
}
