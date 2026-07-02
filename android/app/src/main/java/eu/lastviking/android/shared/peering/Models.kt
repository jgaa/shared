package eu.lastviking.android.shared.peering

import eu.lastviking.shared.proto.SharedProto

enum class ConnectionStatus {
    CONNECTED,
    MAYBE_AVAILABLE,
    UNREACHABLE
}

data class PeerStatus(
    val peerId: String,
    val name: String,
    val status: ConnectionStatus,
    val lastSeenMs: Long
)

data class ReceivedFile(
    val filename: String,
    val size: Long,
    val mimeType: String,
    val senderName: String,
    val timestampMs: Long,
    val internalPath: String
)

data class PendingOffer(
    val transferId: String,
    val senderId: String,
    val senderName: String,
    val type: SharedProto.TransferType,
    val filename: String,
    val size: Long
)
