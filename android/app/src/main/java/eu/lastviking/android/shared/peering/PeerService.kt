package eu.lastviking.android.shared.peering

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.provider.OpenableColumns
import android.util.Log
import androidx.core.app.NotificationCompat
import eu.lastviking.android.shared.crypto.CryptoUtils
import eu.lastviking.android.shared.data.EnrollmentInfo
import eu.lastviking.android.shared.data.PeeringRepository
import eu.lastviking.shared.proto.SharedProto
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.io.File
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.security.KeyStore
import java.security.SecureRandom
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory

class PeerService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private lateinit var repository: PeeringRepository
    private var enrollmentInfo: EnrollmentInfo? = null
    private var sslContext: SSLContext? = null
    
    private val connections = ConcurrentHashMap<String, PeerConnection>()
    private val peerAddresses = ConcurrentHashMap<String, List<SharedProto.PeerAddress>>()
    private val lastSeen = ConcurrentHashMap<String, Long>()
    private val localIps = mutableSetOf<String>()
    private val relayReachability = ConcurrentHashMap<String, Set<String>>()

    // Stitched topology cache: link_key -> (link, expiry_ms)
    private val topologyCache = ConcurrentHashMap<String, Pair<SharedProto.TopologyLink, Long>>()

    private val activeTransfers = ConcurrentHashMap<String, TransferState>()
    private val incomingTransfers = ConcurrentHashMap<String, IncomingTransfer>()

    private val _peerStatuses = MutableStateFlow<List<PeerStatus>>(emptyList())
    val peerStatuses: StateFlow<List<PeerStatus>> = _peerStatuses.asStateFlow()

    private val _events = MutableSharedFlow<Unit>(replay = 0)
    val events: SharedFlow<Unit> = _events.asSharedFlow()

    private val _pendingOffers = MutableStateFlow<List<PendingOffer>>(emptyList())
    val pendingOffers: StateFlow<List<PendingOffer>> = _pendingOffers.asStateFlow()

    private var serverSocket: java.net.ServerSocket? = null
    
    private var receivedFilesCount = 0
    private var hasClipboardNotification = false
    private val INCOMING_NOTIFICATION_ID = 2

    inner class LocalBinder : Binder() {
        fun getService(): PeerService = this@PeerService
    }
    private val binder = LocalBinder()

    override fun onCreate() {
        super.onCreate()
        repository = PeeringRepository(this)
        enrollmentInfo = repository.getEnrollmentInfo()
        
        Log.i("PeerService", "Service onCreate. Peered: ${enrollmentInfo != null}")
        
        startForegroundService()
        
        enrollmentInfo?.let { info ->
            Log.i("PeerService", "Initializing for peer: ${info.name} (${info.peerId})")
            setupSslContext(info)
            startConnectionLoop()
            startKeepAliveLoop()
            startStatusRefreshLoop()
            startNetworkRefreshLoop()
            refreshSettings()
        }
    }

    private fun startNetworkRefreshLoop() {
        scope.launch {
            while (isActive) {
                refreshLocalAddresses()
                delay(60000) // Refresh local IPs every minute
            }
        }
    }

    private fun refreshLocalAddresses() {
        val newIps = NetworkUtils.getLocalIpAddresses()
        synchronized(localIps) {
            if (localIps == newIps.toSet()) return
            localIps.clear()
            localIps.addAll(newIps)
        }
        Log.i("PeerService", "Local addresses refreshed: $newIps")
        
        val info = enrollmentInfo ?: return
        val currentAddresses = peerAddresses[info.peerId] ?: emptyList()
        
        // Replace prior local entries
        val filtered = currentAddresses.filter { it.source != "local" }
        val newAddresses = filtered + newIps.map { ip ->
            SharedProto.PeerAddress.newBuilder()
                .setIp(ip)
                .setPort(47124) // Should we include mtls server port? if enabled. 
                // Using 47124 as it is used for inbound connections when enabled.
                .setSource("local")
                .setObservedTimeMs(System.currentTimeMillis())
                .build()
        }
        
        peerAddresses[info.peerId] = newAddresses
        
        // Gossip to all connected peers
        val hint = SharedProto.AddressHint.newBuilder()
            .setPeerId(SharedProto.PeerId.newBuilder().setUuid(info.peerId))
            .addAllAddresses(newAddresses)
            .build()
            
        val envelope = SharedProto.Envelope.newBuilder()
            .setProtocolVersion(1)
            .setMessageId(UUID.randomUUID().toString())
            .setAddressHint(hint)
            .build()
            
        scope.launch {
            connections.values.forEach { it.send(envelope) }
        }
    }

    fun refreshSettings() {
        if (repository.isMtlsServerEnabled()) {
            startMtlsServer()
        } else {
            stopMtlsServer()
        }
    }

    private fun startMtlsServer() {
        if (serverSocket != null) return
        val context = sslContext ?: return
        
        scope.launch(Dispatchers.IO) {
            try {
                val ss = context.serverSocketFactory.createServerSocket(47124) as javax.net.ssl.SSLServerSocket
                ss.needClientAuth = true
                serverSocket = ss
                Log.i("PeerService", "mTLS server listening on port 47124")
                
                while (isActive && !ss.isClosed) {
                    val socket = ss.accept() as SSLSocket
                    Log.i("PeerService", "Inbound connection from ${socket.inetAddress}")
                    
                    val pendingId = "pending-${UUID.randomUUID()}"
                    val connection = PeerConnection(pendingId, false, socket, scope, ::handleMessage, ::onDisconnected)
                    connections[pendingId] = connection
                    sendPeerInfo(connection)
                }
            } catch (e: Exception) {
                Log.e("PeerService", "mTLS server error", e)
            } finally {
                stopMtlsServer()
            }
        }
    }

    private fun stopMtlsServer() {
        try {
            serverSocket?.close()
        } catch (e: Exception) {}
        serverSocket = null
    }

    fun clearIncomingNotifications() {
        receivedFilesCount = 0
        hasClipboardNotification = false
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.cancel(INCOMING_NOTIFICATION_ID)
    }

    private fun startStatusRefreshLoop() {
        scope.launch {
            while (isActive) {
                refreshStatuses()
                delay(5000)
            }
        }
    }

    private fun refreshStatuses() {
        val info = enrollmentInfo ?: return
        val currentPeerList = repository.getEnrollmentInfo()?.peerList ?: return
        
        val reachableViaRelay = mutableSetOf<String>()
        connections.keys.forEach { relayId ->
            relayReachability[relayId]?.let { reachableViaRelay.addAll(it) }
        }

        val statuses = currentPeerList.peersList.map { peer ->
            val peerId = peer.identity.peerId.uuid
            val isConnected = connections.containsKey(peerId)
            val seen = lastSeen[peerId] ?: 0L
            
            val status = when {
                isConnected -> ConnectionStatus.CONNECTED
                reachableViaRelay.contains(peerId) -> ConnectionStatus.MAYBE_AVAILABLE
                seen > System.currentTimeMillis() - 120000 -> ConnectionStatus.MAYBE_AVAILABLE
                else -> ConnectionStatus.UNREACHABLE
            }
            
            PeerStatus(
                peerId = peerId,
                name = peer.identity.name,
                status = status,
                lastSeenMs = if (isConnected) System.currentTimeMillis() else seen
            )
        }.filter { it.peerId != info.peerId }
            .sortedWith(compareBy({ it.status.ordinal }, { it.name.lowercase() }))
        
        _peerStatuses.value = statuses
    }

    private fun startForegroundService() {
        val channelId = "peer_service"
        val channelName = "Shared Peer Service"
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(channelId, channelName, NotificationManager.IMPORTANCE_LOW)
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
            
            val incomingChannel = NotificationChannel("incoming_transfers", "Incoming Transfers", NotificationManager.IMPORTANCE_DEFAULT)
            manager.createNotificationChannel(incomingChannel)
        }

        val notification: Notification = NotificationCompat.Builder(this, channelId)
            .setContentTitle("Shared")
            .setContentText("Peer-to-peer service is active")
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(1, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
        } else {
            startForeground(1, notification)
        }
    }

    private fun updateIncomingNotification() {
        if (receivedFilesCount == 0 && !hasClipboardNotification) return

        val title = "Shared: New Items Received"
        val messages = mutableListOf<String>()
        if (hasClipboardNotification) messages.add("Clipboard updated")
        if (receivedFilesCount > 0) messages.add("$receivedFilesCount file(s) received")
        
        val contentText = messages.joinToString(", ")

        val intent = Intent(this, eu.lastviking.android.shared.MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = android.app.PendingIntent.getActivity(this, 0, intent, android.app.PendingIntent.FLAG_IMMUTABLE or android.app.PendingIntent.FLAG_UPDATE_CURRENT)

        val notification = NotificationCompat.Builder(this, "incoming_transfers")
            .setContentTitle(title)
            .setContentText(contentText)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(INCOMING_NOTIFICATION_ID, notification)
    }

    private fun setupSslContext(info: EnrollmentInfo) {
        try {
            val peerCert = CryptoUtils.loadX509Certificate(info.signedCertificate)
            val taCert = CryptoUtils.loadX509Certificate(info.caCertificate)
            val privateKey = CryptoUtils.loadPrivateKey(info.tlsPrivateKey, "EC")

            val keyStore = KeyStore.getInstance("PKCS12")
            keyStore.load(null, null)
            keyStore.setKeyEntry("peer", privateKey, null, arrayOf(peerCert))

            val trustStore = KeyStore.getInstance("PKCS12")
            trustStore.load(null, null)
            trustStore.setCertificateEntry("ta", taCert)

            val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            kmf.init(keyStore, charArrayOf())

            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(trustStore)

            val context = SSLContext.getInstance("TLS")
            context.init(kmf.keyManagers, tmf.trustManagers, SecureRandom())
            sslContext = context
        } catch (e: Exception) {
            Log.e("PeerService", "Failed to setup SSL context", e)
        }
    }

    private fun startConnectionLoop() {
        scope.launch {
            while (isActive) {
                val info = repository.getEnrollmentInfo() ?: break
                val peerList = info.peerList
                
                info.trustedAgentHost?.let { host ->
                    val taId = peerList.trustedAgentPeerId.uuid
                    if (!peerAddresses.containsKey(taId)) {
                        peerAddresses[taId] = listOf(
                            SharedProto.PeerAddress.newBuilder()
                                .setIp(host)
                                .setPort(47124)
                                .setSource("manual")
                                .build()
                        )
                    }
                }

                for (peer in peerList.peersList) {
                    val peerId = peer.identity.peerId.uuid
                    if (peerId == info.peerId) continue
                    
                    // Never open more than one active or pending connection to the same peer
                    if (!connections.containsKey(peerId)) {
                        attemptConnection(peer)
                    }
                }
                delay(30000)
            }
        }
    }

    private fun attemptConnection(peer: SharedProto.PeerListEntry) {
        val context = sslContext ?: return
        val peerId = peer.identity.peerId.uuid
        val allHints = peerAddresses[peerId] ?: emptyList()
        
        // Preference: manual, then direct, then local, then other hints
        val sortedHints = allHints.sortedWith(compareBy { addr ->
            when (addr.source) {
                "manual" -> 0
                "direct" -> 1
                "local" -> 2
                else -> 3
            }
        })

        val currentLocalIps = synchronized(localIps) { localIps.toSet() }

        scope.launch(Dispatchers.IO) {
            for (addr in sortedHints) {
                if (currentLocalIps.contains(addr.ip)) {
                    Log.d("PeerService", "Skipping self-dial attempt to ${addr.ip}")
                    continue
                }

                try {
                    val socket = context.socketFactory.createSocket() as? SSLSocket ?: continue
                    socket.connect(InetSocketAddress(addr.ip, addr.port), 5000)
                    socket.startHandshake()
                    
                    val connection = PeerConnection(peerId, true, socket, scope, ::handleMessage, ::onDisconnected)
                    connections[peerId] = connection
                    sendPeerInfo(connection)
                    break
                } catch (e: Exception) {
                    Log.w("PeerService", "Failed to connect to $peerId at ${addr.ip}:${addr.port}: ${e.message}")
                }
            }
        }
    }

    private fun startKeepAliveLoop() {
        scope.launch {
            while (isActive) {
                val keepAlive = SharedProto.Envelope.newBuilder()
                    .setProtocolVersion(1)
                    .setMessageId(UUID.randomUUID().toString())
                    .setKeepAlive(SharedProto.KeepAlive.newBuilder().setTimeMs(System.currentTimeMillis()))
                    .build()
                
                connections.values.forEach { it.send(keepAlive) }
                delay(15000)
            }
        }
    }

    private suspend fun handleMessage(connection: PeerConnection, envelope: SharedProto.Envelope) {
        when {
            envelope.hasPeerInfo() -> handlePeerInfo(connection, envelope.peerInfo)
            envelope.hasKeepAlive() -> handleKeepAlive(connection, envelope.keepAlive, envelope.messageId)
            envelope.hasPeerList() -> handlePeerList(connection, envelope.peerList)
            envelope.hasAddressHint() -> handleAddressHint(envelope.addressHint)
            envelope.hasTransferStatus() -> handleTransferStatus(connection, envelope.transferStatus)
            envelope.hasTransferOffer() -> handleTransferOffer(connection, envelope.transferOffer)
            envelope.hasTransferChunk() -> handleTransferChunk(connection, envelope.transferChunk)
            envelope.hasReachabilityAdvertisement() -> handleReachabilityAdvertisement(connection, envelope.reachabilityAdvertisement)
            envelope.hasRelayEnvelope() -> handleRelayEnvelope(connection, envelope.relayEnvelope)
            envelope.hasWhoHas() -> handleWhoHas(connection, envelope.whoHas)
            envelope.hasTopologyAdvertisement() -> handleTopologyAdvertisement(connection, envelope.topologyAdvertisement)
        }
    }

    private suspend fun handlePeerInfo(connection: PeerConnection, peerInfo: SharedProto.PeerInfo) {
        val peerId = peerInfo.identity.peerId.uuid
        val oldPeerId = connection.peerId
        if (oldPeerId != peerId) {
            connection.peerId = peerId
            connections.remove(oldPeerId)
            connections[peerId] = connection
            broadcastTopology()
        }
        lastSeen[peerId] = System.currentTimeMillis()
        peerAddresses[peerId] = peerInfo.knownAddressesList
        sendHandshakeCompletion(connection, peerInfo.peerListVersion)
    }

    private suspend fun sendHandshakeCompletion(connection: PeerConnection, remotePeerListVersion: Int) {
        val info = enrollmentInfo ?: return
        val currentPeerList = info.peerList
        
        val reachability = SharedProto.ReachabilityAdvertisement.newBuilder()
            .setAdvertiserPeerId(SharedProto.PeerId.newBuilder().setUuid(info.peerId))
            .addDirectlyReachablePeerIds(SharedProto.PeerId.newBuilder().setUuid(connection.peerId))
            .setCreatedTimeMs(System.currentTimeMillis())
            .setTtlMs(90000)
            .build()
        
        connection.send(SharedProto.Envelope.newBuilder()
            .setProtocolVersion(1)
            .setMessageId(UUID.randomUUID().toString())
            .setReachabilityAdvertisement(reachability)
            .build())
            
        if (remotePeerListVersion < currentPeerList.version) {
            connection.send(SharedProto.Envelope.newBuilder()
                .setProtocolVersion(1)
                .setMessageId(UUID.randomUUID().toString())
                .setPeerList(currentPeerList)
                .build())
        }
    }

    private suspend fun handleKeepAlive(connection: PeerConnection, keepAlive: SharedProto.KeepAlive, messageId: String) {
        lastSeen[connection.peerId] = System.currentTimeMillis()
        if (keepAlive.replyToTimeMs == 0L) {
            val reply = SharedProto.Envelope.newBuilder()
                .setProtocolVersion(1)
                .setMessageId(UUID.randomUUID().toString())
                .setKeepAlive(SharedProto.KeepAlive.newBuilder()
                    .setTimeMs(System.currentTimeMillis())
                    .setReplyToTimeMs(keepAlive.timeMs))
                .build()
            connection.send(reply)
        }
    }

    private fun handlePeerList(connection: PeerConnection, peerList: SharedProto.PeerList) {
        val current = repository.getEnrollmentInfo()?.peerList
        if (current == null || peerList.version > current.version) {
            repository.updatePeerList(peerList)
        }
    }

    private fun handleAddressHint(hint: SharedProto.AddressHint) {
        val peerId = hint.peerId.uuid
        peerAddresses[peerId] = hint.addressesList
    }

    private fun handleTopologyAdvertisement(connection: PeerConnection, ad: SharedProto.TopologyAdvertisement) {
        val now = System.currentTimeMillis()
        val expiry = now + ad.ttlMs
        
        ad.directLinksList.forEach { link ->
            val key = "${link.initiatorPeerId.uuid}->${link.acceptorPeerId.uuid}"
            topologyCache[key] = Pair(link, expiry)
        }
        Log.d("PeerService", "Received TopologyAdvertisement from ${ad.advertiserPeerId.uuid}, ${ad.directLinksCount} links")
    }

    private fun handleReachabilityAdvertisement(connection: PeerConnection, ad: SharedProto.ReachabilityAdvertisement) {
        val relayId = connection.peerId
        val reachableIds = ad.directlyReachablePeerIdsList.map { it.uuid }.toSet()
        relayReachability[relayId] = reachableIds
    }

    private suspend fun handleRelayEnvelope(connection: PeerConnection, relay: SharedProto.RelayEnvelope) {
        val destId = relay.destinationPeerId.uuid
        val info = enrollmentInfo ?: return
        
        if (destId == info.peerId) {
            // We are the final destination of this relayed message
            try {
                // Record that source is reachable via this relay connection
                val relayId = connection.peerId
                val sourceId = relay.sourcePeerId.uuid
                val current = relayReachability[relayId] ?: emptySet()
                if (!current.contains(sourceId)) {
                    relayReachability[relayId] = current + sourceId
                }

                val inner = SharedProto.Envelope.parseFrom(relay.innerEnvelope)
                Log.d("PeerService", "Processing relayed message from ${relay.sourcePeerId.uuid}: ${inner.bodyCase}")
                handleMessage(connection, inner)
            } catch (e: Exception) {
                Log.e("PeerService", "Failed to parse inner envelope from relay", e)
            }
            return
        }

        val destConn = connections[destId]
        if (destConn != null) {
            // Forward the inner envelope as-is
            destConn.send(SharedProto.Envelope.newBuilder()
                .setProtocolVersion(1)
                .setMessageId(UUID.randomUUID().toString())
                .setRelayEnvelope(relay)
                .build())
        }
    }

    private suspend fun handleWhoHas(connection: PeerConnection, query: SharedProto.WhoHas) {
        val destId = query.destinationPeerId.uuid
        val isReachable = connections.containsKey(destId)
        val info = enrollmentInfo ?: return
        val reply = SharedProto.WhoHasReply.newBuilder()
            .setDestinationPeerId(query.destinationPeerId)
            .setReachable(isReachable)
            .setRelayPeerId(SharedProto.PeerId.newBuilder().setUuid(info.peerId))
            .setRttMs(0)
            .build()
        connection.send(SharedProto.Envelope.newBuilder()
            .setProtocolVersion(1)
            .setMessageId(UUID.randomUUID().toString())
            .setWhoHasReply(reply)
            .build())
    }

    private suspend fun handleTransferStatus(connection: PeerConnection, status: SharedProto.TransferStatus) {
        val transferId = status.transferId.uuid
        val destPeerId = status.peerId.uuid
        val transfer = activeTransfers[transferId] ?: return
        
        when (status.status) {
            SharedProto.TransferStatusCode.TRANSFER_STATUS_ACCEPTED -> {
                if (transfer is TransferState.Clipboard) {
                    sendClipboardChunk(destPeerId, transfer)
                } else if (transfer is TransferState.FileTransfer) {
                    sendFileChunks(destPeerId, transfer)
                }
            }
            SharedProto.TransferStatusCode.TRANSFER_STATUS_REJECTED -> {
                activeTransfers.remove(transferId)
            }
            else -> {}
        }
    }

    private suspend fun handleTransferOffer(connection: PeerConnection, offer: SharedProto.TransferOffer) {
        val transferId = offer.transferId.uuid
        val info = enrollmentInfo ?: return
        val recipientKey = offer.recipientKeysList.find { it.peerId.uuid == info.peerId } ?: return

        try {
            val currentPeerList = repository.getEnrollmentInfo()?.peerList ?: return
            val senderEntry = currentPeerList.peersList.find { it.identity.peerId.uuid == offer.senderPeerId.uuid } ?: return

            val myX25519Priv = CryptoUtils.loadPrivateKey(info.x25519PrivateKey, "X25519")
            val sharedSecret = CryptoUtils.deriveX25519SharedSecret(myX25519Priv, senderEntry.x25519PublicKey.toByteArray())
            val wrappingKey = CryptoUtils.hkdfSha256(sharedSecret, "shared-transfer-key-wrap-v1", 32)
            
            val encryptedKeyBytes = recipientKey.encryptedKey.toByteArray()
            val payloadKey = CryptoUtils.aesGcmDecrypt(wrappingKey, encryptedKeyBytes.sliceArray(28 until encryptedKeyBytes.size), encryptedKeyBytes.sliceArray(0 until 12), encryptedKeyBytes.sliceArray(12 until 28))
            
            val isAutoAccept = if (offer.transferType == SharedProto.TransferType.TRANSFER_TYPE_CLIPBOARD_TEXT) {
                repository.isAutoAcceptClipboard()
            } else {
                repository.isAutoAcceptFiles()
            }

            if (isAutoAccept) {
                processAcceptedOffer(offer, payloadKey, senderEntry.identity.name)
            } else {
                incomingTransfers[transferId] = if (offer.transferType == SharedProto.TransferType.TRANSFER_TYPE_CLIPBOARD_TEXT) {
                    IncomingTransfer.Clipboard(offer, payloadKey, senderEntry.identity.name)
                } else {
                    val file = File(filesDir, "received_${System.currentTimeMillis()}_${offer.metadata.filename}.part")
                    IncomingTransfer.FileTransfer(offer, payloadKey, senderEntry.identity.name, file, FileOutputStream(file))
                }
                
                _pendingOffers.update { current ->
                    current + PendingOffer(transferId, offer.senderPeerId.uuid, senderEntry.identity.name, offer.transferType, offer.metadata.filename, offer.metadata.size)
                }
                sendTransferStatus(offer.senderPeerId.uuid, offer.transferId, SharedProto.TransferStatusCode.TRANSFER_STATUS_PENDING_APPROVAL)
            }
        } catch (e: Exception) {
            sendTransferStatus(offer.senderPeerId.uuid, offer.transferId, SharedProto.TransferStatusCode.TRANSFER_STATUS_REJECTED)
        }
    }

    private suspend fun processAcceptedOffer(offer: SharedProto.TransferOffer, payloadKey: ByteArray, senderName: String) {
        val transferId = offer.transferId.uuid
        if (offer.transferType == SharedProto.TransferType.TRANSFER_TYPE_CLIPBOARD_TEXT) {
            incomingTransfers[transferId] = IncomingTransfer.Clipboard(offer, payloadKey, senderName)
            sendTransferStatus(offer.senderPeerId.uuid, offer.transferId, SharedProto.TransferStatusCode.TRANSFER_STATUS_ACCEPTED)
        } else if (offer.transferType == SharedProto.TransferType.TRANSFER_TYPE_FILE) {
            val file = File(filesDir, "received_${System.currentTimeMillis()}_${offer.metadata.filename}.part")
            incomingTransfers[transferId] = IncomingTransfer.FileTransfer(offer, payloadKey, senderName, file, FileOutputStream(file))
            sendTransferStatus(offer.senderPeerId.uuid, offer.transferId, SharedProto.TransferStatusCode.TRANSFER_STATUS_ACCEPTED)
        }
    }

    fun acceptTransfer(transferId: String) {
        scope.launch {
            val transfer = incomingTransfers[transferId] ?: return@launch
            sendTransferStatus(transfer.offer.senderPeerId.uuid, transfer.offer.transferId, SharedProto.TransferStatusCode.TRANSFER_STATUS_ACCEPTED)
            _pendingOffers.update { it.filter { it.transferId != transferId } }
        }
    }

    fun rejectTransfer(transferId: String) {
        scope.launch {
            val transfer = incomingTransfers[transferId] ?: return@launch
            sendTransferStatus(transfer.offer.senderPeerId.uuid, transfer.offer.transferId, SharedProto.TransferStatusCode.TRANSFER_STATUS_REJECTED)
            incomingTransfers.remove(transferId)
            _pendingOffers.update { it.filter { it.transferId != transferId } }
        }
    }

    private suspend fun handleTransferChunk(connection: PeerConnection, chunk: SharedProto.TransferChunk) {
        val transferId = chunk.transferId.uuid
        val incoming = incomingTransfers[transferId] ?: return
        
        try {
            val plaintext = CryptoUtils.aesGcmDecrypt(incoming.payloadKey, chunk.ciphertext.toByteArray(), chunk.nonce.toByteArray(), chunk.authTag.toByteArray())
            
            when (incoming) {
                is IncomingTransfer.Clipboard -> {
                    val text = String(plaintext, Charsets.UTF_8)
                    withContext(Dispatchers.Main) {
                        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        cm.setPrimaryClip(android.content.ClipData.newPlainText("Shared", text))
                        
                        if (repository.isAutoAcceptClipboard()) {
                            hasClipboardNotification = true
                            updateIncomingNotification()
                        }
                    }
                    sendTransferStatus(incoming.offer.senderPeerId.uuid, incoming.offer.transferId, SharedProto.TransferStatusCode.TRANSFER_STATUS_COMPLETED)
                    incomingTransfers.remove(transferId)
                }
                is IncomingTransfer.FileTransfer -> {
                    incoming.outputStream.write(plaintext)
                    if (chunk.offset + plaintext.size >= incoming.offer.metadata.size) {
                        incoming.outputStream.close()
                        val digest = java.security.MessageDigest.getInstance("SHA-256")
                        incoming.partFile.inputStream().use { input ->
                            val buffer = ByteArray(8192)
                            var read: Int
                            while (input.read(buffer).also { read = it } >= 0) { digest.update(buffer, 0, read) }
                        }
                        val hash = CryptoUtils.toHex(digest.digest())
                        if (hash != incoming.offer.metadata.sha256) {
                            sendTransferStatus(incoming.offer.senderPeerId.uuid, incoming.offer.transferId, SharedProto.TransferStatusCode.TRANSFER_STATUS_ERROR)
                            incoming.partFile.delete()
                            incomingTransfers.remove(transferId)
                            return
                        }
                        val finalFile = File(filesDir, incoming.offer.metadata.filename)
                        incoming.partFile.renameTo(finalFile)
                        repository.addReceivedFile(ReceivedFile(incoming.offer.metadata.filename, incoming.offer.metadata.size, incoming.offer.metadata.mimeType, incoming.senderName, System.currentTimeMillis(), finalFile.absolutePath))
                        _events.emit(Unit)
                        
                        if (repository.isAutoAcceptFiles()) {
                            receivedFilesCount++
                            updateIncomingNotification()
                        }

                        sendTransferStatus(incoming.offer.senderPeerId.uuid, incoming.offer.transferId, SharedProto.TransferStatusCode.TRANSFER_STATUS_COMPLETED)
                        incomingTransfers.remove(transferId)
                    }
                }
            }
        } catch (e: Exception) {
            sendTransferStatus(incoming.offer.senderPeerId.uuid, incoming.offer.transferId, SharedProto.TransferStatusCode.TRANSFER_STATUS_ERROR)
        }
    }

    private suspend fun sendClipboardChunk(destPeerId: String, transfer: TransferState.Clipboard) {
        val nonce = CryptoUtils.generateRandomBytes(12)
        val (ciphertext, tag) = CryptoUtils.aesGcmEncrypt(transfer.payloadKey, transfer.content, nonce)
        val chunk = SharedProto.TransferChunk.newBuilder()
            .setTransferId(transfer.offer.transferId).setChunkIndex(0).setOffset(0)
            .setCiphertext(com.google.protobuf.ByteString.copyFrom(ciphertext))
            .setNonce(com.google.protobuf.ByteString.copyFrom(nonce))
            .setAuthTag(com.google.protobuf.ByteString.copyFrom(tag)).build()
        sendToPeer(destPeerId, SharedProto.Envelope.newBuilder().setProtocolVersion(1).setMessageId(UUID.randomUUID().toString()).setTransferChunk(chunk).build())
        activeTransfers.remove(transfer.offer.transferId.uuid)
    }

    private suspend fun sendFileChunks(destPeerId: String, transfer: TransferState.FileTransfer) {
        val info = contentResolver.openAssetFileDescriptor(transfer.uri, "r") ?: return
        val inputStream = info.createInputStream()
        var offset = 0L
        var index = 0L
        val buffer = ByteArray(4194304)
        while (true) {
            val read = inputStream.read(buffer)
            if (read <= 0) break
            val chunkData = if (read == buffer.size) buffer else buffer.sliceArray(0 until read)
            val nonce = CryptoUtils.generateRandomBytes(12)
            val (ciphertext, tag) = CryptoUtils.aesGcmEncrypt(transfer.payloadKey, chunkData, nonce)
            val chunk = SharedProto.TransferChunk.newBuilder().setTransferId(transfer.offer.transferId).setChunkIndex(index).setOffset(offset)
                .setCiphertext(com.google.protobuf.ByteString.copyFrom(ciphertext))
                .setNonce(com.google.protobuf.ByteString.copyFrom(nonce))
                .setAuthTag(com.google.protobuf.ByteString.copyFrom(tag)).build()
            sendToPeer(destPeerId, SharedProto.Envelope.newBuilder().setProtocolVersion(1).setMessageId(UUID.randomUUID().toString()).setTransferChunk(chunk).build())
            offset += read
            index++
        }
        inputStream.close()
        info.close()
        activeTransfers.remove(transfer.offer.transferId.uuid)
    }

    fun sendClipboard(targetPeerIds: List<String>) {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clipData = cm.primaryClip
        if (clipData == null || clipData.itemCount == 0) return
        val text = clipData.getItemAt(0).text?.toString() ?: return
        val content = text.toByteArray(Charsets.UTF_8)
        scope.launch {
            try {
                val transferId = UUID.randomUUID().toString()
                val payloadKey = CryptoUtils.generateRandomBytes(32)
                val info = enrollmentInfo ?: return@launch
                val offer = buildOffer(transferId, info.peerId, SharedProto.TransferType.TRANSFER_TYPE_CLIPBOARD_TEXT, "text/plain; charset=utf-8", content.size.toLong(), CryptoUtils.toHex(CryptoUtils.sha256(content)), "", targetPeerIds, payloadKey)
                activeTransfers[transferId] = TransferState.Clipboard(offer, payloadKey, content)
                val envelope = SharedProto.Envelope.newBuilder().setProtocolVersion(1).setMessageId(UUID.randomUUID().toString()).setTransferOffer(offer).build()
                targetPeerIds.forEach { sendToPeer(it, envelope) }
            } catch (e: Exception) { Log.e("PeerService", "Failed clipboard transfer", e) }
        }
    }

    fun sendFiles(targetPeerIds: List<String>, uris: List<Uri>) {
        scope.launch {
            for (uri in uris) {
                try {
                    val transferId = UUID.randomUUID().toString()
                    val payloadKey = CryptoUtils.generateRandomBytes(32)
                    val info = enrollmentInfo ?: return@launch
                    var filename = "file"
                    var size = 0L
                    contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                        val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                        val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                        cursor.moveToFirst()
                        filename = cursor.getString(nameIndex)
                        size = cursor.getLong(sizeIndex)
                    }
                    val digest = java.security.MessageDigest.getInstance("SHA-256")
                    contentResolver.openInputStream(uri)?.use { input ->
                        val buffer = ByteArray(8192)
                        var read: Int
                        while (input.read(buffer).also { read = it } >= 0) { digest.update(buffer, 0, read) }
                    }
                    val hash = CryptoUtils.toHex(digest.digest())
                    val offer = buildOffer(transferId, info.peerId, SharedProto.TransferType.TRANSFER_TYPE_FILE, contentResolver.getType(uri) ?: "application/octet-stream", size, hash, filename, targetPeerIds, payloadKey)
                    activeTransfers[transferId] = TransferState.FileTransfer(offer, payloadKey, uri)
                    val envelope = SharedProto.Envelope.newBuilder().setProtocolVersion(1).setMessageId(UUID.randomUUID().toString()).setTransferOffer(offer).build()
                    targetPeerIds.forEach { sendToPeer(it, envelope) }
                } catch (e: Exception) { Log.e("PeerService", "Failed file transfer", e) }
            }
        }
    }

    private suspend fun sendToPeer(destPeerId: String, envelope: SharedProto.Envelope) {
        val direct = connections[destPeerId]
        if (direct != null) {
            direct.send(envelope)
            return
        }
        val relayId = relayReachability.entries.find { it.value.contains(destPeerId) && connections.containsKey(it.key) }?.key
        if (relayId != null) {
            val info = enrollmentInfo ?: return
            val relayEnvelope = SharedProto.RelayEnvelope.newBuilder()
                .setSourcePeerId(SharedProto.PeerId.newBuilder().setUuid(info.peerId))
                .setDestinationPeerId(SharedProto.PeerId.newBuilder().setUuid(destPeerId))
                .setInnerEnvelope(com.google.protobuf.ByteString.copyFrom(envelope.toByteArray())).build()
            connections[relayId]?.send(SharedProto.Envelope.newBuilder().setProtocolVersion(1).setMessageId(UUID.randomUUID().toString()).setRelayEnvelope(relayEnvelope).build())
        }
    }

    private suspend fun buildOffer(transferId: String, myPeerId: String, type: SharedProto.TransferType, mime: String, size: Long, hash: String, filename: String, targets: List<String>, payloadKey: ByteArray): SharedProto.TransferOffer {
        val currentPeerList = repository.getEnrollmentInfo()?.peerList ?: throw Exception("No peer list")
        val info = enrollmentInfo ?: throw Exception("No enrollment info")
        val myX25519Priv = CryptoUtils.loadPrivateKey(info.x25519PrivateKey, "X25519")
        val builder = SharedProto.TransferOffer.newBuilder()
            .setTransferId(SharedProto.TransferId.newBuilder().setUuid(transferId)).setTransferType(type).setSenderPeerId(SharedProto.PeerId.newBuilder().setUuid(myPeerId)).setCreatedTimeMs(System.currentTimeMillis())
            .setMetadata(SharedProto.TransferMetadata.newBuilder().setMimeType(mime).setSize(size).setSha256(hash).setFilename(filename).setChunkSize(4194304).setChunkCount((size + 4194303) / 4194304))
        for (peerId in targets) {
            val peerEntry = currentPeerList.peersList.find { it.identity.peerId.uuid == peerId } ?: continue
            val sharedSecret = CryptoUtils.deriveX25519SharedSecret(myX25519Priv, peerEntry.x25519PublicKey.toByteArray())
            val wrappingKey = CryptoUtils.hkdfSha256(sharedSecret, "shared-transfer-key-wrap-v1", 32)
            val nonce = CryptoUtils.generateRandomBytes(12)
            val (ciphertext, tag) = CryptoUtils.aesGcmEncrypt(wrappingKey, payloadKey, nonce)
            builder.addRecipientPeerIds(SharedProto.PeerId.newBuilder().setUuid(peerId))
            builder.addRecipientKeys(SharedProto.RecipientKey.newBuilder().setPeerId(SharedProto.PeerId.newBuilder().setUuid(peerId)).setEncryptedKey(com.google.protobuf.ByteString.copyFrom(nonce + tag + ciphertext)).setKeyAlgorithm("x25519-hkdf-sha256"))
        }
        return builder.build()
    }

    private sealed class TransferState {
        data class Clipboard(val offer: SharedProto.TransferOffer, val payloadKey: ByteArray, val content: ByteArray) : TransferState()
        data class FileTransfer(val offer: SharedProto.TransferOffer, val payloadKey: ByteArray, val uri: Uri) : TransferState()
    }

    private sealed class IncomingTransfer(val offer: SharedProto.TransferOffer, val payloadKey: ByteArray, val senderName: String) {
        class Clipboard(offer: SharedProto.TransferOffer, payloadKey: ByteArray, senderName: String) : IncomingTransfer(offer, payloadKey, senderName)
        class FileTransfer(offer: SharedProto.TransferOffer, payloadKey: ByteArray, senderName: String, val partFile: File, val outputStream: FileOutputStream) : IncomingTransfer(offer, payloadKey, senderName)
    }

    private suspend fun sendTransferStatus(destPeerId: String, transferId: SharedProto.TransferId, status: SharedProto.TransferStatusCode) {
        val info = enrollmentInfo ?: return
        val envelope = SharedProto.Envelope.newBuilder()
            .setProtocolVersion(1)
            .setMessageId(UUID.randomUUID().toString())
            .setTransferStatus(SharedProto.TransferStatus.newBuilder()
                .setTransferId(transferId)
                .setPeerId(SharedProto.PeerId.newBuilder().setUuid(info.peerId))
                .setStatus(status))
            .build()
        sendToPeer(destPeerId, envelope)
    }

    private fun onDisconnected(connection: PeerConnection) {
        connections.remove(connection.peerId)
        broadcastTopology()
    }

    private fun broadcastTopology() {
        val info = enrollmentInfo ?: return
        val now = System.currentTimeMillis()
        
        // Cleanup expired links
        topologyCache.entries.removeIf { it.value.second < now }
        
        val localLinks = connections.values.filter { !it.peerId.startsWith("pending-") }.map { conn ->
            SharedProto.TopologyLink.newBuilder().apply {
                if (conn.isInitiator) {
                    setInitiatorPeerId(SharedProto.PeerId.newBuilder().setUuid(info.peerId))
                    setAcceptorPeerId(SharedProto.PeerId.newBuilder().setUuid(conn.peerId))
                } else {
                    setInitiatorPeerId(SharedProto.PeerId.newBuilder().setUuid(conn.peerId))
                    setAcceptorPeerId(SharedProto.PeerId.newBuilder().setUuid(info.peerId))
                }
            }.build()
        }
        
        val advertisement = SharedProto.TopologyAdvertisement.newBuilder()
            .setAdvertiserPeerId(SharedProto.PeerId.newBuilder().setUuid(info.peerId))
            .addAllDirectLinks(localLinks)
            .addAllDirectLinks(topologyCache.values.map { it.first })
            .setCreatedTimeMs(now)
            .setTtlMs(90000)
            .build()
        
        val envelope = SharedProto.Envelope.newBuilder()
            .setProtocolVersion(1)
            .setMessageId(UUID.randomUUID().toString())
            .setTopologyAdvertisement(advertisement)
            .build()

        scope.launch {
            connections.values.forEach { it.send(envelope) }
        }
    }

    private suspend fun sendPeerInfo(connection: PeerConnection) {
        val info = enrollmentInfo ?: return
        val currentPeerList = repository.getEnrollmentInfo()?.peerList ?: return
        
        val knownAddresses = peerAddresses[info.peerId] ?: emptyList()
        
        val peerInfo = SharedProto.PeerInfo.newBuilder()
            .setIdentity(SharedProto.PeerIdentity.newBuilder()
                .setPeerId(SharedProto.PeerId.newBuilder().setUuid(info.peerId))
                .setName(info.name)
                .setPlatform(SharedProto.Platform.PLATFORM_ANDROID))
            .setPeerListVersion(currentPeerList.version)
            .setConnectionId(UUID.randomUUID().toString())
            .addAllKnownAddresses(knownAddresses)
            .build()

        connection.send(SharedProto.Envelope.newBuilder()
            .setProtocolVersion(1)
            .setMessageId(UUID.randomUUID().toString())
            .setPeerInfo(peerInfo)
            .build())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        refreshStatuses()
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
        connections.values.forEach { it.disconnect() }
    }
}
