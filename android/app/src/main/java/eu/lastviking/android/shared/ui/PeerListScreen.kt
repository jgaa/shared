package eu.lastviking.android.shared.ui

import android.net.Uri
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import eu.lastviking.android.shared.R
import eu.lastviking.android.shared.peering.ConnectionStatus
import eu.lastviking.android.shared.peering.PeerStatus
import eu.lastviking.android.shared.peering.ReceivedFile
import eu.lastviking.android.shared.peering.PendingOffer
import eu.lastviking.shared.proto.SharedProto
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PeerListScreen(
    peers: List<PeerStatus>,
    receivedFiles: List<ReceivedFile>,
    pendingUris: List<Uri>,
    onSendClipboardToAll: () -> Unit,
    onSendClipboardToPeer: (String) -> Unit,
    onSendFiles: (List<String>, List<Uri>) -> Unit,
    onDismissPendingUris: () -> Unit,
    onShareFile: (ReceivedFile) -> Unit,
    onSaveToDownloads: (ReceivedFile) -> Unit,
    onDeleteFile: (ReceivedFile) -> Unit,
    onInstallApk: (ReceivedFile) -> Unit,
    pendingOffers: List<PendingOffer>,
    onAcceptTransfer: (String) -> Unit,
    onRejectTransfer: (String) -> Unit,
    isAutoAcceptClipboard: Boolean,
    isAutoAcceptFiles: Boolean,
    isMtlsServerEnabled: Boolean,
    isConnectivityEnabled: Boolean,
    onSettingsChanged: (Boolean, Boolean, Boolean, Boolean) -> Unit
) {
    var selectedTab by remember { mutableStateOf(0) }
    var showMenu by remember { mutableStateOf(false) }
    var showPeerSelectionForClipboard by remember { mutableStateOf(false) }
    var showSettings by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            painter = painterResource(id = R.drawable.ic_shared_logo),
                            contentDescription = null,
                            modifier = Modifier.size(32.dp),
                            tint = Color.Unspecified
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Shared")
                    }
                },
                actions = {
                    Text("Online", style = MaterialTheme.typography.labelSmall)
                    Switch(
                        checked = isConnectivityEnabled,
                        onCheckedChange = { 
                            onSettingsChanged(isAutoAcceptClipboard, isAutoAcceptFiles, isMtlsServerEnabled, it) 
                        },
                        modifier = Modifier.padding(horizontal = 8.dp).scale(0.8f)
                    )
                    IconButton(onClick = { showMenu = true }) {
                        Icon(Icons.Default.MoreVert, contentDescription = "Menu")
                    }
                    DropdownMenu(
                        expanded = showMenu,
                        onDismissRequest = { showMenu = false }
                    ) {
                        DropdownMenuItem(
                            text = { Text("Copy Clipboard to peer") },
                            onClick = {
                                showMenu = false
                                showPeerSelectionForClipboard = true
                            }
                        )
                        DropdownMenuItem(
                            text = { Text("Copy Clipboard to all") },
                            onClick = {
                                showMenu = false
                                onSendClipboardToAll()
                            }
                        )
                        DropdownMenuItem(
                            text = { Text("Settings") },
                            onClick = {
                                showMenu = false
                                showSettings = true
                            }
                        )
                    }
                }
            )
        },
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    icon = { Icon(Icons.Default.Devices, contentDescription = null) },
                    label = { Text("Peers") }
                )
                NavigationBarItem(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    icon = { Icon(Icons.Default.Folder, contentDescription = null) },
                    label = { Text("Files") }
                )
            }
        }
    ) { innerPadding ->
        Column(modifier = Modifier.fillMaxSize().padding(innerPadding)) {
            if (selectedTab == 0) {
                PeerTab(peers)
            } else {
                FilesTab(receivedFiles, onShareFile, onSaveToDownloads, onDeleteFile, onInstallApk)
            }
        }
    }

    if (showPeerSelectionForClipboard) {
        PeerSelectionDialog(
            peers = peers.filter { it.status == ConnectionStatus.CONNECTED || it.status == ConnectionStatus.MAYBE_AVAILABLE },
            title = "Send Clipboard",
            onDismiss = { showPeerSelectionForClipboard = false },
            onSend = { selectedIds ->
                showPeerSelectionForClipboard = false
                onSendClipboardToPeer(selectedIds.first())
            }
        )
    }

    if (pendingUris.isNotEmpty()) {
        PeerSelectionDialog(
            peers = peers.filter { it.status == ConnectionStatus.CONNECTED || it.status == ConnectionStatus.MAYBE_AVAILABLE },
            title = "Send ${pendingUris.size} File(s)",
            multiSelect = true,
            onDismiss = onDismissPendingUris,
            onSend = { selectedIds ->
                onSendFiles(selectedIds, pendingUris)
                onDismissPendingUris()
            }
        )
    }

    if (showSettings) {
        SettingsDialog(
            isAutoAcceptClipboard = isAutoAcceptClipboard,
            isAutoAcceptFiles = isAutoAcceptFiles,
            isMtlsServerEnabled = isMtlsServerEnabled,
            isConnectivityEnabled = isConnectivityEnabled,
            onDismiss = { showSettings = false },
            onSave = onSettingsChanged
        )
    }

    pendingOffers.forEach { offer ->
        val typeStr = if (offer.type == SharedProto.TransferType.TRANSFER_TYPE_CLIPBOARD_TEXT) "Clipboard" else "File"
        val detail = if (offer.type == SharedProto.TransferType.TRANSFER_TYPE_FILE) ": ${offer.filename} (${offer.size} bytes)" else ""
        
        AlertDialog(
            onDismissRequest = { /* Force action */ },
            title = { Text("Incoming $typeStr") },
            text = { Text("Accept $typeStr from ${offer.senderName}$detail?") },
            confirmButton = {
                Button(onClick = { onAcceptTransfer(offer.transferId) }) { Text("Accept") }
            },
            dismissButton = {
                TextButton(onClick = { onRejectTransfer(offer.transferId) }) { Text("Reject") }
            }
        )
    }
}

@Composable
fun SettingsDialog(
    isAutoAcceptClipboard: Boolean,
    isAutoAcceptFiles: Boolean,
    isMtlsServerEnabled: Boolean,
    isConnectivityEnabled: Boolean,
    onDismiss: () -> Unit,
    onSave: (Boolean, Boolean, Boolean, Boolean) -> Unit
) {
    var autoClipboard by remember { mutableStateOf(isAutoAcceptClipboard) }
    var autoFiles by remember { mutableStateOf(isAutoAcceptFiles) }
    var mtlsServer by remember { mutableStateOf(isMtlsServerEnabled) }
    var connectivity by remember { mutableStateOf(isConnectivityEnabled) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Settings") },
        text = {
            Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = autoClipboard, onCheckedChange = { autoClipboard = it })
                    Text("Auto-accept clipboard")
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = autoFiles, onCheckedChange = { autoFiles = it })
                    Text("Auto-accept files")
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = mtlsServer, onCheckedChange = { mtlsServer = it })
                    Text("Enable mTLS server")
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = connectivity, onCheckedChange = { connectivity = it })
                    Text("Enable Connectivity (Background)")
                }
            }
        },
        confirmButton = {
            Button(onClick = { 
                onSave(autoClipboard, autoFiles, mtlsServer, connectivity)
                onDismiss()
            }) {
                Text("Save")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

@Composable
fun PeerTab(peers: List<PeerStatus>) {
    LazyColumn(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        item {
            Text(text = "Peers", style = MaterialTheme.typography.headlineMedium)
            Spacer(modifier = Modifier.height(16.dp))
        }
        if (peers.isEmpty()) {
            item {
                Box(modifier = Modifier.fillMaxWidth().height(200.dp), contentAlignment = Alignment.Center) {
                    Text(text = "No other peers found.")
                }
            }
        } else {
            items(peers) { peer ->
                PeerItem(peer)
                HorizontalDivider()
            }
        }
    }
}

@Composable
fun FilesTab(
    files: List<ReceivedFile>,
    onShare: (ReceivedFile) -> Unit,
    onSave: (ReceivedFile) -> Unit,
    onDelete: (ReceivedFile) -> Unit,
    onInstall: (ReceivedFile) -> Unit
) {
    LazyColumn(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        item {
            Text(text = "Received Files", style = MaterialTheme.typography.headlineMedium)
            Spacer(modifier = Modifier.height(16.dp))
        }
        if (files.isEmpty()) {
            item {
                Box(modifier = Modifier.fillMaxWidth().height(200.dp), contentAlignment = Alignment.Center) {
                    Text(text = "No files received yet.")
                }
            }
        } else {
            items(files.reversed()) { file ->
                ReceivedFileItem(file, onShare, onSave, onDelete, onInstall)
                HorizontalDivider()
            }
        }
    }
}

@Composable
fun ReceivedFileItem(
    file: ReceivedFile,
    onShare: (ReceivedFile) -> Unit,
    onSave: (ReceivedFile) -> Unit,
    onDelete: (ReceivedFile) -> Unit,
    onInstall: (ReceivedFile) -> Unit
) {
    val sdf = SimpleDateFormat("MMM dd, HH:mm", Locale.getDefault())
    val dateStr = sdf.format(Date(file.timestampMs))
    val isApk = file.filename.lowercase().endsWith(".apk")

    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Description, contentDescription = null, modifier = Modifier.size(24.dp))
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(text = file.filename, style = MaterialTheme.typography.titleMedium)
                Text(text = "From: ${file.senderName} • $dateStr", style = MaterialTheme.typography.bodySmall)
            }
            IconButton(onClick = { onDelete(file) }) {
                Icon(Icons.Default.Delete, contentDescription = "Delete", tint = MaterialTheme.colorScheme.error)
            }
        }
        Row(horizontalArrangement = Arrangement.End, modifier = Modifier.fillMaxWidth()) {
            if (isApk) {
                TextButton(onClick = { onInstall(file) }) { Text("Install") }
            }
            TextButton(onClick = { onSave(file) }) { Text("Save to Downloads") }
            TextButton(onClick = { onShare(file) }) { Text("Share") }
        }
    }
}

@Composable
fun PeerItem(peer: PeerStatus) {
    val statusColor = when (peer.status) {
        ConnectionStatus.CONNECTED -> Color(0xFF2E9D50)
        ConnectionStatus.MAYBE_AVAILABLE -> Color(0xFFD6B11F)
        ConnectionStatus.UNREACHABLE -> Color(0xFFB23A2E)
    }

    val lastSeenStr = if (peer.lastSeenMs == 0L) {
        "Never"
    } else {
        val sdf = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
        sdf.format(Date(peer.lastSeenMs))
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = Icons.Default.Circle,
            contentDescription = null,
            tint = statusColor,
            modifier = Modifier.size(16.dp)
        )
        Spacer(modifier = Modifier.width(16.dp))
        Column {
            Text(text = peer.name, style = MaterialTheme.typography.titleMedium)
            Text(
                text = "Last seen: $lastSeenStr",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
fun PeerSelectionDialog(
    peers: List<PeerStatus>,
    title: String,
    multiSelect: Boolean = false,
    onDismiss: () -> Unit,
    onSend: (List<String>) -> Unit
) {
    val selectedPeerIds = remember { mutableStateListOf<String>() }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column {
                if (multiSelect) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Checkbox(
                            checked = selectedPeerIds.size == peers.size && peers.isNotEmpty(),
                            onCheckedChange = { checked ->
                                if (checked) {
                                    selectedPeerIds.clear()
                                    selectedPeerIds.addAll(peers.map { it.peerId })
                                } else {
                                    selectedPeerIds.clear()
                                }
                            }
                        )
                        Text(text = "Select All", modifier = Modifier.padding(start = 8.dp))
                    }
                    HorizontalDivider()
                }
                
                if (peers.isEmpty()) {
                    Text("No peers currently connected.")
                } else {
                    LazyColumn(modifier = Modifier.heightIn(max = 300.dp)) {
                        items(peers) { peer ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                if (multiSelect) {
                                    Checkbox(
                                        checked = selectedPeerIds.contains(peer.peerId),
                                        onCheckedChange = { checked ->
                                            if (checked) selectedPeerIds.add(peer.peerId)
                                            else selectedPeerIds.remove(peer.peerId)
                                        }
                                    )
                                } else {
                                    RadioButton(
                                        selected = selectedPeerIds.contains(peer.peerId),
                                        onClick = {
                                            selectedPeerIds.clear()
                                            selectedPeerIds.add(peer.peerId)
                                        }
                                    )
                                }
                                Text(
                                    text = peer.name,
                                    modifier = Modifier.padding(start = 8.dp)
                                )
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = { onSend(selectedPeerIds.toList()) },
                enabled = selectedPeerIds.isNotEmpty()
            ) {
                Text("Send")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}
