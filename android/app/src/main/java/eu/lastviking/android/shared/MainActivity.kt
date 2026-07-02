package eu.lastviking.android.shared

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import eu.lastviking.android.shared.ui.PeerListScreen
import eu.lastviking.android.shared.ui.MainViewModel
import eu.lastviking.android.shared.ui.PeeringScreen
import eu.lastviking.android.shared.ui.PeeringUiState
import eu.lastviking.android.shared.ui.PeeringViewModel
import eu.lastviking.android.shared.ui.theme.SharedTheme

import android.content.Intent
import android.util.Log
import androidx.core.content.ContextCompat
import eu.lastviking.android.shared.data.PeeringRepository
import eu.lastviking.android.shared.peering.PeerService

import android.net.Uri
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

import android.content.ContentValues
import android.os.Environment
import android.provider.MediaStore
import androidx.core.content.FileProvider
import eu.lastviking.android.shared.peering.ReceivedFile
import java.io.File

class MainActivity : ComponentActivity() {
    private val peeringViewModel: PeeringViewModel by viewModels()
    private val mainViewModel: MainViewModel by viewModels()
    
    private var pendingSharedFiles by mutableStateOf<List<Uri>>(emptyList())

    private fun shareFile(receivedFile: ReceivedFile) {
        try {
            val file = File(receivedFile.internalPath)
            if (!file.exists()) {
                Log.e("MainActivity", "File does not exist: ${receivedFile.internalPath}")
                return
            }
            Log.i("MainActivity", "Sharing file: ${file.absolutePath}, size: ${file.length()}")
            val uri = FileProvider.getUriForFile(this, "eu.lastviking.android.shared.fileprovider", file)
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = receivedFile.mimeType
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(Intent.createChooser(intent, "Share File"))
        } catch (e: Exception) {
            Log.e("MainActivity", "Failed to share file", e)
        }
    }

    private fun saveFileToDownloads(receivedFile: ReceivedFile) {
        val file = File(receivedFile.internalPath)
        val resolver = contentResolver
        val contentValues = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, receivedFile.filename)
            put(MediaStore.MediaColumns.MIME_TYPE, receivedFile.mimeType)
            put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
        }
        val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
        if (uri != null) {
            resolver.openOutputStream(uri)?.use { output ->
                file.inputStream().use { input ->
                    input.copyTo(output)
                }
            }
            Log.i("MainActivity", "File saved to Downloads: ${receivedFile.filename}")
        }
    }

    private fun installApk(receivedFile: ReceivedFile) {
        try {
            val file = File(receivedFile.internalPath)
            if (!file.exists()) return
            
            val uri = FileProvider.getUriForFile(this, "eu.lastviking.android.shared.fileprovider", file)
            val intent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, "application/vnd.android.package-archive")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startActivity(intent)
        } catch (e: Exception) {
            Log.e("MainActivity", "Failed to install APK", e)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent) {
        when (intent.action) {
            Intent.ACTION_SEND -> {
                (intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM) ?: intent.getParcelableExtra<Uri>("android.intent.extra.STREAM"))?.let { uri ->
                    pendingSharedFiles = listOf(uri)
                }
            }
            Intent.ACTION_SEND_MULTIPLE -> {
                intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM)?.let { uris ->
                    pendingSharedFiles = uris
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        Log.i("MainActivity", "--- APP STARTING ---")
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        
        handleIntent(intent)
        
        Log.i("MainActivity", "onCreate: Checking peering status")
        // PeerService initialization is now handled by MainViewModel init and setConnectivityEnabled

        setContent {
            SharedTheme {
                val uiState = peeringViewModel.uiState
                if (uiState !is PeeringUiState.Success) {
                    PeeringScreen(
                        uiState = uiState,
                        onEnroll = { host, port, fingerprint, name ->
                            peeringViewModel.enroll(host, port, fingerprint, name) {
                                Log.i("MainActivity", "Enrollment successful callback, enabling connectivity")
                                mainViewModel.setConnectivityEnabled(true)
                            }
                        }
                    )
                } else {
                    val peerStatuses by mainViewModel.peerStatuses.collectAsState()
                    val receivedFiles by mainViewModel.receivedFiles.collectAsState()
                    val pendingOffers by mainViewModel.pendingOffers.collectAsState()
                    val isConnectivityEnabled by mainViewModel.isConnectivityEnabled.collectAsState()

                    PeerListScreen(
                        peers = peerStatuses,
                        receivedFiles = receivedFiles,
                        pendingUris = pendingSharedFiles,
                        onSendClipboardToAll = {
                            val targetPeerIds = peerStatuses
                                .filter { it.status == eu.lastviking.android.shared.peering.ConnectionStatus.CONNECTED || it.status == eu.lastviking.android.shared.peering.ConnectionStatus.MAYBE_AVAILABLE }
                                .map { it.peerId }
                            mainViewModel.sendClipboard(targetPeerIds)
                        },
                        onSendClipboardToPeer = { peerId ->
                            mainViewModel.sendClipboard(listOf(peerId))
                        },
                        onSendFiles = { peerIds, uris ->
                            mainViewModel.sendFiles(peerIds, uris)
                        },
                        onDismissPendingUris = {
                            pendingSharedFiles = emptyList()
                        },
                        onShareFile = { file ->
                            shareFile(file)
                        },
                        onSaveToDownloads = { file ->
                            saveFileToDownloads(file)
                        },
                        onDeleteFile = { file ->
                            mainViewModel.deleteFile(file)
                        },
                        onInstallApk = { file ->
                            installApk(file)
                        },
                        pendingOffers = pendingOffers,
                        onAcceptTransfer = { mainViewModel.acceptTransfer(it) },
                        onRejectTransfer = { mainViewModel.rejectTransfer(it) },
                        isAutoAcceptClipboard = mainViewModel.isAutoAcceptClipboard(),
                        isAutoAcceptFiles = mainViewModel.isAutoAcceptFiles(),
                        isMtlsServerEnabled = mainViewModel.isMtlsServerEnabled(),
                        isConnectivityEnabled = isConnectivityEnabled,
                        onSettingsChanged = { autoClipboard, autoFiles, mtlsServer, connectivity ->
                            mainViewModel.setAutoAcceptClipboard(autoClipboard)
                            mainViewModel.setAutoAcceptFiles(autoFiles)
                            mainViewModel.setMtlsServerEnabled(mtlsServer)
                            mainViewModel.setConnectivityEnabled(connectivity)
                        }
                    )
                }
            }
        }
    }
}

@Composable
fun MainContent() {
    Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
        Greeting(
            name = "Android",
            modifier = Modifier.padding(innerPadding)
        )
    }
}

@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
    Text(
        text = "Hello $name!",
        modifier = modifier
    )
}
