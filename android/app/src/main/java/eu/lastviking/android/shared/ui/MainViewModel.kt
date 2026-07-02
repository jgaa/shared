package eu.lastviking.android.shared.ui

import android.app.Application
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.Uri
import android.os.IBinder
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import eu.lastviking.android.shared.data.PeeringRepository
import eu.lastviking.android.shared.peering.PeerService
import eu.lastviking.android.shared.peering.PeerStatus
import eu.lastviking.android.shared.peering.PendingOffer
import eu.lastviking.android.shared.peering.ReceivedFile
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class MainViewModel(application: Application) : AndroidViewModel(application) {
    private val repository = PeeringRepository(application)

    private val _peerStatuses = MutableStateFlow<List<PeerStatus>>(emptyList())
    val peerStatuses: StateFlow<List<PeerStatus>> = _peerStatuses.asStateFlow()

    private val _receivedFiles = MutableStateFlow<List<ReceivedFile>>(emptyList())
    val receivedFiles: StateFlow<List<ReceivedFile>> = _receivedFiles.asStateFlow()

    private val _pendingOffers = MutableStateFlow<List<PendingOffer>>(emptyList())
    val pendingOffers: StateFlow<List<PendingOffer>> = _pendingOffers.asStateFlow()

    private val _isConnectivityEnabled = MutableStateFlow(repository.isConnectivityEnabled())
    val isConnectivityEnabled: StateFlow<Boolean> = _isConnectivityEnabled.asStateFlow()

    private var peerService: PeerService? = null
    private var isBound = false

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            val binder = service as PeerService.LocalBinder
            val s = binder.getService()
            peerService = s
            isBound = true
            
            viewModelScope.launch {
                s.peerStatuses.collect { 
                    _peerStatuses.value = it 
                }
            }
            viewModelScope.launch {
                s.events.collect {
                    refreshReceivedFiles()
                }
            }
            viewModelScope.launch {
                s.pendingOffers.collect {
                    _pendingOffers.value = it
                }
            }
            s.clearIncomingNotifications()
            refreshReceivedFiles()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            peerService = null
            isBound = false
            _peerStatuses.value = emptyList()
            _pendingOffers.value = emptyList()
        }
    }

    init {
        if (repository.isPeered() && repository.isConnectivityEnabled()) {
            startPeerService()
        }
    }

    private fun startPeerService() {
        val intent = Intent(getApplication(), PeerService::class.java)
        ContextCompat.startForegroundService(getApplication(), intent)
        getApplication<Application>().bindService(intent, connection, Context.BIND_AUTO_CREATE)
    }

    private fun stopPeerService() {
        if (isBound) {
            getApplication<Application>().unbindService(connection)
            isBound = false
        }
        getApplication<Application>().stopService(Intent(getApplication(), PeerService::class.java))
        peerService = null
        _peerStatuses.value = emptyList()
        _pendingOffers.value = emptyList()
    }

    fun setConnectivityEnabled(enabled: Boolean) {
        repository.setConnectivityEnabled(enabled)
        _isConnectivityEnabled.value = enabled
        if (enabled) {
            if (repository.isPeered()) {
                startPeerService()
            }
        } else {
            stopPeerService()
        }
    }

    fun sendClipboard(peerIds: List<String>) {
        peerService?.sendClipboard(peerIds)
    }

    fun sendFiles(peerIds: List<String>, uris: List<Uri>) {
        peerService?.sendFiles(peerIds, uris)
    }

    fun deleteFile(file: ReceivedFile) {
        repository.deleteReceivedFile(file)
        refreshReceivedFiles()
    }

    fun acceptTransfer(transferId: String) {
        peerService?.acceptTransfer(transferId)
    }

    fun rejectTransfer(transferId: String) {
        peerService?.rejectTransfer(transferId)
    }

    fun isAutoAcceptClipboard(): Boolean = repository.isAutoAcceptClipboard()
    fun setAutoAcceptClipboard(value: Boolean) = repository.setAutoAcceptClipboard(value)

    fun isAutoAcceptFiles(): Boolean = repository.isAutoAcceptFiles()
    fun setAutoAcceptFiles(value: Boolean) = repository.setAutoAcceptFiles(value)

    fun isMtlsServerEnabled(): Boolean = repository.isMtlsServerEnabled()
    fun setMtlsServerEnabled(value: Boolean) {
        repository.setMtlsServerEnabled(value)
        peerService?.refreshSettings()
    }

    fun refreshReceivedFiles() {
        _receivedFiles.value = repository.getReceivedFiles()
    }

    override fun onCleared() {
        super.onCleared()
        if (isBound) {
            getApplication<Application>().unbindService(connection)
            isBound = false
        }
    }
}
