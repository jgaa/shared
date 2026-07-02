package eu.lastviking.android.shared.ui

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import eu.lastviking.android.shared.data.PeeringRepository
import eu.lastviking.android.shared.peering.EnrollmentService
import kotlinx.coroutines.launch

sealed class PeeringUiState {
    object Idle : PeeringUiState()
    data class Enrolling(val verificationCode: String) : PeeringUiState()
    data class Success(val message: String) : PeeringUiState()
    data class Error(val message: String) : PeeringUiState()
}

class PeeringViewModel(application: Application) : AndroidViewModel(application) {
    private val enrollmentService = EnrollmentService()
    private val repository = PeeringRepository(application)
    
    var uiState by mutableStateOf<PeeringUiState>(
        if (repository.getEnrollmentInfo() != null) PeeringUiState.Success("Already enrolled")
        else PeeringUiState.Idle
    )
        private set

    fun enroll(host: String, port: Int, fingerprint: String, name: String, onFinished: () -> Unit) {
        viewModelScope.launch {
            uiState = PeeringUiState.Idle // Reset to Idle so we can set Enrolling with code
            val cleanFingerprint = fingerprint.replace("-", "").trim()
            val result = enrollmentService.enroll(host, port, cleanFingerprint, name) { code ->
                uiState = PeeringUiState.Enrolling(code)
            }
            result.onSuccess { info ->
                repository.saveEnrollment(info)
                uiState = PeeringUiState.Success("Enrolled successfully!")
                onFinished()
            }.onFailure {
                uiState = PeeringUiState.Error(it.message ?: "Unknown error")
            }
        }
    }
}
