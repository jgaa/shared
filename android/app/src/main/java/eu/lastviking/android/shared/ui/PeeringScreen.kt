package eu.lastviking.android.shared.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun PeeringScreen(
    uiState: PeeringUiState,
    onEnroll: (host: String, port: Int, fingerprint: String, name: String) -> Unit
) {
    var host by remember { mutableStateOf("") }
    var port by remember { mutableStateOf("47123") }
    var fingerprint by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("android@device") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(text = "Enroll with Trusted Agent", style = MaterialTheme.typography.headlineMedium)
        Spacer(modifier = Modifier.height(16.dp))

        if (uiState is PeeringUiState.Error) {
            Text(text = uiState.message, color = MaterialTheme.colorScheme.error)
            Spacer(modifier = Modifier.height(8.dp))
        }

        TextField(
            value = host,
            onValueChange = { host = it },
            label = { Text("Trusted Agent Host/IP") },
            modifier = Modifier.fillMaxWidth(),
            enabled = uiState !is PeeringUiState.Enrolling
        )
        Spacer(modifier = Modifier.height(8.dp))
        TextField(
            value = port,
            onValueChange = { port = it },
            label = { Text("Enrollment Port") },
            modifier = Modifier.fillMaxWidth(),
            enabled = uiState !is PeeringUiState.Enrolling
        )
        Spacer(modifier = Modifier.height(8.dp))
        TextField(
            value = fingerprint,
            onValueChange = { fingerprint = it },
            label = { Text("Enrollment Fingerprint") },
            modifier = Modifier.fillMaxWidth(),
            enabled = uiState !is PeeringUiState.Enrolling
        )
        Spacer(modifier = Modifier.height(8.dp))
        TextField(
            value = name,
            onValueChange = { name = it },
            label = { Text("Identity Name (user@host)") },
            modifier = Modifier.fillMaxWidth(),
            enabled = uiState !is PeeringUiState.Enrolling
        )
        Spacer(modifier = Modifier.height(24.dp))
        
        if (uiState is PeeringUiState.Enrolling) {
            Text(
                text = "Verification Code:",
                style = MaterialTheme.typography.labelLarge
            )
            Text(
                text = formatVerificationCode(uiState.verificationCode),
                style = MaterialTheme.typography.headlineLarge,
                color = MaterialTheme.colorScheme.primary
            )
            Spacer(modifier = Modifier.height(16.dp))
            CircularProgressIndicator()
            Spacer(modifier = Modifier.height(8.dp))
            Text(text = "Waiting for approval on Trusted Agent...")
        } else {
            Button(
                onClick = {
                    val portInt = port.toIntOrNull() ?: 47123
                    onEnroll(host, portInt, fingerprint, name)
                },
                enabled = host.isNotBlank() && fingerprint.isNotBlank() && name.isNotBlank()
            ) {
                Text("Enroll")
            }
        }
    }
}

private fun formatVerificationCode(code: String): String {
    if (code.length != 8) return code
    return code.substring(0, 4) + "-" + code.substring(4)
}
