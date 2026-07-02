package eu.lastviking.android.shared.data

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import eu.lastviking.android.shared.peering.ReceivedFile
import eu.lastviking.shared.proto.SharedProto
import java.util.Base64

data class EnrollmentInfo(
    val peerId: String,
    val name: String,
    val tlsPrivateKey: ByteArray,
    val x25519PrivateKey: ByteArray,
    val signedCertificate: ByteArray,
    val caCertificate: ByteArray,
    val peerList: SharedProto.PeerList,
    val trustedAgentHost: String? = null
)

class PeeringRepository(context: Context) {
    private val gson = Gson()
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        "peering_prefs",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun isPeered(): Boolean = prefs.contains("signed_certificate")

    fun saveEnrollment(info: EnrollmentInfo) {
        prefs.edit().apply {
            putString("peer_id", info.peerId)
            putString("name", info.name)
            putString("tls_private_key", Base64.getEncoder().encodeToString(info.tlsPrivateKey))
            putString("x25519_private_key", Base64.getEncoder().encodeToString(info.x25519PrivateKey))
            putString("signed_certificate", Base64.getEncoder().encodeToString(info.signedCertificate))
            putString("ca_certificate", Base64.getEncoder().encodeToString(info.caCertificate))
            putString("peer_list", Base64.getEncoder().encodeToString(info.peerList.toByteArray()))
            putString("ta_host", info.trustedAgentHost)
            apply()
        }
    }

    fun getEnrollmentInfo(): EnrollmentInfo? {
        if (!isPeered()) return null
        return try {
            val peerId = prefs.getString("peer_id", null) ?: ""
            val name = prefs.getString("name", null) ?: ""
            val tlsKeyStr = prefs.getString("tls_private_key", null)
            val x25519KeyStr = prefs.getString("x25519_private_key", null)
            val certStr = prefs.getString("signed_certificate", null)
            val caStr = prefs.getString("ca_certificate", null)
            val plStr = prefs.getString("peer_list", null)
            val taHost = prefs.getString("ta_host", null)

            if (tlsKeyStr == null || x25519KeyStr == null || certStr == null || caStr == null || plStr == null) {
                android.util.Log.w("PeeringRepository", "Missing fields: tls=${tlsKeyStr!=null}, x25519=${x25519KeyStr!=null}, cert=${certStr!=null}, ca=${caStr!=null}, pl=${plStr!=null}")
                return null
            }

            val decoder = Base64.getDecoder()
            val tlsKey = decoder.decode(tlsKeyStr)
            val x25519Key = decoder.decode(x25519KeyStr)
            val cert = decoder.decode(certStr)
            val ca = decoder.decode(caStr)
            val plBytes = decoder.decode(plStr)
            val peerList = SharedProto.PeerList.parseFrom(plBytes)
            
            EnrollmentInfo(peerId, name, tlsKey, x25519Key, cert, ca, peerList, taHost)
        } catch (e: Exception) {
            android.util.Log.e("PeeringRepository", "Failed to load enrollment info", e)
            null
        }
    }
    
    fun updatePeerList(peerList: SharedProto.PeerList) {
        prefs.edit().putString("peer_list", Base64.getEncoder().encodeToString(peerList.toByteArray())).apply()
    }

    fun getReceivedFiles(): List<ReceivedFile> {
        val json = prefs.getString("received_files", null) ?: return emptyList()
        val type = object : TypeToken<List<ReceivedFile>>() {}.type
        return gson.fromJson(json, type)
    }

    fun addReceivedFile(file: ReceivedFile) {
        val files = getReceivedFiles().toMutableList()
        files.add(file)
        prefs.edit().putString("received_files", gson.toJson(files)).apply()
    }

    fun deleteReceivedFile(file: ReceivedFile) {
        val files = getReceivedFiles().toMutableList()
        if (files.removeAll { it.internalPath == file.internalPath }) {
            prefs.edit().putString("received_files", gson.toJson(files)).apply()
        }
        val diskFile = java.io.File(file.internalPath)
        if (diskFile.exists()) {
            diskFile.delete()
        }
    }

    fun isAutoAcceptClipboard(): Boolean = prefs.getBoolean("auto_accept_clipboard", false)
    fun setAutoAcceptClipboard(value: Boolean) = prefs.edit().putBoolean("auto_accept_clipboard", value).apply()

    fun isAutoAcceptFiles(): Boolean = prefs.getBoolean("auto_accept_files", false)
    fun setAutoAcceptFiles(value: Boolean) = prefs.edit().putBoolean("auto_accept_files", value).apply()

    fun isMtlsServerEnabled(): Boolean = prefs.getBoolean("mtls_server_enabled", false)
    fun setMtlsServerEnabled(value: Boolean) = prefs.edit().putBoolean("mtls_server_enabled", value).apply()

    fun isConnectivityEnabled(): Boolean = prefs.getBoolean("connectivity_enabled", true)
    fun setConnectivityEnabled(value: Boolean) = prefs.edit().putBoolean("connectivity_enabled", value).apply()
}
