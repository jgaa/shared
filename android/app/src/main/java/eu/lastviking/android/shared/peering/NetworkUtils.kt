package eu.lastviking.android.shared.peering

import java.net.Inet4Address
import java.net.NetworkInterface

object NetworkUtils {
    fun getLocalIpAddresses(): List<String> {
        val result = mutableListOf<String>()
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()
            while (interfaces.hasMoreElements()) {
                val iface = interfaces.nextElement()
                if (iface.isLoopback || !iface.isUp) continue
                
                // Exclude container-only or virtual interfaces if they match known prefixes
                val name = iface.name.lowercase()
                if (name.startsWith("docker") || name.startsWith("veth") || name.startsWith("br-")) continue

                val addresses = iface.inetAddresses
                while (addresses.hasMoreElements()) {
                    val addr = addresses.nextElement()
                    if (addr.isLoopbackAddress || addr.isLinkLocalAddress) continue
                    
                    // We only support IPv4 for now as per most peer addresses seen in logs
                    if (addr is Inet4Address) {
                        result.add(addr.hostAddress)
                    }
                }
            }
        } catch (e: Exception) {}
        return result
    }
}
