package com.tunnel.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import gomobile.TunnelEngine

/**
 * TunnelVpnService runs as a foreground service and owns the VPN lifecycle.
 *
 * Started via Intent from MainActivity with action ACTION_CONNECT.
 * Stopped via Intent with action ACTION_DISCONNECT or when the user
 * removes the persistent notification.
 */
class TunnelVpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT    = "com.tunnel.client.CONNECT"
        const val ACTION_DISCONNECT = "com.tunnel.client.DISCONNECT"

        const val EXTRA_HOSTNAME       = "hostname"
        const val EXTRA_PORT           = "port"
        const val EXTRA_TUN_ADDR       = "tun_addr"
        const val EXTRA_CERT_PEM       = "cert_pem"
        const val EXTRA_KEY_PEM        = "key_pem"
        const val EXTRA_CA_PEM         = "ca_pem"
        const val EXTRA_SERVER_NAME    = "server_name"

        private const val NOTIF_CHANNEL = "tunnel_vpn"
        private const val NOTIF_ID      = 1
        private const val TAG           = "TunnelVpnService"
    }

    private val engine = TunnelEngine()
    private var tunPfd: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_CONNECT -> {
                val hostname   = intent.getStringExtra(EXTRA_HOSTNAME)   ?: return START_NOT_STICKY
                val port       = intent.getIntExtra(EXTRA_PORT, 443)
                val tunAddr    = intent.getStringExtra(EXTRA_TUN_ADDR)   ?: "10.66.0.2/24"
                val certPem    = intent.getStringExtra(EXTRA_CERT_PEM)   ?: return START_NOT_STICKY
                val keyPem     = intent.getStringExtra(EXTRA_KEY_PEM)    ?: return START_NOT_STICKY
                val caPem      = intent.getStringExtra(EXTRA_CA_PEM)     ?: return START_NOT_STICKY
                val serverName = intent.getStringExtra(EXTRA_SERVER_NAME) ?: hostname

                startForeground(NOTIF_ID, buildNotification("Connecting to $serverName…"))
                connect(hostname, port, tunAddr, certPem, keyPem, caPem, serverName)
                START_STICKY
            }
            ACTION_DISCONNECT -> {
                disconnect()
                stopSelf()
                START_NOT_STICKY
            }
            else -> START_NOT_STICKY
        }
    }

    private fun connect(
        hostname: String, port: Int, tunAddr: String,
        certPem: String, keyPem: String, caPem: String, serverName: String
    ) {
        // Parse the tun address "10.66.0.2/24" into addr + prefix length.
        val parts  = tunAddr.split("/")
        val addr   = parts[0]
        val prefix = parts.getOrNull(1)?.toIntOrNull() ?: 24

        // Build the VPN interface.
        val builder = Builder()
            .setSession("PersonalTunnel")
            .addAddress(addr, prefix)
            .addRoute("0.0.0.0", 0)          // Route all IPv4 traffic through the tunnel
            .addDnsServer("1.1.1.1")
            .setMtu(1350)
            .allowBypass()                    // allowBypass(false) would give a kill switch; we leave it on for now

        val pfd = builder.establish() ?: run {
            Log.e(TAG, "VpnService.establish() returned null — permission not granted?")
            return
        }
        tunPfd = pfd

        // Protect the QUIC/TCP socket so it doesn't loop back into the VPN.
        // The engine must call protect() before dialing — we do it via the
        // VpnService.protect(fd) callback mechanism. The Go engine passes the
        // raw socket fd through ProtectSocketFd below before connecting.
        ProtectSocketHelper.service = this

        // Start the Go engine relay on a background thread.
        Thread {
            try {
                val err = engine.connect(
                    pfd.fd,
                    certPem, keyPem, caPem,
                    hostname, port.toLong()
                )
                if (err != null) {
                    Log.e(TAG, "Engine connect error: $err")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Engine exception: ${e.message}")
            } finally {
                updateNotification("Disconnected")
            }
        }.start()

        updateNotification("Connected to $serverName")
    }

    private fun disconnect() {
        engine.disconnect()
        tunPfd?.close()
        tunPfd = null
        stopForeground(true)
    }

    override fun onDestroy() {
        disconnect()
        super.onDestroy()
    }

    // --- Notification helpers ---

    private fun buildNotification(text: String): Notification {
        createNotifChannel()
        val disconnectIntent = PendingIntent.getService(
            this, 0,
            Intent(this, TunnelVpnService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, NOTIF_CHANNEL)
            .setContentTitle("Personal Tunnel")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setOngoing(true)
            .addAction(android.R.drawable.ic_delete, "Disconnect", disconnectIntent)
            .build()
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIF_ID, buildNotification(text))
    }

    private fun createNotifChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIF_CHANNEL, "VPN Status", NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }
}

/**
 * Singleton helper so the Go engine can call VpnService.protect() on its
 * raw socket fd before dialing, preventing a routing loop.
 */
object ProtectSocketHelper {
    var service: VpnService? = null

    /** Called from Go via gomobile before the QUIC/TCP socket is connected. */
    @JvmStatic
    fun protectFd(fd: Int): Boolean = service?.protect(fd) ?: false
}
