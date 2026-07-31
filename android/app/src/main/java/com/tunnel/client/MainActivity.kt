package com.tunnel.client

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.view.View
import android.widget.*
import gomobile.GoMobile
import gomobile.ProbeResult

/**
 * MainActivity — Server selection and connect/disconnect UI.
 *
 * Flow:
 *  1. Load profiles from app config (stored in app-private storage).
 *  2. Probe each server for latency in the background.
 *  3. Display the server list with live RTT values.
 *  4. User taps a server → request VPN permission → start TunnelVpnService.
 */
class MainActivity : Activity() {

    private val REQUEST_VPN_PERMISSION = 1

    // Populated from app config storage (see ConfigManager).
    private var profiles: List<ServerProfile> = emptyList()
    private var selectedProfile: ServerProfile? = null

    private lateinit var listView: ListView
    private lateinit var connectBtn: Button
    private lateinit var disconnectBtn: Button
    private lateinit var statusText: TextView
    private lateinit var adapter: ServerListAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        listView      = findViewById(R.id.server_list)
        connectBtn    = findViewById(R.id.btn_connect)
        disconnectBtn = findViewById(R.id.btn_disconnect)
        statusText    = findViewById(R.id.status_text)

        profiles = ConfigManager.loadProfiles(this)
        adapter  = ServerListAdapter(this, profiles.toMutableList())
        listView.adapter = adapter

        listView.setOnItemClickListener { _, _, pos, _ ->
            selectedProfile = profiles[pos]
            connectBtn.isEnabled = true
        }

        connectBtn.setOnClickListener {
            selectedProfile?.let { requestVpnPermissionAndConnect(it) }
        }

        disconnectBtn.setOnClickListener {
            disconnect()
        }

        probeAllServers()
    }

    private fun probeAllServers() {
        val creds = ConfigManager.loadCredentials(this) ?: return
        statusText.text = "Probing servers…"

        profiles.forEachIndexed { i, profile ->
            Thread {
                val result: ProbeResult = GoMobile.probeServer(
                    creds.certPem,
                    creds.keyPem,
                    creds.caPem,
                    profile.hostname,
                    profile.port.toLong()
                )
                runOnUiThread {
                    adapter.updateRTT(i, result.rTTMs)
                    adapter.notifyDataSetChanged()
                    statusText.text = "Select a server"
                }
            }.start()
        }
    }

    private fun requestVpnPermissionAndConnect(profile: ServerProfile) {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, REQUEST_VPN_PERMISSION)
        } else {
            // Permission already granted.
            startTunnel(profile)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == REQUEST_VPN_PERMISSION && resultCode == RESULT_OK) {
            selectedProfile?.let { startTunnel(it) }
        }
    }

    private fun startTunnel(profile: ServerProfile) {
        val creds = ConfigManager.loadCredentials(this) ?: run {
            statusText.text = "Error: certificates not configured"
            return
        }
        statusText.text = "Connecting to ${profile.name}…"
        connectBtn.isEnabled    = false
        disconnectBtn.isEnabled = true

        val intent = Intent(this, TunnelVpnService::class.java).apply {
            action = TunnelVpnService.ACTION_CONNECT
            putExtra(TunnelVpnService.EXTRA_HOSTNAME,    profile.hostname)
            putExtra(TunnelVpnService.EXTRA_PORT,        profile.port)
            putExtra(TunnelVpnService.EXTRA_TUN_ADDR,    profile.tunClientAddr)
            putExtra(TunnelVpnService.EXTRA_CERT_PEM,    creds.certPem)
            putExtra(TunnelVpnService.EXTRA_KEY_PEM,     creds.keyPem)
            putExtra(TunnelVpnService.EXTRA_CA_PEM,      creds.caPem)
            putExtra(TunnelVpnService.EXTRA_SERVER_NAME, profile.name)
        }
        startService(intent)
    }

    private fun disconnect() {
        startService(Intent(this, TunnelVpnService::class.java).apply {
            action = TunnelVpnService.ACTION_DISCONNECT
        })
        connectBtn.isEnabled    = true
        disconnectBtn.isEnabled = false
        statusText.text         = "Disconnected"
        selectedProfile         = null
    }
}

/** A single server profile loaded from the app config. */
data class ServerProfile(
    val name: String,
    val hostname: String,
    val port: Int,
    val regionLabel: String,
    val tunClientAddr: String
)

/** Credentials (PEM strings) loaded from app-private storage. */
data class Credentials(
    val certPem: String,
    val keyPem: String,
    val caPem: String
)
