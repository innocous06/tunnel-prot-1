package com.tunnel.client

import android.content.Context
import org.json.JSONArray
import java.io.File

/**
 * ConfigManager — reads server profiles and device credentials from app-private storage.
 *
 * File locations (app-private, not accessible to other apps):
 *   filesDir/profiles.json  — server list (same format as client_config.example.json)
 *   filesDir/cert.pem       — device certificate
 *   filesDir/key.pem        — device private key
 *   filesDir/ca.pem         — CA certificate
 *
 * How to import certs on Android:
 *   Use the Import screen (future UI) which writes the PEM files to filesDir.
 *   Or push via `adb push` during development:
 *     adb push device-cert.pem /sdcard/Download/
 *     (then import from the app's Import screen)
 */
object ConfigManager {

    fun loadProfiles(context: Context): List<ServerProfile> {
        val file = File(context.filesDir, "profiles.json")
        if (!file.exists()) return emptyList()

        return try {
            val json = JSONArray(file.readText())
            (0 until json.length()).map { i ->
                val obj = json.getJSONObject(i)
                ServerProfile(
                    name          = obj.getString("name"),
                    hostname      = obj.getString("hostname"),
                    port          = obj.optInt("port", 443),
                    regionLabel   = obj.optString("region_label", ""),
                    tunClientAddr = obj.optString("tun_client_addr", "10.66.0.2/24")
                )
            }
        } catch (e: Exception) {
            emptyList()
        }
    }

    fun loadCredentials(context: Context): Credentials? {
        val certFile = File(context.filesDir, "cert.pem")
        val keyFile  = File(context.filesDir, "key.pem")
        val caFile   = File(context.filesDir, "ca.pem")
        if (!certFile.exists() || !keyFile.exists() || !caFile.exists()) return null
        return try {
            Credentials(
                certPem = certFile.readText(),
                keyPem  = keyFile.readText(),
                caPem   = caFile.readText()
            )
        } catch (e: Exception) { null }
    }

    /** Save a profiles JSON array string to app-private storage. */
    fun saveProfiles(context: Context, json: String) {
        File(context.filesDir, "profiles.json").writeText(json)
    }

    /** Save a PEM cert/key/ca to app-private storage. */
    fun saveCert(context: Context, certPem: String, keyPem: String, caPem: String) {
        File(context.filesDir, "cert.pem").writeText(certPem)
        File(context.filesDir, "key.pem").writeText(keyPem)
        File(context.filesDir, "ca.pem").writeText(caPem)
    }
}
