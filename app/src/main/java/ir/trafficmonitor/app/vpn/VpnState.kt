package ir.trafficmonitor.app.vpn

import android.content.Context

internal object VpnState {
    private const val FILE = "vpn_state"

    fun setRunning(context: Context, running: Boolean) {
        context.openFileOutput(FILE, Context.MODE_PRIVATE).use {
            it.write(if (running) 1 else 0)
        }
    }

    fun isRunning(context: Context): Boolean {
        return try {
            context.openFileInput(FILE).use { it.read() == 1 }
        } catch (_: Exception) { false }
    }
}
