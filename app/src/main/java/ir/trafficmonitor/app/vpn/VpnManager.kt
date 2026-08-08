package ir.trafficmonitor.app.vpn

import android.content.Context

object VpnManager {
    const val ACTION_TOGGLE_VPN = "ir.trafficmonitor.TOGGLE_VPN"
    const val ACTION_START_VPN = "ir.trafficmonitor.START_VPN"
    const val ACTION_STOP_VPN = "ir.trafficmonitor.STOP_VPN"

    fun isRunning(context: Context): Boolean = VpnState.isRunning(context)
}
