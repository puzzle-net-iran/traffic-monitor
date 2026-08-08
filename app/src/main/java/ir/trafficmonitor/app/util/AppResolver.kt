package ir.trafficmonitor.app.util

import android.content.Context
import android.content.pm.PackageManager

class AppResolver(private val context: Context) {

    private val pm = context.packageManager
    private val cache = HashMap<Int, AppInfo>()

    fun getInfo(uid: Int): AppInfo? {
        if (uid < 0) return null
        cache[uid]?.let { return it }
        val pkg = try {
            pm.getPackagesForUid(uid)?.firstOrNull() ?: "uid:$uid"
        } catch (e: Exception) { "uid:$uid" }
        val label = try {
            val appInfo = pm.getApplicationInfo(pkg, 0)
            appInfo.loadLabel(pm).toString()
        } catch (e: Exception) { pkg }
        val info = AppInfo(uid, pkg, label)
        cache[uid] = info
        return info
    }

    data class AppInfo(val uid: Int, val packageName: String, val label: String)
}