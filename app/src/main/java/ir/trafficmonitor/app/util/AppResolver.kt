package ir.trafficmonitor.app.util

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build

class AppResolver(private val context: Context) {

    private val pm = context.packageManager
    private val cache = HashMap<Int, AppInfo>()

    fun getInfo(uid: Int): AppInfo? {
        if (uid < 0) return null
        cache[uid]?.let { return it }
        val pkg = try {
            pm.getPackagesForUid(uid)?.firstOrNull()
        } catch (e: Exception) { null }
        val label = pkg?.let {
            try { pm.getApplicationInfo(it, 0).loadLabel(pm).toString() } catch (e: Exception) { it }
        }
        val info = AppInfo(uid, pkg, label)
        cache[uid] = info
        return info
    }

    fun internetApps(): List<AppInfo> {
        val apps = pm.getInstalledApplications(PackageManager.MATCH_ALL)
        val result = mutableListOf<AppInfo>()
        for (app in apps) {
            val hasInternet = try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    val info = pm.getApplicationInfo(app.packageName, PackageManager.ApplicationInfoFlags.of(0))
                    val perAppInfo = pm.getPackageInfo(app.packageName, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
                    perAppInfo.requestedPermissions?.contains(android.Manifest.permission.INTERNET) == true
                } else {
                    @Suppress("DEPRECATION")
                    val perAppInfo = pm.getPackageInfo(app.packageName, PackageManager.GET_PERMISSIONS)
                    perAppInfo.requestedPermissions?.contains(android.Manifest.permission.INTERNET) == true
                }
            } catch (e: Exception) { false }
            if (!hasInternet) continue
            val label = try { app.loadLabel(pm).toString() } catch (e: Exception) { app.packageName }
            result.add(AppInfo(app.uid, app.packageName, label))
        }
        return result.sortedBy { it.label }
    }

    data class AppInfo(val uid: Int, val packageName: String?, val label: String?)
}
