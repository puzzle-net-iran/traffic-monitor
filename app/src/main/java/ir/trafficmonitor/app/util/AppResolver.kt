package ir.trafficmonitor.app.util

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Process

/**
 * نگاشت UID به بسته/نام اپ + کش.
 */
class AppResolver(private val context: Context) {

    private val pm = context.packageManager
    private val cache = HashMap<Int, AppInfo>()
    private val labelCache = HashMap<String, String>()

    fun getInfo(uid: Int): AppInfo? {
        if (uid < 0) return null
        cache[uid]?.let { return it }
        val pkg = uidToPackage(uid) ?: run {
            cache[uid] = AppInfo(uid, null, null)
            return null
        }
        val label = labelCache.getOrPut(pkg) {
            try {
                pm.getApplicationInfo(pkg, 0).loadLabel(pm).toString()
            } catch (e: PackageManager.NameNotFoundException) {
                pkg
            }
        }
        val info = AppInfo(uid, pkg, label)
        cache[uid] = info
        return info
    }

    private fun uidToPackage(uid: Int): String? {
        // UIDهای سیستمی شناخته‌شده
        KNOWN_UIDS[uid]?.let { return it }
        try {
            val pkgs = pm.getPackagesForUid(uid) ?: return null
            return pkgs.firstOrNull()
        } catch (e: Exception) {
            return null
        }
    }

    /** همه اپ‌های نصب‌شده دارای مجوز اینترنت (برای صفحه برنامه‌ها). */
    fun internetApps(): List<AppInfo> {
        val apps = pm.getInstalledApplications(PackageManager.MATCH_ALL)
        val result = mutableListOf<AppInfo>()
        for (app in apps) {
            val perms = try { app.requestedPermissions } catch (e: Exception) { null }
            if (perms == null || !perms.contains(android.Manifest.permission.INTERNET)) continue
            val uid = app.uid
            val label = try {
                app.loadLabel(pm).toString()
            } catch (e: Exception) {
                app.packageName
            }
            result.add(AppInfo(uid, app.packageName, label))
        }
        return result.sortedBy { it.label }
    }

    data class AppInfo(val uid: Int, val packageName: String?, val label: String?)

    companion object {
        private val KNOWN_UIDS = mapOf(
            0 to "system",
            1000 to "android",
            1013 to "media",
            1016 to "telephony",
            1021 to "nfc",
            2000 to "shell",
            9999 to "system"
        )
    }
}
