package ir.trafficmonitor.app.prefs

import android.content.Context
import ir.trafficmonitor.app.db.AppDatabase

/**
 * تنظیمات برنامه؛ مقادیر پیش‌فرض‌های مهم:
 *  - retentionDays: چند روز لاگ نگه داشته شود (پیش‌فرض ۷)
 *  - autoStartVpn: روشن بودن خودکار VPN بعد از بوت
 *  - groupByApp: گروه‌بندی پیش‌فرض داشبورد
 *  - blockOnExit: مسدود کردن ترافیک اپ‌های مسدود هنگام خروج
 */
class SettingsStore(context: Context) {

    private val db: AppDatabase =
        (context.applicationContext as ir.trafficmonitor.app.App).database

    var retentionDays: Int
        get() = db.getSetting(KEY_RETENTION, "7").toIntOrNull() ?: 7
        set(value) = db.setSetting(KEY_RETENTION, value.toString())

    var autoStartVpn: Boolean
        get() = db.getSetting(KEY_AUTO_START, "false").toBoolean()
        set(value) = db.setSetting(KEY_AUTO_START, value.toString())

    var groupByApp: Boolean
        get() = db.getSetting(KEY_GROUP_BY_APP, "true").toBoolean()
        set(value) = db.setSetting(KEY_GROUP_BY_APP, value.toString())

    var blockOnExit: Boolean
        get() = db.getSetting(KEY_BLOCK_ON_EXIT, "false").toBoolean()
        set(value) = db.setSetting(KEY_BLOCK_ON_EXIT, value.toString())

    var vpnEstablishedAt: Long
        get() = db.getSetting(KEY_VPN_ESTABLISHED, "0").toLongOrNull() ?: 0L
        set(value) = db.setSetting(KEY_VPN_ESTABLISHED, value.toString())

    companion object {
        private const val KEY_RETENTION = "retention_days"
        private const val KEY_AUTO_START = "auto_start_vpn"
        private const val KEY_GROUP_BY_APP = "group_by_app"
        private const val KEY_BLOCK_ON_EXIT = "block_on_exit"
        private const val KEY_VPN_ESTABLISHED = "vpn_established_at"
    }
}
