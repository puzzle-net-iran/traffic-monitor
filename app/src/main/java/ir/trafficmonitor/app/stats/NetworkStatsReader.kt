package ir.trafficmonitor.app.stats

import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.content.Context
import android.net.ConnectivityManager

/**
 * خواندن مصرف داده هر اپ از NetworkStatsManager — همان API که «استفاده از داده»
 * در تنظیمات اندروید نشان می‌دهد. بدون VPN — فقط خواندن آمار.
 *
 * نیاز: مجوز PACKAGE_USAGE_STATS که کاربر باید در تنظیمات فعال کند.
 */
class NetworkStatsReader(context: Context) {

    private val manager =
        context.getSystemService(Context.NETWORK_STATS_SERVICE) as NetworkStatsManager

    data class AppUsage(
        val uid: Int,
        val rxBytes: Long,
        val txBytes: Long
    )

    /**
     * جمع مصرف هر UID در بازه [from, to] روی همه شبکه‌ها (wifi + موبایل + ethernet).
     */
    fun readAll(from: Long, to: Long): List<AppUsage> {
        val out = LinkedHashMap<Int, AppUsage>()
        process(ConnectivityManager.TYPE_WIFI, null, from, to, out)
        process(ConnectivityManager.TYPE_MOBILE, null, from, to, out)
        process(ConnectivityManager.TYPE_ETHERNET, null, from, to, out)
        return out.values.toList()
    }

    private fun process(type: Int, subId: String?, from: Long, to: Long, out: MutableMap<Int, AppUsage>) {
        try {
            val query: NetworkStats = manager.querySummaryForDevice(type, subId, from, to)
            try {
                val bucket = NetworkStats.Bucket()
                while (query.hasNextBucket()) {
                    query.getNextBucket(bucket)
                    val uid = bucket.uid
                    if (uid >= 0) {
                        val prev = out[uid] ?: AppUsage(uid, 0, 0)
                        out[uid] = AppUsage(
                            uid,
                            prev.rxBytes + bucket.rxBytes,
                            prev.txBytes + bucket.txBytes
                        )
                    }
                }
            } finally {
                query.close()
            }
        } catch (e: Exception) {
            // بدون مجوز یا خطای موقت — نادیده بگیر
        }
    }

    companion object {
        /** اسنپ‌شات ساده از ترافیک چند ساعت اخیر. */
        fun snapshot(context: Context, hours: Int = 2): List<AppUsage> {
            val end = System.currentTimeMillis()
            val start = end - hours * 60L * 60L * 1000L
            return NetworkStatsReader(context).readAll(start, end)
        }
    }
}