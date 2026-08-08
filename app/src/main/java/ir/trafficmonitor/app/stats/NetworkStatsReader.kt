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
     * از querySummaryForDevice (کل دستگاه) برای دریافت bucket استفاده می‌شود.
     */
    fun readAll(from: Long, to: Long): List<AppUsage> {
        val out = LinkedHashMap<Int, AppUsage>()
        // WiFi
        accumulate(ConnectivityManager.TYPE_WIFI, null, from, to, out)
        // Mobile
        accumulate(ConnectivityManager.TYPE_MOBILE, null, from, to, out)
        // Ethernet
        accumulate(ConnectivityManager.TYPE_ETHERNET, null, from, to, out)
        return out.values.toList()
    }

    /**
     * استفاده از querySummaryForDevice — که فقط کل مصرف را می‌دهد؛ برای جداسازی
     * هر اپ نیاز به queryDetailsForUid برای هر UID است.
     * در این نسخه، کل مصرف به هر UID که در system bucket بود نسبت داده می‌شود.
     */
    private fun accumulate(type: Int, subId: String?, from: Long, to: Long, out: MutableMap<Int, AppUsage>) {
        try {
            // ۱. کل مصرف دستگاه
            val total = manager.querySummaryForDevice(type, subId, from, to)
            if (total.uid >= 0) {
                val prev = out[total.uid] ?: AppUsage(total.uid, 0, 0)
                out[total.uid] = AppUsage(total.uid, prev.rxBytes + total.rxBytes, prev.txBytes + total.txBytes)
            }
            total.close()

            // ۲. مصرف تفکیکی هر UID (نیاز به مجوز)
            try {
                val details = manager.querySummary(type, subId, from, to)
                val bucket = NetworkStats.Bucket()
                while (details.hasNextBucket()) {
                    details.getNextBucket(bucket)
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
                details.close()
            } catch (e: Exception) {
                // بدون مجوز یا خطا — فقط کل دستگاه را داریم
            }
        } catch (e: Exception) {
            // بدون مجوز یا خطا — نادیده بگیر
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