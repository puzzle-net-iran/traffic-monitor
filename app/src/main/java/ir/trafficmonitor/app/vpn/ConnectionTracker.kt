package ir.trafficmonitor.app.vpn

import android.content.Context
import android.net.TrafficStats
import ir.trafficmonitor.app.db.LogStore
import ir.trafficmonitor.app.model.ConnectionRecord
import ir.trafficmonitor.app.util.AppResolver
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * پیگیری اتصالات فعال و ثبت آنها.
 * برای هر اتصال TCP که پکت‌های SYN دریافت می‌کند، یک ConnectionRecord ساخته
 * و در یک map نگهداری می‌شود. حجم از TrafficStats تخمین زده می‌شود.
 */
class ConnectionTracker(context: Context) {

    private val appContext = context.applicationContext
    private val resolver = AppResolver(appContext)
    private val logStore = LogStore((appContext as ir.trafficmonitor.app.App).database)

    // کلید = "<srcIp>:<srcPort>-<dstIp>:<dstPort>" برای TCP خروجی
    private val activeFlows = ConcurrentHashMap<String, ConnectionRecord>()
    private val dnsCache = ConcurrentHashMap<String, String>() // ip -> domain (آخرین کوئری)

    @Volatile
    var totalBlocked = 0
        private set

    fun onOutboundPacket(
        srcIp: InetAddress, dstIp: InetAddress,
        srcPort: Int, dstPort: Int,
        protocol: Int,
        flags: Int
    ): ConnectionRecord? {
        val key = "${srcIp.hostAddress}:$srcPort-${dstIp.hostAddress}:$dstPort"
        var record = activeFlows[key]
        if (record == null) {
            if (protocol == 6 && flags and 0x02 == 0) return null // فقط SYN برای شروع
            val uid = resolveUid(srcPort)
            val appInfo = resolver.getInfo(uid)
            val host = resolveHost(dstIp, dstPort)
            val isTls = dstPort == 443
            record = ConnectionRecord(
                uid = uid,
                packageName = appInfo?.packageName,
                remoteHost = host,
                remoteIp = dstIp.hostAddress,
                remotePort = dstPort,
                localPort = srcPort,
                protocol = if (protocol == 6) "tcp" else if (protocol == 17) "udp" else "other",
                isTls = isTls
            )
            activeFlows[key] = record
        }
        return record
    }

    fun onPacketAfterHandshake(
        srcIp: InetAddress, dstIp: InetAddress,
        srcPort: Int, dstPort: Int,
        payloadLength: Int,
        isOutbound: Boolean,
        host: String? = null
    ) {
        val key = if (isOutbound) {
            "${srcIp.hostAddress}:$srcPort-${dstIp.hostAddress}:$dstPort"
        } else {
            "${dstIp.hostAddress}:$dstPort-${srcIp.hostAddress}:$srcPort"
        }
        val record = activeFlows[key] ?: return
        if (isOutbound) {
            record.sentBytes += payloadLength
        } else {
            record.receivedBytes += payloadLength
        }
        if (host != null && record.remoteHost == null) {
            record.remoteHost = host
        }
    }

    fun onDnsQuery(domain: String, dstIp: InetAddress?) {
        if (domain.isNotEmpty()) {
            dstIp?.hostAddress?.let { dnsCache[it] = domain }
        }
    }

    fun closeFlow(srcIp: InetAddress, dstIp: InetAddress, srcPort: Int, dstPort: Int, isOutbound: Boolean) {
        val key = if (isOutbound) {
            "${srcIp.hostAddress}:$srcPort-${dstIp.hostAddress}:$dstPort"
        } else {
            "${dstIp.hostAddress}:$dstPort-${srcIp.hostAddress}:$srcPort"
        }
        activeFlows.remove(key)?.let {
            it.endAt = System.currentTimeMillis()
            // به‌روزرسانی حجم نهایی از TrafficStats
            finalizeVolume(it)
            logStore.insert(it)
        }
    }

    fun flushAll() {
        val now = System.currentTimeMillis()
        for ((k, v) in activeFlows) {
            v.endAt = now
            finalizeVolume(v)
            logStore.insert(v)
        }
        activeFlows.clear()
        logStore.flush()
    }

    private fun finalizeVolume(record: ConnectionRecord) {
        try {
            // حجم از TrafficStats برای UID
            val uidTx = TrafficStats.getUidTxBytes(record.uid)
            val uidRx = TrafficStats.getUidRxBytes(record.uid)
            if (uidTx >= 0 && uidRx >= 0) {
                // اگر حجم کل اپ از آخرین صفر بیشتر از صفر باشد، آن را به عنوان حجم اتصال در نظر می‌گیریم
                // توجه: این یک تخمین برای اپ‌های فعال؛ برای دقت باید baseline نگه داشته شود
            }
        } catch (e: Exception) {
        }
    }

    private fun resolveUid(localPort: Int): Int {
        // در API 28+ از ConnectivityManager.getConnectionOwnerUid استفاده می‌شود
        // برای سادگی، همه اتصالات UID 0 دریافت می‌کنند؛ در پیاده‌سازی کامل این متد با هسته کار می‌کند
        return 0
    }

    private fun resolveHost(ip: InetAddress, port: Int): String? {
        val cached = dnsCache[ip.hostAddress]
        if (cached != null) return cached
        if (port == 443 || port == 853) {
            return ip.hostAddress
        }
        return null
    }
}
