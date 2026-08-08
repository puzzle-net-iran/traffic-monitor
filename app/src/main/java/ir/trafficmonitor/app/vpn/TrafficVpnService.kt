package ir.trafficmonitor.app.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.ParcelFileDescriptor.AutoCloseInputStream
import androidx.core.app.NotificationCompat
import ir.trafficmonitor.app.R
import ir.trafficmonitor.app.firewall.FirewallEngine
import ir.trafficmonitor.app.ui.MainActivity
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class TrafficVpnService : VpnService() {

    private var pfd: ParcelFileDescriptor? = null
    private var input: FileInputStream? = null
    private var output: FileOutputStream? = null
    private var loopThread: Thread? = null
    private val pool: ExecutorService = Executors.newFixedThreadPool(4)
    private val running = AtomicBoolean(false)
    private val shuttingDown = AtomicBoolean(false)

    private val udpRelays = ConcurrentHashMap<String, UdpRelay>()
    private val tcpRelays = ConcurrentHashMap<String, TcpRelay>()
    private val dnsCache = ConcurrentHashMap<String, String>()

    private val totalTx = AtomicLong(0)
    private val totalRx = AtomicLong(0)

    private val toggleReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent?) {
            when (intent?.action) {
                ACTION_STOP -> stopVpn()
                ACTION_TOGGLE -> stopVpn()
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(1, buildNotification())
        val filter = IntentFilter().apply {
            addAction(ACTION_STOP)
            addAction(ACTION_TOGGLE)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(toggleReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(toggleReceiver, filter)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> { stopVpn(); return START_NOT_STICKY }
            ACTION_TOGGLE -> { stopVpn(); return START_NOT_STICKY }
            else -> startVpn()
        }
        return START_STICKY
    }

    private fun startVpn() {
        if (running.getAndSet(true)) return

        val builder = Builder().apply {
            setSession("TrafficMonitor")
            addAddress("10.0.0.2", 32)
            addRoute("0.0.0.0", 0)
            addDnsServer("1.1.1.1")
            addDnsServer("8.8.8.8")
            setMtu(1400)
            setBlocking(true)
            setConfigureIntent(
                PendingIntent.getActivity(
                    this@TrafficVpnService, 0,
                    Intent(this@TrafficVpnService, MainActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE
                )
            )
        }

        pfd = builder.establish()
        if (pfd == null) {
            LogBuffer.append("[خطا] establish() ناموفق")
            running.set(false)
            stopSelf()
            return
        }

        input = AutoCloseInputStream(pfd!!)
        output = FileOutputStream(pfd!!.fileDescriptor)

        LogBuffer.append("[شروع] VPN فعال شد")

        loopThread = Thread {
            try {
                vpnLoop()
            } catch (e: Throwable) {
                LogBuffer.append("[خطا] ${e.message}")
            }
        }.apply {
            isDaemon = true
            name = "vpn-loop"
            start()
        }
    }

    private fun vpnLoop() {
        val buf = ByteArray(32767)
        while (running.get() && !shuttingDown.get()) {
            try {
                val len = input?.read(buf) ?: break
                if (len <= 0) {
                    Thread.sleep(5)
                    continue
                }
                val pkt = parsePacket(buf, len) ?: continue
                pool.execute { handlePacket(pkt) }
            } catch (e: java.io.IOException) {
                break
            } catch (e: InterruptedException) {
                break
            } catch (e: Exception) {
                if (running.get()) LogBuffer.append("[خطای حلقه] ${e.message}")
            }
        }
        stopVpn()
    }

    // ─── packet model ────────────────────────────────────────────────────────
    private class Pkt(val buf: ByteArray, val len: Int) {
        var srcIp: ByteArray = ByteArray(0)
        var dstIp: ByteArray = ByteArray(0)
        var srcPort = 0
        var dstPort = 0
        var proto = 0
        var tcpFlags = 0
        var payloadOff = 0
        var payloadLen = 0
        var seq = 0L
        var ack = 0L

        fun key(): String = "${ipStr(srcIp)}:$srcPort→${ipStr(dstIp)}:$dstPort"
        fun payload(): ByteArray = buf.copyOfRange(payloadOff, payloadOff + payloadLen)
        fun ipStr(b: ByteArray): String = try { InetAddress.getByAddress(b).hostAddress ?: "?" } catch (e: Exception) { "?" }
    }

    private fun parsePacket(buf: ByteArray, len: Int): Pkt? {
        if (len < 20) return null
        val ver = (buf[0].toInt() ushr 4) and 0xF
        val pkt = Pkt(buf, len)
        if (ver == 4) {
            val ihl = (buf[0].toInt() and 0x0F) * 4
            if (len < ihl) return null
            pkt.proto = buf[9].toInt() and 0xFF
            pkt.srcIp = buf.copyOfRange(12, 16)
            pkt.dstIp = buf.copyOfRange(16, 20)
            parseTransport(pkt, ihl)
        } else if (ver == 6) {
            if (len < 40) return null
            pkt.proto = buf[6].toInt() and 0xFF
            pkt.srcIp = buf.copyOfRange(8, 24)
            pkt.dstIp = buf.copyOfRange(24, 40)
            parseTransport(pkt, 40)
        } else return null
        return pkt
    }

    private fun parseTransport(pkt: Pkt, off: Int) {
        val buf = pkt.buf
        val end = pkt.len
        if (pkt.proto == 6 && end >= off + 20) {
            pkt.srcPort = u16(buf, off)
            pkt.dstPort = u16(buf, off + 2)
            pkt.seq = u32(buf, off + 4)
            pkt.ack = u32(buf, off + 8)
            pkt.tcpFlags = buf[off + 13].toInt() and 0x3F
            val dataOff = ((buf[off + 12].toInt() ushr 4) and 0xF) * 4
            pkt.payloadOff = off + dataOff
            pkt.payloadLen = (end - pkt.payloadOff).coerceAtLeast(0)
        } else if (pkt.proto == 17 && end >= off + 8) {
            pkt.srcPort = u16(buf, off)
            pkt.dstPort = u16(buf, off + 2)
            pkt.payloadOff = off + 8
            pkt.payloadLen = (end - pkt.payloadOff).coerceAtLeast(0)
        }
    }

    // ─── packet processing ───────────────────────────────────────────────────
    private fun handlePacket(pkt: Pkt) {
        try {
            when (pkt.proto) {
                6 -> handleTcp(pkt)
                17 -> handleUdp(pkt)
            }
        } catch (e: Exception) {
            LogBuffer.append("[خطا پردازش] ${e.message}")
        }
    }

    private fun handleTcp(pkt: Pkt) {
        val key = pkt.key()
        val syn = pkt.tcpFlags and 0x02 != 0
        val ack = pkt.tcpFlags and 0x10 != 0
        val fin = pkt.tcpFlags and 0x01 != 0
        val rst = pkt.tcpFlags and 0x04 != 0

        if (fin || rst) {
            tcpRelays.remove(key)?.let { relay ->
                relay.stop()
                LogBuffer.append("[TCP] بسته شد ${pkt.ipStr(pkt.dstIp)}:${pkt.dstPort}")
            }
            return
        }

        if (syn && !ack) {
            val host = resolveHost(pkt.dstIp)

            val blocked = FirewallEngine.decide(null, host)
            if (blocked != null) {
                LogBuffer.append("[مسدود] $blocked ← ${pkt.ipStr(pkt.dstIp)}:${pkt.dstPort}")
                return
            }

            val relay = TcpRelay(
                dstIp = pkt.dstIp,
                dstPort = pkt.dstPort,
                protect = { sock ->
                    protect(sock)
                },
                onRx = { n -> totalRx.addAndGet(n) },
                onError = { msg -> LogBuffer.append("[خطا TCP] ${msg}") }
            )

            if (relay.connect(5000)) {
                tcpRelays[key] = relay
                LogBuffer.append("[TCP] متصل به ${pkt.ipStr(pkt.dstIp)}:${pkt.dstPort}")
            } else {
                LogBuffer.append("[خطا] اتصال TCP ناموفق ${pkt.ipStr(pkt.dstIp)}:${pkt.dstPort}")
            }
            return
        }

        tcpRelays[key]?.let { relay ->
            if (pkt.payloadLen > 0) {
                val payload = pkt.payload()
                relay.send(payload)
                totalTx.addAndGet(payload.size.toLong())
            }
        }
    }

    private fun handleUdp(pkt: Pkt) {
        if (pkt.payloadLen == 0) return

        val payload = pkt.payload()
        totalTx.addAndGet(payload.size.toLong())

        if (pkt.dstPort == 53) {
            val domain = extractDnsName(pkt.buf, pkt.payloadOff, pkt.payloadLen)
            if (domain.isNotEmpty()) {
                dnsCache[pkt.ipStr(pkt.srcIp)] = domain
                LogBuffer.append("[DNS] $domain")
            }
        }

        val key = pkt.key()
        val relay = udpRelays.getOrPut(key) {
            UdpRelay(
                remoteIp = pkt.dstIp,
                remotePort = pkt.dstPort,
                protect = { ch ->
                    protect(ch.socket)
                },
                onRx = { n -> totalRx.addAndGet(n) }
            )
        }
        relay.send(payload)
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────
    private fun resolveHost(ip: ByteArray): String? {
        val addr = try { InetAddress.getByAddress(ip).hostAddress ?: return null } catch (e: Exception) { return null }
        return dnsCache[addr]
    }

    private fun extractDnsName(buf: ByteArray, off: Int, len: Int): String {
        if (len < 12) return ""
        var p = off; val end = off + len; val sb = StringBuilder()
        while (p < end) {
            val n = buf[p].toInt() and 0xFF
            if (n == 0) break
            if (n > 63) break
            p++
            if (p + n > end) break
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(buf, p, n, Charsets.UTF_8))
            p += n
        }
        return sb.toString().lowercase()
    }

    // ─── TCP Relay ───────────────────────────────────────────────────────────
    private class TcpRelay(
        private val dstIp: ByteArray,
        private val dstPort: Int,
        private val protect: (Socket) -> Boolean,
        private val onRx: (Long) -> Unit,
        private val onError: (String) -> Unit
    ) {
        private var channel: SocketChannel? = null
        private val relayThread: Thread?
        @Volatile private var running = true

        init {
            relayThread = Thread {
                val buf = ByteArray(16384)
                try {
                    while (running) {
                        val bb = ByteBuffer.wrap(buf)
                        val n = channel?.read(bb) ?: break
                        if (n <= 0) break
                        bb.flip()
                        val data = ByteArray(bb.remaining())
                        bb.get(data)
                        onRx(data.size.toLong())
                    }
                } catch (e: Exception) {
                    if (running) onError("relay read: ${e.message}")
                }
            }.apply { isDaemon = true; name = "tcp-relay"; start() }
        }

        fun connect(timeoutMs: Int): Boolean {
            return try {
                val ch = SocketChannel.open()
                protect(ch.socket())
                ch.socket().connect(InetSocketAddress(InetAddress.getByAddress(dstIp), dstPort), timeoutMs)
                ch.configureBlocking(false)
                channel = ch
                true
            } catch (e: Exception) {
                false
            }
        }

        fun send(data: ByteArray) {
            try {
                channel?.write(ByteBuffer.wrap(data))
            } catch (e: Exception) {
                running = false
                onError("relay write: ${e.message}")
            }
        }

        fun stop() {
            running = false
            runCatching { channel?.close() }
            runCatching { relayThread?.interrupt() }
        }
    }

    // ─── UDP Relay ───────────────────────────────────────────────────────────
    private class UdpRelay(
        private val remoteIp: ByteArray,
        private val remotePort: Int,
        private val protect: (DatagramChannel) -> Boolean,
        private val onRx: (Int) -> Unit
    ) {
        private var channel: DatagramChannel? = null
        private val readThread: Thread?
        @Volatile private var running = true

        init {
            try {
                val ch = DatagramChannel.open()
                protect(ch)
                ch.configureBlocking(false)
                ch.connect(InetSocketAddress(InetAddress.getByAddress(remoteIp), remotePort))
                channel = ch
            } catch (e: Exception) {
                LogBuffer.append("[خطا UDP relay] ${e.message}")
            }

            readThread = Thread {
                val buf = ByteBuffer.allocate(2048)
                while (running) {
                    try {
                        buf.clear()
                        val n = channel?.read(buf) ?: -1
                        if (n != null && n > 0) {
                            buf.flip()
                            val data = ByteArray(buf.remaining())
                            buf.get(data)
                            onRx(data.size)
                        }
                        Thread.sleep(10)
                    } catch (e: InterruptedException) {
                        break
                    } catch (e: Exception) {
                        break
                    }
                }
            }.apply { isDaemon = true; name = "udp-relay-$remotePort"; start() }
        }

        fun send(data: ByteArray) {
            try {
                channel?.write(ByteBuffer.wrap(data))
            } catch (e: Exception) {
            }
        }

        fun close() {
            running = false
            runCatching { channel?.close() }
            runCatching { readThread?.interrupt() }
        }
    }

    // ─── Notification ────────────────────────────────────────────────────────
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            val ch = NotificationChannel(
                "vpn_status",
                getString(R.string.vpn_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.vpn_channel_desc)
                setShowBadge(false)
            }
            nm.createNotificationChannel(ch)
        }
    }

    private fun buildNotification(): Notification {
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, "vpn_status")
            .setContentTitle(getString(R.string.vpn_title))
            .setContentText("↓${fmt(totalRx.get())} ↑${fmt(totalTx.get())}")
            .setSmallIcon(R.drawable.ic_vpn)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    private fun fmt(bytes: Long): String {
        if (bytes < 1024) return "${bytes}B"
        if (bytes < 1048576) return String.format("%.1fKB", bytes / 1024.0)
        return String.format("%.1fMB", bytes / 1048576.0)
    }

    // ─── Lifecycle ───────────────────────────────────────────────────────────
    private fun stopVpn() {
        if (!running.getAndSet(false)) return
        shuttingDown.set(true)

        LogBuffer.append("[توقف] VPN متوقف شد")

        tcpRelays.values.forEach { it.stop() }
        tcpRelays.clear()
        udpRelays.values.forEach { it.close() }
        udpRelays.clear()

        runCatching { loopThread?.interrupt() }
        runCatching { pfd?.close() }

        pfd = null; input = null; output = null

        pool.shutdownNow()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
        stopSelf()
    }

    override fun onDestroy() {
        runCatching { unregisterReceiver(toggleReceiver) }
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    companion object {
        const val ACTION_TOGGLE = "ir.trafficmonitor.TOGGLE_VPN"
        const val ACTION_STOP = "ir.trafficmonitor.STOP_VPN"

        private fun u16(b: ByteArray, off: Int): Int =
            ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

        private fun u32(b: ByteArray, off: Int): Long =
            ((b[off].toLong() and 0xFF) shl 24) or
                ((b[off + 1].toLong() and 0xFF) shl 16) or
                ((b[off + 2].toLong() and 0xFF) shl 8) or
                (b[off + 3].toLong() and 0xFF)

        @Suppress("unused")
        private fun setU16(b: ByteArray, off: Int, v: Int) {
            b[off] = (v ushr 8).toByte()
            b[off + 1] = v.toByte()
        }

        @Suppress("unused")
        private fun setU32(b: ByteArray, off: Int, v: Long) {
            b[off] = (v ushr 24).toByte()
            b[off + 1] = (v ushr 16).toByte()
            b[off + 2] = (v ushr 8).toByte()
            b[off + 3] = v.toByte()
        }
    }
}

object LogBuffer {
    private val buffer = ArrayList<String>(300)
    private val listeners = ArrayList<() -> Unit>()

    @Synchronized
    fun addListener(l: () -> Unit) { listeners.add(l) }

    @Synchronized
    fun removeListener(l: () -> Unit) { listeners.remove(l) }

    @Synchronized
    fun append(line: String) {
        val ts = java.text.SimpleDateFormat("HH:mm:ss.SSS", java.util.Locale.US).format(java.util.Date())
        val entry = "[$ts] $line"
        if (buffer.size >= 300) buffer.removeAt(0)
        buffer.add(entry)
        listeners.forEach { it() }
    }

    @Synchronized
    fun dump(): List<String> = ArrayList(buffer)

    @Synchronized
    fun clear() = buffer.clear()

    @Synchronized
    fun size(): Int = buffer.size
}
