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
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class TrafficVpnService : VpnService() {

    private var pfd: ParcelFileDescriptor? = null
    private var input: FileInputStream? = null
    private var output: FileOutputStream? = null
    private var loopThread: Thread? = null
    private val pool: ExecutorService = Executors.newFixedThreadPool(4)
    private val running = AtomicBoolean(false)

    private val tcpFlows = ConcurrentHashMap<String, TcpFlow>()
    private val udpFlows = ConcurrentHashMap<String, UdpFlow>()
    private val dnsCache = ConcurrentHashMap<String, String>()
    private val uidCache = ConcurrentHashMap<Int, String>()

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
            addDnsServer("8.8.8.8")
            addDnsServer("8.8.4.4")
            setMtu(1400)
            setBlocking(true)
            setConfigureIntent(PendingIntent.getActivity(this@TrafficVpnService, 0, Intent(this@TrafficVpnService, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE))
        }
        pfd = builder.establish()
        if (pfd == null) { running.set(false); stopSelf(); return }
        input = AutoCloseInputStream(pfd!!)
        output = FileOutputStream(pfd!!.fileDescriptor)
        loopThread = Thread(this::loop, "vpn-loop").apply { isDaemon = true; start() }
    }

    private fun loop() {
        val buf = ByteArray(32767)
        while (running.get()) {
            try {
                val len = input?.read(buf) ?: break
                if (len <= 0) continue
                val pkt = Pkt(buf, len) ?: continue
                pool.execute { handle(pkt) }
            } catch (e: Exception) {
                if (running.get()) e.printStackTrace()
                break
            }
        }
        stopVpn()
    }

    private class Pkt(val buf: ByteArray, val len: Int) {
        var srcIp: ByteArray = ByteArray(0); var dstIp: ByteArray = ByteArray(0)
        var srcPort = 0; var dstPort = 0; var proto = 0; var tcpFlags = 0
        var payloadOff = 0; var payloadLen = 0; var seq = 0L; var ack = 0L; var ipv4 = true

        fun key(): String = "${ipStr(srcIp)}:$srcPort-${ipStr(dstIp)}:$dstPort"
        fun payload(): ByteArray = buf.copyOfRange(payloadOff, payloadOff + payloadLen)
        fun ipStr(b: ByteArray): String = try { InetAddress.getByAddress(b).hostAddress ?: "?" } catch (e: Exception) { "?" }
    }

    private fun parse(buf: ByteArray, len: Int): Pkt? {
        if (len < 20) return null
        val ver = (buf[0].toInt() ushr 4) and 0xF
        val pkt = Pkt(buf, len)
        if (ver == 4) {
            val ihl = (buf[0].toInt() and 0x0F) * 4
            if (len < ihl + 4) return null
            pkt.ipv4 = true
            pkt.proto = buf[9].toInt() and 0xFF
            pkt.srcIp = buf.copyOfRange(12, 16)
            pkt.dstIp = buf.copyOfRange(16, 20)
            parseTransport(pkt, ihl)
        } else if (ver == 6) {
            if (len < 40) return null
            pkt.ipv4 = false
            pkt.proto = buf[6].toInt() and 0xFF
            pkt.srcIp = buf.copyOfRange(8, 24)
            pkt.dstIp = buf.copyOfRange(24, 40)
            parseTransport(pkt, 40)
        } else return null
        return pkt
    }

    private fun parseTransport(pkt: Pkt, off: Int) {
        val buf = pkt.buf; val end = pkt.len
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

    private fun handle(pkt: Pkt) {
        if (pkt.proto == 6) handleTcp(pkt)
        else if (pkt.proto == 17) handleUdp(pkt)
    }

    private fun handleTcp(pkt: Pkt) {
        val key = pkt.key()
        val syn = pkt.tcpFlags and 0x02 != 0
        val ack = pkt.tcpFlags and 0x10 != 0
        val fin = pkt.tcpFlags and 0x01 != 0
        val rst = pkt.tcpFlags and 0x04 != 0

        if (fin || rst) {
            tcpFlows.remove(key)?.let { it.close(); LogBuffer.append("CLOSE $key") }
            return
        }
        if (syn && !ack) {
            val flow = TcpFlow(pkt.srcIp, pkt.dstIp, pkt.srcPort, pkt.dstPort, pkt.ack, pkt.seq + 1)
            tcpFlows[key] = flow
            writeTcp(pkt.dstIp, pkt.srcIp, pkt.dstPort, pkt.srcPort, flow.seqRx, flow.ackRx, 0x12)
            flow.seqRx++
            LogBuffer.append("NEW TCP ${pkt.ipStr(pkt.dstIp)}:${pkt.dstPort} -> ${pkt.ipStr(pkt.srcIp)}:${pkt.srcPort}")
            return
        }
        val flow = tcpFlows[key] ?: return
        if (pkt.payloadLen > 0) {
            flow.ackRx = (pkt.seq + pkt.payloadLen) and 0xFFFFFFFFL
            flow.ackRx = (flow.ackRx + 1) and 0xFFFFFFFFL
            writeTcp(pkt.dstIp, pkt.srcIp, pkt.dstPort, pkt.srcPort, flow.seqRx, flow.ackRx, 0x10)
            LogBuffer.append("DATA ${pkt.ipStr(pkt.dstIp)}:${pkt.dstPort} ${pkt.payloadLen}B")
        }
        if (ack && pkt.payloadLen == 0 && flow.acked.compareAndSet(false, true)) {
            LogBuffer.append("ACK ${pkt.ipStr(pkt.dstIp)}:${pkt.dstPort}")
        }
    }

    private fun handleUdp(pkt: Pkt) {
        if (pkt.payloadLen == 0) return
        LogBuffer.append("UDP ${pkt.ipStr(pkt.dstIp)}:${pkt.dstPort} ${pkt.payloadLen}B")
        if (pkt.dstPort == 53) {
            val domain = extractDnsName(pkt.buf, pkt.payloadOff, pkt.payloadLen)
            if (domain.isNotEmpty()) {
                dnsCache[pkt.ipStr(pkt.srcIp)] = domain
                LogBuffer.append("DNS $domain")
            }
            val resp = ByteArray(pkt.payloadLen)
            System.arraycopy(pkt.buf, pkt.payloadOff, resp, 0, pkt.payloadLen.coerceAtMost(resp.size))
            if (resp.size >= 4) {
                resp[2] = (resp[2].toInt() or 0x80).toByte()
            }
            writeUdp(pkt.dstIp, pkt.srcIp, pkt.dstPort, pkt.srcPort, resp)
        }
    }

    private fun extractDnsName(buf: ByteArray, off: Int, len: Int): String {
        if (len < 13) return ""
        var p = off + 12; val end = off + len; val sb = StringBuilder()
        while (p < end) {
            val n = buf[p].toInt() and 0xFF
            if (n == 0) break
            if (n > 63) break
            p++
            if (p + n > end) break
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(buf, p, n))
            p += n
        }
        return sb.toString().lowercase()
    }

    private fun writeTcp(srcIp: ByteArray, dstIp: ByteArray, sp: Int, dp: Int, seq: Long, ack: Long, flags: Int) {
        val tcp = ByteArray(20)
        setU16(tcp, 0, sp); setU16(tcp, 2, dp)
        setU32(tcp, 4, seq); setU32(tcp, 8, ack)
        tcp[12] = 0x50.toByte(); tcp[13] = flags.toByte()
        setU16(tcp, 14, 65535)
        setU16(tcp, 16, tcpChecksum(srcIp, dstIp, tcp))
        val ip = buildIp(srcIp, dstIp, 6, tcp)
        output?.write(ip)
    }

    private fun writeUdp(srcIp: ByteArray, dstIp: ByteArray, sp: Int, dp: Int, payload: ByteArray) {
        val udp = ByteArray(8 + payload.size)
        setU16(udp, 0, sp); setU16(udp, 2, dp); setU16(udp, 4, 8 + payload.size)
        System.arraycopy(payload, 0, udp, 8, payload.size)
        setU16(udp, 6, tcpChecksum(srcIp, dstIp, udp))
        val ip = buildIp(srcIp, dstIp, 17, udp)
        output?.write(ip)
    }

    private fun buildIp(src: ByteArray, dst: ByteArray, proto: Int, transport: ByteArray): ByteArray {
        val total = 20 + transport.size
        val buf = ByteArray(total)
        buf[0] = 0x45; setU16(buf, 2, total); buf[8] = 64; buf[9] = proto.toByte()
        System.arraycopy(src, 0, buf, 12, 4); System.arraycopy(dst, 0, buf, 16, 4)
        setU16(buf, 10, ipv4Checksum(buf))
        System.arraycopy(transport, 0, buf, 20, transport.size)
        return buf
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            val ch = NotificationChannel("vpn_status", getString(R.string.vpn_channel_name), NotificationManager.IMPORTANCE_LOW).apply {
                description = getString(R.string.vpn_channel_desc); setShowBadge(false)
            }
            nm.createNotificationChannel(ch)
        }
    }

    private fun buildNotification(): Notification {
        val pi = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, "vpn_status")
            .setContentTitle(getString(R.string.vpn_title))
            .setContentText(getString(R.string.vpn_text))
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(pi).setOngoing(true).build()
    }

    private fun stopVpn() {
        if (!running.getAndSet(false)) return
        tcpFlows.values.forEach { it.close() }; tcpFlows.clear()
        udpFlows.values.forEach { it.sock.close() }; udpFlows.clear()
        runCatching { pfd?.close() }
        pfd = null; input = null; output = null
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) stopForeground(STOP_FOREGROUND_REMOVE)
        else @Suppress("DEPRECATION") stopForeground(true)
        stopSelf()
    }

    override fun onDestroy() { runCatching { unregisterReceiver(toggleReceiver) }; stopVpn(); super.onDestroy() }
    override fun onRevoke() { stopVpn(); super.onRevoke() }

    private class TcpFlow(srcIp: ByteArray, dstIp: ByteArray, sp: Int, dp: Int, initSeq: Long, initAck: Long) {
        fun close() { runCatching { socket?.close() } }
    }

    private class UdpFlow(val sock: DatagramSocket)

    companion object {
        const val ACTION_TOGGLE = "ir.trafficmonitor.TOGGLE_VPN"
        const val ACTION_STOP = "ir.trafficmonitor.STOP_VPN"

        private fun u16(b: ByteArray, off: Int) = ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)
        private fun u32(b: ByteArray, off: Int): Long = ((b[off].toLong() and 0xFF) shl 24) or ((b[off+1].toLong() and 0xFF) shl 16) or ((b[off+2].toLong() and 0xFF) shl 8) or (b[off+3].toLong() and 0xFF)
        private fun setU16(b: ByteArray, off: Int, v: Int) { b[off] = (v ushr 8).toByte(); b[off+1] = v.toByte() }
        private fun setU32(b: ByteArray, off: Int, v: Long) { b[off]=(v ushr 24).toByte(); b[off+1]=(v ushr 16).toByte(); b[off+2]=(v ushr 8).toByte(); b[off+3]=v.toByte() }

        private fun ipv4Checksum(buf: ByteArray): Int {
            var sum = 0; var i = 0; val end = 20
            while (i < end) { sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i+1].toInt() and 0xFF); i += 2 }
            while (sum ushr 16 != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
            return sum.inv() and 0xFFFF
        }

        private fun tcpChecksum(src: ByteArray, dst: ByteArray, transport: ByteArray): Int {
            var sum = 0L
            for (i in 0 until 16 step 2) { sum += ((src[i].toInt() and 0xFF) shl 8) or (src[i+1].toInt() and 0xFF); sum += ((dst[i].toInt() and 0xFF) shl 8) or (dst[i+1].toInt() and 0xFF) }
            sum += transport.size; sum += 6
            var i = 0; while (i < transport.size - 1) { sum += ((transport[i].toInt() and 0xFF) shl 8) or (transport[i+1].toInt() and 0xFF); i += 2 }
            if (i < transport.size) sum += (transport[i].toInt() and 0xFF) shl 8
            while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
            return (sum.inv() and 0xFFFF).toInt()
        }
    }
}

object LogBuffer {
    private val buffer = ArrayList<String>(200)
    @Synchronized fun append(line: String) { if (buffer.size > 200) buffer.removeAt(0); buffer.add(line) }
    @Synchronized fun dump(): List<String> = ArrayList(buffer)
    @Synchronized fun clear() = buffer.clear()
}
