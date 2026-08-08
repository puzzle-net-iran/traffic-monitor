package ir.trafficmonitor.app.vpn

import android.net.VpnService
import ir.trafficmonitor.app.net.RawPacket
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * رله UDP: پکت‌های UDP از tun خوانده می‌شوند، به مقصد واقعی فرستاده می‌شوند،
 * و پاسخ‌ها به همان سوکت tun برگردانده می‌شوند.
 * برای هر جفت‌نشینی یک سوکت DatagramSocket اختصاص داده می‌شود.
 */
class UdpRelay(private val vpnService: VpnService) {

    private val sockets = ConcurrentHashMap<String, DatagramSocket>()
    private val listeners = mutableListOf<Thread>()
    @Volatile
    private var running = false

    fun start() {
        running = true
    }

    fun stop() {
        running = false
        for (s in sockets.values) runCatching { s.close() }
        sockets.clear()
    }

    /** ارسال یک پکت UDP از tun. */
    fun send(packet: RawPacket, tracker: ConnectionTracker, tunnel: java.io.FileOutputStream) {
        if (packet.payloadLength <= 0) return
        val srcIp = packet.srcIp ?: return
        val dstIp = packet.dstIp ?: return
        val key = "${srcIp.hostAddress}:${packet.localPort}-${dstIp.hostAddress}:${packet.remotePort()}"
        val payload = packet.payloadCopy()
        val socket = sockets.getOrPut(key) {
            DatagramSocket().also { s ->
                vpnService.protect(s)
                startListener(s, dstIp, srcIp, packet.remotePort(), packet.localPort(), key, tunnel, tracker)
            }
        }
        try {
            val dp = DatagramPacket(payload, payload.size, dstIp, packet.remotePort())
            socket.send(dp)
            tracker.onPacketAfterHandshake(srcIp, dstIp, packet.localPort(), packet.remotePort(), payload.size, true)
            tracker.onOutboundPacket(srcIp, dstIp, packet.localPort(), packet.remotePort(), 17, 0)
        } catch (e: Exception) {
            // خطا در ارسال — اتصال را می‌بندیم
            tracker.closeFlow(srcIp, dstIp, packet.localPort(), packet.remotePort(), true)
            sockets.remove(key)
        }
    }

    private fun startListener(
        socket: DatagramSocket, remoteIp: InetAddress, localIp: InetAddress,
        remotePort: Int, localPort: Int, key: String,
        tunnel: java.io.FileOutputStream, tracker: ConnectionTracker
    ) {
        val thread = Thread {
            val buf = ByteArray(2048)
            while (running && !socket.isClosed) {
                try {
                    val dp = DatagramPacket(buf, buf.size)
                    socket.soTimeout = 5000
                    socket.receive(dp)
                    // ساخت پکت UDP معکوس و نوشتن به tun
                    val response = buildUdpPacket(
                        srcIp = remoteIp, dstIp = localIp,
                        srcPort = remotePort, dstPort = localPort,
                        payload = dp.data.copyOfRange(0, dp.length)
                    )
                    synchronized(tunnel) { tunnel.write(response) }
                    tracker.onPacketAfterHandshake(localIp, remoteIp, localPort, remotePort, dp.length, false)
                } catch (e: java.net.SocketTimeoutException) {
                    // OK — بررسی وضعیت
                } catch (e: Exception) {
                    break
                }
            }
            sockets.remove(key)
        }.apply {
            isDaemon = true
            name = "udp-$key"
        }
        listeners.add(thread)
        thread.start()
    }

    private fun buildUdpPacket(
        srcIp: InetAddress, dstIp: InetAddress,
        srcPort: Int, dstPort: Int, payload: ByteArray
    ): ByteArray {
        val isV4 = srcIp.address.size == 4
        val hdrLen = if (isV4) 20 else 40
        val udpLen = 8 + payload.size
        val totalLen = hdrLen + udpLen
        val buf = ByteArray(totalLen)
        if (isV4) {
            val s = srcIp.address
            val d = dstIp.address
            buf[0] = 0x45
            buf[2] = (totalLen ushr 8).toByte(); buf[3] = totalLen.toByte()
            buf[8] = 64.toByte() // TTL
            buf[9] = 17.toByte() // UDP
            System.arraycopy(s, 0, buf, 12, 4)
            System.arraycopy(d, 0, buf, 16, 4)
            // IPv4 checksum
            writeU16(buf, 10, ipv4Checksum(buf, 0, 20))
            // UDP header
            var p = 20
            writeU16(buf, p, srcPort); writeU16(buf, p + 2, dstPort)
            writeU16(buf, p + 4, udpLen)
            writeU16(buf, p + 6, 0) // checksum = 0
            System.arraycopy(payload, 0, buf, p + 8, payload.size)
        } else {
            // IPv6
            buf[0] = 0x60.toByte()
            writeU16(buf, 4, udpLen)
            buf[6] = 17.toByte()
            buf[7] = 64.toByte()
            val s = srcIp.address
            val d = dstIp.address
            System.arraycopy(s, 0, buf, 8, 16)
            System.arraycopy(d, 0, buf, 24, 16)
            var p = 40
            writeU16(buf, p, srcPort); writeU16(buf, p + 2, dstPort)
            writeU16(buf, p + 4, udpLen)
            System.arraycopy(payload, 0, buf, p + 8, payload.size)
        }
        return buf
    }

    private fun writeU16(b: ByteArray, off: Int, v: Int) {
        b[off] = (v ushr 8).toByte()
        b[off + 1] = v.toByte()
    }

    private fun ipv4Checksum(b: ByteArray, off: Int, len: Int): Int {
        var sum = 0
        var i = off
        val end = off + len
        while (i < end) {
            sum += ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)
            i += 2
        }
        while (sum ushr 16 != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.inv() and 0xFFFF
    }
}
