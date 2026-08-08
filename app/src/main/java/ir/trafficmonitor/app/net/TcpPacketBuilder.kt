package ir.trafficmonitor.app.net

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/**
 * ساخت پکت‌های TCP/IP برای تزریق به tun: SYN-ACK ساختگی، ACK، FIN، RST.
 * همه چیز از صفر ساخته می‌شود و چک‌سام محاسبه می‌شود.
 */
object TcpPacketBuilder {

    /**
     * @param srcIp آی‌پی مبدا (سمت اپ / tun)
     * @param dstIp آی‌پی مقصد
     * @param srcPort پورت مبدا
     * @param dstPort پورت مقصد
     * @param seq شماره سکانس
     * @param ack شماره تایید
     * @param flags پرچم‌های TCP (SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04, PSH=0x08)
     * @param payload پیلود (اختیاری)
     * @param mss پنجره MSS در SYN (اختیاری)
     */
    fun build(
        srcIp: InetAddress, dstIp: InetAddress,
        srcPort: Int, dstPort: Int,
        seq: Long, ack: Long,
        flags: Int,
        payload: ByteArray = EMPTY,
        mss: Int = 0
    ): ByteArray {
        return when (dstIp) {
            is Inet4Address -> buildV4(srcIp, dstIp, srcPort, dstPort, seq, ack, flags, payload, mss)
            is Inet6Address -> buildV6(srcIp, dstIp, srcPort, dstPort, seq, ack, flags, payload, mss)
            else -> buildV4(srcIp, dstIp, srcPort, dstPort, seq, ack, flags, payload, mss)
        }
    }

    private fun buildV4(
        srcIp: InetAddress, dstIp: InetAddress,
        srcPort: Int, dstPort: Int,
        seq: Long, ack: Long,
        flags: Int, payload: ByteArray, mss: Int
    ): ByteArray {
        val tcpHdrLen = 20 + if (flags and 0x02 != 0 && mss > 0) 12 else 0
        val totalLen = 20 + tcpHdrLen + payload.size
        val buf = ByteArray(totalLen)
        // IPv4 header
        buf[0] = 0x45
        buf[1] = 0
        writeU16(buf, 2, totalLen)
        val id = nextId()
        writeU16(buf, 4, id)
        writeU16(buf, 6, 0x4000) // DF
        buf[8] = 64.toByte()    // TTL
        buf[9] = 6.toByte()     // TCP
        val src = srcIp.address
        val dst = dstIp.address
        System.arraycopy(src, 0, buf, 12, 4)
        System.arraycopy(dst, 0, buf, 16, 4)
        writeU16(buf, 10, ipv4Checksum(buf, 0, 20))
        // TCP header
        var p = 20
        writeU16(buf, p, srcPort); writeU16(buf, p + 2, dstPort)
        writeU32(buf, p + 4, seq)
        writeU32(buf, p + 8, ack)
        buf[p + 12] = ((tcpHdrLen / 4) shl 4).toByte()
        buf[p + 13] = flags.toByte()
        writeU16(buf, p + 14, 65535) // window
        writeU16(buf, p + 16, 0)     // checksum (بعداً)
        writeU16(buf, p + 18, 0)     // urgent
        p += 20
        if (flags and 0x02 != 0 && mss > 0) {
            buf[p] = 2; buf[p + 1] = 4
            writeU16(buf, p + 2, mss)
            buf[p + 4] = 4; buf[p + 5] = 2 // SACK permitted
            buf[p + 6] = 3; buf[p + 7] = 3; buf[p + 8] = 7 // WS 7
            p += 12
        }
        System.arraycopy(payload, 0, buf, p, payload.size)
        // TCP checksum با pseudo-header
        writeU16(buf, 16, tcpChecksumV4(src, dst, buf, 20, tcpHdrLen + payload.size))
        return buf
    }

    private fun buildV6(
        srcIp: InetAddress, dstIp: InetAddress,
        srcPort: Int, dstPort: Int,
        seq: Long, ack: Long,
        flags: Int, payload: ByteArray, mss: Int
    ): ByteArray {
        val tcpHdrLen = 20 + if (flags and 0x02 != 0 && mss > 0) 12 else 0
        val tcpLen = tcpHdrLen + payload.size
        val buf = ByteArray(40 + tcpLen)
        // IPv6 header
        buf[0] = 0x60.toByte()
        writeU16(buf, 4, tcpLen)
        buf[6] = 6.toByte() // next header TCP
        buf[7] = 64.toByte() // hop limit
        val src = srcIp.address
        val dst = dstIp.address
        System.arraycopy(src, 0, buf, 8, 16)
        System.arraycopy(dst, 0, buf, 24, 16)
        // TCP header
        var p = 40
        writeU16(buf, p, srcPort); writeU16(buf, p + 2, dstPort)
        writeU32(buf, p + 4, seq)
        writeU32(buf, p + 8, ack)
        buf[p + 12] = ((tcpHdrLen / 4) shl 4).toByte()
        buf[p + 13] = flags.toByte()
        writeU16(buf, p + 14, 65535)
        writeU16(buf, p + 16, 0)
        writeU16(buf, p + 18, 0)
        p += 20
        if (flags and 0x02 != 0 && mss > 0) {
            buf[p] = 2; buf[p + 1] = 4
            writeU16(buf, p + 2, mss)
            buf[p + 4] = 4; buf[p + 5] = 2
            buf[p + 6] = 3; buf[p + 7] = 3; buf[p + 8] = 7
            p += 12
        }
        System.arraycopy(payload, 0, buf, p, payload.size)
        writeU16(buf, 16, tcpChecksumV6(src, dst, buf, 40, tcpLen))
        return buf
    }

    private var ipIdCounter = 0
    private fun nextId(): Int {
        ipIdCounter = (ipIdCounter + 1) and 0xFFFF
        return ipIdCounter
    }

    private fun writeU16(b: ByteArray, off: Int, v: Int) {
        b[off] = (v ushr 8).toByte()
        b[off + 1] = v.toByte()
    }

    private fun writeU32(b: ByteArray, off: Int, v: Long) {
        b[off] = (v ushr 24).toByte()
        b[off + 1] = (v ushr 16).toByte()
        b[off + 2] = (v ushr 8).toByte()
        b[off + 3] = v.toByte()
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

    private fun tcpChecksumV4(src: ByteArray, dst: ByteArray, tcp: ByteArray, off: Int, len: Int): Int {
        var sum = 0L
        // pseudo-header
        for (i in 0 until 4 step 2) sum += ((src[i].toInt() and 0xFF) shl 8) or (src[i + 1].toInt() and 0xFF)
        for (i in 0 until 4 step 2) sum += ((dst[i].toInt() and 0xFF) shl 8) or (dst[i + 1].toInt() and 0xFF)
        sum += 6 // protocol
        sum += len
        return finishChecksum(sum, tcp, off, len)
    }

    private fun tcpChecksumV6(src: ByteArray, dst: ByteArray, tcp: ByteArray, off: Int, len: Int): Int {
        var sum = 0L
        for (i in 0 until 16 step 2) sum += ((src[i].toInt() and 0xFF) shl 8) or (src[i + 1].toInt() and 0xFF)
        for (i in 0 until 16 step 2) sum += ((dst[i].toInt() and 0xFF) shl 8) or (dst[i + 1].toInt() and 0xFF)
        sum += len
        sum += 6
        return finishChecksum(sum, tcp, off, len)
    }

    private fun finishChecksum(start: Long, tcp: ByteArray, off: Int, len: Int): Int {
        var sum = start
        var i = off
        val end = off + len
        while (i < end) {
            val b0 = tcp[i].toInt() and 0xFF
            val b1 = if (i + 1 < end) tcp[i + 1].toInt() and 0xFF else 0
            sum += (b0 shl 8) or b1
            i += 2
        }
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }

    private val EMPTY = ByteArray(0)
}
