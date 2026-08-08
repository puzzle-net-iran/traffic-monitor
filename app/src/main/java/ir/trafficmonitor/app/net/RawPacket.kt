package ir.trafficmonitor.app.net

import java.net.InetAddress

/**
 * پکت خام از tun. آی‌پی‌ها به‌صورت بایت (۴ یا ۱۶) نگهداری می‌شوند؛
 * از InetAddress برای نمایش و مقایسه استفاده می‌کنیم.
 */
class RawPacket(
    val data: ByteArray,
    val offset: Int,
    val length: Int,
    val isIpv4: Boolean,
    val srcIp: InetAddress?,
    val dstIp: InetAddress?,
    val protocol: Int,           // 6=TCP, 17=UDP, 1=ICMP, 0=نامشخص
    val srcPort: Int,
    val dstPort: Int,
    val payloadOffset: Int,
    val payloadLength: Int,
    val srcIpBytes: ByteArray,
    val dstIpBytes: ByteArray,
    val totalLength: Int,
    val ipHeaderLength: Int,
    val tcpFlags: Int,           // برای TCP
    val tcpSeq: Long,            // برای TCP
    val tcpAck: Long
) {
    val isTcp: Boolean get() = protocol == 6
    val isUdp: Boolean get() = protocol == 17

    fun payloadCopy(): ByteArray = data.copyOfRange(payloadOffset, payloadOffset + payloadLength)

    fun remotePort(): Int = dstPort
    fun localPort(): Int = srcPort

    companion object {
        /**
         * پارس پکت. VpnService پکت‌های IP خام (بدون هدر اترنت) تحویل می‌دهد؛
         * برای اطمینان اگر هدر اترنت بود هم پشتیبانی می‌کنیم.
         */
        fun parse(data: ByteArray, offset: Int, length: Int): RawPacket? {
            if (length < 1) return null
            val firstNibble = (data[offset].toInt() ushr 4) and 0xF
            if (firstNibble == 4 || firstNibble == 6) {
                return parseIp(data, offset, length)
            }
            // اترنت اختیاری (تست‌ها / شبیه‌سازها)
            if (length < 14) return null
            val etherType = ((data[offset + 12].toInt() and 0xFF) shl 8) or
                (data[offset + 13].toInt() and 0xFF)
            var ipOff = offset + 14
            var ipLen = length - 14
            if (etherType == 0x8100) { // VLAN
                if (length < 18) return null
                ipOff += 4
                ipLen -= 4
            }
            return parseIp(data, ipOff, ipLen)
        }

        private fun parseIp(data: ByteArray, off: Int, len: Int): RawPacket? {
            if (len < 1) return null
            return when ((data[off].toInt() ushr 4) and 0xF) {
                4 -> parseIpv4(data, off, len)
                6 -> parseIpv6(data, off, len)
                else -> null
            }
        }

        private fun parseIpv4(data: ByteArray, off: Int, len: Int): RawPacket? {
            if (len < 20) return null
            val ihl = (data[off].toInt() and 0x0F) * 4
            if (ihl < 20 || len < ihl) return null
            val totalLen = ((data[off + 2].toInt() and 0xFF) shl 8) or
                (data[off + 3].toInt() and 0xFF)
            val proto = data[off + 9].toInt() and 0xFF
            val src = data.copyOfRange(off + 12, off + 16)
            val dst = data.copyOfRange(off + 16, off + 20)
            val hdrLen = ihl
            val payloadOff = off + hdrLen
            val payloadLen = (totalLen - hdrLen).coerceAtMost(len - hdrLen).coerceAtLeast(0)
            return when (proto) {
                6 -> parseTcp(data, off, len, payloadOff, payloadLen, src, dst, proto, true)
                17 -> parseUdp(data, off, len, payloadOff, payloadLen, src, dst, proto, true)
                else -> RawPacket(
                    data, off, len, true,
                    InetAddress.getByAddress(src), InetAddress.getByAddress(dst),
                    proto, 0, 0, payloadOff, payloadLen, src, dst, totalLen, hdrLen,
                    0, 0, 0
                )
            }
        }

        private fun parseIpv6(data: ByteArray, off: Int, len: Int): RawPacket? {
            if (len < 40) return null
            val payloadLenField = ((data[off + 4].toInt() and 0xFF) shl 8) or
                (data[off + 5].toInt() and 0xFF)
            val proto = data[off + 6].toInt() and 0xFF
            val src = data.copyOfRange(off + 8, off + 24)
            val dst = data.copyOfRange(off + 24, off + 40)
            val hdrLen = 40
            val payloadLen = payloadLenField.coerceAtMost(len - hdrLen).coerceAtLeast(0)
            val payloadOff = off + hdrLen
            return when (proto) {
                6 -> parseTcp(data, off, len, payloadOff, payloadLen, src, dst, proto, false)
                17 -> parseUdp(data, off, len, payloadOff, payloadLen, src, dst, proto, false)
                44, 51, 50 -> {
                    // Fragment/ESP/AH — برای سادگی بدون پارس عمیق؛ ترافیک باز می‌ماند
                    RawPacket(
                        data, off, len, false,
                        InetAddress.getByAddress(src), InetAddress.getByAddress(dst),
                        proto, 0, 0, payloadOff, payloadLen, src, dst, payloadLen, hdrLen,
                        0, 0, 0
                    )
                }
                else -> RawPacket(
                    data, off, len, false,
                    InetAddress.getByAddress(src), InetAddress.getByAddress(dst),
                    proto, 0, 0, payloadOff, payloadLen, src, dst, payloadLen, hdrLen,
                    0, 0, 0
                )
            }
        }

        private fun parseTcp(
            data: ByteArray, ipOff: Int, ipLen: Int,
            payloadOff: Int, payloadLen: Int,
            src: ByteArray, dst: ByteArray, proto: Int, isV4: Boolean
        ): RawPacket? {
            if (payloadLen < 20) return null
            val srcPort = ((data[payloadOff].toInt() and 0xFF) shl 8) or
                (data[payloadOff + 1].toInt() and 0xFF)
            val dstPort = ((data[payloadOff + 2].toInt() and 0xFF) shl 8) or
                (data[payloadOff + 3].toInt() and 0xFF)
            val seq = readUInt(data, payloadOff + 4)
            val ack = readUInt(data, payloadOff + 8)
            val dataOff = ((data[payloadOff + 12].toInt() ushr 4) and 0xF) * 4
            if (dataOff < 20 || dataOff > payloadLen) return null
            val flags = data[payloadOff + 13].toInt() and 0xFF
            val appOff = payloadOff + dataOff
            val appLen = payloadLen - dataOff
            return RawPacket(
                data, ipOff, ipLen, isV4,
                InetAddress.getByAddress(src), InetAddress.getByAddress(dst),
                proto, srcPort, dstPort, appOff, appLen, src, dst, ipLen, 0,
                flags, seq, ack
            )
        }

        private fun parseUdp(
            data: ByteArray, ipOff: Int, ipLen: Int,
            payloadOff: Int, payloadLen: Int,
            src: ByteArray, dst: ByteArray, proto: Int, isV4: Boolean
        ): RawPacket? {
            if (payloadLen < 8) return null
            val srcPort = ((data[payloadOff].toInt() and 0xFF) shl 8) or
                (data[payloadOff + 1].toInt() and 0xFF)
            val dstPort = ((data[payloadOff + 2].toInt() and 0xFF) shl 8) or
                (data[payloadOff + 3].toInt() and 0xFF)
            val appOff = payloadOff + 8
            val appLen = payloadLen - 8
            return RawPacket(
                data, ipOff, ipLen, isV4,
                InetAddress.getByAddress(src), InetAddress.getByAddress(dst),
                proto, srcPort, dstPort, appOff, appLen, src, dst, ipLen, 0,
                0, 0, 0
            )
        }

        private fun readUInt(data: ByteArray, off: Int): Long {
            return ((data[off].toLong() and 0xFF) shl 24) or
                ((data[off + 1].toLong() and 0xFF) shl 16) or
                ((data[off + 2].toLong() and 0xFF) shl 8) or
                (data[off + 3].toLong() and 0xFF)
        }
    }
}
