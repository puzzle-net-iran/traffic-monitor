package ir.trafficmonitor.app.net

/**
 * استخراج نام دامنه از SNI (ClientHello) — برای HTTPS.
 * فقط اولین پیام ClientHello هر جریان؛ بایت‌های دست‌ها را رد می‌کنیم.
 */
object TlsParser {

    /**
     * @return نام دامنه SNI یا null اگر ClientHello کامل/پیدا نشد.
     */
    fun extractSni(data: ByteArray, offset: Int, length: Int): String? {
        if (length < 5) return null
        val contentType = data[offset].toInt() and 0xFF
        if (contentType != 0x16) return null // handshake
        // version (2) + length (2)
        val hsOff = offset + 5
        if (length < 9) return null
        val hsType = data[hsOff].toInt() and 0xFF
        if (hsType != 0x01) return null // ClientHello
        // 3-byte handshake length + version(2) + random(32) = از بایت 4
        var p = hsOff + 4
        if (hsOff + 4 + 2 + 32 > offset + length) return null
        p += 2 + 32 // version + random
        if (p + 1 > offset + length) return null
        val sessionIdLen = data[p].toInt() and 0xFF
        p += 1 + sessionIdLen
        if (p + 2 > offset + length) return null
        val cipherLen = ((data[p].toInt() and 0xFF) shl 8) or (data[p + 1].toInt() and 0xFF)
        p += 2 + cipherLen
        if (p + 1 > offset + length) return null
        val compressionLen = data[p].toInt() and 0xFF
        p += 1 + compressionLen
        if (p + 2 > offset + length) return null
        val extTotalLen = ((data[p].toInt() and 0xFF) shl 8) or (data[p + 1].toInt() and 0xFF)
        p += 2
        val extEnd = (p + extTotalLen).coerceAtMost(offset + length)
        var extType = 0
        while (p + 4 <= extEnd) {
            extType = ((data[p].toInt() and 0xFF) shl 8) or (data[p + 1].toInt() and 0xFF)
            val extLen = ((data[p + 2].toInt() and 0xFF) shl 8) or (data[p + 3].toInt() and 0xFF)
            p += 4
            if (p + extLen > extEnd) break
            if (extType == 0x0000) { // server_name
                val sni = parseSni(data, p, extLen)
                if (sni != null) return sni
            }
            p += extLen
        }
        return null
    }

    private fun parseSni(data: ByteArray, off: Int, len: Int): String? {
        if (len < 3) return null
        // server name list length (2) ; سپس یک ورودی: type(1) + nameLen(2) + name
        var p = off + 2
        val end = off + len
        while (p + 3 <= end) {
            val type = data[p].toInt() and 0xFF
            val nameLen = ((data[p + 1].toInt() and 0xFF) shl 8) or (data[p + 2].toInt() and 0xFF)
            p += 3
            if (p + nameLen > end) break
            if (type == 0x00 && nameLen > 0 && nameLen <= 253) {
                return String(data, p, nameLen, Charsets.US_ASCII)
            }
            p += nameLen
        }
        return null
    }
}
