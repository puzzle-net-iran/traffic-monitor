package ir.trafficmonitor.app.net

/**
 * پارس پرس‌وجوهای DNS (ساده، فقط سوال‌ها — بدون پاسخیابی عمیق).
 * برای UDP بندر ۵۳ هر دو جهت.
 */
object DnsParser {

    /**
     * @return نام دامنه پرسیده‌شده (اولین سوال) یا null اگر پرس‌وجوی معتبر نبود.
     */
    fun extractQuery(data: ByteArray, offset: Int, length: Int): String? {
        if (length < 12) return null
        // header: id(2) flags(2) qdcount(2) ...
        val flags = ((data[offset + 2].toInt() and 0xFF) shl 8) or
            (data[offset + 3].toInt() and 0xFF)
        val qr = (flags ushr 15) and 1
        if (qr != 0) return null // این یک پاسخ است
        val qdCount = ((data[offset + 4].toInt() and 0xFF) shl 8) or
            (data[offset + 5].toInt() and 0xFF)
        if (qdCount == 0) return null
        var p = offset + 12
        val end = offset + length
        // یک سوال: نام (labels) + type(2) + class(2)
        val name = StringBuilder()
        var labelLen = 0
        var hops = 0
        while (p < end) {
            labelLen = data[p].toInt() and 0xFF
            if (labelLen == 0) { p++; break }
            if (labelLen > 63) return null // فشرده‌سازی — برای سادگی رد می‌کنیم
            if (hops++ > 10) return null
            p++
            if (p + labelLen > end) return null
            if (name.isNotEmpty()) name.append('.')
            name.append(String(data, p, labelLen, Charsets.US_ASCII))
            p += labelLen
        }
        if (name.isEmpty()) return null
        return name.toString().lowercase()
    }
}
