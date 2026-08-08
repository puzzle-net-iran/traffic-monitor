package ir.trafficmonitor.app.net

import ir.trafficmonitor.app.model.HttpInfo

/**
 * پارس درخواست HTTP ساده (برای پورت ۸۰ یا متن‌هایی که شبیه HTTP هستند).
 * فقط خط اول + هدرها + چند بایت اول بدنه.
 */
object HttpParser {

    /**
     * @param data داده پکت (پیلود TCP)
     * @return HttpInfo یا null اگر درخواست HTTP نبود
     */
    fun parseRequest(data: ByteArray, offset: Int, length: Int): HttpInfo? {
        if (length < 14) return null
        val ascii = String(data, offset, length, Charsets.ISO_8859_1)
        val firstLineEnd = ascii.indexOf("\r\n")
        val firstLine = if (firstLineEnd >= 0) ascii.substring(0, firstLineEnd) else ascii
        val parts = firstLine.split(" ")
        if (parts.size < 3) return null
        val method = parts[0]
        if (method !in KNOWN_METHODS) return null
        val path = parts[1]
        val headers = linkedMapOf<String, String>()
        var bodyStart = length
        if (firstLineEnd >= 0) {
            var p = firstLineEnd + 2
            while (p + 2 <= length) {
                val lineEnd = indexOfCrlf(ascii, p)
                if (lineEnd < 0) break
                val line = ascii.substring(p, lineEnd)
                if (line.isEmpty()) { // انتهای هدرها
                    bodyStart = lineEnd + 2
                    break
                }
                val colon = line.indexOf(':')
                if (colon > 0) {
                    val key = line.substring(0, colon).trim().lowercase()
                    val value = line.substring(colon + 1).trim()
                    headers[key] = value
                }
                p = lineEnd + 2
            }
        }
        val bodySnippet = if (bodyStart < length) {
            String(data, offset + bodyStart, (length - bodyStart).coerceAtMost(1024), Charsets.ISO_8859_1)
        } else null
        return HttpInfo(
            method = method,
            path = path,
            headers = headers,
            bodySnippet = bodySnippet
        )
    }

    private fun indexOfCrlf(s: String, from: Int): Int {
        val i = s.indexOf("\r\n", from)
        return if (i >= 0) i else -1
    }

    private val KNOWN_METHODS = setOf(
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"
    )
}
