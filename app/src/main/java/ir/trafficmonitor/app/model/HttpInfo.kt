package ir.trafficmonitor.app.model

/**
 * اطلاعات ساده از ترافیک HTTP (پورت 80 یا متن درخواست).
 * برای HTTPS فقط دامنه (SNI) و گواهی ثبت می‌شود؛ بدنه رمزنگاری‌شده است.
 */
data class HttpInfo(
    val method: String? = null,      // GET / POST / ...
    val path: String? = null,        // /index.html?x=1
    val headers: Map<String, String> = emptyMap(),
    val bodySnippet: String? = null  // تا ۱ کیلوبایت از بدنه درخواست (فقط HTTP)
)
