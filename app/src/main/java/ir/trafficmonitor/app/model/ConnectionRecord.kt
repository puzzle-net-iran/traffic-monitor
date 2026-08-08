package ir.trafficmonitor.app.model

/**
 * یک رکورد اتصال ثبت‌شده.
 *
 * یک جفت‌نشینی (flow) یک اتصال منطقی را نشان می‌دهد — مثلاً یک اتصال TCP از
 * یک اپ به یک سرور. برای اتصالاتی که از سمت اپ (بدون کانکشن میان‌افزار) باز
 * می‌شوند، endTime تا بسته شدن flow معلوم نمی‌شود، پس endTime = 0 یعنی «هنوز
 * بسته نشده» و حجم‌ها تجمعی هستند تا زمان بسته‌شدن (تخمین با TrafficStats).
 *
 * @property uid شناسه اپ (0 = ترافیک سیستم/هسته، یا نامشخص)
 * @property packageName نام بسته اپ (null اگر نامشخص)
 * @property remoteHost نام دامنه (از SNI یا DNS درخواستی) — IP اگر نامشخص باشد
 * @property remoteIp آی‌پی مقصد
 * @property remotePort پورت مقصد
 * @property localPort پورت محلی (سمت اپ)
 * @property protocol 'tcp' یا 'udp' یا 'other'
 * @property isTls آیا ترافیک TLS/HTTPS شناسایی شد
 * @property sentBytes بایت ارسال‌شده (از سمت اپ)
 * @property receivedBytes بایت دریافت‌شده (به سمت اپ)
 * @property createdAt زمان شروع اتصال (epochMillis)
 * @property endAt زمان پایان (0 = باز)
 * @property blocked آیا این اتصال توسط فایروال مسدود شد
 * @property blockedRule نام قانون مسدودکننده (مثلاً «اپ مسدود» یا «دامنه مسدود»)
 * @property dnsQueries نام‌های دامنه‌ای که این اپ پرسیده (برای تشخیص نام‌های بعدی)
 * @property httpInfo اطلاعات HTTP/HTTPS ساده استخراج‌شده (متد، مسیر، هدرها)
 */
data class ConnectionRecord(
    val id: Long = 0,
    val uid: Int = 0,
    val packageName: String? = null,
    val remoteHost: String? = null,
    val remoteIp: String? = null,
    val remotePort: Int = 0,
    val localPort: Int = 0,
    val protocol: String = "tcp",
    val isTls: Boolean = false,
    var sentBytes: Long = 0,
    var receivedBytes: Long = 0,
    val createdAt: Long = System.currentTimeMillis(),
    var endAt: Long = 0,
    var blocked: Boolean = false,
    var blockedRule: String? = null,
    val dnsQueries: MutableList<String> = mutableListOf(),
    val httpInfo: HttpInfo? = null
) {
    val isClosed: Boolean get() = endAt > 0
}
