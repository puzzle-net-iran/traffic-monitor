package ir.trafficmonitor.app.model

/**
 * قانون فایروال: اجازه یا مسدود کردن بر اساس اپ یا دامنه.
 *
 * @property type 'app' برای کل اپ، 'host' برای دامنه (الگوی * پشتیبانی می‌شود)
 * @property value برای 'app' شناسه بسته (packageName)، برای 'host' نام دامنه یا الگو
 * @property allowed true = اجازه، false = مسدود
 * @property priority ترتیب ارزیابی؛ هرچه بزرگ‌تر اول بررسی شود
 */
data class FirewallRule(
    val id: Long = 0,
    val type: String,
    val value: String,
    val allowed: Boolean,
    val priority: Int = 0
)
