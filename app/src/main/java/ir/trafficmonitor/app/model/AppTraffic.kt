package ir.trafficmonitor.app.model

/** جمع حجم ترافیک یک اپ در یک بازه. */
data class AppTraffic(
    val uid: Int,
    val packageName: String?,
    val appLabel: String?,
    val sentBytes: Long,
    val receivedBytes: Long,
    val flowCount: Int,
    val blockedCount: Int
)
