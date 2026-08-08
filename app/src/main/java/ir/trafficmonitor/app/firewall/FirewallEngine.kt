package ir.trafficmonitor.app.firewall

import ir.trafficmonitor.app.db.AppDatabase

/**
 * موتور تصمیم‌گیری فایروال. قوانین به‌صورت کش در حافظه نگهداری می‌شوند
 * (reload از DB هنگام تغییر) تا تصمیم‌گیری در مسیر داده سریع باشد.
 */
object FirewallEngine {

    @Volatile
    private var db: AppDatabase? = null
    @Volatile
    private var rules: List<FirewallRuleEntry> = emptyList()

    private data class FirewallRuleEntry(val type: String, val value: String, val allowed: Boolean, val priority: Int)

    fun init(database: AppDatabase) {
        db = database
        reload()
    }

    fun reload() {
        val list = mutableListOf<FirewallRuleEntry>()
        db?.readableDatabase?.rawQuery(
            "SELECT * FROM firewall_rules ORDER BY priority DESC, id ASC", null
        )?.use { c ->
            while (c.moveToNext()) list.add(readRule(c))
        }
        rules = list
    }

    fun clearAll() {
        db?.writableDatabase?.delete("firewall_rules", null, null)
        rules = emptyList()
    }

    fun allRules(): List<Pair<String, String>> = rules.map { it.type to it.value }

    /**
     * تصمیم برای یک اتصال.
     * @return null = اجازه (پیش‌فرض)، یا String حاوی دلیل مسدودیت.
     */
    fun decide(packageName: String?, host: String?): String? {
        for (r in rules) {
            if (!r.allowed && matches(r, packageName, host)) return r.value
        }
        return null
    }

    private fun matches(r: FirewallRuleEntry, packageName: String?, host: String?): Boolean {
        return when (r.type) {
            "app" -> packageName != null && wildcardMatch(r.value, packageName)
            "host" -> host != null && wildcardMatch(r.value, host)
            else -> false
        }
    }

    fun wildcardMatch(pattern: String, value: String): Boolean {
        val p = pattern.lowercase()
        val v = value.lowercase()
        if (p == "*" || p == v) return true
        if (!p.contains('*')) return p == v
        val regex = buildString {
            append('^')
            for (ch in p) {
                when (ch) {
                    '*' -> append(".*")
                    '.' -> append("\\.")
                    else -> append(Regex.escape(ch.toString()))
                }
            }
            append('$')
        }
        return runCatching { Regex(regex).matches(v) }.getOrDefault(false)
    }

    private fun readRule(c: android.database.Cursor): FirewallRuleEntry {
        return FirewallRuleEntry(
            type = c.getString(c.getColumnIndexOrThrow("type")),
            value = c.getString(c.getColumnIndexOrThrow("value")),
            allowed = c.getInt(c.getColumnIndexOrThrow("allowed")) == 1,
            priority = c.getInt(c.getColumnIndexOrThrow("priority"))
        )
    }
}
