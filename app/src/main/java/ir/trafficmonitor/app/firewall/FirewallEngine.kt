package ir.trafficmonitor.app.firewall

import ir.trafficmonitor.app.db.AppDatabase

object FirewallEngine {

    @Volatile private var db: AppDatabase? = null
    @Volatile private var rules: List<Rule> = emptyList()

    private data class Rule(val type: String, val value: String, val allowed: Boolean, val priority: Int)

    fun init(database: AppDatabase) {
        db = database
        reload()
    }

    fun reload() {
        val list = mutableListOf<Rule>()
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

    fun decide(packageName: String?, host: String?): String? {
        if (packageName == null && host == null) return null
        for (r in rules) {
            if (!r.allowed) {
                when (r.type) {
                    "app" -> if (packageName != null && wildcardMatch(r.value, packageName)) return r.value
                    "host" -> if (host != null && wildcardMatch(r.value, host)) return r.value
                }
            }
        }
        return null
    }

    fun decidePkg(packageName: String?, host: String?): String? = decide(packageName, host)

    private fun readRule(c: android.database.Cursor): Rule {
        return Rule(
            type = c.getString(c.getColumnIndexOrThrow("type")),
            value = c.getString(c.getColumnIndexOrThrow("value")),
            allowed = c.getInt(c.getColumnIndexOrThrow("allowed")) == 1,
            priority = c.getInt(c.getColumnIndexOrThrow("priority"))
        )
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
}
