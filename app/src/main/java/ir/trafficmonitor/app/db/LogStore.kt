package ir.trafficmonitor.app.db

import android.content.ContentValues
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import ir.trafficmonitor.app.model.ConnectionRecord
import org.json.JSONObject

class LogStore(private val db: AppDatabase) {

    private val buffer = ArrayList<ConnectionRecord>(512)

    @Synchronized
    fun insert(record: ConnectionRecord) {
        buffer.add(record)
        if (buffer.size >= FLUSH_BATCH) flush()
    }

    @Synchronized
    fun flush() {
        if (buffer.isEmpty()) return
        val records = ArrayList(buffer)
        buffer.clear()
        try {
            val wdb = db.writableDatabase
            wdb.beginTransaction()
            try {
                for (r in records) insertLocked(wdb, r)
                wdb.setTransactionSuccessful()
            } finally {
                wdb.endTransaction()
            }
        } catch (e: Exception) {
            synchronized(this) { buffer.addAll(0, records) }
        }
    }

    @Synchronized
    private fun insertLocked(wdb: SQLiteDatabase, r: ConnectionRecord) {
        val cv = ContentValues().apply {
            put("uid", r.uid)
            put("package_name", r.packageName)
            put("remote_host", r.remoteHost)
            put("remote_ip", r.remoteIp)
            put("remote_port", r.remotePort)
            put("local_port", r.localPort)
            put("protocol", r.protocol)
            put("is_tls", if (r.isTls) 1 else 0)
            put("sent_bytes", r.sentBytes)
            put("received_bytes", r.receivedBytes)
            put("created_at", r.createdAt)
            put("end_at", r.endAt)
            put("blocked", if (r.blocked) 1 else 0)
            put("blocked_rule", r.blockedRule)
            if (r.dnsQueries.isNotEmpty()) {
                put("dns_queries", JSONObject().put("q", r.dnsQueries).toString())
            }
            if (r.httpInfo != null) {
                put("http_info", JSONObject().apply {
                    put("method", r.httpInfo.method)
                    put("path", r.httpInfo.path)
                    put("headers", JSONObject(r.httpInfo.headers))
                    put("body", r.httpInfo.bodySnippet)
                }.toString())
            }
        }
        wdb.insert("connections", null, cv)
    }

    @Synchronized
    fun deleteOlderThan(horizonMillis: Long): Int {
        val wdb = db.writableDatabase
        return wdb.delete("connections", "created_at < ?", arrayOf(horizonMillis.toString()))
    }

    @Synchronized
    fun appTraffic(from: Long, to: Long): List<Pair<Int, LongArray>> {
        val out = HashMap<Int, LongArray>()
        db.readableDatabase.rawQuery(
            """
            SELECT uid, SUM(sent_bytes), SUM(received_bytes), COUNT(*), SUM(blocked)
            FROM connections
            WHERE created_at BETWEEN ? AND ?
            GROUP BY uid
            """.trimIndent(),
            arrayOf(from.toString(), to.toString())
        ).use { c ->
            while (c.moveToNext()) {
                val uid = c.getInt(0)
                out[uid] = longArrayOf(c.getLong(1), c.getLong(2), c.getLong(3), c.getLong(4))
            }
        }
        return out.map { it.key to it.value }.sortedByDescending { it.second[0] + it.second[1] }
    }

    @Synchronized
    fun recent(limit: Int): List<ConnectionRecord> {
        val out = ArrayList<ConnectionRecord>()
        db.readableDatabase.rawQuery(
            "SELECT * FROM connections ORDER BY created_at DESC LIMIT ?",
            arrayOf(limit.toString())
        ).use { c ->
            while (c.moveToNext()) out.add(readRecord(c))
        }
        return out
    }

    @Synchronized
    fun clearAll() {
        db.writableDatabase.delete("connections", null, null)
    }

    private fun readRecord(c: Cursor): ConnectionRecord {
        val col = { name: String -> c.getColumnIndexOrThrow(name) }
        return ConnectionRecord(
            id = c.getLong(col("id")),
            uid = c.getInt(col("uid")),
            packageName = c.getString(col("package_name")),
            remoteHost = c.getString(col("remote_host")),
            remoteIp = c.getString(col("remote_ip")),
            remotePort = c.getInt(col("remote_port")),
            localPort = c.getInt(col("local_port")),
            protocol = c.getString(col("protocol")) ?: "tcp",
            isTls = c.getInt(col("is_tls")) == 1,
            sentBytes = c.getLong(col("sent_bytes")),
            receivedBytes = c.getLong(col("received_bytes")),
            createdAt = c.getLong(col("created_at")),
            endAt = c.getLong(col("end_at")),
            blocked = c.getInt(col("blocked")) == 1,
            blockedRule = c.getString(col("blocked_rule")),
            dnsQueries = c.getString(col("dns_queries"))?.let { parseQueries(it) } ?: mutableListOf(),
            httpInfo = c.getString(col("http_info"))?.let { parseHttp(it) }
        )
    }

    private fun parseQueries(s: String): MutableList<String> {
        return try {
            val arr = JSONObject(s).optJSONArray("q")
            val list = mutableListOf<String>()
            for (i in 0 until (arr?.length() ?: 0)) list.add(arr.getString(i))
            list
        } catch (e: Exception) { mutableListOf() }
    }

    private fun parseHttp(s: String): ir.trafficmonitor.app.model.HttpInfo? {
        return try {
            val o = JSONObject(s)
            val hdr = JSONObject(o.optString("headers", "{}"))
            val map = HashMap<String, String>()
            hdr.keys().forEach { k -> map[k] = hdr.getString(k) }
            ir.trafficmonitor.app.model.HttpInfo(
                method = o.optString("method").takeIf { it.isNotEmpty() },
                path = o.optString("path").takeIf { it.isNotEmpty() },
                headers = map,
                bodySnippet = o.optString("body").takeIf { it.isNotEmpty() }
            )
        } catch (e: Exception) { null }
    }

    companion object {
        private const val FLUSH_BATCH = 200
    }
}
