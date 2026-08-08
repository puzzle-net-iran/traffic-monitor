package ir.trafficmonitor.app.db

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/**
 * دیتابیس محلی (SQLite) برای لاگ اتصالات و قوانین فایروال.
 * جداول:
 *  - connections: هر اتصال ثبت‌شده
 *  - firewall_rules: قوانین فایروال
 *  - settings: تنظیمات ساده (شامل آستانه‌های متغیر)
 */
class AppDatabase(context: Context) : SQLiteOpenHelper(
    context, DB_NAME, null, DB_VERSION
) {

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uid INTEGER NOT NULL,
                package_name TEXT,
                remote_host TEXT,
                remote_ip TEXT,
                remote_port INTEGER,
                local_port INTEGER,
                protocol TEXT NOT NULL DEFAULT 'tcp',
                is_tls INTEGER NOT NULL DEFAULT 0,
                sent_bytes INTEGER NOT NULL DEFAULT 0,
                received_bytes INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                end_at INTEGER NOT NULL DEFAULT 0,
                blocked INTEGER NOT NULL DEFAULT 0,
                blocked_rule TEXT,
                dns_queries TEXT,
                http_info TEXT
            )
            """.trimIndent()
        )
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS firewall_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                allowed INTEGER NOT NULL,
                priority INTEGER NOT NULL DEFAULT 0
            )
            """.trimIndent()
        )
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
            """.trimIndent()
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS idx_conn_created ON connections(created_at)"
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS idx_conn_uid ON connections(uid)"
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        // نسخه‌های آینده: مهاجرت تدریجی. نسخه ۱ نیازی ندارد.
    }

    fun setSetting(key: String, value: String) {
        writableDatabase.execSQL(
            "INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)",
            arrayOf(key, value)
        )
    }

    fun getSetting(key: String, default: String): String {
        writableDatabase.rawQuery(
            "SELECT value FROM settings WHERE key = ?", arrayOf(key)
        ).use { c ->
            return if (c.moveToFirst()) c.getString(0) else default
        }
    }

    companion object {
        private const val DB_NAME = "traffic_monitor.db"
        private const val DB_VERSION = 1
    }
}
