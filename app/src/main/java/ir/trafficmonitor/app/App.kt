package ir.trafficmonitor.app

import android.app.Application
import ir.trafficmonitor.app.db.AppDatabase
import ir.trafficmonitor.app.firewall.FirewallEngine

class App : Application() {
    val database: AppDatabase by lazy { AppDatabase(this) }

    override fun onCreate() {
        super.onCreate()
        FirewallEngine.init(database)
    }
}
