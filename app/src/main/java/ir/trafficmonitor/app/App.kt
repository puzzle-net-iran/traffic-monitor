package ir.trafficmonitor.app

import android.app.Application
import ir.trafficmonitor.app.db.AppDatabase

class App : Application() {
    val database: AppDatabase by lazy { AppDatabase(this) }
}
