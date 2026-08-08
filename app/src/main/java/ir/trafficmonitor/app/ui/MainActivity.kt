package ir.trafficmonitor.app.ui

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.view.Menu
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.widget.addTextChangedListener
import ir.trafficmonitor.app.R
import ir.trafficmonitor.app.databinding.ActivityMainBinding
import ir.trafficmonitor.app.vpn.VpnManager

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)
        binding.toolbar.setTitle(R.string.app_name)

        binding.bottomNav.setOnItemSelectedListener { item ->
            val id = item.itemId
            val navIds = mapOf(
                R.id.nav_dashboard to "dashboard",
                R.id.nav_apps to "apps",
                R.id.nav_log to "log",
                R.id.nav_settings to "settings"
            )
            val name = navIds[id] ?: return@setOnItemSelectedListener false
            val fm = supportFragmentManager
            val fragment = when (name) {
                "apps" -> AppsFragment()
                "log" -> LogFragment()
                "settings" -> SettingsFragment()
                else -> DashboardFragment()
            }
            fm.beginTransaction()
                .replace(R.id.nav_host_fragment, fragment, name)
                .commit()
            true
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.main_menu, menu)
        val toggle = menu.findItem(R.id.action_toggle)
        updateToggle(toggle)
        return true
    }

    override fun onOptionsItemSelected(item: android.view.MenuItem): Boolean {
        if (item.itemId == R.id.action_toggle) {
            toggleVpn()
            return true
        }
        return super.onOptionsItemSelected(item)
    }

    private fun toggleVpn() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            // اولین بار: درخواست مجوز از کاربر
            startActivityForResult(intent, REQ_VPN_PREPARE)
            return
        }
        sendToggleBroadcast()
    }

    private fun sendToggleBroadcast() {
        val i = Intent(VpnManager.ACTION_TOGGLE_VPN).apply { setPackage(packageName) }
        sendBroadcast(i)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN_PREPARE && resultCode == RESULT_OK) {
            sendToggleBroadcast()
        }
    }

    override fun onResume() {
        super.onResume()
        invalidateOptionsMenu()
    }

    private fun updateToggle(item: android.view.MenuItem) {
        val running = VpnManager.isRunning(this)
        item.setIcon(
            ContextCompat.getDrawable(
                this,
                if (running) R.drawable.ic_pause else R.drawable.ic_play
            )
        )
    }

    companion object {
        private const val REQ_VPN_PREPARE = 42
    }
}
