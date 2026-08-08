package ir.trafficmonitor.app.ui

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import ir.trafficmonitor.app.R
import ir.trafficmonitor.app.databinding.ActivityMainBinding
import ir.trafficmonitor.app.stats.NetworkStatsReader
import ir.trafficmonitor.app.util.AppResolver
import ir.trafficmonitor.app.util.FormatUtils
import ir.trafficmonitor.app.util.UsageAccessHelper
import java.util.Timer
import kotlin.concurrent.timer

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val resolver by lazy { AppResolver(this) }
    private var refreshTimer: Timer? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)

        binding.rvApps.layoutManager = LinearLayoutManager(this)

        binding.btnGrantPermission.setOnClickListener {
            UsageAccessHelper.openUsageAccessSettings(this)
        }

        refreshData()
    }

    override fun onResume() {
        super.onResume()
        refreshData()
        refreshTimer = timer(period = 3000) { runOnUiThread { refreshData() } }
    }

    override fun onPause() {
        super.onPause()
        refreshTimer?.cancel()
        refreshTimer = null
    }

    private fun refreshData() {
        val hasAccess = UsageAccessHelper.hasUsageAccess(this)
        binding.layoutPermission.visibility = if (hasAccess) android.view.View.GONE else android.view.View.VISIBLE
        if (!hasAccess) return

        val usages = NetworkStatsReader.snapshot(this).sortedByDescending { it.rxBytes + it.txBytes }
        val items = usages.map { usage ->
            val app = resolver.getInfo(usage.uid)
            AppTrafficItem(
                label = app?.label ?: "UID ${usage.uid}",
                sub = app?.packageName ?: "",
                rx = usage.rxBytes,
                tx = usage.txBytes
            )
        }

        val totalRx = usages.sumOf { it.rxBytes }
        val totalTx = usages.sumOf { it.txBytes }

        binding.tvTotalReceived.text = FormatUtils.formatBytes(totalRx)
        binding.tvTotalSent.text = FormatUtils.formatBytes(totalTx)
        binding.tvAppCount.text = usages.size.toString()

        binding.rvApps.adapter = AppTrafficAdapter(items)
    }

    override fun onDestroy() {
        refreshTimer?.cancel()
        super.onDestroy()
    }
}

data class AppTrafficItem(
    val label: String,
    val sub: String,
    val rx: Long,
    val tx: Long
)

class AppTrafficAdapter(private val items: List<AppTrafficItem>) :
    androidx.recyclerview.widget.RecyclerView.Adapter<AppTrafficAdapter.VH>() {

    override fun onCreateViewHolder(parent: android.view.ViewGroup, viewType: Int): VH {
        val v = android.view.LayoutInflater.from(parent.context)
            .inflate(R.layout.item_app_traffic, parent, false)
        return VH(v)
    }

    override fun onBindViewHolder(h: VH, pos: Int) {
        val item = items[pos]
        h.tvLabel.text = item.label
        h.tvSub.text = item.sub
        h.tvRx.text = "↓ ${FormatUtils.formatBytes(item.rx)}"
        h.tvTx.text = "↑ ${FormatUtils.formatBytes(item.tx)}"
    }

    override fun getItemCount() = items.size

    class VH(v: android.view.View) : androidx.recyclerview.widget.RecyclerView.ViewHolder(v) {
        val tvLabel: android.widget.TextView = v.findViewById(R.id.tv_label)
        val tvSub: android.widget.TextView = v.findViewById(R.id.tv_sub)
        val tvRx: android.widget.TextView = v.findViewById(R.id.tv_rx)
        val tvTx: android.widget.TextView = v.findViewById(R.id.tv_tx)
    }
}