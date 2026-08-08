package ir.trafficmonitor.app.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import ir.trafficmonitor.app.R
import ir.trafficmonitor.app.databinding.FragmentDashboardBinding
import ir.trafficmonitor.app.db.LogStore
import ir.trafficmonitor.app.model.AppTraffic
import ir.trafficmonitor.app.util.AppResolver
import ir.trafficmonitor.app.util.FormatUtils
import kotlinx.coroutines.launch

class DashboardFragment : Fragment() {

    private var _binding: FragmentDashboardBinding? = null
    private val binding get() = _binding!!
    private val resolver by lazy { AppResolver(requireContext()) }
    private val logStore by lazy { LogStore((requireContext().applicationContext as ir.trafficmonitor.app.App).database) }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentDashboardBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        binding.rvTopApps.layoutManager = LinearLayoutManager(requireContext())
        refresh()
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    private fun refresh() {
        lifecycleScope.launch {
            val now = System.currentTimeMillis()
            val dayStart = now - 24 * 60 * 60 * 1000
            val traffic = logStore.appTraffic(dayStart, now)
            val apps = resolver.internetApps()
            val appMap = apps.associateBy { it.uid }
            val items = traffic.map { (uid, vals) ->
                val app = appMap[uid]
                AppTraffic(
                    uid = uid,
                    packageName = app?.packageName,
                    appLabel = app?.label ?: app?.packageName ?: "UID $uid",
                    sentBytes = vals[0],
                    receivedBytes = vals[1],
                    flowCount = vals[2].toInt(),
                    blockedCount = vals[3].toInt()
                )
            }
            requireActivity().runOnUiThread {
                binding.rvTopApps.adapter = TopAppsAdapter(items)
                val totalSent = traffic.sumOf { it.second[0] }
                val totalRecv = traffic.sumOf { it.second[1] }
                binding.tvSent.text = FormatUtils.formatBytes(totalSent)
                binding.tvReceived.text = FormatUtils.formatBytes(totalRecv)
                binding.tvFlows.text = traffic.sumOf { it.second[2] }.toString()
                binding.tvBlocked.text = traffic.sumOf { it.second[3] }.toString()
            }
        }
    }

    override fun onDestroyView() {
        _binding = null
        super.onDestroyView()
    }
}

class TopAppsAdapter(
    private val items: List<AppTraffic> = emptyList()
) : androidx.recyclerview.widget.RecyclerView.Adapter<TopAppsAdapter.VH>() {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_stat_card, parent, false)
        return VH(view)
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        val t = items[position]
        holder.tvLabel.text = t.appLabel
        holder.tvValue.text = "${FormatUtils.formatBytes(t.sentBytes + t.receivedBytes)} (${t.flowCount} اتصال)"
    }

    override fun getItemCount() = items.size

    class VH(view: View) : androidx.recyclerview.widget.RecyclerView.ViewHolder(view) {
        val tvLabel: TextView = view.findViewById(R.id.tv_label)
        val tvValue: TextView = view.findViewById(R.id.tv_value)
    }
}
