package ir.trafficmonitor.app.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import ir.trafficmonitor.app.R
import ir.trafficmonitor.app.databinding.FragmentAppsBinding
import ir.trafficmonitor.app.db.AppDatabase
import ir.trafficmonitor.app.firewall.FirewallEngine
import ir.trafficmonitor.app.model.FirewallRule
import ir.trafficmonitor.app.util.AppResolver

class AppsFragment : Fragment() {

    private var _binding: FragmentAppsBinding? = null
    private val binding get() = _binding!!
    private val resolver by lazy { AppResolver(requireContext()) }
    private val db by lazy { (requireContext().applicationContext as ir.trafficmonitor.app.App).database }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentAppsBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        binding.rvApps.layoutManager = LinearLayoutManager(requireContext())
        binding.btnResetRules.setOnClickListener {
            FirewallEngine.clearAll()
            refresh()
        }
        refresh()
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    private fun refresh() {
        val apps = resolver.internetApps()
        val rules = AppDatabase.db.readableDatabase?.rawQuery(
            "SELECT * FROM firewall_rules WHERE type = 'app' ORDER BY priority DESC, id ASC", null
        )?.use { it } ?: return

        val appRules = mutableMapOf<String, Boolean>()
        while (rules.moveToNext()) {
            val pkg = rules.getString(rules.getColumnIndexOrThrow("value"))
            val allowed = rules.getInt(rules.getColumnIndexOrThrow("allowed")) == 1
            appRules[pkg] = !allowed
        }

        binding.rvApps.adapter = AppsAdapter(apps, appRules) { app, block ->
            if (block) {
                val cv = android.content.ContentValues().apply {
                    put("type", "app")
                    put("value", app.packageName)
                    put("allowed", 0)
                    put("priority", 100)
                }
                db.writableDatabase.insert("firewall_rules", null, cv)
            } else {
                db.writableDatabase.delete("firewall_rules", "type = 'app' AND value = ?", arrayOf(app.packageName))
            }
            FirewallEngine.reload()
            refresh()
        }
    }

    override fun onDestroyView() {
        _binding = null
        super.onDestroyView()
    }
}

class AppsAdapter(
    private val apps: List<AppResolver.AppInfo>,
    private val blockedPkgs: Map<String, Boolean>,
    private val onToggle: (AppResolver.AppInfo, Boolean) -> Unit
) : androidx.recyclerview.widget.RecyclerView.Adapter<AppsAdapter.VH>() {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val v = LayoutInflater.from(parent.context).inflate(R.layout.item_app, parent, false)
        return VH(v)
    }

    override fun onBindViewHolder(h: VH, pos: Int) {
        val app = apps[pos]
        h.tvLabel.text = app.label ?: app.packageName
        val blocked = blockedPkgs[app.packageName] == true
        h.switchBlock.isChecked = !blocked
        h.switchBlock.setOnCheckedChangeListener(null)
        h.switchBlock.setOnCheckedChangeListener { _, checked ->
            onToggle(app, !checked) // checked=toggle off → block
        }
        h.ivIcon.setImageResource(android.R.drawable.sym_def_app_icon)
    }

    override fun getItemCount() = apps.size

    class VH(v: View) : androidx.recyclerview.widget.RecyclerView.ViewHolder(v) {
        val tvLabel: TextView = v.findViewById(R.id.tv_label)
        val ivIcon: ImageView = v.findViewById(R.id.iv_icon)
        val switchBlock: com.google.android.material.switchmaterial.SwitchMaterial = v.findViewById(R.id.switch_block)
    }
}