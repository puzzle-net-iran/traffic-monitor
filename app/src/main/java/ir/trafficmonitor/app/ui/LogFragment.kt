package ir.trafficmonitor.app.ui

import android.os.Bundle
import android.text.format.DateFormat
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import ir.trafficmonitor.app.R
import ir.trafficmonitor.app.databinding.FragmentLogBinding
import ir.trafficmonitor.app.vpn.LogBuffer

class LogFragment : Fragment() {

    private var _binding: FragmentLogBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentLogBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        binding.rvLog.layoutManager = LinearLayoutManager(requireContext())
        binding.rvLog.adapter = StringLogAdapter()
        refresh()
    }

    private fun refresh() {
        val items = LogBuffer.dump().reversed()
        (binding.rvLog.adapter as? StringLogAdapter)?.submit(items)
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    override fun onDestroyView() { _binding = null; super.onDestroyView() }
}

class StringLogAdapter : androidx.recyclerview.widget.RecyclerView.Adapter<StringLogAdapter.VH>() {
    private var items: List<String> = emptyList()
    fun submit(list: List<String>) { items = list; notifyDataSetChanged() }
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val v = LayoutInflater.from(parent.context).inflate(R.layout.item_log, parent, false); return VH(v)
    }
    override fun onBindViewHolder(h: VH, pos: Int) {
        val s = items[pos]
        h.tvTime.text = ""
        h.tvProto.text = ""
        h.tvApp.text = s
        h.tvDestination.text = ""
        h.tvSizes.text = ""
        h.tvTls.visibility = View.GONE
    }
    override fun getItemCount() = items.size
    class VH(v: View) : androidx.recyclerview.widget.RecyclerView.ViewHolder(v) {
        val tvTime: TextView = v.findViewById(R.id.tv_time)
        val tvProto: TextView = v.findViewById(R.id.tv_proto)
        val tvApp: TextView = v.findViewById(R.id.tv_app)
        val tvDestination: TextView = v.findViewById(R.id.tv_destination)
        val tvSizes: TextView = v.findViewById(R.id.tv_sizes)
        val tvTls: TextView = v.findViewById(R.id.tv_tls)
    }
}