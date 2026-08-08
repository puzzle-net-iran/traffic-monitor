package ir.trafficmonitor.app.ui

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import ir.trafficmonitor.app.R
import ir.trafficmonitor.app.databinding.FragmentLogBinding
import ir.trafficmonitor.app.vpn.LogBuffer

class LogFragment : Fragment() {

    private var _binding: FragmentLogBinding? = null
    private val binding get() = _binding!!
    private val handler = Handler(Looper.getMainLooper())
    private var lastLogSize = 0

    private val refreshRunnable = object : Runnable {
        override fun run() {
            if (_binding != null) {
                refresh()
                handler.postDelayed(this, 500)
            }
        }
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentLogBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        binding.rvLog.layoutManager = LinearLayoutManager(requireContext())
        binding.rvLog.adapter = LogAdapter()
        lastLogSize = 0
        refresh()
    }

    override fun onResume() {
        super.onResume()
        handler.post(refreshRunnable)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(refreshRunnable)
    }

    private fun refresh() {
        val current = LogBuffer.dump()
        if (current.size != lastLogSize) {
            lastLogSize = current.size
            (binding.rvLog.adapter as? LogAdapter)?.submit(current.reversed())
        }
    }

    override fun onDestroyView() {
        _binding = null
        super.onDestroyView()
    }
}

class LogAdapter : androidx.recyclerview.widget.RecyclerView.Adapter<LogAdapter.VH>() {
    private var items: List<String> = emptyList()

    fun submit(list: List<String>) {
        items = list
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val v = LayoutInflater.from(parent.context).inflate(R.layout.item_log, parent, false)
        return VH(v)
    }

    override fun onBindViewHolder(h: VH, pos: Int) {
        val line = items[pos]
        h.tvApp.text = line
        h.tvTime.text = ""
        h.tvProto.text = ""
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
