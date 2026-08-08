package ir.trafficmonitor.app.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import ir.trafficmonitor.app.R
import ir.trafficmonitor.app.databinding.FragmentSettingsBinding
import ir.trafficmonitor.app.prefs.SettingsStore
import kotlinx.coroutines.launch

class SettingsFragment : Fragment() {

    private var _binding: FragmentSettingsBinding? = null
    private val binding get() = _binding!!
    private val settings by lazy { SettingsStore(requireContext()) }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentSettingsBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        binding.switchAutoStart.isChecked = settings.autoStartVpn
        binding.switchAutoStart.setOnCheckedChangeListener { _, checked ->
            settings.autoStartVpn = checked
        }
        binding.switchBlockOnExit.isChecked = settings.blockOnExit
        binding.switchBlockOnExit.setOnCheckedChangeListener { _, checked ->
            settings.blockOnExit = checked
        }
        binding.sliderRetention.value = settings.retentionDays.toFloat()
        binding.tvRetentionValue.text = "${settings.retentionDays} روز"
        binding.sliderRetention.addOnChangeListener { _, value, _ ->
            val days = value.toInt()
            settings.retentionDays = days
            binding.tvRetentionValue.text = "$days روز"
        }
        binding.btnClearLog.setOnClickListener {
            val db = (requireContext().applicationContext as ir.trafficmonitor.app.App).database
            db.writableDatabase.delete("connections", null, null)
        }
    }

    override fun onDestroyView() {
        _binding = null
        super.onDestroyView()
    }
}