package app.shizuku.smb

import android.app.Application
import android.os.RemoteException
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import app.shizuku.smb.data.SettingsStore
import app.shizuku.smb.data.ShareConfig
import app.shizuku.smb.shizuku.ShizukuManager
import app.shizuku.smb.shizuku.ShizukuState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.net.Inet4Address
import java.net.NetworkInterface

data class ServerState(
    val running: Boolean = false,
    val busy: Boolean = false,
    val message: String? = null,
)

class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val store = SettingsStore(application)
    val shizuku = ShizukuManager()

    private val _config = MutableStateFlow(store.load())
    val config: StateFlow<ShareConfig> = _config.asStateFlow()

    private val _server = MutableStateFlow(ServerState())
    val server: StateFlow<ServerState> = _server.asStateFlow()

    init {
        shizuku.register()
        viewModelScope.launch {
            // Pick up the state of a service left running by a previous app session.
            shizuku.service.collect { service ->
                val running = service?.let { runCatching { it.isRunning }.getOrNull() } ?: false
                val message = service?.let { runCatching { it.status }.getOrNull() }
                _server.update { it.copy(running = running, message = message ?: it.message) }
            }
        }
    }

    fun updateConfig(transform: (ShareConfig) -> ShareConfig) {
        _config.update(transform)
        store.save(_config.value)
    }

    fun startServer() {
        val config = _config.value
        config.validate().firstOrNull()?.let { error ->
            _server.update { it.copy(message = error) }
            return
        }
        if (shizuku.state.value !is ShizukuState.Ready) {
            _server.update { it.copy(message = "Shizuku is not ready") }
            return
        }
        _server.update { it.copy(busy = true, message = "Starting…") }
        viewModelScope.launch {
            shizuku.bindService()
            val service = withTimeoutOrNull(SERVICE_TIMEOUT_MS) {
                shizuku.service.filterNotNull().first()
            }
            if (service == null) {
                _server.update { ServerState(message = "Could not start the Shizuku service") }
                return@launch
            }
            try {
                val error = service.start(
                    config.sharePath,
                    config.shareName,
                    config.port,
                    config.username,
                    config.password,
                    config.readOnly,
                )
                _server.value = ServerState(running = error == null, message = error ?: service.status)
            } catch (e: RemoteException) {
                _server.value = ServerState(message = "Service error: ${e.message}")
            }
        }
    }

    fun stopServer() {
        runCatching { shizuku.service.value?.stop() }
        shizuku.removeService()
        _server.value = ServerState(message = "Stopped")
    }

    /** IPv4 addresses clients on the local network can connect to. */
    fun localAddresses(): List<String> = runCatching {
        NetworkInterface.getNetworkInterfaces().toList()
            .filter { it.isUp && !it.isLoopback }
            .flatMap { it.inetAddresses.toList() }
            .filterIsInstance<Inet4Address>()
            .map { it.hostAddress.orEmpty() }
    }.getOrDefault(emptyList())

    override fun onCleared() {
        shizuku.unregister()
    }

    private companion object {
        const val SERVICE_TIMEOUT_MS = 10_000L
    }
}
