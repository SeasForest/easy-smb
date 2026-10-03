package app.shizuku.smb

import android.app.Application
import android.os.RemoteException
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import app.shizuku.smb.data.SettingsStore
import app.shizuku.smb.data.ShareConfig
import app.shizuku.smb.shizuku.ShizukuManager
import app.shizuku.smb.shizuku.ShizukuState
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
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
    val clientCount: Int = 0,
    val log: String = "",
)

class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val store = SettingsStore(application)
    val shizuku = ShizukuManager()

    private val _config = MutableStateFlow(store.load())
    val config: StateFlow<ShareConfig> = _config.asStateFlow()

    private val _server = MutableStateFlow(ServerState())
    val server: StateFlow<ServerState> = _server.asStateFlow()

    private var pollJob: Job? = null

    init {
        shizuku.register()
        viewModelScope.launch {
            // Reattach to the service if the user left the server on in a previous app session.
            shizuku.state.collect { state ->
                if (state is ShizukuState.Ready && store.serverEnabled && shizuku.service.value == null) {
                    shizuku.bindService()
                }
            }
        }
        viewModelScope.launch {
            shizuku.service.collect { service ->
                if (service == null) {
                    _server.update { it.copy(running = false) }
                    return@collect
                }
                if (_server.value.busy) return@collect
                val running = runCatching { service.isRunning }.getOrDefault(false)
                if (!running && store.serverEnabled) {
                    // The service process was restarted (e.g. Shizuku restarted); start again.
                    startServer()
                } else {
                    val message = runCatching { service.status }.getOrNull()
                    _server.update { it.copy(running = running, message = message ?: it.message) }
                }
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
            store.serverEnabled = false
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
                store.serverEnabled = false
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
                store.serverEnabled = error == null
                _server.value = ServerState(
                    running = error == null,
                    message = error ?: service.status,
                    log = service.log.orEmpty(),
                )
            } catch (e: RemoteException) {
                store.serverEnabled = false
                _server.value = ServerState(message = "Service error: ${e.message}")
            }
        }
    }

    fun stopServer() {
        store.serverEnabled = false
        runCatching { shizuku.service.value?.stop() }
        shizuku.removeService()
        _server.update { ServerState(message = "Stopped", log = it.log) }
    }

    /** Refreshes live server details (clients, activity) while the screen is visible. */
    fun setVisible(visible: Boolean) {
        pollJob?.cancel()
        pollJob = null
        if (!visible) return
        pollJob = viewModelScope.launch {
            while (true) {
                refreshDetails()
                delay(POLL_INTERVAL_MS)
            }
        }
    }

    private fun refreshDetails() {
        val service = shizuku.service.value ?: return
        if (_server.value.busy) return
        try {
            val running = service.isRunning
            val clients = if (running) service.clientCount else 0
            val log = service.log.orEmpty()
            _server.update { it.copy(running = running, clientCount = clients, log = log) }
        } catch (e: RemoteException) {
            // The service died; ShizukuManager reports the disconnect separately.
        }
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
        const val POLL_INTERVAL_MS = 2_000L
    }
}
