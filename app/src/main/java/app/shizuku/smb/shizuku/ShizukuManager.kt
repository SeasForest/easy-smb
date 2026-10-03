package app.shizuku.smb.shizuku

import android.content.ComponentName
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.IBinder
import app.shizuku.smb.BuildConfig
import app.shizuku.smb.IShareService
import app.shizuku.smb.service.ShareService
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import rikka.shizuku.Shizuku

sealed interface ShizukuState {
    /** Shizuku isn't installed or its server isn't running. */
    data object NotRunning : ShizukuState
    /** Running, but too old to support user services. */
    data object Unsupported : ShizukuState
    data object PermissionRequired : ShizukuState
    data object PermissionDenied : ShizukuState
    /** [uid] is the Shizuku server's uid: 0 for root, 2000 for adb/shell. */
    data class Ready(val uid: Int) : ShizukuState
}

/** Tracks Shizuku availability and owns the connection to [ShareService]. */
class ShizukuManager {

    private val _state = MutableStateFlow<ShizukuState>(ShizukuState.NotRunning)
    val state: StateFlow<ShizukuState> = _state.asStateFlow()

    private val _service = MutableStateFlow<IShareService?>(null)
    val service: StateFlow<IShareService?> = _service.asStateFlow()

    private val serviceArgs = Shizuku.UserServiceArgs(
        ComponentName(BuildConfig.APPLICATION_ID, ShareService::class.java.name),
    )
        // Keep serving after the app is closed; stopping the server removes the process.
        .daemon(true)
        .processNameSuffix("smb")
        .debuggable(BuildConfig.DEBUG)
        .version(BuildConfig.VERSION_CODE)

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            _service.value = binder?.takeIf { it.pingBinder() }?.let(IShareService.Stub::asInterface)
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            _service.value = null
        }
    }

    private val binderReceived = Shizuku.OnBinderReceivedListener { refresh() }
    private val binderDead = Shizuku.OnBinderDeadListener {
        _service.value = null
        refresh()
    }
    private val permissionResult = Shizuku.OnRequestPermissionResultListener { code, _ ->
        if (code == PERMISSION_REQUEST_CODE) refresh()
    }

    fun register() {
        Shizuku.addBinderReceivedListenerSticky(binderReceived)
        Shizuku.addBinderDeadListener(binderDead)
        Shizuku.addRequestPermissionResultListener(permissionResult)
        refresh()
    }

    fun unregister() {
        Shizuku.removeBinderReceivedListener(binderReceived)
        Shizuku.removeBinderDeadListener(binderDead)
        Shizuku.removeRequestPermissionResultListener(permissionResult)
    }

    fun refresh() {
        val newState = when {
            !Shizuku.pingBinder() -> ShizukuState.NotRunning
            Shizuku.isPreV11() -> ShizukuState.Unsupported
            Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED ->
                ShizukuState.Ready(Shizuku.getUid())
            Shizuku.shouldShowRequestPermissionRationale() -> ShizukuState.PermissionDenied
            else -> ShizukuState.PermissionRequired
        }
        _state.value = newState
        // Reattach to a service that is still running from a previous app session.
        if (newState is ShizukuState.Ready && _service.value == null) bindService()
    }

    fun requestPermission() {
        if (Shizuku.pingBinder()) Shizuku.requestPermission(PERMISSION_REQUEST_CODE)
    }

    fun bindService() {
        if (_state.value is ShizukuState.Ready) Shizuku.bindUserService(serviceArgs, connection)
    }

    /** Stops the service process entirely. */
    fun removeService() {
        if (Shizuku.pingBinder()) Shizuku.unbindUserService(serviceArgs, connection, true)
        _service.value = null
    }

    private companion object {
        const val PERMISSION_REQUEST_CODE = 4445
    }
}
