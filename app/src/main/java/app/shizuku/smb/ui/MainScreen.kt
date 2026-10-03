package app.shizuku.smb.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.shizuku.smb.MainViewModel
import app.shizuku.smb.ServerState
import app.shizuku.smb.data.ShareConfig
import app.shizuku.smb.data.StoragePaths
import app.shizuku.smb.shizuku.ShizukuState

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(viewModel: MainViewModel) {
    val shizukuState by viewModel.shizuku.state.collectAsStateWithLifecycle()
    val config by viewModel.config.collectAsStateWithLifecycle()
    val server by viewModel.server.collectAsStateWithLifecycle()

    Scaffold(topBar = { TopAppBar(title = { Text("Easy SMB") }) }) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            ShizukuCard(shizukuState, onRequestPermission = viewModel.shizuku::requestPermission)
            ServerCard(
                server = server,
                config = config,
                enabled = shizukuState is ShizukuState.Ready,
                addresses = remember(server.running) { viewModel.localAddresses() },
                onStart = viewModel::startServer,
                onStop = viewModel::stopServer,
            )
            ShareCard(
                config = config,
                editable = !server.running && !server.busy,
                onChange = viewModel::updateConfig,
            )
            if (server.log.isNotBlank()) ActivityCard(server.log)
        }
    }
}

@Composable
private fun ShizukuCard(state: ShizukuState, onRequestPermission: () -> Unit) {
    val context = LocalContext.current
    val shizukuLaunchIntent = remember {
        context.packageManager.getLaunchIntentForPackage(SHIZUKU_PACKAGE)
    }
    SectionCard("Shizuku") {
        val text = when (state) {
            ShizukuState.NotRunning -> if (shizukuLaunchIntent == null) {
                "Shizuku is not installed. Install it from shizuku.rikka.app or Google Play, " +
                    "then start it with wireless debugging or root."
            } else {
                "Shizuku is installed but not running. Open Shizuku and start it, then come back."
            }
            ShizukuState.Unsupported -> "This Shizuku version is too old. Update Shizuku to v11 or newer."
            ShizukuState.PermissionRequired -> "Easy SMB needs Shizuku permission to read the " +
                "shared folder and run the server."
            ShizukuState.PermissionDenied -> "Shizuku permission was denied. Allow Easy SMB in " +
                "the Shizuku app under \"Authorized applications\"."
            is ShizukuState.Ready -> if (state.uid == 0) {
                "Ready. Running as root."
            } else {
                "Ready. Running as shell (uid ${state.uid}), so the server needs a port of 1024 or above."
            }
        }
        Text(text)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (state == ShizukuState.PermissionRequired) {
                Button(onClick = onRequestPermission) { Text("Grant permission") }
            }
            val showOpen = state == ShizukuState.NotRunning || state == ShizukuState.PermissionDenied ||
                state == ShizukuState.Unsupported
            if (showOpen && shizukuLaunchIntent != null) {
                OutlinedButton(onClick = { context.startActivity(shizukuLaunchIntent) }) {
                    Text("Open Shizuku")
                }
            }
        }
    }
}

@Composable
private fun ServerCard(
    server: ServerState,
    config: ShareConfig,
    enabled: Boolean,
    addresses: List<String>,
    onStart: () -> Unit,
    onStop: () -> Unit,
) {
    SectionCard("Server") {
        Row(verticalAlignment = Alignment.CenterVertically) {
            val title = when {
                !server.running -> "Stopped"
                server.clientCount == 1 -> "Running · 1 client"
                else -> "Running · ${server.clientCount} clients"
            }
            Text(
                title,
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.weight(1f),
            )
            Switch(
                checked = server.running,
                enabled = (enabled || server.running) && !server.busy,
                onCheckedChange = { if (it) onStart() else onStop() },
            )
        }
        server.message?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        if (server.running) {
            if (addresses.isEmpty()) {
                Text("No network connection. Connect to Wi-Fi so other devices can reach this phone.")
            }
            addresses.forEach { address ->
                SelectionContainer {
                    Text(
                        "smb://$address:${config.port}/${config.shareName}",
                        style = MaterialTheme.typography.bodyLarge,
                        fontFamily = FontFamily.Monospace,
                    )
                }
            }
            addresses.firstOrNull()?.let { address ->
                Text(
                    "Sign in as \"${config.username}\". Windows 11 (24H2 or newer): " +
                        "net use Z: \\\\$address\\${config.shareName} /TCPPORT:${config.port} " +
                        "/USER:${config.username}",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

@Composable
private fun ActivityCard(log: String) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    SectionCard("Activity") {
        val lines = log.lines()
        val shown = if (expanded) lines else lines.takeLast(COLLAPSED_LOG_LINES)
        SelectionContainer {
            Text(
                shown.joinToString("\n"),
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
            )
        }
        if (lines.size > COLLAPSED_LOG_LINES) {
            TextButton(onClick = { expanded = !expanded }) {
                Text(if (expanded) "Show less" else "Show all")
            }
        }
    }
}

@Composable
private fun ShareCard(
    config: ShareConfig,
    editable: Boolean,
    onChange: ((ShareConfig) -> ShareConfig) -> Unit,
) {
    var pickerError by remember { mutableStateOf<String?>(null) }
    val folderPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree(),
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        val path = StoragePaths.treeUriToPath(uri.toString())
        pickerError = if (path == null) "That location can't be shared; pick a folder on device storage." else null
        if (path != null) onChange { it.copy(sharePath = path) }
    }

    SectionCard("Shared folder") {
        OutlinedTextField(
            value = config.sharePath,
            onValueChange = { value -> onChange { it.copy(sharePath = value) } },
            label = { Text("Folder path") },
            enabled = editable,
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedButton(onClick = { folderPicker.launch(null) }, enabled = editable) {
            Text("Choose folder")
        }
        pickerError?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        OutlinedTextField(
            value = config.shareName,
            onValueChange = { value -> onChange { it.copy(shareName = value) } },
            label = { Text("Share name") },
            enabled = editable,
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Read-only", modifier = Modifier.weight(1f))
            Switch(
                checked = config.readOnly,
                enabled = editable,
                onCheckedChange = { value -> onChange { it.copy(readOnly = value) } },
            )
        }
        Row {
            OutlinedTextField(
                value = config.username,
                onValueChange = { value -> onChange { it.copy(username = value.trim()) } },
                label = { Text("Username") },
                enabled = editable,
                singleLine = true,
                modifier = Modifier.weight(1f),
            )
            Spacer(Modifier.width(8.dp))
            // Kept as text so the field can be cleared while typing; invalid input maps to 0,
            // which validation reports.
            var portText by rememberSaveable { mutableStateOf(config.port.toString()) }
            OutlinedTextField(
                value = portText,
                onValueChange = { value ->
                    val digits = value.filter(Char::isDigit).take(5)
                    portText = digits
                    onChange { it.copy(port = digits.toIntOrNull() ?: 0) }
                },
                label = { Text("Port") },
                enabled = editable,
                singleLine = true,
                isError = config.port !in ShareConfig.MIN_PORT..ShareConfig.MAX_PORT,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.width(110.dp),
            )
        }
        OutlinedTextField(
            value = config.password,
            onValueChange = { value -> onChange { it.copy(password = value) } },
            label = { Text("Password") },
            enabled = editable,
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth(),
        )
        val problems = config.validate()
        if (problems.isNotEmpty()) {
            problems.forEach {
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun SectionCard(title: String, content: @Composable () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(title, style = MaterialTheme.typography.titleLarge)
            content()
        }
    }
}

private const val SHIZUKU_PACKAGE = "moe.shizuku.privileged.api"
private const val COLLAPSED_LOG_LINES = 5
