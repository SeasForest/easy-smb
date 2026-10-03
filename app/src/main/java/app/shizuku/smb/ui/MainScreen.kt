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
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
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
        }
    }
}

@Composable
private fun ShizukuCard(state: ShizukuState, onRequestPermission: () -> Unit) {
    SectionCard("Shizuku") {
        val text = when (state) {
            ShizukuState.NotRunning -> "Shizuku is not running. Install Shizuku and start it, " +
                "then come back to this app."
            ShizukuState.Unsupported -> "This Shizuku version is too old. Please update Shizuku."
            ShizukuState.PermissionRequired -> "Easy SMB needs permission to use Shizuku."
            ShizukuState.PermissionDenied -> "Permission was denied. Grant it from the Shizuku app."
            is ShizukuState.Ready -> "Connected, running as " +
                if (state.uid == 0) "root." else "shell (uid ${state.uid})."
        }
        Text(text)
        if (state == ShizukuState.PermissionRequired) {
            Button(onClick = onRequestPermission) { Text("Grant permission") }
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
            Text(
                if (server.running) "Running" else "Stopped",
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
            addresses.forEach { address ->
                Text("smb://$address:${config.port}/${config.shareName}")
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
            OutlinedTextField(
                value = if (config.port == 0) "" else config.port.toString(),
                onValueChange = { value ->
                    value.ifEmpty { "0" }.toIntOrNull()?.let { port -> onChange { it.copy(port = port) } }
                },
                label = { Text("Port") },
                enabled = editable,
                singleLine = true,
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
