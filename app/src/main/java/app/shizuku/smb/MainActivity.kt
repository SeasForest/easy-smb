package app.shizuku.smb

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import app.shizuku.smb.ui.MainScreen
import app.shizuku.smb.ui.theme.EasySmbTheme

class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            EasySmbTheme {
                MainScreen(viewModel)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // Shizuku may have been started or stopped while we were in the background.
        viewModel.shizuku.refresh()
        viewModel.setVisible(true)
    }

    override fun onPause() {
        super.onPause()
        viewModel.setVisible(false)
    }
}
