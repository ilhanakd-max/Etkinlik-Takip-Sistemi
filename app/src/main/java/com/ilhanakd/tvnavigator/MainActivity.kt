package com.ilhanakd.tvnavigator

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.ilhanakd.tvnavigator.R
import com.ilhanakd.tvnavigator.service.CursorService
import com.ilhanakd.tvnavigator.ui.theme.TvMouseNavigatorTheme

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (intent?.getBooleanExtra(EXTRA_EXIT, false) == true) {
            finish()
            return
        }
        setContent {
            TvMouseNavigatorTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    ControlScreen(
                        onStart = { ensureOverlayPermissionAndStartService() },
                        onStop = { stopService(Intent(this, CursorService::class.java)) }
                    )
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        if (intent?.getBooleanExtra(EXTRA_EXIT, false) == true) {
            finish()
        }
    }

    private fun ensureOverlayPermissionAndStartService() {
        if (!Settings.canDrawOverlays(this)) {
            val intent = Intent(
                Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                Uri.parse("package:$packageName")
            )
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            startActivity(intent)
        } else {
            startCursorService()
        }
    }

    override fun onResume() {
        super.onResume()
        if (intent?.getBooleanExtra(EXTRA_EXIT, false) == true) {
            finish()
            return
        }
        if (Settings.canDrawOverlays(this)) {
            startCursorService()
        }
    }

    private fun startCursorService() {
        val serviceIntent = Intent(this, CursorService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent)
        } else {
            startService(serviceIntent)
        }
    }

    companion object {
        const val EXTRA_EXIT = "extra_exit"
    }
}

@Composable
private fun ControlScreen(onStart: () -> Unit, onStop: () -> Unit) {
    val context = LocalContext.current

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
        verticalArrangement = Arrangement.spacedBy(24.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Button(onClick = {
            if (Settings.canDrawOverlays(context)) {
                onStart()
            } else {
                val intent = Intent(
                    Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                    Uri.parse("package:${context.packageName}")
                )
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(intent)
            }
        }) {
            Text(text = context.getString(R.string.start_service))
        }

        Button(onClick = { onStop() }) {
            Text(text = context.getString(R.string.stop_service))
        }

        Button(onClick = { openAccessibilitySettings(context) }) {
            Text(text = context.getString(R.string.open_accessibility_settings))
        }
    }
}

private fun openAccessibilitySettings(context: Context) {
    val intent = Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    context.startActivity(intent)
}
