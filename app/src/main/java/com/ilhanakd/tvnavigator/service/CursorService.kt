package com.ilhanakd.tvnavigator.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.graphics.PixelFormat
import android.os.Build
import android.os.IBinder
import android.provider.Settings
import android.view.KeyEvent
import android.view.WindowManager
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.toDp
import androidx.core.app.NotificationCompat
import com.ilhanakd.tvnavigator.MainActivity
import com.ilhanakd.tvnavigator.R
import kotlin.math.roundToInt

class CursorService : Service() {

    private lateinit var windowManager: WindowManager
    private var overlayView: CursorOverlayView? = null

    override fun onCreate() {
        super.onCreate()
        windowManager = getSystemService(Context.WINDOW_SERVICE) as WindowManager
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())
        showCursorOverlay()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        showCursorOverlay()
        return START_STICKY
    }

    override fun onDestroy() {
        removeCursorOverlay()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun showCursorOverlay() {
        if (overlayView != null) return

        if (!Settings.canDrawOverlays(this)) {
            stopSelf()
            return
        }

        val metrics = resources.displayMetrics
        CursorManager.updateBounds(metrics.widthPixels.toFloat(), metrics.heightPixels.toFloat())
        CursorManager.centerCursor()

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
            } else {
                WindowManager.LayoutParams.TYPE_PHONE
            },
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE or
                WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN or
                WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS,
            PixelFormat.TRANSLUCENT
        )

        val view = CursorOverlayView(this)
        overlayView = view
        windowManager.addView(view, params)
    }

    private fun removeCursorOverlay() {
        overlayView?.let {
            windowManager.removeView(it)
        }
        overlayView = null
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.notification_channel_description)
            }
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_media_play)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(getString(R.string.notification_message))
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(pendingIntent)
            .build()
    }

    private fun exitApplication() {
        val exitIntent = Intent(this, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            putExtra(MainActivity.EXTRA_EXIT, true)
        }
        startActivity(exitIntent)
    }

    inner class CursorOverlayView(context: Context) : ComposeView(context) {
        init {
            isFocusable = true
            isFocusableInTouchMode = true
            setContent { CursorOverlay() }
        }

        override fun onKeyDown(keyCode: Int, event: KeyEvent): Boolean {
            when (keyCode) {
                KeyEvent.KEYCODE_DPAD_LEFT -> CursorManager.moveLeft()
                KeyEvent.KEYCODE_DPAD_RIGHT -> CursorManager.moveRight()
                KeyEvent.KEYCODE_DPAD_UP -> CursorManager.moveUp()
                KeyEvent.KEYCODE_DPAD_DOWN -> CursorManager.moveDown()
                KeyEvent.KEYCODE_ENTER, KeyEvent.KEYCODE_DPAD_CENTER -> {
                    CursorAccessibilityService.performClick(CursorManager.currentClickPoint())
                }
                KeyEvent.KEYCODE_BACK -> {
                    stopSelf()
                    exitApplication()
                    return true
                }
                else -> return super.onKeyDown(keyCode, event)
            }
            return true
        }
    }

    companion object {
        private const val CHANNEL_ID = "cursor_overlay_channel"
        private const val NOTIFICATION_ID = 1001
    }
}

@Composable
fun CursorOverlay() {
    val position = CursorManager.position
    val density = LocalDensity.current
    val cursorSizeDp = with(density) { CursorManager.CURSOR_SIZE.toDp() }

    Box(modifier = Modifier.fillMaxSize()) {
        Box(
            modifier = Modifier
                .align(Alignment.TopStart)
                .offset { IntOffset(position.x.roundToInt(), position.y.roundToInt()) }
                .size(cursorSizeDp)
                .clip(CircleShape)
                .background(color = Color.White.copy(alpha = 0.85f))
                .border(width = 2.dp, color = MaterialTheme.colorScheme.primary, shape = CircleShape)
        )
    }
}
