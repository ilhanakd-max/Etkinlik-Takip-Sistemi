package com.ilhanakd.tvnavigator.service

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.accessibilityservice.GestureDescription.StrokeDescription
import android.content.Intent
import android.graphics.Path
import android.graphics.PointF
import android.hardware.input.InputManager
import android.os.SystemClock
import android.view.InputDevice
import android.view.InputEvent
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.accessibility.AccessibilityEvent
import androidx.core.content.getSystemService
import com.ilhanakd.tvnavigator.MainActivity

class CursorAccessibilityService : AccessibilityService() {

    override fun onServiceConnected() {
        super.onServiceConnected()
        instance = this
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) = Unit

    override fun onInterrupt() = Unit

    override fun onKeyEvent(event: KeyEvent): Boolean {
        if (event.action != KeyEvent.ACTION_DOWN) return super.onKeyEvent(event)
        return when (event.keyCode) {
            KeyEvent.KEYCODE_DPAD_LEFT -> {
                CursorManager.moveLeft(); true
            }
            KeyEvent.KEYCODE_DPAD_RIGHT -> {
                CursorManager.moveRight(); true
            }
            KeyEvent.KEYCODE_DPAD_UP -> {
                CursorManager.moveUp(); true
            }
            KeyEvent.KEYCODE_DPAD_DOWN -> {
                CursorManager.moveDown(); true
            }
            KeyEvent.KEYCODE_ENTER, KeyEvent.KEYCODE_DPAD_CENTER -> {
                performClick(CursorManager.currentClickPoint()); true
            }
            KeyEvent.KEYCODE_BACK -> {
                applicationContext.stopService(Intent(applicationContext, CursorService::class.java))
                exitApplication()
                true
            }
            else -> super.onKeyEvent(event)
        }
    }

    override fun onDestroy() {
        if (instance == this) {
            instance = null
        }
        super.onDestroy()
    }

    private fun injectMotionEvent(event: MotionEvent): Boolean {
        val inputManager: InputManager? = getSystemService()
        if (inputManager != null) {
            return try {
                val method = InputManager::class.java.getMethod(
                    "injectInputEvent",
                    InputEvent::class.java,
                    Integer.TYPE
                )
                method.isAccessible = true
                method.invoke(inputManager, event, 0) as? Boolean ?: false
            } catch (t: Throwable) {
                false
            }
        }
        return false
    }

    private fun dispatchGestureFallback(point: PointF) {
        val path = Path().apply {
            moveTo(point.x, point.y)
            lineTo(point.x, point.y)
        }
        val gesture = GestureDescription.Builder()
            .addStroke(StrokeDescription(path, 0, 100))
            .build()
        dispatchGesture(gesture, null, null)
    }

    private fun sendTap(point: PointF) {
        val downTime = SystemClock.uptimeMillis()
        val downEvent = MotionEvent.obtain(
            downTime,
            downTime,
            MotionEvent.ACTION_DOWN,
            point.x,
            point.y,
            0
        )
        val upEvent = MotionEvent.obtain(
            downTime,
            downTime + 80,
            MotionEvent.ACTION_UP,
            point.x,
            point.y,
            0
        )
        downEvent.source = InputDevice.SOURCE_TOUCHSCREEN
        upEvent.source = InputDevice.SOURCE_TOUCHSCREEN
        val injectedDown = injectMotionEvent(downEvent)
        val injectedUp = injectMotionEvent(upEvent)
        downEvent.recycle()
        upEvent.recycle()
        if (!(injectedDown && injectedUp)) {
            dispatchGestureFallback(point)
        }
    }

    private fun exitApplication() {
        val exitIntent = Intent(this, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            putExtra(MainActivity.EXTRA_EXIT, true)
        }
        startActivity(exitIntent)
    }

    companion object {
        @Volatile
        private var instance: CursorAccessibilityService? = null

        fun performClick(point: PointF) {
            instance?.sendTap(point)
        }
    }
}
