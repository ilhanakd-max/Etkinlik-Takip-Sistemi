package com.ilhanakd.tvnavigator.service

import android.graphics.PointF
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlin.math.max

object CursorManager {
    private const val STEP = 25f

    private var screenWidth: Float = 1920f
    private var screenHeight: Float = 1080f

    var position by mutableStateOf(PointF(screenWidth / 2f, screenHeight / 2f))
        private set

    fun updateBounds(width: Float, height: Float) {
        screenWidth = width
        screenHeight = height
        clampPosition()
    }

    fun moveLeft() = moveBy(-STEP, 0f)
    fun moveRight() = moveBy(STEP, 0f)
    fun moveUp() = moveBy(0f, -STEP)
    fun moveDown() = moveBy(0f, STEP)

    fun currentPosition(): PointF = PointF(position.x, position.y)

    fun currentClickPoint(): PointF = PointF(
        position.x + CURSOR_SIZE / 2f,
        position.y + CURSOR_SIZE / 2f
    )

    fun centerCursor() {
        position = PointF(
            (screenWidth - CURSOR_SIZE) / 2f,
            (screenHeight - CURSOR_SIZE) / 2f
        )
    }

    private fun moveBy(dx: Float, dy: Float) {
        val newX = position.x + dx
        val newY = position.y + dy
        position = PointF(
            newX.coerceIn(0f, max(0f, screenWidth - CURSOR_SIZE)),
            newY.coerceIn(0f, max(0f, screenHeight - CURSOR_SIZE))
        )
    }

    private fun clampPosition() {
        position = PointF(
            position.x.coerceIn(0f, max(0f, screenWidth - CURSOR_SIZE)),
            position.y.coerceIn(0f, max(0f, screenHeight - CURSOR_SIZE))
        )
    }

    const val CURSOR_SIZE = 48f
}
