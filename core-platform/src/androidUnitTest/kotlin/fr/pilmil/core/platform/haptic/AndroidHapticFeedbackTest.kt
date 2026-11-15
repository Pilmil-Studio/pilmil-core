package fr.pilmil.core.platform.haptic

import android.content.Context
import android.content.ContextWrapper
import org.junit.Test
import kotlin.test.assertFalse

class AndroidHapticFeedbackTest {

    private fun fakeContext(service: Any?): Context = object : ContextWrapper(null) {
        @Suppress("DEPRECATION")
        override fun getSystemService(name: String): Any? =
            if (name == Context.VIBRATOR_SERVICE) service else null
    }

    @Test
    fun returnsUnsupportedAndNoOpsWhenVibratorServiceIsMissing() {
        val haptic = AndroidHapticFeedback(fakeContext(null))

        assertFalse(haptic.isSupported())
        haptic.pulseClick()
        haptic.pulseWarning()
    }

    @Test
    fun returnsUnsupportedAndNoOpsWhenServiceIsNotAVibrator() {
        val haptic = AndroidHapticFeedback(fakeContext("not-a-vibrator"))

        assertFalse(haptic.isSupported())
        haptic.pulseClick()
        haptic.pulseWarning()
    }
}
