package fr.pilmil.core.designsystem

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class PilmilColorValuesTest {

    @Test
    fun allColorsHaveOpaqueAlphaChannel() {
        val colors = listOf(
            PilmilColorValues.PureBlack,
            PilmilColorValues.DarkSurface,
            PilmilColorValues.DarkContainer,
            PilmilColorValues.PaperLight,
            PilmilColorValues.CreamSurface,
            PilmilColorValues.TextInk,
            PilmilColorValues.TextMuted,
            PilmilColorValues.LifeGreen,
            PilmilColorValues.AlertCrimson,
            PilmilColorValues.PlumPrimary,
            PilmilColorValues.NightBlue,
        )

        colors.forEach { argb ->
            assertEquals(0xFFL, (argb ushr 24) and 0xFFL, "La couleur 0x${argb.toString(16)} doit être opaque")
        }
    }

    @Test
    fun colorConstantsMatchExpectedHexValues() {
        assertEquals(0xFF000000L, PilmilColorValues.PureBlack)
        assertEquals(0xFF121212L, PilmilColorValues.DarkSurface)
        assertEquals(0xFF1E1E1EL, PilmilColorValues.DarkContainer)
        assertEquals(0xFFFFFCFAL, PilmilColorValues.PaperLight)
        assertEquals(0xFFFBF5F2L, PilmilColorValues.CreamSurface)
        assertEquals(0xFF1C1B1FL, PilmilColorValues.TextInk)
        assertEquals(0xFF49454FL, PilmilColorValues.TextMuted)
        assertEquals(0xFF2E7D32L, PilmilColorValues.LifeGreen)
        assertEquals(0xFFB3261EL, PilmilColorValues.AlertCrimson)
        assertEquals(0xFF4A2C4FL, PilmilColorValues.PlumPrimary)
        assertEquals(0xFF1A237EL, PilmilColorValues.NightBlue)
    }

    @Test
    fun surfaceAndTextTiersAreDistinct() {
        assertNotEquals(PilmilColorValues.PureBlack, PilmilColorValues.DarkSurface)
        assertNotEquals(PilmilColorValues.DarkSurface, PilmilColorValues.DarkContainer)
        assertNotEquals(PilmilColorValues.PaperLight, PilmilColorValues.CreamSurface)
        assertNotEquals(PilmilColorValues.TextInk, PilmilColorValues.TextMuted)
    }
}
