package fr.pilmil.core.designsystem

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PilmilTokensTest {

    @Test
    fun pilmilColorsMatchCommonColorValues() {
        assertEquals(Color(PilmilColorValues.PureBlack), PilmilColors.PureBlack)
        assertEquals(Color(PilmilColorValues.DarkSurface), PilmilColors.DarkSurface)
        assertEquals(Color(PilmilColorValues.DarkContainer), PilmilColors.DarkContainer)
        assertEquals(Color(PilmilColorValues.PaperLight), PilmilColors.PaperLight)
        assertEquals(Color(PilmilColorValues.CreamSurface), PilmilColors.CreamSurface)
        assertEquals(Color(PilmilColorValues.TextInk), PilmilColors.TextInk)
        assertEquals(Color(PilmilColorValues.TextMuted), PilmilColors.TextMuted)
        assertEquals(Color(PilmilColorValues.LifeGreen), PilmilColors.LifeGreen)
        assertEquals(Color(PilmilColorValues.AlertCrimson), PilmilColors.AlertCrimson)
        assertEquals(Color(PilmilColorValues.PlumPrimary), PilmilColors.PlumPrimary)
        assertEquals(Color(PilmilColorValues.NightBlue), PilmilColors.NightBlue)
    }

    @Test
    fun pilmilSpacingValuesAreStrictlyIncreasing() {
        assertEquals(4.dp, PilmilSpacing.xs)
        assertEquals(8.dp, PilmilSpacing.sm)
        assertEquals(16.dp, PilmilSpacing.md)
        assertEquals(24.dp, PilmilSpacing.lg)
        assertEquals(32.dp, PilmilSpacing.xl)

        assertTrue(PilmilSpacing.xs < PilmilSpacing.sm)
        assertTrue(PilmilSpacing.sm < PilmilSpacing.md)
        assertTrue(PilmilSpacing.md < PilmilSpacing.lg)
        assertTrue(PilmilSpacing.lg < PilmilSpacing.xl)
    }
}
