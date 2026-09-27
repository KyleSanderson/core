package com.wgtunnel.backend.system

import com.wgtunnel.backend.ApplicationProvider
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow

/**
 * A desktop process is frozen while the machine sleeps, so it never observes being asleep, only the
 * resume.
 */
actual class PowerManager actual constructor(applicationProvider: ApplicationProvider) {
    actual fun isDeviceAwake(): Boolean = true

    actual val powerState: Flow<PowerState> = flow {
        var wakeCount = 0L
        emit(PowerState(awake = true, wakeCount = wakeCount))

        var lastTick = System.currentTimeMillis()
        while (true) {
            delay(TICK)
            val now = System.currentTimeMillis()
            // A backwards clock step gives a negative gap and is ignored
            if (now - lastTick - TICK.inWholeMilliseconds > RESUME_GAP.inWholeMilliseconds) {
                wakeCount++
                emit(PowerState(awake = true, wakeCount = wakeCount))
            }
            lastTick = now
        }
    }

    private companion object {
        val TICK = 5.seconds
        // A GC pause or a busy machine never stalls the heartbeat this long
        val RESUME_GAP = 20.seconds
    }
}
