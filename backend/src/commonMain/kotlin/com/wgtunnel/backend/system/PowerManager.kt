package com.wgtunnel.backend.system

import com.wgtunnel.backend.ApplicationProvider
import kotlinx.coroutines.flow.Flow

data class PowerState(val awake: Boolean, val wakeCount: Long = 0L)

expect class PowerManager(applicationProvider: ApplicationProvider) {
    fun isDeviceAwake(): Boolean

    val powerState: Flow<PowerState>
}
