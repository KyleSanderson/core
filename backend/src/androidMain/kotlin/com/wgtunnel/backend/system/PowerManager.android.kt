package com.wgtunnel.backend.system

import android.app.UiModeManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.os.Build
import android.os.PowerManager as AndroidPowerManager
import androidx.core.content.getSystemService
import com.wgtunnel.backend.AndroidApplicationProvider
import com.wgtunnel.backend.ApplicationProvider
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.distinctUntilChanged

actual class PowerManager actual constructor(applicationProvider: ApplicationProvider) {

    private val context = (applicationProvider as AndroidApplicationProvider).context

    private val powerManager: AndroidPowerManager =
        context.getSystemService(Context.POWER_SERVICE) as AndroidPowerManager

    // Standby on a TV isn't Doze and idle state is not reported reliably there
    private val isTelevision: Boolean by lazy {
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_LEANBACK) ||
            context.getSystemService<UiModeManager>()?.currentModeType ==
                Configuration.UI_MODE_TYPE_TELEVISION
    }

    private fun isAsleep(): Boolean {
        if (isTelevision) return false
        if (powerManager.isInteractive) return false
        val deepIdle = powerManager.isDeviceIdleMode
        val lightIdle =
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                powerManager.isDeviceLightIdleMode
        return deepIdle || lightIdle
    }

    actual fun isDeviceAwake(): Boolean = !isAsleep()

    actual val powerState: Flow<PowerState> = callbackFlow {
        var awake = isDeviceAwake()
        var wakeCount = 0L
        trySend(PowerState(awake, wakeCount))

        val receiver =
            object : BroadcastReceiver() {
                override fun onReceive(context: Context?, intent: Intent?) {
                    val nowAwake = isDeviceAwake()
                    val wakeSignal =
                        intent?.action == Intent.ACTION_SCREEN_ON ||
                            intent?.action == Intent.ACTION_USER_PRESENT
                    if ((nowAwake && !awake) || wakeSignal) wakeCount++
                    awake = nowAwake
                    trySend(PowerState(awake, wakeCount))
                }
            }

        val filter =
            IntentFilter().apply {
                addAction(AndroidPowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    addAction(AndroidPowerManager.ACTION_DEVICE_LIGHT_IDLE_MODE_CHANGED)
                }
                addAction(Intent.ACTION_SCREEN_ON)
                addAction(Intent.ACTION_SCREEN_OFF)
                addAction(Intent.ACTION_USER_PRESENT)
            }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag") context.registerReceiver(receiver, filter)
        }

        awaitClose {
            try {
                context.unregisterReceiver(receiver)
            } catch (_: IllegalArgumentException) {
                // already unregistered
            }
        }
    }
        .distinctUntilChanged()
}
