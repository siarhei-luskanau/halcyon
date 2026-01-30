package tigase.halcyon.core.xmpp.modules.tick

import platform.darwin.*
import tigase.halcyon.core.Context
import tigase.halcyon.core.TickEvent
import tigase.halcyon.core.logger.LoggerFactory
import tigase.halcyon.core.utils.Lock

actual fun createTickTimer(): TickTimer = DefaultTickTimer()

class DefaultTickTimer : TickTimer {

    private val logger = LoggerFactory.logger("DefaultTickTimer")
    private val queue = dispatch_queue_create("tick_timer", null)
    private var tickCounter: Long = 0
    private val lock = Lock()
    private var timerSource: NSObject? = null;

    override fun startTimer(context: Context) {
        lock.withLock {
            if (timerSource != null) {
                return@withLock
            }
            timerSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0u, 0u, queue)
            dispatch_source_set_event_handler(timerSource) {
                tick(context)
            }
            dispatch_source_set_timer(timerSource, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC.toLong()), NSEC_PER_SEC, 100u * NSEC_PER_MSEC);
            dispatch_resume(timerSource)
            logger.finest("Started timer, timer: ${timerSource}")
        }
    }

    override fun stopTimer(context: Context) {
        lock.withLock {
            logger.finest("Stopping timer, timer: ${timerSource}")
            timerSource?.let { dispatch_source_cancel(it) }
            timerSource = null
        }
    }

    private fun tick(context: Context) {
        context.eventBus.fire(TickEvent(++tickCounter))
    }

}