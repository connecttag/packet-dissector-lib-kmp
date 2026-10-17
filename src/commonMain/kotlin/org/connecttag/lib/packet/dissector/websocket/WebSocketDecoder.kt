package org.connecttag.lib.packet.dissector.websocket

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

/**
 * RFC 6455 WebSocket frame decoder.
 * Handles frame parsing, masking removal (client unmasking), multi-chunk reassembly,
 * fragmentation handling (FIN=0 / Continuation frames), and control frame validation.
 * Pure Kotlin implementation for KMP.
 */
class WebSocketDecoder(
    private val listener: DecodedFrameListener,
    private val logCallback: ((level: String, tag: String, message: String) -> Unit)? = null
) {
    companion object {
        private const val TAG = "WebSocketDecoder"

        // RFC 6455 Section 5.2 Opcodes
        const val OPCODE_CONTINUATION: Int = 0x0
        const val OPCODE_TEXT: Int = 0x1
        const val OPCODE_BINARY: Int = 0x2
        const val OPCODE_CLOSE: Int = 0x8
        const val OPCODE_PING: Int = 0x9
        const val OPCODE_PONG: Int = 0xA

        private const val MAX_PENDING_CHUNKS = 100
        private const val MAX_FRAME_SIZE = 16 * 1024 * 1024 // 16 MB limit
        private const val MAX_FRAGMENT_SIZE = 64 * 1024 * 1024 // 64 MB limit

        fun isControlOpcode(opcode: Int): Boolean = opcode >= OPCODE_CLOSE

        fun isValidOpcode(opcode: Int): Boolean {
            return opcode == OPCODE_CONTINUATION ||
                    opcode == OPCODE_TEXT ||
                    opcode == OPCODE_BINARY ||
                    opcode == OPCODE_CLOSE ||
                    opcode == OPCODE_PING ||
                    opcode == OPCODE_PONG
        }

        fun getOpcodeName(opcode: Int): String {
            return when (opcode) {
                OPCODE_CONTINUATION -> "CONTINUATION"
                OPCODE_TEXT -> "TEXT"
                OPCODE_BINARY -> "BINARY"
                OPCODE_CLOSE -> "CLOSE"
                OPCODE_PING -> "PING"
                OPCODE_PONG -> "PONG"
                else -> "UNKNOWN($opcode)"
            }
        }

        fun unmaskPayload(payload: ByteArray, maskingKey: ByteArray) {
            for (i in payload.indices) {
                payload[i] = (payload[i].toInt() xor maskingKey[i % 4].toInt()).toByte()
            }
        }
    }

    private fun log(level: String, message: String) {
        logCallback?.invoke(level, TAG, message)
    }

    data class WebSocketFrame(
        val opcode: Int,
        val fin: Boolean,
        val wasFragmented: Boolean,
        val isSent: Boolean,
        val timestamp: Long,
        val payload: ByteArray?,
        val text: String?
    ) {
        val opcodeName: String get() = getOpcodeName(opcode)
        val isControl: Boolean get() = isControlOpcode(opcode)
        val size: Int get() = payload?.size ?: 0

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is WebSocketFrame) return false
            return opcode == other.opcode &&
                    fin == other.fin &&
                    isSent == other.isSent &&
                    timestamp == other.timestamp &&
                    payload.contentEquals(other.payload)
        }

        override fun hashCode(): Int {
            var result = opcode
            result = 31 * result + fin.hashCode()
            result = 31 * result + isSent.hashCode()
            result = 31 * result + timestamp.hashCode()
            result = 31 * result + (payload?.contentHashCode() ?: 0)
            return result
        }

        override fun toString(): String {
            val dir = if (isSent) "Client->Server" else "Server->Client"
            val textPreview = text?.take(100)?.replace("\r", " ")?.replace("\n", " ")
            return "WS $opcodeName [$dir] fin=$fin size=${size}B${if (!textPreview.isNullOrBlank()) " \"$textPreview\"" else ""}"
        }
    }

    interface DecodedFrameListener {
        fun onWebSocketFrame(frame: WebSocketFrame)
    }

    private data class PendingChunk(
        val data: ByteArray,
        val isSent: Boolean,
        val timestamp: Long
    )

    private enum class ParseStatus {
        INCOMPLETE,
        SUCCESS,
        ERROR
    }

    private class FrameParseResult(
        val status: ParseStatus,
        val opcode: Int = 0,
        val fin: Boolean = false,
        val payload: ByteArray? = null,
        val bytesConsumed: Int = 0,
        val errorMessage: String? = null
    )

    private val pendingChunks = ArrayDeque<PendingChunk>()
    private var pendingOffset = 0

    private var fragmentBuffer: ByteArrayOutputStream? = null
    private var fragmentOpcode = -1
    private var fragmentTimestamp = 0L

    @Synchronized
    fun handleChunk(data: ByteArray, isSent: Boolean, timestamp: Long) {
        if (data.isEmpty()) return

        if (pendingChunks.size >= MAX_PENDING_CHUNKS) {
            log("W", "Too many pending chunks, emitting as raw error")
            emitPendingAsRaw()
        }

        val totalPending = totalPendingBytes
        if (totalPending + data.size > MAX_FRAME_SIZE) {
            log("W", "Pending bytes limit exceeded ($totalPending + ${data.size}), emitting as raw")
            emitPendingAsRaw()
        }

        pendingChunks.add(PendingChunk(data, isSent, timestamp))

        while (true) {
            val result = parseFrame(isSent)

            if (result.status == ParseStatus.INCOMPLETE) break

            if (result.status == ParseStatus.ERROR) {
                log("W", "Frame parse error: ${result.errorMessage}")
                emitPendingAsRaw()
                break
            }

            consumeBytes(result.bytesConsumed)
            handleParsedFrame(result, isSent, timestamp)
        }
    }

    private fun parseFrame(isSent: Boolean): FrameParseResult {
        val available = totalPendingBytes
        if (available < 2) return FrameParseResult(ParseStatus.INCOMPLETE)

        val byte0 = readByte(0).toInt() and 0xFF
        val byte1 = readByte(1).toInt() and 0xFF

        val fin = (byte0 and 0x80) != 0
        val rsv = (byte0 shr 4) and 0x07
        val opcode = byte0 and 0x0F
        val masked = (byte1 and 0x80) != 0
        val payloadLen = byte1 and 0x7F

        if (rsv != 0) {
            log("D", "RSV bits set: $rsv (extensions not negotiated)")
        }

        var headerSize = 2
        var actualPayloadLen: Long = payloadLen.toLong()

        if (payloadLen == 126) {
            headerSize += 2
            if (available < headerSize) return FrameParseResult(ParseStatus.INCOMPLETE)
            actualPayloadLen = (((readByte(2).toInt() and 0xFF) shl 8) or (readByte(3).toInt() and 0xFF)).toLong()
        } else if (payloadLen == 127) {
            headerSize += 8
            if (available < headerSize) return FrameParseResult(ParseStatus.INCOMPLETE)
            actualPayloadLen = 0L
            for (i in 0..7) {
                actualPayloadLen = (actualPayloadLen shl 8) or (readByte(2 + i).toInt() and 0xFF).toLong()
            }
            if (actualPayloadLen < 0) {
                return FrameParseResult(ParseStatus.ERROR, errorMessage = "Payload length overflow")
            }
        }

        if (actualPayloadLen > MAX_FRAME_SIZE) {
            return FrameParseResult(ParseStatus.ERROR, errorMessage = "Payload too large: $actualPayloadLen")
        }

        if (opcode >= OPCODE_CLOSE) {
            if (!fin) {
                log("W", "Control frame with FIN=0 (RFC violation)")
            }
            if (actualPayloadLen > 125) {
                log("W", "Control frame payload $actualPayloadLen > 125 bytes (RFC violation)")
            }
        }

        var maskingKey: ByteArray? = null
        if (masked) {
            if (available < headerSize + 4) return FrameParseResult(ParseStatus.INCOMPLETE)
            maskingKey = ByteArray(4)
            readBytes(headerSize, maskingKey, 0, 4)
            headerSize += 4
        }

        val totalFrameSize = headerSize + actualPayloadLen.toInt()
        if (available < totalFrameSize) return FrameParseResult(ParseStatus.INCOMPLETE)

        val payload = ByteArray(actualPayloadLen.toInt())
        readBytes(headerSize, payload, 0, actualPayloadLen.toInt())

        if (masked && maskingKey != null) {
            unmaskPayload(payload, maskingKey)
        }

        return FrameParseResult(
            status = ParseStatus.SUCCESS,
            opcode = opcode,
            fin = fin,
            payload = payload,
            bytesConsumed = totalFrameSize
        )
    }

    private fun handleParsedFrame(result: FrameParseResult, isSent: Boolean, timestamp: Long) {
        val opcode = result.opcode
        val fin = result.fin
        val payload = result.payload ?: ByteArray(0)

        if (opcode >= OPCODE_CLOSE) {
            emitFrame(opcode, fin, payload, false, isSent, timestamp)
            return
        }

        if (opcode != OPCODE_CONTINUATION && !fin) {
            if (fragmentBuffer != null) {
                log("W", "New fragmented message started while previous was incomplete")
            }
            fragmentBuffer = ByteArrayOutputStream()
            fragmentOpcode = opcode
            fragmentTimestamp = timestamp
            try {
                fragmentBuffer?.write(payload)
            } catch (e: Throwable) {
                log("E", "Error writing to fragment buffer: ${e.message}")
            }
            return
        }

        if (opcode == OPCODE_CONTINUATION) {
            if (fragmentBuffer == null) {
                log("W", "Continuation frame without initial frame")
                emitFrame(opcode, fin, payload, false, isSent, timestamp)
                return
            }

            if ((fragmentBuffer?.size() ?: 0) + payload.size > MAX_FRAGMENT_SIZE) {
                log("W", "Fragment size limit exceeded")
                fragmentBuffer = null
                return
            }

            try {
                fragmentBuffer?.write(payload)
            } catch (e: Throwable) {
                log("E", "Error writing continuation chunk: ${e.message}")
            }

            if (fin) {
                val reassembled = fragmentBuffer?.toByteArray() ?: ByteArray(0)
                val origOpcode = fragmentOpcode
                val origTime = fragmentTimestamp
                fragmentBuffer = null
                fragmentOpcode = -1
                emitFrame(origOpcode, true, reassembled, true, isSent, origTime)
            }
            return
        }

        emitFrame(opcode, fin, payload, false, isSent, timestamp)
    }

    private fun emitFrame(
        opcode: Int,
        fin: Boolean,
        payload: ByteArray?,
        wasFragmented: Boolean,
        isSent: Boolean,
        timestamp: Long
    ) {
        val text = if (payload != null && (opcode == OPCODE_TEXT || isPrintableText(payload))) {
            try {
                String(payload, StandardCharsets.UTF_8)
            } catch (_: Throwable) {
                null
            }
        } else null

        val frame = WebSocketFrame(
            opcode = opcode,
            fin = fin,
            wasFragmented = wasFragmented,
            isSent = isSent,
            timestamp = timestamp,
            payload = payload,
            text = text
        )

        try {
            listener.onWebSocketFrame(frame)
        } catch (t: Throwable) {
            log("E", "Error in DecodedFrameListener: ${t.message}")
        }
    }

    private fun emitPendingAsRaw() {
        pendingChunks.clear()
        pendingOffset = 0
    }

    private val totalPendingBytes: Int
        get() {
            var total = -pendingOffset
            for (c in pendingChunks) total += c.data.size
            return maxOf(0, total)
        }

    private fun readByte(pos: Int): Byte {
        var remaining = pos
        var first = true
        for (c in pendingChunks) {
            val start = if (first) pendingOffset else 0
            val available = c.data.size - start
            if (remaining < available) return c.data[start + remaining]
            remaining -= available
            first = false
        }
        throw IndexOutOfBoundsException("Position $pos out of bounds")
    }

    private fun readBytes(pos: Int, dest: ByteArray, offset: Int, length: Int) {
        var remaining = length
        var curPos = pos
        var destOff = offset
        var first = true
        for (c in pendingChunks) {
            val start = if (first) pendingOffset else 0
            val available = c.data.size - start
            if (curPos < available) {
                val toCopy = minOf(remaining, available - curPos)
                System.arraycopy(c.data, start + curPos, dest, destOff, toCopy)
                destOff += toCopy
                remaining -= toCopy
                curPos = 0
                if (remaining <= 0) break
            } else {
                curPos -= available
            }
            first = false
        }
        if (remaining > 0) {
            throw IndexOutOfBoundsException("Position $pos + length $length out of bounds")
        }
    }

    private fun consumeBytes(count: Int) {
        var remaining = count
        while (remaining > 0 && pendingChunks.isNotEmpty()) {
            val first = pendingChunks.first()
            val available = first.data.size - pendingOffset
            if (remaining >= available) {
                pendingChunks.removeFirst()
                pendingOffset = 0
                remaining -= available
            } else {
                pendingOffset += remaining
                remaining = 0
            }
        }
    }

    private fun isPrintableText(data: ByteArray): Boolean {
        if (data.isEmpty()) return true
        val checkLen = minOf(data.size, 64)
        for (i in 0 until checkLen) {
            val b = data[i].toInt() and 0xFF
            if (b < 0x20 && b != 0x09 && b != 0x0A && b != 0x0D) {
                return false
            }
        }
        return true
    }

    fun reset() {
        pendingChunks.clear()
        pendingOffset = 0
        fragmentBuffer = null
        fragmentOpcode = -1
        fragmentTimestamp = 0L
    }
}
