package org.connecttag.lib.packet.dissector.http

import org.connecttag.lib.packet.dissector.model.UnavailableReason

/** Metadata-only HTTP/1 framing. Bodies are skipped, never buffered or decoded. */
class HttpHeaderStream(private val requestStream: Boolean) {
    enum class Decision { DEFAULT, NO_BODY, STOP }
    private enum class Phase { HEADER, FIXED_BODY, CHUNK_SIZE, CHUNK_BODY, CHUNK_CRLF, TRAILERS, STOP }
    private var phase = Phase.HEADER
    private var buffer: ByteArray? = null
    private var used = 0
    private var remaining = 0L
    private var chunkCrlf = 0
    private var trailerBytes = 0
    private var trailerLines = 0
    var missingReason: UnavailableReason? = UnavailableReason.NOT_OBSERVED
        private set

    fun stop(reason: UnavailableReason = UnavailableReason.NOT_APPLICABLE) {
        if (phase == Phase.STOP && reason == UnavailableReason.NOT_APPLICABLE) return
        phase = Phase.STOP
        buffer = null
        used = 0
        missingReason = reason
    }

    fun feed(data: ByteArray, onBlock: (InspectionHttpHeaders.Block) -> Decision) {
        var offset = 0
        while (offset < data.size && phase != Phase.STOP) {
            when (phase) {
                Phase.HEADER -> {
                    if (used == 0 && data[offset].toInt().toChar() !in 'A'..'Z') { stop(); return }
                    if (!append(data[offset++], 16384)) return
                    missingReason = UnavailableReason.INCOMPLETE_CAPTURE
                    if (used >= 4 && endsWithCrlf() && buffer!![used - 3] == 10.toByte() && buffer!![used - 4] == 13.toByte()) {
                        val header = buffer!!.copyOf(used)
                        val block = InspectionHttpHeaders.parseBlock(header)
                        buffer = null
                        used = 0
                        if (block == null || requestStream != (block.statusCode == null)) {
                            stop(if (InspectionHttpHeaders.headerLimitExceeded(header)) UnavailableReason.INSPECTION_LIMIT else UnavailableReason.UNSUPPORTED_FORMAT)
                            return
                        }
                        missingReason = null
                        val transfer = block.fields.filter { it.first == "transfer-encoding" }.flatMap { it.second.split(',') }.map { it.trim().lowercase() }
                        if (transfer.isNotEmpty() && (transfer.last() != "chunked" || transfer.count { it == "chunked" } != 1 || transfer.any { token -> token.isEmpty() || token.any { it !in 'a'..'z' && it != '-' } })) {
                            stop(UnavailableReason.UNSUPPORTED_FORMAT)
                            return
                        }
                        val decision = onBlock(block)
                        when {
                            decision == Decision.STOP || block.statusCode == 101 -> stop()
                            decision == Decision.NO_BODY || block.statusCode in 100..199 || block.statusCode in listOf(204, 304) -> phase = Phase.HEADER
                            transfer.isNotEmpty() -> phase = Phase.CHUNK_SIZE
                            else -> {
                                val length = block.fields.firstOrNull { it.first == "content-length" }?.second?.substringBefore(',')?.trim()?.toLongOrNull()
                                when {
                                    length != null && length > 0 -> { remaining = length; phase = Phase.FIXED_BODY }
                                    length == 0L || requestStream -> phase = Phase.HEADER
                                    else -> stop() // close-delimited response: following bytes are all body
                                }
                            }
                        }
                    }
                }
                Phase.FIXED_BODY, Phase.CHUNK_BODY -> {
                    val size = minOf(remaining, (data.size - offset).toLong()).toInt()
                    offset += size
                    remaining -= size
                    if (remaining == 0L) {
                        if (phase == Phase.FIXED_BODY) phase = Phase.HEADER
                        else { phase = Phase.CHUNK_CRLF; chunkCrlf = 0 }
                    }
                }
                Phase.CHUNK_SIZE -> {
                    if (!append(data[offset++], 1024)) return
                    if (endsWithCrlf()) {
                        val line = buffer!!.copyOf(used - 2).toString(Charsets.US_ASCII)
                        used = 0
                        val hex = line.substringBefore(';')
                        val size = hex.takeIf { it.length in 1..15 && it.all { char -> char in "0123456789abcdefABCDEF" } }?.toLongOrNull(16)
                        if (size == null || line.any { it < ' ' || it > '~' }) { stop(UnavailableReason.UNSUPPORTED_FORMAT); return }
                        if (size == 0L) { phase = Phase.TRAILERS; trailerBytes = 0; trailerLines = 0 }
                        else { remaining = size; phase = Phase.CHUNK_BODY }
                    }
                }
                Phase.CHUNK_CRLF -> {
                    if (data[offset++] != (if (chunkCrlf == 0) 13 else 10).toByte()) { stop(UnavailableReason.UNSUPPORTED_FORMAT); return }
                    if (++chunkCrlf == 2) phase = Phase.CHUNK_SIZE
                }
                Phase.TRAILERS -> {
                    if (++trailerBytes > 16384 || !append(data[offset++], 4096)) { stop(UnavailableReason.INSPECTION_LIMIT); return }
                    if (endsWithCrlf()) {
                        if (++trailerLines > 128) { stop(UnavailableReason.INSPECTION_LIMIT); return }
                        if (used == 2) { phase = Phase.HEADER; buffer = null }
                        else if (buffer!!.copyOf(used - 2).none { it == ':'.code.toByte() }) { stop(UnavailableReason.UNSUPPORTED_FORMAT); return }
                        used = 0
                    }
                }
                Phase.STOP -> return
            }
        }
    }

    private fun append(value: Byte, limit: Int): Boolean {
        if (used >= limit) { stop(UnavailableReason.INSPECTION_LIMIT); return false }
        if (buffer == null) buffer = ByteArray(minOf(1024, limit))
        if (used == buffer!!.size) buffer = buffer!!.copyOf(minOf(limit, used * 2))
        buffer!![used++] = value
        return true
    }

    private fun endsWithCrlf() = used >= 2 && buffer!![used - 2] == 13.toByte() && buffer!![used - 1] == 10.toByte()
}
