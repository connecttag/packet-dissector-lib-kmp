package org.connecttag.lib.packet.dissector.quic

/** Unauthenticated wire observations; this does not verify Retry tags or decrypt application data. */
object QuicLongHeaderParser {
    data class Observation(
        val version: Long,
        val type: QuicHeaderMetadata.ObservationType,
        val dcid: String,
        val scid: String,
        val advertisedVersions: List<Long>? = null
    )

    fun parse(data: ByteArray): Observation? {
        if (data.size < 7 || data[0].toInt() and 0x80 == 0) return null
        val version = u32(data, 1)
        val dcidSize = data[5].toInt() and 255
        val scidOffset = 6 + dcidSize
        if (dcidSize > 20 || scidOffset >= data.size) return null
        val scidSize = data[scidOffset].toInt() and 255
        val position = scidOffset + 1 + scidSize
        if (scidSize > 20 || position > data.size) return null
        val dcid = hex(data, 6, dcidSize)
        val scid = hex(data, scidOffset + 1, scidSize)
        if (version == 0L) {
            val remaining = data.size - position
            if (remaining < 4 || remaining % 4 != 0 || remaining / 4 > 32) return null
            val versions = List(remaining / 4) { u32(data, position + it * 4) }
            if (versions.any { it == 0L }) return null
            return Observation(version, QuicHeaderMetadata.ObservationType.VERSION_NEGOTIATION, dcid, scid, versions)
        }
        val type = QuicHeaderMetadata.packetType(version.toInt(), data[0].toInt()) ?: return null
        if (type == QuicHeaderMetadata.PacketType.RETRY) {
            if (data.size - position <= 16) return null // token and 16-byte integrity tag
        } else {
            val tokenLength = varint(data, position) ?: return null
            val payloadOffset = tokenLength.first + tokenLength.second.toInt()
            if (payloadOffset > data.size) return null
            val length = varint(data, payloadOffset) ?: return null
            if (payloadOffset + length.first + length.second > data.size) return null
        }
        return Observation(version, QuicHeaderMetadata.ObservationType.fromPacketType(type), dcid, scid)
    }

    private fun u32(data: ByteArray, pos: Int): Long =
        (0..3).fold(0L) { result, offset -> (result shl 8) or (data[pos + offset].toLong() and 255) }

    private fun hex(data: ByteArray, start: Int, size: Int): String =
        data.copyOfRange(start, start + size).joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }

    private fun varint(data: ByteArray, start: Int): Pair<Int, Long>? {
        if (start >= data.size) return null
        val prefix = (data[start].toInt() and 0xc0) ushr 6
        val length = 1 shl prefix
        if (start + length > data.size) return null
        var value = (data[start].toLong() and 0x3f)
        for (i in 1 until length) value = (value shl 8) or (data[start + i].toLong() and 255)
        return length to value
    }
}
