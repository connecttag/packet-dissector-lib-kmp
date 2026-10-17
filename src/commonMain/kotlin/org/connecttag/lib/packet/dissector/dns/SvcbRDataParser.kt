package org.connecttag.lib.packet.dissector.dns

import org.connecttag.lib.packet.dissector.model.ServiceBindingAdvertisement

/**
 * RFC 9460 SVCB / HTTPS RDATA Parser. TargetName is uncompressed; parameters are strictly ordered.
 */
object SvcbRDataParser {
    data class Parameter(val key: Int, val bytes: ByteArray) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Parameter) return false
            if (key != other.key) return false
            if (!bytes.contentEquals(other.bytes)) return false
            return true
        }

        override fun hashCode(): Int = 31 * key + bytes.contentHashCode()
    }

    data class Record(val priority: Int, val target: String, val parameters: List<Parameter>) {
        fun advertisement(owner: String, recordType: Int, ttlSeconds: Long): ServiceBindingAdvertisement? {
            if (recordType !in listOf(64, 65) || owner.length !in 1..253) return null
            val values = parameters.associate { it.key to it.bytes }
            val mandatory = values[0]?.let { raw -> (raw.indices step 2).map { u16(raw, it) } } ?: emptyList()
            val alpns = values[1]?.let(::parseAlpns) ?: emptyList()
            fun hints(key: Int, size: Int) = values[key]?.let { raw ->
                (raw.indices step size).map { NumericIpAddress.format(raw.copyOfRange(it, it + size)) }
            } ?: emptyList()

            return ServiceBindingAdvertisement(
                owner = owner.lowercase().trimEnd('.'),
                recordType = recordType,
                priority = priority,
                target = target,
                ttlSeconds = ttlSeconds.coerceIn(0, 0xffffffffL),
                alpns = alpns,
                noDefaultAlpn = 2 in values,
                port = values[3]?.let { u16(it, 0) },
                ipv4Hints = hints(4, 4),
                ipv6Hints = hints(6, 16),
                echConfigPresent = values[5]?.isNotEmpty() == true,
                mandatoryKeys = mandatory,
                unsupportedMandatoryKeys = mandatory.filter { it !in 0..6 }
            )
        }
    }

    fun parse(data: ByteArray): Record? {
        if (data.size !in 3..16384) return null
        val priority = u16(data, 0)
        var pos = 2
        val labels = mutableListOf<String>()
        var nameLength = 0
        while (true) {
            if (pos >= data.size) return null
            val size = data[pos++].toInt() and 255
            if (size == 0) break
            if (size > 63 || pos + size > data.size || nameLength + size + 1 > 254) return null
            val label = data.copyOfRange(pos, pos + size)
            if (label.any { (it.toInt() and 255) !in 33..126 || it == '.'.code.toByte() }) return null
            labels += label.toString(Charsets.US_ASCII).lowercase()
            nameLength += size + 1
            pos += size
        }
        val target = labels.joinToString(".").ifEmpty { "." }
        val parameters = mutableListOf<Parameter>()
        var previous = -1
        while (pos < data.size) {
            if (pos + 4 > data.size || parameters.size >= 32) return null
            val key = u16(data, pos)
            val size = u16(data, pos + 2)
            pos += 4
            if (key <= previous || pos + size > data.size) return null
            val bytes = data.copyOfRange(pos, pos + size)
            pos += size
            previous = key
            // AliasMode ignores SvcParams; preserve their wire shape for existing DNS consumers.
            if (priority > 0) when (key) {
                0 -> {
                    if (size == 0 || size % 2 != 0 || size > 64) return null
                    val keys = (bytes.indices step 2).map { u16(bytes, it) }
                    if (keys.first() == 0 || keys.zipWithNext().any { it.first >= it.second }) return null
                }
                1 -> if (parseAlpns(bytes) == null) return null
                2 -> if (size != 0) return null
                3 -> if (size != 2 || u16(bytes, 0) == 0) return null
                4 -> if (size == 0 || size % 4 != 0 || size > 64) return null
                6 -> if (size == 0 || size % 16 != 0 || size > 256) return null
            }
            parameters += Parameter(key, bytes)
        }
        if (priority > 0) {
            val values = parameters.associate { it.key to it.bytes }
            if (2 in values && 1 !in values) return null
            values[0]?.let { keys -> if ((keys.indices step 2).any { u16(keys, it) !in values }) return null }
        }
        return Record(priority, target, if (priority == 0) emptyList() else parameters)
    }

    private fun parseAlpns(bytes: ByteArray): List<String>? {
        if (bytes.isEmpty()) return null
        var pos = 0
        val values = mutableListOf<String>()
        while (pos < bytes.size) {
            val size = bytes[pos++].toInt() and 255
            if (size == 0 || size > 64 || pos + size > bytes.size || values.size >= 16) return null
            val value = bytes.copyOfRange(pos, pos + size)
            if (value.any { (it.toInt() and 255) !in 33..126 }) return null
            values += value.toString(Charsets.US_ASCII)
            pos += size
        }
        return values
    }

    private fun u16(data: ByteArray, pos: Int) = ((data[pos].toInt() and 255) shl 8) or (data[pos + 1].toInt() and 255)
}
