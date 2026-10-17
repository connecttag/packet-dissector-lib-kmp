package org.connecttag.lib.packet.dissector.dns

/**
 * Numeric literals parser and formatter for IPv4 and IPv6.
 * Zero-allocation design, never performs DNS lookups.
 */
object NumericIpAddress {
    fun parse(input: String): ByteArray? {
        val text = if (input.startsWith('[') && input.endsWith(']')) input.substring(1, input.length - 1) else input
        if (text.isEmpty() || text.length > 45 || '%' in text) return null
        if (':' !in text) {
            val parts = text.split('.')
            if (parts.size != 4) return null
            val values = parts.map { part ->
                if (part.length !in 1..3 || part.any { it !in '0'..'9' }) return null
                part.toInt().takeIf { it in 0..255 } ?: return null
            }
            return values.map(Int::toByte).toByteArray()
        }
        val halves = text.split("::")
        if (halves.size > 2) return null
        if (halves.size == 2 && '.' in halves.first()) return null
        fun groups(part: String): List<Int>? {
            if (part.isEmpty()) return emptyList()
            val result = mutableListOf<Int>()
            val pieces = part.split(':')
            for ((index, piece) in pieces.withIndex()) {
                if ('.' in piece) {
                    if (index != pieces.lastIndex) return null
                    val bytes = parse(piece)?.takeIf { it.size == 4 } ?: return null
                    result += ((bytes[0].toInt() and 255) shl 8) or (bytes[1].toInt() and 255)
                    result += ((bytes[2].toInt() and 255) shl 8) or (bytes[3].toInt() and 255)
                } else {
                    if (piece.length !in 1..4 || piece.any { it !in "0123456789abcdefABCDEF" }) return null
                    result += piece.toInt(16)
                }
            }
            return result
        }
        val first = groups(halves.first()) ?: return null
        val second = if (halves.size == 2) groups(halves[1]) ?: return null else emptyList()
        val count = first.size + second.size
        if ((halves.size == 1 && count != 8) || (halves.size == 2 && count >= 8)) return null
        val words = first + List(if (halves.size == 2) 8 - count else 0) { 0 } + second
        return ByteArray(16) { index -> (words[index / 2] ushr (if (index % 2 == 0) 8 else 0)).toByte() }
    }

    fun key(input: String?): String? = input?.let(::parse)?.let(::key)
    fun key(bytes: ByteArray): String = "${bytes.size}:" + bytes.joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }
    fun format(bytes: ByteArray): String = when (bytes.size) {
        4 -> bytes.joinToString(".") { (it.toInt() and 255).toString() }
        16 -> (0..7).joinToString(":") { (((bytes[it * 2].toInt() and 255) shl 8) or (bytes[it * 2 + 1].toInt() and 255)).toString(16) }
        else -> error("Invalid numeric address size")
    }
}
