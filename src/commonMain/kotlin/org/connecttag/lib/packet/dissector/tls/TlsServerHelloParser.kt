package org.connecttag.lib.packet.dissector.tls

import org.connecttag.lib.packet.dissector.model.TlsHeaderFacts

/** Complete cleartext ServerHello records only; never reads TLS 1.3 encrypted extensions. */
object TlsServerHelloParser {
    private val retryRandom = "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
        .chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    fun parseRecord(data: ByteArray): TlsHeaderFacts? {
        if (data.size < 9 || data[0] != 22.toByte() || data[1] != 3.toByte() || data[5] != 2.toByte()) return null
        val recordEnd = 5 + u16(data, 3)
        val handshakeSize = ((data[6].toInt() and 255) shl 16) or u16(data, 7)
        if (recordEnd > data.size || handshakeSize < 38 || 9 + handshakeSize > recordEnd || handshakeSize > 16384) return null
        val end = 9 + handshakeSize
        var pos = 9
        val legacyVersion = u16(data, pos); pos += 2
        val retry = (0..31).all { data[pos + it] == retryRandom[it] }; pos += 32
        val sessionSize = data[pos++].toInt() and 255
        if (sessionSize > 32 || pos + sessionSize + 3 > end) return null
        pos += sessionSize
        val cipher = u16(data, pos); pos += 2
        if (data[pos++].toInt() != 0) return null
        var version = legacyVersion
        var group: Int? = null
        var alpn: String? = null
        var psk = false
        val seen = mutableSetOf<Int>()
        if (pos < end) {
            if (pos + 2 > end) return null
            val size = u16(data, pos); pos += 2
            if (pos + size != end) return null
            while (pos < end) {
                if (pos + 4 > end) return null
                val type = u16(data, pos); val sizeBytes = u16(data, pos + 2); pos += 4
                if (pos + sizeBytes > end || !seen.add(type)) return null
                when (type) {
                    43 -> { if (sizeBytes != 2) return null; version = u16(data, pos) }
                    51 -> {
                        if (retry) { if (sizeBytes != 2) return null }
                        else if (sizeBytes < 4 || u16(data, pos + 2) != sizeBytes - 4) return null
                        group = u16(data, pos)
                    }
                    41 -> { if (sizeBytes != 2 || retry) return null; psk = true }
                    16 -> {
                        if (sizeBytes < 4 || u16(data, pos) != sizeBytes - 2 || (data[pos + 2].toInt() and 255) != sizeBytes - 3) return null
                        val bytes = data.copyOfRange(pos + 3, pos + sizeBytes)
                        if (bytes.all { (it.toInt() and 255) in 33..126 }) alpn = bytes.toString(Charsets.US_ASCII)
                    }
                }
                pos += sizeBytes
            }
        }
        if (version !in 0x0301..0x0304 || (retry && version != 0x0304) || (version == 0x0304 && legacyVersion != 0x0303)) return null
        // TLS 1.3 ALPN is in EncryptedExtensions, not ServerHello.
        if (version == 0x0304 && alpn != null) return null
        return if (retry) TlsHeaderFacts(helloRetryRequestObserved = true, retryRequestedGroup = group)
        else TlsHeaderFacts(
            selectedVersion = version,
            selectedCipher = cipher,
            selectedGroup = group,
            selectedAlpn = alpn,
            pskSelected = if (version == 0x0304) psk else null
        )
    }

    private fun u16(data: ByteArray, pos: Int) = ((data[pos].toInt() and 255) shl 8) or (data[pos + 1].toInt() and 255)
}
