package org.connecttag.lib.packet.dissector.tls

import org.connecttag.lib.packet.dissector.model.EchExtensionForm

/**
 * Shared bounded ClientHello parsing for SNI, JA4 signatures, and inspection flags.
 */
object TlsClientHelloParser {
    data class Hello(
        val recordVersion: Int,
        val legacyVersion: Int,
        val serverName: String?,
        val alpn: String?,
        val ciphers: List<Int>,
        val extensions: List<Int>,
        val supportedVersions: List<Int>,
        val signatureAlgorithms: List<Int>,
        val alpnOffers: List<String> = listOfNotNull(alpn),
        val supportedGroups: List<Int> = emptyList(),
        val alpnOffersComplete: Boolean = true,
        val echForm: EchExtensionForm = EchExtensionForm.NOT_PRESENT,
    )

    fun parseRecord(data: ByteArray): Hello? {
        val offset = recordOffset(data) ?: return null
        if (offset + 5 > data.size) return null
        val version = u16(data, offset + 1)
        val end = offset + 5 + u16(data, offset + 3)
        if (end > data.size) return null
        return parseHandshake(data, offset + 5, end, version)
    }

    fun parseHandshake(data: ByteArray, start: Int = 0, end: Int = data.size, recordVersion: Int = 0x0303): Hello? {
        if (start < 0 || end !in 0..data.size || end - start < 38) return null
        return try {
            val input = Cursor(data, start, end)
            if (input.byte() != 1) return null
            val length = (input.byte() shl 16) or input.short()
            val handshakeEnd = input.position + length
            if (handshakeEnd > end || length < 34 || length > 16384) return null
            val body = Cursor(data, input.position, handshakeEnd)
            val legacyVersion = body.short()
            body.skip(32)
            body.skip(body.byte())
            val cipherBytes = body.short()
            if (cipherBytes == 0 || cipherBytes % 2 != 0 || cipherBytes > 1024) return null
            val ciphers = List(cipherBytes / 2) { body.short() }
            body.skip(body.byte())
            if (body.position == handshakeEnd) return Hello(recordVersion, legacyVersion, null, null, ciphers, emptyList(), emptyList(), emptyList())
            val extensionBytes = body.short()
            if (body.position + extensionBytes != handshakeEnd) return null
            val extensions = mutableListOf<Int>()
            var serverName: String? = null
            var alpn: String? = null
            var versions = emptyList<Int>()
            var signatures = emptyList<Int>()
            val alpns = mutableListOf<String>()
            var alpnComplete = true
            var alpnCount = 0
            var groups = emptyList<Int>()
            var echForm = EchExtensionForm.NOT_PRESENT
            while (body.position < handshakeEnd) {
                val type = body.short()
                val size = body.short()
                val value = body.slice(size)
                if (type in extensions || extensions.size >= 128) return null
                extensions += type
                when (type) {
                    0xfe0d -> {
                        echForm = inspectEch(value.bytes(value.remaining))
                    }
                    0xffce -> if (echForm == EchExtensionForm.NOT_PRESENT) echForm = EchExtensionForm.UNSUPPORTED
                    0 -> {
                        val list = value.slice(value.short())
                        if (value.remaining != 0) return null
                        while (list.remaining > 0) {
                            val nameType = list.byte()
                            val name = list.bytes(list.short())
                            if (nameType == 0 && serverName == null && name.isNotEmpty()) {
                                if (name.any { (it.toInt() and 0xff) !in 33..126 }) return null
                                serverName = name.toString(Charsets.US_ASCII)
                            }
                        }
                    }
                    16 -> {
                        val list = value.slice(value.short())
                        if (value.remaining != 0) return null
                        while (list.remaining > 0) {
                            val protocol = list.bytes(list.byte())
                            if (protocol.isEmpty() || ++alpnCount > 32) return null
                            if (alpn == null) alpn = protocol.toString(Charsets.ISO_8859_1)
                            if (protocol.all { (it.toInt() and 255) in 33..126 }) alpns += protocol.toString(Charsets.US_ASCII)
                            else alpnComplete = false
                        }
                    }
                    10 -> {
                        val sizeBytes = value.short()
                        if (sizeBytes !in 2..1024 || sizeBytes % 2 != 0 || sizeBytes != value.remaining) return null
                        groups = List(sizeBytes / 2) { value.short() }
                    }
                    43 -> {
                        val sizeBytes = value.byte()
                        if (sizeBytes !in 2..64 || sizeBytes % 2 != 0 || sizeBytes != value.remaining) return null
                        versions = List(sizeBytes / 2) { value.short() }
                    }
                    13 -> {
                        val sizeBytes = value.short()
                        if (sizeBytes !in 2..1024 || sizeBytes % 2 != 0 || sizeBytes != value.remaining) return null
                        signatures = List(sizeBytes / 2) { value.short() }
                    }
                }
            }
            Hello(recordVersion, legacyVersion, serverName, alpn, ciphers, extensions, versions, signatures, alpns, groups, alpnComplete, echForm)
        } catch (_: InvalidHello) { null }
    }

    private fun inspectEch(value: ByteArray): EchExtensionForm {
        if (value.size == 1 && value[0] == 1.toByte()) return EchExtensionForm.INNER_MARKER
        if (value.size < 10 || value[0] != 0.toByte()) return EchExtensionForm.UNSUPPORTED
        val encLength = u16(value, 6)
        val payloadOffset = 8 + encLength
        if (payloadOffset + 2 > value.size) return EchExtensionForm.UNSUPPORTED
        val payloadLength = u16(value, payloadOffset)
        return if (payloadLength > 0 && payloadOffset + 2 + payloadLength == value.size) EchExtensionForm.OUTER else EchExtensionForm.UNSUPPORTED
    }

    private fun recordOffset(data: ByteArray): Int? {
        fun matches(offset: Int) = offset + 5 <= data.size && data[offset] == 0x16.toByte() && data[offset + 1] == 3.toByte()
        if (matches(0)) return 0
        if (data.size >= 7 && data[0] == 0x14.toByte() && data[5] == 1.toByte() && matches(6)) return 6
        return (1..minOf(16, data.size - 5)).firstOrNull(::matches)
    }

    private fun u16(data: ByteArray, position: Int) = ((data[position].toInt() and 0xff) shl 8) or (data[position + 1].toInt() and 0xff)
    private class InvalidHello : Exception()
    private class Cursor(private val data: ByteArray, var position: Int, private val end: Int) {
        val remaining get() = end - position
        fun byte(): Int { if (remaining < 1) throw InvalidHello(); return data[position++].toInt() and 0xff }
        fun short(): Int = (byte() shl 8) or byte()
        fun skip(size: Int) { if (size < 0 || size > remaining) throw InvalidHello(); position += size }
        fun bytes(size: Int): ByteArray { val start = position; skip(size); return data.copyOfRange(start, position) }
        fun slice(size: Int): Cursor { val start = position; skip(size); return Cursor(data, start, position) }
    }
}
