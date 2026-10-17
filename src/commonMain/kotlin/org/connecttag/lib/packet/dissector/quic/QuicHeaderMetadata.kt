package org.connecttag.lib.packet.dissector.quic

/** Version-dependent, unprotected long-header type bits (RFC 9000 and RFC 9369). */
object QuicHeaderMetadata {
    const val V1 = 0x00000001
    const val V2 = 0x6b3343cf
    val DRAFT29 = 0xff00001d.toInt()

    enum class PacketType(val protocolName: String) {
        INITIAL("Initial"), ZERO_RTT("0-RTT"), HANDSHAKE("Handshake"), RETRY("Retry")
    }

    enum class ObservationType(val code: String) {
        INITIAL("INITIAL"), ZERO_RTT("ZERO_RTT"), HANDSHAKE("HANDSHAKE"), RETRY("RETRY"),
        VERSION_NEGOTIATION("VERSION_NEGOTIATION");

        companion object {
            fun fromPacketType(type: PacketType): ObservationType = when (type) {
                PacketType.INITIAL -> INITIAL
                PacketType.ZERO_RTT -> ZERO_RTT
                PacketType.HANDSHAKE -> HANDSHAKE
                PacketType.RETRY -> RETRY
            }
        }
    }

    fun packetType(version: Int, firstByte: Int): PacketType? {
        if ((firstByte and 0xc0) != 0xc0) return null
        val encodedType = (firstByte ushr 4) and 3
        return when (version) {
            V1, DRAFT29 -> PacketType.entries[encodedType]
            V2 -> PacketType.entries[(encodedType + 3) and 3]
            else -> null
        }
    }
}
