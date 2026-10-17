package org.connecttag.lib.packet.dissector.icmp

import org.connecttag.lib.packet.dissector.dns.NumericIpAddress
import org.connecttag.lib.packet.dissector.model.MtuObservation

object IcmpMtuParser {
    data class QuotedFlow(
        val version: Int,
        val protocol: Int,
        val sourceKey: String,
        val sourcePort: Int,
        val destinationKey: String,
        val destinationPort: Int
    )

    data class Result(
        val observation: MtuObservation,
        val quotedFlow: QuotedFlow?
    )

    /** Header indications only: never authenticates a router, adjusts an MTU or sends probes. */
    fun parse(protocol: Int, payload: ByteArray): Result? {
        if (payload.size < 8) return null
        val type = payload[0].toInt() and 255
        val code = payload[1].toInt() and 255
        val mtu = when {
            protocol == 1 && type == 3 && code == 4 -> u16(payload, 6).toLong().takeIf { it > 0 }
            protocol == 58 && type == 2 && code == 0 -> u32(payload, 4).takeIf { it > 0 }
            else -> return null
        }
        return Result(
            observation = MtuObservation("UNVERIFIED_ICMP", type, code, mtu),
            quotedFlow = quoted(payload, 8)?.takeIf {
                it.version == if (protocol == 1) 4 else 6
            }
        )
    }

    private fun quoted(data: ByteArray, start: Int): QuotedFlow? {
        if (start >= data.size) return null
        val version = (data[start].toInt() and 255) ushr 4
        val protocol: Int
        val pos: Int
        val source: ByteArray
        val destination: ByteArray
        when (version) {
            4 -> {
                if (data.size - start < 20) return null
                val header = (data[start].toInt() and 15) * 4
                if (header !in 20..60 || header + 8 > data.size - start || u16(data, start + 2) < header + 8 || u16(data, start + 6) and 0x1fff != 0) return null
                protocol = data[start + 9].toInt() and 255
                pos = start + header
                source = data.copyOfRange(start + 12, start + 16)
                destination = data.copyOfRange(start + 16, start + 20)
            }
            6 -> {
                if (data.size - start < 48 || u16(data, start + 4) < 8) return null
                var proto = data[start + 6].toInt() and 255
                var currentPos = start + 40
                source = data.copyOfRange(start + 8, start + 24)
                destination = data.copyOfRange(start + 24, start + 40)
                var extensions = 0
                while (proto in listOf(0, 43, 44, 51, 60)) {
                    if (++extensions > 8 || currentPos + 2 > data.size) return null
                    val size = when (proto) {
                        44 -> {
                            if (currentPos + 8 > data.size || u16(data, currentPos + 2) and 0xfff8 != 0) return null
                            8
                        }
                        51 -> ((data[currentPos + 1].toInt() and 255) + 2) * 4
                        else -> ((data[currentPos + 1].toInt() and 255) + 1) * 8
                    }
                    if (currentPos + size > data.size || (proto == 51 && size < 12)) return null
                    proto = data[currentPos].toInt() and 255
                    currentPos += size
                }
                if (currentPos + 8 > data.size || currentPos + 8 > start + 40 + u16(data, start + 4)) return null
                protocol = proto
                pos = currentPos
            }
            else -> return null
        }
        if (protocol != 6 && protocol != 17) return null
        val srcKey = NumericIpAddress.key(source) ?: return null
        val dstKey = NumericIpAddress.key(destination) ?: return null
        return QuotedFlow(version, protocol, srcKey, u16(data, pos), dstKey, u16(data, pos + 2))
    }

    private fun u16(data: ByteArray, pos: Int) = ((data[pos].toInt() and 255) shl 8) or (data[pos + 1].toInt() and 255)
    private fun u32(data: ByteArray, pos: Int) = (0..3).fold(0L) { result, offset -> (result shl 8) or (data[pos + offset].toLong() and 255) }
}
