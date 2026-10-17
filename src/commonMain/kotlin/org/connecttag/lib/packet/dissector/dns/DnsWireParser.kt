package org.connecttag.lib.packet.dissector.dns

import java.io.ByteArrayOutputStream
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * High-performance binary DNS wire-format parser and synthesizer compliant with
 * RFC 1035, RFC 8484 (DoH), and RFC 9460 (SVCB / HTTPS Resource Records).
 */
object DnsWireParser {

    const val TYPE_A = 1
    const val TYPE_NS = 2
    const val TYPE_CNAME = 5
    const val TYPE_SOA = 6
    const val TYPE_PTR = 12
    const val TYPE_MX = 15
    const val TYPE_TXT = 16
    const val TYPE_AAAA = 28
    const val TYPE_SVCB = 64
    const val TYPE_HTTPS = 65

    const val RCODE_NOERROR = 0
    const val RCODE_FORMERR = 1
    const val RCODE_SERVFAIL = 2
    const val RCODE_NXDOMAIN = 3
    const val RCODE_NOTIMP = 4
    const val RCODE_REFUSED = 5

    // RFC 9460 SvcParamKeys
    const val SVC_PARAM_MANDATORY = 0
    const val SVC_PARAM_ALPN = 1
    const val SVC_PARAM_NO_DEFAULT_ALPN = 2
    const val SVC_PARAM_PORT = 3
    const val SVC_PARAM_IPV4HINT = 4
    const val SVC_PARAM_ECH = 5
    const val SVC_PARAM_IPV6HINT = 6

    data class DnsHeader(
        val id: Int,
        val isResponse: Boolean,
        val opcode: Int,
        val isAuthoritative: Boolean,
        val isTruncated: Boolean,
        val recursionDesired: Boolean,
        val recursionAvailable: Boolean,
        val rcode: Int,
        val qdCount: Int,
        val anCount: Int,
        val nsCount: Int,
        val arCount: Int
    )

    data class DnsQuestion(
        val name: String,
        val qtype: Int,
        val qclass: Int
    )

    data class HttpsSvcParam(
        val key: Int,
        val valueBytes: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is HttpsSvcParam) return false
            if (key != other.key) return false
            if (!valueBytes.contentEquals(other.valueBytes)) return false
            return true
        }

        override fun hashCode(): Int {
            var result = key
            result = 31 * result + valueBytes.contentHashCode()
            return result
        }
    }

    data class HttpsRecord(
        val priority: Int,
        val targetName: String,
        val params: List<HttpsSvcParam>,
        val echConfigList: ByteArray?
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is HttpsRecord) return false
            if (priority != other.priority) return false
            if (targetName != other.targetName) return false
            if (params != other.params) return false
            if (!echConfigList.contentEquals(other.echConfigList)) return false
            return true
        }

        override fun hashCode(): Int {
            var result = priority
            result = 31 * result + targetName.hashCode()
            result = 31 * result + params.hashCode()
            result = 31 * result + (echConfigList?.contentHashCode() ?: 0)
            return result
        }
    }

    data class DnsResourceRecord(
        val name: String,
        val type: Int,
        val rclass: Int,
        val ttl: Long,
        val rdata: ByteArray,
        val httpsRecord: HttpsRecord? = null,
        val canonicalName: String? = null,
        val ptrName: String? = null,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is DnsResourceRecord) return false
            if (name != other.name) return false
            if (type != other.type) return false
            if (rclass != other.rclass) return false
            if (ttl != other.ttl) return false
            if (!rdata.contentEquals(other.rdata)) return false
            if (httpsRecord != other.httpsRecord) return false
            if (canonicalName != other.canonicalName) return false
            if (ptrName != other.ptrName) return false
            return true
        }

        override fun hashCode(): Int {
            var result = name.hashCode()
            result = 31 * result + type
            result = 31 * result + rclass
            result = 31 * result + ttl.hashCode()
            result = 31 * result + rdata.contentHashCode()
            result = 31 * result + (httpsRecord?.hashCode() ?: 0)
            result = 31 * result + (canonicalName?.hashCode() ?: 0)
            result = 31 * result + (ptrName?.hashCode() ?: 0)
            return result
        }
    }

    data class DnsMessage(
        val header: DnsHeader,
        val questions: List<DnsQuestion>,
        val answers: List<DnsResourceRecord>,
        val authorities: List<DnsResourceRecord> = emptyList(),
        val additionals: List<DnsResourceRecord> = emptyList()
    )

    fun parseMessage(data: ByteArray): DnsMessage? {
        if (data.size < 12) return null
        val buf = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)

        val id = buf.short.toInt() and 0xFFFF
        val flags = buf.short.toInt() and 0xFFFF
        val isResponse = ((flags ushr 15) and 0x01) == 1
        val opcode = (flags ushr 11) and 0x0F
        val isAuthoritative = ((flags ushr 10) and 0x01) == 1
        val isTruncated = ((flags ushr 9) and 0x01) == 1
        val recursionDesired = ((flags ushr 8) and 0x01) == 1
        val recursionAvailable = ((flags ushr 7) and 0x01) == 1
        val rcode = flags and 0x0F

        val qdCount = buf.short.toInt() and 0xFFFF
        val anCount = buf.short.toInt() and 0xFFFF
        val nsCount = buf.short.toInt() and 0xFFFF
        val arCount = buf.short.toInt() and 0xFFFF
        if (data.size > 65535 || qdCount > 256 || anCount + nsCount + arCount > 512) return null

        val header = DnsHeader(
            id = id,
            isResponse = isResponse,
            opcode = opcode,
            isAuthoritative = isAuthoritative,
            isTruncated = isTruncated,
            recursionDesired = recursionDesired,
            recursionAvailable = recursionAvailable,
            rcode = rcode,
            qdCount = qdCount,
            anCount = anCount,
            nsCount = nsCount,
            arCount = arCount
        )

        val questions = mutableListOf<DnsQuestion>()
        for (i in 0 until qdCount) {
            val name = readDomainName(buf, data) ?: return null
            if (buf.remaining() < 4) return null
            val qtype = buf.short.toInt() and 0xFFFF
            val qclass = buf.short.toInt() and 0xFFFF
            questions.add(DnsQuestion(name, qtype, qclass))
        }

        val answers = mutableListOf<DnsResourceRecord>()
        for (i in 0 until anCount) {
            val record = readResourceRecord(buf, data) ?: return null
            answers.add(record)
        }

        val authorities = mutableListOf<DnsResourceRecord>()
        for (i in 0 until nsCount) {
            val record = readResourceRecord(buf, data) ?: return null
            authorities.add(record)
        }

        val additionals = mutableListOf<DnsResourceRecord>()
        for (i in 0 until arCount) {
            val record = readResourceRecord(buf, data) ?: return null
            additionals.add(record)
        }

        if (buf.hasRemaining()) return null
        return DnsMessage(header, questions, answers, authorities, additionals)
    }

    private fun readResourceRecord(buf: ByteBuffer, raw: ByteArray): DnsResourceRecord? {
        val name = readDomainName(buf, raw) ?: return null
        if (buf.remaining() < 10) return null
        val type = buf.short.toInt() and 0xFFFF
        val rclass = buf.short.toInt() and 0xFFFF
        val ttl = buf.int.toLong() and 0xFFFFFFFFL
        val rdLength = buf.short.toInt() and 0xFFFF

        if (buf.remaining() < rdLength) return null
        val rdataStart = buf.position()
        val rdata = ByteArray(rdLength)
        buf.get(rdata)
        val domainTarget = if (type == TYPE_CNAME || type == TYPE_PTR) {
            val nameBuffer = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN)
            nameBuffer.limit(rdataStart + rdLength)
            nameBuffer.position(rdataStart)
            val target = readDomainName(nameBuffer, raw) ?: return null
            if (nameBuffer.position() != rdataStart + rdLength || target.isEmpty()) return null
            target
        } else null

        var httpsRecord: HttpsRecord? = null
        if (type == TYPE_HTTPS || type == TYPE_SVCB) {
            httpsRecord = parseHttpsRData(rdata)
        }

        return DnsResourceRecord(
            name = name,
            type = type,
            rclass = rclass,
            ttl = ttl,
            rdata = rdata,
            httpsRecord = httpsRecord,
            canonicalName = domainTarget.takeIf { type == TYPE_CNAME },
            ptrName = domainTarget.takeIf { type == TYPE_PTR },
        )
    }

    private fun parseHttpsRData(rdata: ByteArray): HttpsRecord? {
        val record = SvcbRDataParser.parse(rdata) ?: return null
        return HttpsRecord(
            priority = record.priority,
            targetName = record.target.takeUnless { it == "." }.orEmpty(),
            params = record.parameters.map { HttpsSvcParam(it.key, it.bytes) },
            echConfigList = record.parameters.firstOrNull { it.key == SVC_PARAM_ECH }?.bytes,
        )
    }

    private fun readDomainName(buf: ByteBuffer, raw: ByteArray): String? {
        val sb = StringBuilder()
        var jumped = false
        var jumpsCount = 0
        var savedPos = -1
        var terminated = false

        while (buf.hasRemaining()) {
            val len = buf.get().toInt() and 0xFF
            if (len == 0) {
                terminated = true
                break
            }
            if ((len and 0xC0) == 0xC0) {
                // Pointer to another position in raw packet
                if (!buf.hasRemaining()) return null
                val b2 = buf.get().toInt() and 0xFF
                val offset = ((len and 0x3F) shl 8) or b2
                if (!jumped) {
                    savedPos = buf.position()
                    jumped = true
                }
                if (++jumpsCount > 10 || offset >= buf.position() - 2) {
                    return null // Avoid circular loops
                }
                buf.position(offset)
            } else {
                if (len > 63 || buf.remaining() < len || sb.length + len + (if (sb.isEmpty()) 0 else 1) > 253) return null
                val label = ByteArray(len)
                buf.get(label)
                if (label.any { (it.toInt() and 255) !in 33..126 || it == '.'.code.toByte() }) return null
                if (sb.isNotEmpty()) sb.append('.')
                sb.append(String(label, Charsets.US_ASCII))
            }
        }

        if (!terminated) return null
        if (jumped && savedPos != -1) {
            buf.position(savedPos)
        }

        return sb.toString()
    }

    /**
     * Synthesizes a valid DNS NXDOMAIN response for a given raw DNS query packet.
     */
    fun createNoDataResponse(queryData: ByteArray): ByteArray? = createNxDomainResponse(queryData)?.apply {
        this[3] = (this[3].toInt() and 0xF0).toByte()
    }

    fun createNxDomainResponse(queryData: ByteArray): ByteArray? {
        if (queryData.size < 12) return null
        val queryBuf = ByteBuffer.wrap(queryData).order(ByteOrder.BIG_ENDIAN)
        val id = queryBuf.short.toInt() and 0xFFFF
        val flags = queryBuf.short.toInt() and 0xFFFF
        val qdCount = queryBuf.short.toInt() and 0xFFFF

        if (qdCount < 1) return null

        val qnameStart = 12
        val tempBuf = queryBuf.duplicate()
        tempBuf.position(qnameStart)
        val qname = readDomainName(tempBuf, queryData) ?: return null
        if (tempBuf.remaining() < 4) return null
        tempBuf.position(tempBuf.position() + 4)
        val questionBytesLen = tempBuf.position() - qnameStart

        val outLen = 12 + questionBytesLen
        val outBuf = ByteBuffer.allocate(outLen).order(ByteOrder.BIG_ENDIAN)

        outBuf.putShort(id.toShort())

        val rdBit = (flags ushr 8) and 0x01
        var respFlags = (1 shl 15) // QR = 1
        respFlags = respFlags or (rdBit shl 8) // RD
        respFlags = respFlags or (1 shl 7) // RA = 1
        respFlags = respFlags or RCODE_NXDOMAIN // RCODE = 3
        outBuf.putShort(respFlags.toShort())

        outBuf.putShort(qdCount.toShort())
        outBuf.putShort(0.toShort())
        outBuf.putShort(0.toShort())
        outBuf.putShort(0.toShort())

        outBuf.put(queryData, qnameStart, questionBytesLen)

        return outBuf.array()
    }

    /**
     * Synthesizes a valid DNS A (IPv4) answer response in RFC 1035 wire-format.
     */
    fun createAResponse(queryData: ByteArray, targetIpv4: String, ttlSeconds: Long = 60L): ByteArray? {
        if (queryData.size < 12) return null
        val ipBytes = NumericIpAddress.parse(targetIpv4)?.takeIf { it.size == 4 } ?: try {
            val addr = InetAddress.getByName(targetIpv4)
            if (addr !is Inet4Address) return null
            addr.address
        } catch (_: Exception) {
            return null
        }

        val queryBuf = ByteBuffer.wrap(queryData).order(ByteOrder.BIG_ENDIAN)
        val id = queryBuf.short.toInt() and 0xFFFF
        val flags = queryBuf.short.toInt() and 0xFFFF
        val qdCount = queryBuf.short.toInt() and 0xFFFF
        if (qdCount < 1) return null

        val qnameStart = 12
        val tempBuf = queryBuf.duplicate()
        tempBuf.position(qnameStart)
        readDomainName(tempBuf, queryData) ?: return null
        if (tempBuf.remaining() < 4) return null
        tempBuf.position(tempBuf.position() + 4)
        val questionBytesLen = tempBuf.position() - qnameStart

        val answerLen = 2 + 2 + 2 + 4 + 2 + 4
        val outLen = 12 + questionBytesLen + answerLen
        val outBuf = ByteBuffer.allocate(outLen).order(ByteOrder.BIG_ENDIAN)

        outBuf.putShort(id.toShort())
        val rdBit = (flags ushr 8) and 0x01
        val respFlags = (1 shl 15) or (rdBit shl 8) or (1 shl 7) or RCODE_NOERROR
        outBuf.putShort(respFlags.toShort())

        outBuf.putShort(qdCount.toShort())
        outBuf.putShort(1.toShort()) // ANCOUNT = 1
        outBuf.putShort(0.toShort())
        outBuf.putShort(0.toShort())

        outBuf.put(queryData, qnameStart, questionBytesLen)

        // Answer Section: Name pointer to offset 12 (0xC00C)
        outBuf.putShort(0xC00C.toShort())
        outBuf.putShort(TYPE_A.toShort())
        outBuf.putShort(1.toShort()) // Class IN
        outBuf.putInt(ttlSeconds.coerceIn(5L, 86400L).toInt())
        outBuf.putShort(4.toShort())
        outBuf.put(ipBytes)

        return outBuf.array()
    }

    /**
     * Synthesizes a valid DNS AAAA (IPv6) answer response in RFC 1035 wire-format.
     */
    fun createAaaaResponse(queryData: ByteArray, targetIpv6: String, ttlSeconds: Long = 60L): ByteArray? {
        if (queryData.size < 12) return null
        val ipBytes = NumericIpAddress.parse(targetIpv6)?.takeIf { it.size == 16 } ?: try {
            val addr = InetAddress.getByName(targetIpv6)
            if (addr !is Inet6Address) return null
            addr.address
        } catch (_: Exception) {
            return null
        }

        val queryBuf = ByteBuffer.wrap(queryData).order(ByteOrder.BIG_ENDIAN)
        val id = queryBuf.short.toInt() and 0xFFFF
        val flags = queryBuf.short.toInt() and 0xFFFF
        val qdCount = queryBuf.short.toInt() and 0xFFFF
        if (qdCount < 1) return null

        val qnameStart = 12
        val tempBuf = queryBuf.duplicate()
        tempBuf.position(qnameStart)
        readDomainName(tempBuf, queryData) ?: return null
        if (tempBuf.remaining() < 4) return null
        tempBuf.position(tempBuf.position() + 4)
        val questionBytesLen = tempBuf.position() - qnameStart

        val answerLen = 2 + 2 + 2 + 4 + 2 + 16
        val outLen = 12 + questionBytesLen + answerLen
        val outBuf = ByteBuffer.allocate(outLen).order(ByteOrder.BIG_ENDIAN)

        outBuf.putShort(id.toShort())
        val rdBit = (flags ushr 8) and 0x01
        val respFlags = (1 shl 15) or (rdBit shl 8) or (1 shl 7) or RCODE_NOERROR
        outBuf.putShort(respFlags.toShort())

        outBuf.putShort(qdCount.toShort())
        outBuf.putShort(1.toShort())
        outBuf.putShort(0.toShort())
        outBuf.putShort(0.toShort())

        outBuf.put(queryData, qnameStart, questionBytesLen)

        outBuf.putShort(0xC00C.toShort())
        outBuf.putShort(TYPE_AAAA.toShort())
        outBuf.putShort(1.toShort())
        outBuf.putInt(ttlSeconds.coerceIn(5L, 86400L).toInt())
        outBuf.putShort(16.toShort())
        outBuf.put(ipBytes)

        return outBuf.array()
    }

    /**
     * Synthesizes a valid DNS CNAME answer response in RFC 1035 wire-format.
     */
    fun createCnameResponse(queryData: ByteArray, cnameTarget: String, ttlSeconds: Long = 60L): ByteArray? {
        if (queryData.size < 12) return null
        val cnameBytes = encodeDomainName(cnameTarget)
        if (cnameBytes.isEmpty()) return null

        val queryBuf = ByteBuffer.wrap(queryData).order(ByteOrder.BIG_ENDIAN)
        val id = queryBuf.short.toInt() and 0xFFFF
        val flags = queryBuf.short.toInt() and 0xFFFF
        val qdCount = queryBuf.short.toInt() and 0xFFFF
        if (qdCount < 1) return null

        val qnameStart = 12
        val tempBuf = queryBuf.duplicate()
        tempBuf.position(qnameStart)
        readDomainName(tempBuf, queryData) ?: return null
        if (tempBuf.remaining() < 4) return null
        tempBuf.position(tempBuf.position() + 4)
        val questionBytesLen = tempBuf.position() - qnameStart

        val answerLen = 2 + 2 + 2 + 4 + 2 + cnameBytes.size
        val outLen = 12 + questionBytesLen + answerLen
        val outBuf = ByteBuffer.allocate(outLen).order(ByteOrder.BIG_ENDIAN)

        outBuf.putShort(id.toShort())
        val rdBit = (flags ushr 8) and 0x01
        val respFlags = (1 shl 15) or (rdBit shl 8) or (1 shl 7) or RCODE_NOERROR
        outBuf.putShort(respFlags.toShort())

        outBuf.putShort(qdCount.toShort())
        outBuf.putShort(1.toShort())
        outBuf.putShort(0.toShort())
        outBuf.putShort(0.toShort())

        outBuf.put(queryData, qnameStart, questionBytesLen)

        outBuf.putShort(0xC00C.toShort())
        outBuf.putShort(TYPE_CNAME.toShort())
        outBuf.putShort(1.toShort())
        outBuf.putInt(ttlSeconds.coerceIn(5L, 86400L).toInt())
        outBuf.putShort(cnameBytes.size.toShort())
        outBuf.put(cnameBytes)

        return outBuf.array()
    }

    /**
     * Synthesizes an immediate Sinkhole response (0.0.0.0 for A, :: for AAAA).
     */
    fun createSinkholeResponse(queryData: ByteArray, qtype: Int): ByteArray? {
        return if (qtype == TYPE_AAAA) {
            createAaaaResponse(queryData, "::", 300L)
        } else {
            createAResponse(queryData, "0.0.0.0", 300L)
        }
    }

    /**
     * Encodes a domain name string into DNS wire-format labels.
     */
    fun encodeDomainName(domain: String): ByteArray {
        val clean = domain.trim().removeSuffix(".")
        if (clean.isEmpty()) return byteArrayOf(0)
        val parts = clean.split(".")
        val out = ByteArrayOutputStream()
        for (part in parts) {
            val bytes = part.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size and 0xFF)
            out.write(bytes)
        }
        out.write(0)
        return out.toByteArray()
    }

    fun getTypeName(qtype: Int): String {
        return when (qtype) {
            TYPE_A -> "A"
            TYPE_NS -> "NS"
            TYPE_CNAME -> "CNAME"
            TYPE_SOA -> "SOA"
            TYPE_PTR -> "PTR"
            TYPE_MX -> "MX"
            TYPE_TXT -> "TXT"
            TYPE_AAAA -> "AAAA"
            TYPE_SVCB -> "SVCB"
            TYPE_HTTPS -> "HTTPS"
            else -> "TYPE_$qtype"
        }
    }
}
