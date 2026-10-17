package org.connecttag.lib.packet.dissector.http

import org.connecttag.lib.packet.dissector.model.HttpHeaderFacts

/** Stable presence bits; cookies and authorization values are never copied into inspection metadata. */
object InspectionHttpHeaders {
    val legacyNames = linkedMapOf(
        "referer" to "Referer", "origin" to "Origin", "sec-fetch-site" to "Fetch-Site",
        "sec-fetch-mode" to "Fetch-Mode", "sec-fetch-dest" to "Fetch-Dest", "sec-fetch-user" to "Fetch-User",
        "range" to "Range", "content-type" to "Content-Type", "upgrade" to "Upgrade", "connection" to "Connection",
        "accept" to "Accept", "accept-language" to "Accept-Language", "sec-ch-ua" to "CH-UA",
        "sec-ch-ua-platform" to "CH-Platform", "sec-ch-ua-model" to "CH-Model", "cookie" to "Cookie",
        "authorization" to "Authorization", "user-agent" to "User-Agent", "set-cookie" to "Set-Cookie", "cache-control" to "Cache-Control", "age" to "Age", "etag" to "ETag", "content-range" to "Content-Range",
    )
    val names: Set<String> = legacyNames.keys
    fun flag(name: String): Long {
        val index = legacyNames.keys.indexOf(name.lowercase())
        return if (index < 0) 0 else 1L shl index
    }
    fun present(flags: Long?, name: String): Boolean = flags != null && (flags and flag(name)) != 0L
    fun fromHeaders(headers: Map<String, String>): Long = headers.keys.fold(0L) { bits, key -> bits or flag(key) }

    /** Connection: close/keep-alive alone is not a protocol upgrade request. */
    fun indicatesProtocolUpgrade(flags: Long?, statusCode: Int?): Boolean = present(flags, "upgrade") || statusCode == 101

    data class Block(val statusCode: Int?, val fields: List<Pair<String, String>>, val method: String? = null) {
        fun asMap(): Map<String, String> = fields.toMap()
        fun responseFacts(): HttpHeaderFacts? {
            val status = statusCode ?: return null
            fun all(name: String) = fields.filter { it.first == name }.map { it.second }
            val hsts = all("strict-transport-security")
            val directives = hsts.singleOrNull()?.split(';')?.map { it.trim() }
            val maxAge = directives?.filter { it.substringBefore('=').equals("max-age", true) }
                ?.singleOrNull()?.substringAfter('=', "")?.trim()?.removeSurrounding("\"")?.decimal()
            val cookies = all("set-cookie").filter { cookie ->
                val pair = cookie.substringBefore(';')
                val name = pair.substringBefore('=', "")
                name.isNotEmpty() && name.all(::isToken) && '=' in pair
            }
            fun cookieFlag(cookie: String, name: String) = cookie.split(';').drop(1)
                .any { it.trim().substringBefore('=').equals(name, true) }
            val retry = all("retry-after").singleOrNull()
            val target = if (status in 300..399 && status != 304) all("location").singleOrNull()?.let(::redirectAuthority) else null
            return HttpHeaderFacts(
                statusCode = status,
                hstsPresent = hsts.isNotEmpty(),
                hstsMaxAgeSeconds = maxAge,
                hstsIncludeSubdomains = if (maxAge != null) directives.any { it.equals("includeSubDomains", true) } else null,
                setCookieCount = cookies.size,
                secureCookieCount = cookies.count { cookieFlag(it, "secure") },
                httpOnlyCookieCount = cookies.count { cookieFlag(it, "httponly") },
                retryAfterSeconds = retry?.decimal(),
                retryAfterEpochSeconds = retry?.let(::httpDateEpochSeconds),
                redirectTargetHost = target?.second,
                redirectTargetScheme = target?.first,
            )
        }
    }

    fun parseCompleteBlock(payload: ByteArray): Map<String, String>? = parseBlock(payload)?.asMap()

    /** Complete bounded HTTP/1 headers only. Duplicates remain distinct (especially Set-Cookie). */
    fun parseBlock(payload: ByteArray): Block? {
        if (headerLimitExceeded(payload)) return null
        if (payload.isEmpty()) return null
        val text = payload.copyOfRange(0, minOf(payload.size, 16384)).toString(Charsets.ISO_8859_1)
        val end = text.indexOf("\r\n\r\n").takeIf { it >= 0 } ?: return null
        val lines = text.substring(0, end).split("\r\n")
        val first = lines.firstOrNull() ?: return null
        val response = Regex("^HTTP/1\\.[01] ([1-5][0-9]{2})(?: [\\x20-\\x7e\\x80-\\xff]*)?$").matchEntire(first)
        if (response == null && !Regex("^[!#$%&'*+.^_`|~0-9A-Za-z-]+ [^\\x00-\\x20\\x7f]+ HTTP/1\\.[01]$").matches(first)) return null
        val result = mutableListOf<Pair<String, String>>()
        for (line in lines.drop(1)) {
            val separator = line.indexOf(':')
            if (separator <= 0) return null
            val name = line.substring(0, separator).lowercase()
            val value = line.substring(separator + 1).trim(' ', '\t')
            if (!name.all(::isToken) || value.any { it == '\u007f' || (it < ' ' && it != '\t') }) return null
            result += name to value
        }
        // Ambiguous framing must never produce trusted derived facts.
        val lengths = result.filter { it.first == "content-length" }.flatMap { it.second.split(',') }.map { it.trim().decimal() }
        if (lengths.any { it == null } || lengths.distinct().size > 1) return null
        if (lengths.isNotEmpty() && result.any { it.first == "transfer-encoding" }) return null
        return Block(response?.groupValues?.get(1)?.toInt(), result, if (response == null) first.substringBefore(' ') else null)
    }

    fun headerLimitExceeded(payload: ByteArray): Boolean {
        val text = payload.copyOfRange(0, minOf(payload.size, 16384)).toString(Charsets.ISO_8859_1)
        val end = text.indexOf("\r\n\r\n")
        if (end < 0) return payload.size >= 16384
        val lines = text.substring(0, end).split("\r\n")
        return lines.size > 129 || lines.drop(1).any { it.substringAfter(':', "").trim(' ', '\t').length > 4096 }
    }

    private fun isToken(char: Char) = char in 'a'..'z' || char in 'A'..'Z' || char in '0'..'9' || char in "!#$%&'*+-.^_`|~"
    private fun String.decimal(): Long? = takeIf { it.isNotEmpty() && it.length <= 19 && it.all { c -> c in '0'..'9' } }?.toLongOrNull()

    /** Only the advertised authority is retained. Never retain URL credentials, path, query or fragment. */
    private fun redirectAuthority(location: String): Pair<String?, String>? {
        if (location.length > 2048 || location.any { it <= ' ' || it >= '\u007f' || it == '\\' }) return null
        val scheme = when {
            location.startsWith("https://", true) -> "https"
            location.startsWith("http://", true) -> "http"
            location.startsWith("//") -> null
            else -> return null
        }
        val authority = (if (scheme == null) location.drop(2) else location.substringAfter("://"))
            .takeWhile { it != '/' && it != '?' && it != '#' }
        return scheme to (authorityHost(authority) ?: return null)
    }

    /** Shared strict HTTP authority parsing; never accepts credentials or URL suffixes. */
    fun authorityHost(authority: String): String? {
        if (authority.length !in 1..300 || authority.any { it <= ' ' || it >= '\u007f' || it in "/?#\\" }) return null
        if ('@' in authority || '%' in authority) return null
        val host: String
        val port: String
        if (authority.startsWith('[')) {
            val closing = authority.indexOf(']')
            if (closing <= 1) return null
            host = authority.substring(0, closing + 1)
            if (!ipv6Literal(host.drop(1).dropLast(1))) return null
            port = authority.substring(closing + 1)
        } else {
            host = authority.substringBefore(':')
            port = authority.removePrefix(host)
            if (host.length !in 1..253 || host.trimEnd('.').split('.').any { label ->
                label.length !in 1..63 || label.startsWith('-') || label.endsWith('-') || label.any { !it.isLetterOrDigit() && it != '-' }
            }) return null
        }
        if (port.isNotEmpty() && (!port.startsWith(':') || port.drop(1).decimal()?.let { it in 1L..65535L } != true)) return null
        return host.lowercase().trimEnd('.')
    }

    private fun ipv6Literal(value: String): Boolean {
        val parts = value.split("::")
        if (parts.size > 2) return false
        val groups = parts.flatMap { if (it.isEmpty()) emptyList() else it.split(':') }
        if (groups.any { it.length !in 1..4 || it.any { char -> char !in "0123456789abcdefABCDEF" } }) return false
        return if (parts.size == 2) groups.size < 8 else groups.size == 8
    }

    /** IMF-fixdate only; unsupported/invalid date formats remain unavailable. Pure Kotlin, no I/O. */
    internal fun httpDateEpochSeconds(value: String): Long? {
        val match = Regex("^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), ([0-9]{2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ([0-9]{4}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) GMT$").matchEntire(value) ?: return null
        val parts = match.groupValues
        val year = parts[4].toInt()
        val month = listOf("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec").indexOf(parts[3])
        val day = parts[2].toInt()
        val leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
        val months = intArrayOf(31, if (leap) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
        val hour = parts[5].toInt()
        val minute = parts[6].toInt()
        val second = parts[7].toInt()
        if (year < 1601 || day !in 1..months[month] || hour > 23 || minute > 59 || second > 59) return null
        fun beforeYear(y: Int): Long { val previous = y - 1L; return 365 * previous + previous / 4 - previous / 100 + previous / 400 }
        val days = beforeYear(year) - beforeYear(1970) + months.take(month).sum() + day - 1
        return days * 86400 + hour * 3600 + minute * 60 + second
    }
}
