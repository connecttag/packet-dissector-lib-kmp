package org.connecttag.lib.packet.dissector.useragent

/**
 * High-performance, pure Kotlin User-Agent parser and scanner.
 * Designed for real-time firewall packet analysis with zero-allocation byte scanning
 * and LRU caching. Fully decoupled from Android SDK for KMP compatibility.
 */
object UserAgentParser {

    private const val MAX_CACHE_SIZE = 1000

    // Synchronized LRU cache for parsed User-Agent strings
    private val cache = object : LinkedHashMap<String, ParsedUserAgent>(128, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, ParsedUserAgent>?): Boolean {
            return size > MAX_CACHE_SIZE
        }
    }

    private val lock = Any()

    // Byte constants for HTTP scanning
    private val UA_HEADER_PREFIX = "user-agent:".toByteArray(Charsets.US_ASCII)
    private val SEC_CH_UA_PREFIX = "sec-ch-ua:".toByteArray(Charsets.US_ASCII)

    /**
     * Extracts User-Agent string directly from raw byte array without allocating full strings.
     * Searches case-insensitively for "User-Agent:" and returns the trimmed value.
     */
    fun extractUserAgentFromBytes(data: ByteArray, offset: Int = 0, length: Int = data.size): String? {
        return extractHeader(data, offset, length, UA_HEADER_PREFIX)
    }

    /**
     * Extracts Sec-CH-UA (Client Hints) string directly from raw bytes.
     */
    fun extractClientHintsFromBytes(data: ByteArray, offset: Int = 0, length: Int = data.size): String? {
        return extractHeader(data, offset, length, SEC_CH_UA_PREFIX)
    }

    private fun extractHeader(data: ByteArray, offset: Int, length: Int, prefix: ByteArray): String? {
        if (offset !in 0..data.size || length <= 0) return null
        val limit = offset + minOf(length, data.size - offset)
        var lineStart = offset
        while (lineStart < limit) {
            var lineEnd = lineStart
            while (lineEnd < limit && data[lineEnd] != '\n'.code.toByte()) lineEnd++
            // An incomplete header value must not be reported as a complete identity.
            if (lineEnd == limit) return null
            val contentEnd = if (lineEnd > lineStart && data[lineEnd - 1] == '\r'.code.toByte()) lineEnd - 1 else lineEnd
            if (contentEnd == lineStart) return null // End of headers; ignore the body.
            if (contentEnd - lineStart >= prefix.size && matchesHeaderPrefix(data, lineStart, prefix)) {
                var valueStart = lineStart + prefix.size
                while (valueStart < contentEnd && (data[valueStart] == ' '.code.toByte() || data[valueStart] == '\t'.code.toByte())) valueStart++
                if (valueStart < contentEnd) return String(data, valueStart, minOf(contentEnd - valueStart, 512), Charsets.UTF_8).trim()
            }
            lineStart = lineEnd + 1
        }
        return null
    }

    private fun matchesHeaderPrefix(data: ByteArray, start: Int, prefix: ByteArray): Boolean {
        for (j in prefix.indices) {
            val b = data[start + j]
            val lower = if (b in 65..90) (b + 32).toByte() else b
            if (lower != prefix[j]) return false
        }
        return true
    }

    /**
     * Parses a User-Agent string into a structured ParsedUserAgent object with caching.
     */
    fun parse(userAgent: String?): ParsedUserAgent {
        if (userAgent.isNullOrBlank()) {
            return ParsedUserAgent(rawString = "")
        }

        val trimmed = userAgent.trim()
        synchronized(lock) {
            val cached = cache[trimmed]
            if (cached != null) return cached
        }

        val parsed = parseInternal(trimmed)
        synchronized(lock) {
            cache[trimmed] = parsed
        }
        return parsed
    }

    private fun parseInternal(ua: String): ParsedUserAgent {
        val lower = ua.lowercase()

        // 1. High-risk security scanner / exploit tools
        checkSuspiciousTools(ua, lower)?.let { return it }

        // 2. Bots & Web Crawlers
        checkBotsAndCrawlers(ua, lower)?.let { return it }

        // 3. Android & Mobile HTTP Libraries
        checkHttpLibraries(ua, lower)?.let { return it }

        // 4. In-App WebViews (Social Media / Messaging in-app browsers)
        checkInAppWebViews(ua, lower)?.let { return it }

        // 5. Standard Browsers & Platform extraction
        return parseStandardBrowserOrApp(ua, lower)
    }

    private fun checkSuspiciousTools(ua: String, lower: String): ParsedUserAgent? {
        val tool = when {
            lower.contains("sqlmap") -> "sqlmap"
            lower.contains("nikto") -> "Nikto"
            lower.contains("masscan") -> "Masscan"
            lower.contains("nmap") -> "Nmap"
            lower.contains("dirbuster") || lower.contains("gobuster") -> "Directory Buster"
            lower.contains("acunetix") -> "Acunetix"
            lower.contains("hydra") -> "Hydra"
            lower.contains("metasploit") || lower.contains("meterpreter") -> "Metasploit"
            lower.contains("burpcollaborator") -> "Burp Suite"
            lower.contains("zaproxy") -> "OWASP ZAP"
            lower.contains("libwww-perl") -> "libwww-perl"
            else -> null
        }

        if (tool != null) {
            return ParsedUserAgent(
                rawString = ua,
                clientType = UaClientType.SUSPICIOUS_TOOL,
                clientName = tool,
                isSuspicious = true,
                riskScore = 95
            )
        }
        return null
    }

    private fun checkBotsAndCrawlers(ua: String, lower: String): ParsedUserAgent? {
        val botName = when {
            lower.contains("googlebot") -> "Googlebot"
            lower.contains("bingbot") -> "Bingbot"
            lower.contains("baiduspider") -> "Baiduspider"
            lower.contains("yandexbot") -> "YandexBot"
            lower.contains("duckduckbot") -> "DuckDuckBot"
            lower.contains("applebot") -> "Applebot"
            lower.contains("sogou") -> "Sogou Spider"
            lower.contains("facebookexternalhit") -> "Facebook External Hit"
            lower.contains("twitterbot") -> "Twitterbot"
            lower.contains("telegrambot") -> "TelegramBot"
            lower.contains("discordbot") -> "Discordbot"
            lower.contains("slackbot") -> "Slackbot"
            lower.contains("crawler") || lower.contains("spider") -> "Generic Web Crawler"
            else -> null
        }

        if (botName != null) {
            return ParsedUserAgent(
                rawString = ua,
                clientType = UaClientType.BOT_CRAWLER,
                clientName = botName,
                deviceType = UaDeviceType.BOT,
                isBot = true,
                riskScore = 20
            )
        }
        return null
    }

    private fun checkHttpLibraries(ua: String, lower: String): ParsedUserAgent? {
        val (libName, version) = when {
            lower.startsWith("okhttp/") -> "OkHttp" to productVersion(ua, lower, "okhttp/")
            lower.startsWith("dalvik/") -> "Dalvik" to productVersion(ua, lower, "dalvik/")
            lower.startsWith("curl/") -> "cURL" to productVersion(ua, lower, "curl/")
            lower.startsWith("python-requests/") -> "python-requests" to productVersion(ua, lower, "python-requests/")
            lower.startsWith("go-http-client/") -> "Go-http-client" to productVersion(ua, lower, "go-http-client/")
            lower.startsWith("wget/") -> "Wget" to productVersion(ua, lower, "wget/")
            lower.contains("apache-httpclient") -> "Apache-HttpClient" to null
            lower.contains("volley") -> "Volley" to null
            lower.contains("retrofit") -> "Retrofit" to null
            lower.contains("dart/") -> "Dart (Flutter)" to productVersion(ua, lower, "dart/")
            lower.contains("unityplayer/") -> "Unity" to ua.substringAfter("UnityPlayer/").substringBefore(" ").trim()
            lower.contains("cronet/") -> "Cronet" to ua.substringAfter("Cronet/").substringBefore(" ").trim()
            else -> null
        } ?: return null

        val isSuspicious = libName == "cURL" || libName == "python-requests" || libName == "Go-http-client" || libName == "Wget"
        val risk = if (isSuspicious) 45 else 10

        val (os, osVer, device) = extractPlatformInfo(ua)

        return ParsedUserAgent(
            rawString = ua,
            clientType = if (isSuspicious) UaClientType.SUSPICIOUS_TOOL else UaClientType.HTTP_LIBRARY,
            clientName = libName,
            clientVersion = version,
            osName = os,
            osVersion = osVer,
            deviceModel = device,
            deviceType = if (os == "Android" || os == "iOS") UaDeviceType.MOBILE else UaDeviceType.UNKNOWN,
            isSuspicious = isSuspicious,
            riskScore = risk
        )
    }

    private fun checkInAppWebViews(ua: String, lower: String): ParsedUserAgent? {
        val container = when {
            ua.contains("FB_IAB") || ua.contains("FBAN/") || ua.contains("FBAV/") -> "Facebook"
            ua.contains("Instagram") -> "Instagram"
            lower.contains("bytedancewebview") || lower.contains("musical_ly") || lower.contains("trill") -> "TikTok"
            ua.contains("WhatsApp/") -> "WhatsApp"
            lower.contains("twitterandroid") || lower.contains("twitter for android") -> "X (Twitter)"
            lower.contains("snapchat") -> "Snapchat"
            lower.contains("micromessenger/") -> "WeChat"
            lower.contains("line/") -> "Line"
            lower.contains("wv") || ua.contains("Version/4.0 Chrome/") -> "Android System WebView"
            else -> null
        }

        if (container != null) {
            val (os, osVer, device) = extractPlatformInfo(ua)
            val (browser, bVer) = extractBrowserEngine(ua, lower)
            return ParsedUserAgent(
                rawString = ua,
                clientType = UaClientType.IN_APP_BROWSER,
                clientName = browser ?: container,
                clientVersion = bVer,
                osName = os ?: "Android",
                osVersion = osVer,
                deviceModel = device,
                deviceType = UaDeviceType.MOBILE,
                engine = "Blink/WebKit",
                inAppContainer = container,
                riskScore = 5
            )
        }
        return null
    }

    private fun parseStandardBrowserOrApp(ua: String, lower: String): ParsedUserAgent {
        val (os, osVer, device) = extractPlatformInfo(ua)
        val (browser, bVer) = extractBrowserEngine(ua, lower)
        val devType = when {
            lower.contains("tablet") || lower.contains("ipad") -> UaDeviceType.TABLET
            lower.contains("mobile") || os == "Android" || os == "iOS" -> UaDeviceType.MOBILE
            os == "Windows" || os == "macOS" || os == "Linux" -> UaDeviceType.DESKTOP
            lower.contains("tv") || lower.contains("smarttv") -> UaDeviceType.TV
            else -> UaDeviceType.UNKNOWN
        }

        val engine = when {
            lower.contains("applewebkit") -> "WebKit"
            lower.contains("gecko") && !lower.contains("webkit") -> "Gecko"
            lower.contains("trident") -> "Trident"
            else -> null
        }

        return ParsedUserAgent(
            rawString = ua,
            clientType = if (browser != null) UaClientType.BROWSER else UaClientType.UNKNOWN,
            clientName = browser ?: "Unknown Client",
            clientVersion = bVer,
            osName = os,
            osVersion = osVer,
            deviceModel = device,
            deviceType = devType,
            engine = engine,
            riskScore = 0
        )
    }

    private fun extractBrowserEngine(ua: String, lower: String): Pair<String?, String?> {
        return when {
            lower.contains("edg/") || lower.contains("edge/") -> {
                val ver = productVersion(ua, lower, "edg/", "edge/")
                "Microsoft Edge" to ver
            }
            lower.contains("samsungbrowser/") -> {
                val ver = productVersion(ua, lower, "samsungbrowser/")
                "Samsung Internet" to ver
            }
            lower.contains("opr/") || lower.contains("opera/") -> {
                val ver = productVersion(ua, lower, "opr/", "opera/")
                "Opera" to ver
            }
            lower.contains("ucbrowser/") -> {
                val ver = productVersion(ua, lower, "ucbrowser/")
                "UC Browser" to ver
            }
            lower.contains("chrome/") -> {
                val ver = productVersion(ua, lower, "chrome/")
                "Google Chrome" to ver
            }
            lower.contains("firefox/") -> {
                val ver = productVersion(ua, lower, "firefox/")
                "Mozilla Firefox" to ver
            }
            lower.contains("safari/") && lower.contains("version/") -> {
                val ver = productVersion(ua, lower, "version/")
                "Apple Safari" to ver
            }
            else -> null to null
        }
    }

    private fun productVersion(ua: String, lower: String, vararg products: String): String? {
        val product = products.firstOrNull { lower.contains(it) } ?: return null
        return ua.substring(lower.indexOf(product) + product.length).takeWhile { !it.isWhitespace() && it != ')' && it != ';' }.takeIf { it.isNotEmpty() }
    }

    private fun extractPlatformInfo(ua: String): Triple<String?, String?, String?> {
        val pStart = ua.indexOf('(')
        val pEnd = ua.indexOf(')', pStart + 1)
        if (pStart == -1 || pEnd <= pStart) {
            return Triple(null, null, null)
        }

        val platformToken = ua.substring(pStart + 1, pEnd)
        val lower = platformToken.lowercase()

        var os: String? = null
        var osVersion: String? = null
        var device: String? = null

        when {
            lower.contains("android") -> {
                os = "Android"
                val match = Regex("android\\s+([0-9]+(?:\\.[0-9]+)*)", RegexOption.IGNORE_CASE).find(platformToken)
                osVersion = match?.groupValues?.getOrNull(1)

                if (platformToken.contains("Build/")) {
                    val preBuild = platformToken.substringBefore("Build/").trim()
                    val lastSemi = preBuild.lastIndexOf(';')
                    if (lastSemi != -1) {
                        device = preBuild.substring(lastSemi + 1).trim()
                    }
                }
            }
            lower.contains("iphone") -> {
                os = "iOS"
                device = "iPhone"
                val match = Regex("os\\s+([0-9_]+)", RegexOption.IGNORE_CASE).find(platformToken)
                osVersion = match?.groupValues?.getOrNull(1)?.replace('_', '.')
            }
            lower.contains("ipad") -> {
                os = "iOS"
                device = "iPad"
                val match = Regex("os\\s+([0-9_]+)", RegexOption.IGNORE_CASE).find(platformToken)
                osVersion = match?.groupValues?.getOrNull(1)?.replace('_', '.')
            }
            lower.contains("windows nt") -> {
                os = "Windows"
                val match = Regex("windows nt\\s+([0-9]+(?:\\.[0-9]+)*)", RegexOption.IGNORE_CASE).find(platformToken)
                osVersion = when (match?.groupValues?.getOrNull(1)) {
                    "10.0" -> "10 / 11"
                    "6.3" -> "8.1"
                    "6.2" -> "8"
                    "6.1" -> "7"
                    else -> match?.groupValues?.getOrNull(1)
                }
            }
            lower.contains("macintosh") || lower.contains("mac os x") -> {
                os = "macOS"
                val match = Regex("mac os x\\s+([0-9_]+)", RegexOption.IGNORE_CASE).find(platformToken)
                osVersion = match?.groupValues?.getOrNull(1)?.replace('_', '.')
            }
            lower.contains("linux") -> {
                os = "Linux"
            }
        }

        return Triple(os, osVersion, device)
    }

    fun detectAppMasquerading(packageName: String?, parsedUa: ParsedUserAgent): Boolean {
        if (packageName.isNullOrBlank() || parsedUa.rawString.isBlank()) return false
        val pkg = packageName.lowercase()

        if (parsedUa.clientName == "Google Chrome" && parsedUa.inAppContainer == null) {
            val isLegitChrome = pkg == "com.android.chrome" ||
                    pkg == "com.chrome.beta" ||
                    pkg == "com.chrome.dev" ||
                    pkg == "com.chrome.canary"
            if (!isLegitChrome && !parsedUa.rawString.contains("; wv") && !parsedUa.rawString.contains("Version/4.0")) {
                return true
            }
        }

        if (parsedUa.clientName == "WhatsApp" && pkg != "com.whatsapp" && pkg != "com.whatsapp.w4b") {
            return true
        }

        if (parsedUa.clientName == "Mozilla Firefox" && !pkg.contains("mozilla.firefox") && !pkg.contains("org.mozilla")) {
            return true
        }

        if ((parsedUa.osName == "Windows" || parsedUa.osName == "macOS") && parsedUa.deviceType == UaDeviceType.DESKTOP) {
            return true
        }

        return false
    }

    fun clearCache() {
        synchronized(lock) {
            cache.clear()
        }
    }
}
