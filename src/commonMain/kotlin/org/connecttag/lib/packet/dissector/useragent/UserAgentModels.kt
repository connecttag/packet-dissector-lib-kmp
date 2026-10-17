package org.connecttag.lib.packet.dissector.useragent

import kotlinx.serialization.Serializable

/**
 * High-level classification of HTTP User-Agent clients.
 */
@Serializable
enum class UaClientType {
    BROWSER,
    IN_APP_BROWSER,
    HTTP_LIBRARY,
    BOT_CRAWLER,
    SYSTEM_SERVICE,
    SUSPICIOUS_TOOL,
    UNKNOWN;

    fun isAutomatedOrTool(): Boolean =
        this == BOT_CRAWLER || this == SUSPICIOUS_TOOL || this == HTTP_LIBRARY
}

/**
 * Device form-factor classification.
 */
@Serializable
enum class UaDeviceType {
    MOBILE,
    TABLET,
    DESKTOP,
    TV,
    BOT,
    UNKNOWN
}

/**
 * Structured breakdown of a parsed User-Agent string.
 */
@Serializable
data class ParsedUserAgent(
    val rawString: String,
    val clientType: UaClientType = UaClientType.UNKNOWN,
    val clientName: String = "",
    val clientVersion: String? = null,
    val osName: String? = null,
    val osVersion: String? = null,
    val deviceModel: String? = null,
    val deviceType: UaDeviceType = UaDeviceType.UNKNOWN,
    val engine: String? = null,
    val inAppContainer: String? = null,
    val isBot: Boolean = false,
    val isSuspicious: Boolean = false,
    val riskScore: Int = 0 // 0 (Clean) to 100 (High Risk / Exploitation Tool)
) {
    val displayName: String
        get() {
            if (inAppContainer != null) {
                return "$inAppContainer (In-App)"
            }
            if (clientName.isNotEmpty()) {
                return if (clientVersion != null) "$clientName $clientVersion" else clientName
            }
            return if (rawString.length > 32) rawString.take(32) + "..." else rawString
        }

    val platformDescription: String
        get() {
            val os = listOfNotNull(osName, osVersion).joinToString(" ").trim()
            val dev = deviceModel.orEmpty()
            return when {
                os.isNotEmpty() && dev.isNotEmpty() -> "$os ($dev)"
                os.isNotEmpty() -> os
                dev.isNotEmpty() -> dev
                else -> ""
            }
        }
}
