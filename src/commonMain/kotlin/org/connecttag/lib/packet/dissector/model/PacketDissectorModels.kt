package org.connecttag.lib.packet.dissector.model

import kotlinx.serialization.Serializable

/**
 * Observed Encrypted Client Hello (ECH) extension forms.
 */
enum class EchExtensionForm {
    NOT_PRESENT,
    OUTER,
    INNER_MARKER,
    UNSUPPORTED,
    PRESENT_UNCLASSIFIED
}

/**
 * Structured observations from cleartext TLS ClientHello and ServerHello handshakes.
 */
@Serializable
data class TlsHeaderFacts(
    val clientLegacyVersion: Int? = null,
    val offeredVersions: List<Int>? = null,
    val offeredCiphers: List<Int>? = null,
    val offeredGroups: List<Int>? = null,
    val offeredAlpns: List<String>? = null,
    val selectedVersion: Int? = null,
    val selectedCipher: Int? = null,
    val selectedGroup: Int? = null,
    val selectedAlpn: String? = null,
    val pskSelected: Boolean? = null,
    val helloRetryRequestObserved: Boolean? = null,
    val retryRequestedGroup: Int? = null,
) {
    fun mergeWith(next: TlsHeaderFacts): TlsHeaderFacts = TlsHeaderFacts(
        clientLegacyVersion = next.clientLegacyVersion ?: clientLegacyVersion,
        offeredVersions = if (next.clientLegacyVersion != null) next.offeredVersions else next.offeredVersions ?: offeredVersions,
        offeredCiphers = if (next.clientLegacyVersion != null) next.offeredCiphers else next.offeredCiphers ?: offeredCiphers,
        offeredGroups = if (next.clientLegacyVersion != null) next.offeredGroups else next.offeredGroups ?: offeredGroups,
        offeredAlpns = if (next.clientLegacyVersion != null) next.offeredAlpns else next.offeredAlpns ?: offeredAlpns,
        selectedVersion = if (next.clientLegacyVersion != null || next.selectedVersion != null) next.selectedVersion else selectedVersion,
        selectedCipher = if (next.clientLegacyVersion != null || next.selectedCipher != null) next.selectedCipher else selectedCipher,
        selectedGroup = if (next.clientLegacyVersion != null || next.selectedGroup != null) next.selectedGroup else selectedGroup,
        selectedAlpn = if (next.clientLegacyVersion != null || next.selectedAlpn != null) next.selectedAlpn else selectedAlpn,
        pskSelected = if (next.clientLegacyVersion != null || next.pskSelected != null) next.pskSelected else pskSelected,
        helloRetryRequestObserved = if (next.clientLegacyVersion != null || next.helloRetryRequestObserved != null) next.helloRetryRequestObserved else helloRetryRequestObserved,
        retryRequestedGroup = if (next.clientLegacyVersion != null || next.retryRequestedGroup != null) next.retryRequestedGroup else retryRequestedGroup,
    )
}

/**
 * Structured facts observed from cleartext HTTP/1 headers.
 */
@Serializable
data class HttpHeaderFacts(
    val statusCode: Int,
    val hstsPresent: Boolean,
    val hstsMaxAgeSeconds: Long? = null,
    val hstsIncludeSubdomains: Boolean? = null,
    val setCookieCount: Int = 0,
    val secureCookieCount: Int = 0,
    val httpOnlyCookieCount: Int = 0,
    val retryAfterSeconds: Long? = null,
    val retryAfterEpochSeconds: Long? = null,
    val redirectTargetHost: String? = null,
    val redirectTargetScheme: String? = null,
    val headerBlockComplete: Boolean = true,
)

/**
 * Structured facts observed from DNS header flags and EDNS options.
 */
@Serializable
data class DnsHeaderFacts(
    val isResponse: Boolean,
    val responseCode: Int,
    val extendedErrorCodes: List<Int> = emptyList(),
    val authenticatedDataBit: Boolean,
    val checkingDisabledBit: Boolean,
    val truncatedBit: Boolean,
    val ednsVersion: Int? = null,
)

/**
 * Observed Path MTU discovery parameters from ICMP notifications.
 */
@Serializable
data class MtuObservation(
    val source: String,
    val icmpType: Int? = null,
    val icmpCode: Int? = null,
    val advertisedMtu: Long? = null,
    val socketErrno: Int? = null,
    val matchedQuotedTuple: Boolean = false,
)

/**
 * Diagnostics reasoning for unavailable inspection metadata.
 */
enum class UnavailableReason {
    ENCRYPTED,
    INCOMPLETE_CAPTURE,
    INSPECTION_LIMIT,
    UNSUPPORTED_FORMAT,
    NOT_OBSERVED,
    NOT_APPLICABLE,
    AMBIGUOUS,
    EXPIRED
}

/**
 * Observed RFC 9460 Service Binding (SVCB / HTTPS) advertisements.
 */
@Serializable
data class ServiceBindingAdvertisement(
    val owner: String,
    val recordType: Int,
    val priority: Int,
    val target: String,
    val ttlSeconds: Long,
    val alpns: List<String> = emptyList(),
    val noDefaultAlpn: Boolean = false,
    val port: Int? = null,
    val ipv4Hints: List<String> = emptyList(),
    val ipv6Hints: List<String> = emptyList(),
    val echConfigPresent: Boolean = false,
    val mandatoryKeys: List<Int> = emptyList(),
    val unsupportedMandatoryKeys: List<Int> = emptyList(),
)

/**
 * Comparative evaluation between observed network connection and DNS SVCB/HTTPS advertisements.
 */
@Serializable
data class ServiceBindingComparison(
    val origin: String,
    val records: List<ServiceBindingAdvertisement>,
    val basis: String,
    val observedPort: Int,
    val observedTransport: String,
    val portListed: Boolean? = null,
    val offeredAlpnOverlap: Boolean? = null,
    val selectedAlpnListed: Boolean? = null,
)
