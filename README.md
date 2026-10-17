# ConnectTag Packet Dissector (KMP)

[![](https://jitpack.io/v/connecttag/packet-dissector-lib-kmp.svg)](https://jitpack.io/#connecttag/packet-dissector-lib-kmp)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A zero-copy, high-throughput network packet dissection and payload inspection library for Kotlin Multiplatform (Android, JVM, iOS/macOS).

Designed for deep packet inspection (DPI), firewall engines (e.g. SoorNet), security monitoring, and diagnostic protocol analysis.

## Features

- 🌐 **100% Kotlin Multiplatform**: Android, JVM, and Apple Native targets.
- 📡 **DNS Protocol Analysis**:
  - `DnsWireParser`: Full RFC 1035 / RFC 3596 wire protocol parser (Queries, Answers, EDNS0, SVCB/HTTPS records).
  - Reverse name compression pointer decompression.
- 🔒 **TLS & QUIC Inspection**:
  - `TlsClientHelloParser` & `TlsServerHelloParser`: SNI (Server Name Indication), ALPN, supported cipher suites, key shares.
  - `QuicLongHeaderParser`: Initial, Handshake, Retry packet dissection and connection ID extraction.
- 🌐 **HTTP & Streaming**:
  - `HttpHeaderStream`: Incremental state-machine HTTP/1.x header parsing over streaming byte chunks.
  - `HarExporter`: Convert dissected HTTP transactions into standard HTTP Archive (HAR 1.2) JSON files.
- ⚡ **WebSocket & ICMP**:
  - `WebSocketDecoder`: Dissects WebSocket frame opcodes, masks, and payload lengths.
  - `IcmpMtuParser`: Dissects ICMP Path MTU Discovery messages and next-hop MTUs.
- 📱 **User-Agent Classification**:
  - `UserAgentParser`: Lightweight, allocation-friendly UA parser identifying OS, browser engine, and device form factor without heavy regexes.

## Installation

Add JitPack repository to your root `settings.gradle.kts`:

```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven { url = java.net.URI("https://jitpack.io") }
    }
}
```

Add the dependency to your `build.gradle.kts`:

```kotlin
dependencies {
    implementation("com.github.connecttag:packet-dissector-lib-kmp:1.0.0")
}
```

## Quick Start

### 1. Dissecting TLS Client Hello SNI

```kotlin
import org.connecttag.lib.packet.dissector.tls.TlsClientHelloParser

val payload: ByteArray = // incoming TCP payload
val clientHello = TlsClientHelloParser.parse(payload)

if (clientHello != null) {
    println("SNI: ${clientHello.serverName}")
    println("ALPN: ${clientHello.alpnProtocols.joinToString()}")
}
```

### 2. Dissecting DNS Wire Payload

```kotlin
import org.connecttag.lib.packet.dissector.dns.DnsWireParser

val dnsPacket: ByteArray = // incoming UDP payload
val dnsMessage = DnsWireParser.parse(dnsPacket)

dnsMessage?.questions?.forEach { q ->
    println("Query: ${q.qName} (${q.qType})")
}
```

## License

```
Copyright 2026 Connect Tag

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```
