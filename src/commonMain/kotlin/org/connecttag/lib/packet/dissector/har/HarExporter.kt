package org.connecttag.lib.packet.dissector.har

import java.io.Closeable
import java.io.Flushable
import java.io.OutputStream
import java.io.OutputStreamWriter
import java.io.Writer
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.ArrayDeque
import java.util.Locale

/**
 * Generic data models for HAR 1.2 generation.
 */
data class HarHttpRequest(
    val method: String? = "GET",
    val url: String? = null,
    val host: String? = null,
    val path: String? = "/",
    val query: String? = null,
    val httpVersion: String? = "HTTP/1.1",
    val headers: Map<String, String> = emptyMap(),
    val bodyText: String? = null,
    val timestamp: Long = 0L
)

data class HarHttpResponse(
    val statusCode: Int? = 200,
    val statusText: String? = "OK",
    val httpVersion: String? = "HTTP/1.1",
    val headers: Map<String, String> = emptyMap(),
    val bodyText: String? = null,
    val rawSize: Int = 0
)

data class HarWebSocketMessage(
    val type: String, // "send" or "receive"
    val time: Double, // seconds since epoch
    val opcode: Int,
    val data: String
)

data class HarTransaction(
    val request: HarHttpRequest,
    val response: HarHttpResponse? = null,
    val webSocketMessages: List<HarWebSocketMessage> = emptyList(),
    val latencyMs: Long = 0L,
    val flowId: String = "flow-0",
    val timestamp: Long = 0L
)

/**
 * Exports HTTP transactions and associated WebSocket frames to standard HAR 1.2 format.
 * Compatible with Chrome DevTools, Postman, and Charles Proxy.
 * Pure Kotlin/JVM streaming JSON output for minimal memory overhead.
 */
object HarExporter {

    private const val HAR_VERSION = "1.2"
    private const val CREATOR_NAME = "ConnectTag-Dissector"
    private const val CREATOR_VERSION = "1.0"

    fun export(
        transactions: List<HarTransaction>,
        outputStream: OutputStream,
        creatorName: String = CREATOR_NAME,
        creatorVersion: String = CREATOR_VERSION
    ) {
        val writer = HarJsonWriter(OutputStreamWriter(outputStream, StandardCharsets.UTF_8))
        writer.setIndent("  ")

        writer.beginObject()
        writer.name("log")
        writer.beginObject()

        writer.name("version").value(HAR_VERSION)

        writer.name("creator")
        writer.beginObject()
        writer.name("name").value(creatorName)
        writer.name("version").value(creatorVersion)
        writer.endObject()

        writer.name("entries")
        writer.beginArray()

        for (tx in transactions) {
            try {
                writeEntry(writer, tx)
            } catch (_: Throwable) {
                // Skip entry on unexpected serialization error
            }
        }

        writer.endArray()
        writer.endObject()
        writer.endObject()

        writer.flush()
    }

    private fun writeEntry(writer: HarJsonWriter, tx: HarTransaction) {
        writer.beginObject()

        val timeEpoch = tx.request.timestamp.takeIf { it > 0 } ?: tx.timestamp
        writer.name("startedDateTime").value(formatIso8601(timeEpoch))

        val timeMs = maxOf(0L, tx.latencyMs)
        writer.name("time").value(timeMs)

        writer.name("connection").value(tx.flowId)
        val serverIp = extractServerIp(tx.flowId)
        if (serverIp != null) {
            writer.name("serverIPAddress").value(serverIp)
        }

        writer.name("request")
        writeRequest(writer, tx)

        writer.name("response")
        writeResponse(writer, tx)

        writer.name("cache")
        writer.beginObject()
        writer.endObject()

        writer.name("timings")
        writer.beginObject()
        writer.name("send").value(-1L)
        writer.name("wait").value(timeMs)
        writer.name("receive").value(-1L)
        writer.endObject()

        if (tx.webSocketMessages.isNotEmpty()) {
            writer.name("_webSocketMessages")
            writer.beginArray()
            for (msg in tx.webSocketMessages) {
                writer.beginObject()
                writer.name("type").value(msg.type)
                writer.name("time").value(msg.time)
                writer.name("opcode").value(msg.opcode)
                writer.name("data").value(msg.data)
                writer.endObject()
            }
            writer.endArray()
        }

        writer.endObject()
    }

    private fun writeRequest(writer: HarJsonWriter, tx: HarTransaction) {
        val req = tx.request
        writer.beginObject()

        writer.name("method").value(req.method ?: "GET")
        val targetUrl = req.url ?: "http://${req.host ?: "unknown"}${req.path ?: "/"}"
        writer.name("url").value(targetUrl)
        writer.name("httpVersion").value(req.httpVersion ?: "HTTP/1.1")

        writer.name("cookies")
        writer.beginArray()
        writer.endArray()

        writer.name("headers")
        writer.beginArray()
        for ((k, v) in req.headers) {
            writer.beginObject()
            writer.name("name").value(k)
            writer.name("value").value(v)
            writer.endObject()
        }
        writer.endArray()

        writer.name("queryString")
        writer.beginArray()
        writer.endArray()

        val method = req.method?.uppercase(Locale.US)
        if ((method == "POST" || method == "PUT" || method == "PATCH") && req.bodyText != null) {
            writer.name("postData")
            writer.beginObject()
            writer.name("mimeType").value(req.headers["content-type"] ?: "application/octet-stream")
            writer.name("text").value(req.bodyText)
            writer.endObject()
        }

        writer.name("headersSize").value(-1L)
        writer.name("bodySize").value(req.bodyText?.length?.toLong() ?: 0L)

        writer.endObject()
    }

    private fun writeResponse(writer: HarJsonWriter, tx: HarTransaction) {
        val resp = tx.response
        writer.beginObject()

        if (resp != null) {
            writer.name("status").value(resp.statusCode ?: 200)
            writer.name("statusText").value(resp.statusText ?: "OK")
            writer.name("httpVersion").value(resp.httpVersion ?: "HTTP/1.1")

            writer.name("cookies")
            writer.beginArray()
            writer.endArray()

            writer.name("headers")
            writer.beginArray()
            for ((k, v) in resp.headers) {
                writer.beginObject()
                writer.name("name").value(k)
                writer.name("value").value(v)
                writer.endObject()
            }
            writer.endArray()

            writer.name("content")
            writer.beginObject()
            writer.name("size").value(resp.bodyText?.length?.toLong() ?: resp.rawSize.toLong())
            writer.name("mimeType").value(resp.headers["content-type"] ?: "application/octet-stream")
            if (resp.bodyText != null) {
                writer.name("text").value(resp.bodyText)
            }
            writer.endObject()

            writer.name("redirectURL").value(resp.headers["location"] ?: "")
            writer.name("headersSize").value(-1L)
            writer.name("bodySize").value(resp.rawSize.toLong())
        } else {
            writer.name("status").value(0)
            writer.name("statusText").value("No Response")
            writer.name("httpVersion").value("HTTP/1.1")
            writer.name("cookies").beginArray().endArray()
            writer.name("headers").beginArray().endArray()
            writer.name("content").beginObject().name("size").value(0L).name("mimeType").value("").endObject()
            writer.name("redirectURL").value("")
            writer.name("headersSize").value(-1L)
            writer.name("bodySize").value(0L)
        }

        writer.endObject()
    }

    private fun extractServerIp(flowId: String): String? {
        val parts = flowId.split("->", "-", ":")
        return parts.firstOrNull { it.count { c -> c == '.' } == 3 || it.contains(":") }
    }

    private fun formatIso8601(epochMs: Long): String {
        val time = if (epochMs <= 0) System.currentTimeMillis() else epochMs
        val sec = time / 1000
        val ms = time % 1000
        return "${sec}.${ms}Z"
    }

    private class HarJsonWriter(private val out: Writer) : Closeable, Flushable {
        private val stack = ArrayDeque<Int>()
        private var indent: String = ""
        private var separator: String = ":"

        companion object {
            private const val EMPTY_ARRAY = 1
            private const val NONEMPTY_ARRAY = 2
            private const val EMPTY_OBJECT = 3
            private const val DANGLING_NAME = 4
            private const val NONEMPTY_OBJECT = 5
        }

        fun setIndent(indent: String) {
            this.indent = indent
            this.separator = if (indent.isEmpty()) ":" else ": "
        }

        fun beginArray(): HarJsonWriter = open(EMPTY_ARRAY, "[")
        fun endArray(): HarJsonWriter = close(EMPTY_ARRAY, NONEMPTY_ARRAY, "]")
        fun beginObject(): HarJsonWriter = open(EMPTY_OBJECT, "{")
        fun endObject(): HarJsonWriter = close(EMPTY_OBJECT, NONEMPTY_OBJECT, "}")

        private fun open(empty: Int, openBracket: String): HarJsonWriter {
            beforeValue()
            stack.push(empty)
            out.write(openBracket)
            return this
        }

        private fun close(empty: Int, nonempty: Int, closeBracket: String): HarJsonWriter {
            val context = peek()
            if (context != nonempty && context != empty) throw IllegalStateException("Nesting problem")
            stack.pop()
            if (context == nonempty) newline()
            out.write(closeBracket)
            return this
        }

        fun name(name: String): HarJsonWriter {
            beforeName()
            string(name)
            return this
        }

        fun value(value: String?): HarJsonWriter {
            if (value == null) return nullValue()
            beforeValue()
            string(value)
            return this
        }

        fun value(value: Long): HarJsonWriter {
            beforeValue()
            out.write(value.toString())
            return this
        }

        fun value(value: Int): HarJsonWriter = value(value.toLong())

        fun value(value: Double): HarJsonWriter {
            beforeValue()
            out.write(value.toString())
            return this
        }

        fun value(value: Boolean): HarJsonWriter {
            beforeValue()
            out.write(if (value) "true" else "false")
            return this
        }

        fun nullValue(): HarJsonWriter {
            beforeValue()
            out.write("null")
            return this
        }

        private fun peek(): Int = if (stack.isEmpty()) 0 else stack.peek()

        private fun beforeName() {
            val context = peek()
            if (context == NONEMPTY_OBJECT) {
                out.write(",")
            } else if (context != EMPTY_OBJECT) {
                throw IllegalStateException("Nesting problem")
            }
            newline()
            stack.pop()
            stack.push(DANGLING_NAME)
        }

        private fun beforeValue() {
            when (peek()) {
                EMPTY_ARRAY -> {
                    stack.pop()
                    stack.push(NONEMPTY_ARRAY)
                    newline()
                }
                NONEMPTY_ARRAY -> {
                    out.write(",")
                    newline()
                }
                DANGLING_NAME -> {
                    out.write(separator)
                    stack.pop()
                    stack.push(NONEMPTY_OBJECT)
                }
            }
        }

        private fun newline() {
            if (indent.isEmpty()) return
            out.write("\n")
            for (i in 0 until stack.size) {
                out.write(indent)
            }
        }

        private fun string(value: String) {
            out.write("\"")
            for (c in value) {
                when (c) {
                    '"' -> out.write("\\\"")
                    '\\' -> out.write("\\\\")
                    '\b' -> out.write("\\b")
                    '\u000C' -> out.write("\\f")
                    '\n' -> out.write("\\n")
                    '\r' -> out.write("\\r")
                    '\t' -> out.write("\\t")
                    else -> if (c.code in 0..0x1f) {
                        out.write(String.format(Locale.US, "\\u%04x", c.code))
                    } else {
                        out.write(c.toString())
                    }
                }
            }
            out.write("\"")
        }

        override fun flush() {
            out.flush()
        }

        override fun close() {
            out.close()
        }
    }
}
