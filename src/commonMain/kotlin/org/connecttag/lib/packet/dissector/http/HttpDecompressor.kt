package org.connecttag.lib.packet.dissector.http

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.zip.GZIPInputStream
import java.util.zip.Inflater
import java.util.zip.InflaterInputStream

/**
 * Handles safe, memory-bounded decompression of HTTP payload bodies (gzip, deflate).
 */
object HttpDecompressor {
    /** Maximum allowed decompressed size (1 MB default) to prevent zip-bomb attacks */
    const val DEFAULT_MAX_DECOMPRESSED_BYTES = 1024 * 1024 // 1 MB
    private const val BUFFER_SIZE = 2048

    enum class HttpContentEncoding {
        NONE,
        GZIP,
        DEFLATE,
        BROTLI,
        UNKNOWN;

        companion object {
            fun fromHeader(value: String?): HttpContentEncoding {
                if (value.isNullOrBlank()) return NONE
                val normalized = value.trim().lowercase()
                return when {
                    normalized.contains("gzip") || normalized.contains("x-gzip") -> GZIP
                    normalized.contains("br") -> BROTLI
                    normalized.contains("deflate") -> DEFLATE
                    normalized == "identity" -> NONE
                    else -> UNKNOWN
                }
            }
        }
    }

    data class DecompressionResult(
        val data: ByteArray,
        val isTruncated: Boolean,
        val encoding: HttpContentEncoding,
        val originalSize: Int,
        val decompressedSize: Int
    ) {
        val compressionRatio: Float
            get() = if (decompressedSize > 0) (1f - (originalSize.toFloat() / decompressedSize.toFloat())) * 100f else 0f

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is DecompressionResult) return false
            return data.contentEquals(other.data) &&
                    isTruncated == other.isTruncated &&
                    encoding == other.encoding
        }

        override fun hashCode(): Int {
            var result = data.contentHashCode()
            result = 31 * result + isTruncated.hashCode()
            result = 31 * result + encoding.hashCode()
            return result
        }
    }

    fun isCompressed(encoding: HttpContentEncoding): Boolean {
        return encoding != HttpContentEncoding.NONE && encoding != HttpContentEncoding.UNKNOWN
    }

    fun decompress(
        compressedData: ByteArray?,
        contentEncodingHeader: String?,
        maxDecompressedBytes: Int = DEFAULT_MAX_DECOMPRESSED_BYTES
    ): DecompressionResult {
        if (compressedData == null || compressedData.isEmpty()) {
            return DecompressionResult(
                data = ByteArray(0),
                isTruncated = false,
                encoding = HttpContentEncoding.NONE,
                originalSize = 0,
                decompressedSize = 0
            )
        }

        val encoding = HttpContentEncoding.fromHeader(contentEncodingHeader)
        val originalSize = compressedData.size

        if (!isCompressed(encoding)) {
            return DecompressionResult(
                data = compressedData,
                isTruncated = false,
                encoding = encoding,
                originalSize = originalSize,
                decompressedSize = originalSize
            )
        }

        return try {
            when (encoding) {
                HttpContentEncoding.GZIP -> decompressGzip(compressedData, maxDecompressedBytes)
                HttpContentEncoding.DEFLATE -> decompressDeflate(compressedData, maxDecompressedBytes)
                else -> DecompressionResult(
                    data = compressedData,
                    isTruncated = false,
                    encoding = encoding,
                    originalSize = originalSize,
                    decompressedSize = originalSize
                )
            }
        } catch (_: Throwable) {
            DecompressionResult(
                data = compressedData,
                isTruncated = false,
                encoding = encoding,
                originalSize = originalSize,
                decompressedSize = originalSize
            )
        }
    }

    private fun decompressGzip(data: ByteArray, maxBytes: Int): DecompressionResult {
        val bais = ByteArrayInputStream(data)
        val gzipStream = GZIPInputStream(bais)
        return readBoundedStream(gzipStream, data.size, HttpContentEncoding.GZIP, maxBytes)
    }

    private fun decompressDeflate(data: ByteArray, maxBytes: Int): DecompressionResult {
        val bais = ByteArrayInputStream(data)
        return try {
            val inflater = Inflater(false)
            val inflaterStream = InflaterInputStream(bais, inflater)
            readBoundedStream(inflaterStream, data.size, HttpContentEncoding.DEFLATE, maxBytes)
        } catch (_: Throwable) {
            val baisRaw = ByteArrayInputStream(data)
            val inflaterRaw = Inflater(true) // nowrap = true (raw deflate without zlib header)
            val inflaterStreamRaw = InflaterInputStream(baisRaw, inflaterRaw)
            readBoundedStream(inflaterStreamRaw, data.size, HttpContentEncoding.DEFLATE, maxBytes)
        }
    }

    private fun readBoundedStream(
        stream: InputStream,
        originalSize: Int,
        encoding: HttpContentEncoding,
        maxBytes: Int
    ): DecompressionResult {
        val baos = ByteArrayOutputStream(minOf(originalSize * 2, maxBytes))
        val buffer = ByteArray(BUFFER_SIZE)
        var totalRead = 0
        var isTruncated = false

        stream.use { input ->
            while (true) {
                val remaining = maxBytes - totalRead
                if (remaining <= 0) {
                    isTruncated = true
                    break
                }

                val toRead = minOf(buffer.size, remaining)
                val bytesRead = input.read(buffer, 0, toRead)
                if (bytesRead == -1) break

                baos.write(buffer, 0, bytesRead)
                totalRead += bytesRead
            }
        }

        val decompressedData = baos.toByteArray()
        return DecompressionResult(
            data = decompressedData,
            isTruncated = isTruncated,
            encoding = encoding,
            originalSize = originalSize,
            decompressedSize = decompressedData.size
        )
    }
}
