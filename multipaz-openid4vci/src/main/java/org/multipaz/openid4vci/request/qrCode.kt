package org.multipaz.openid4vci.request

import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.google.zxing.qrcode.encoder.Encoder
import io.ktor.http.ContentType
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respondBytes
import java.awt.image.BufferedImage
import java.awt.image.DataBufferByte
import java.io.ByteArrayOutputStream
import javax.imageio.ImageIO

/**
 * Encodes text string (passed as `q` parameter) into a QR code.
 */
suspend fun qrCode(call: ApplicationCall) {
    val str = call.request.queryParameters["q"]
        ?: throw IllegalStateException("q parameter required")

    val qr = Encoder.encode(str, ErrorCorrectionLevel.M, null)
    val matrix = qr.matrix

    // Render each QR module as an 8x8 pixel square, with a
    // four-module white quiet zone around the complete symbol.
    val scale = 8
    val quietZone = 4
    val width = (matrix.width + quietZone * 2) * scale
    val height = (matrix.height + quietZone * 2) * scale

    val image = BufferedImage(width, height, BufferedImage.TYPE_BYTE_GRAY)
    val pixels = (image.raster.dataBuffer as DataBufferByte).data

    // Start with a white image, including the quiet zone.
    pixels.fill(0xFF.toByte())

    for (y in 0 until matrix.height) {
        for (x in 0 until matrix.width) {
            // Preserve the existing ZXing matrix black/white mapping.
            if (matrix[x, y].toInt() != 0) {
                val startX = (x + quietZone) * scale
                val startY = (y + quietZone) * scale

                for (dy in 0 until scale) {
                    val rowStart = (startY + dy) * width + startX
                    for (dx in 0 until scale) {
                        pixels[rowStart + dx] = 0
                    }
                }
            }
        }
    }

    val bytes = ByteArrayOutputStream()
    ImageIO.write(image, "png", bytes)
    call.respondBytes(bytes.toByteArray(), ContentType.Image.PNG)
}
