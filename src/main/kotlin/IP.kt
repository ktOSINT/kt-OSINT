package io.github.ktosint

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.request.*
import kotlinx.coroutines.runBlocking
import org.jetbrains.annotations.TestOnly

class IP (val ip: String) {
    fun Locate(): Map<String, String> {
        val body: String
        runBlocking {
            val res = HttpClient(CIO).get("https://db-ip.com/$ip")
            body = res.body()
        }
        val country: String
        val region: String
        val city: String
        val zip: String
        val coordinates: String
        var index = body.findAnyOf(listOf("<a href='/country/"))!!.first
        country = body.slice(body.findAnyOf(listOf(">"), index)!!.first + 1..<body.findAnyOf(listOf("<"), body.findAnyOf(listOf(">"), index)!!.first)!!.first)
        index = body.findAnyOf(listOf("\"stateProv\": "))!!.first
        region = body.slice(body.findAnyOf(listOf(" \""), index)!!.first + 2..<body.findAnyOf(listOf("\""), body.findAnyOf(listOf(" \""), index)!!.first + 2)!!.first)
        index = body.findAnyOf(listOf("\"city\": "))!!.first
        city = body.slice(body.findAnyOf(listOf(" \""), index)!!.first + 2..<body.findAnyOf(listOf("\""), body.findAnyOf(listOf(" \""), index)!!.first + 2)!!.first)
        index = body.findAnyOf(listOf("<tr><th>Zip / Postal code</th><td>"))!!.first
        zip = body.slice(body.findAnyOf(listOf("<td>"), index)!!.first + 4..<body.findAnyOf(listOf("<"), body.findAnyOf(listOf("<td>"), index)!!.first + 4)!!.first)
        index = body.findAnyOf(listOf("<tr><th>Coordinates</th><td>"))!!.first
        coordinates = body.slice(body.findAnyOf(listOf("<td>"), index)!!.first + 4..<body.findAnyOf(listOf("<"), body.findAnyOf(listOf("<td>"), index)!!.first + 4)!!.first)

        return mapOf(
            "country" to country,
            "region" to region,
            "city" to city,
            "zip" to zip,
            "coordinates" to coordinates
        )
    }
}

//@TestOnly
//fun main() {
//    var ip = "9.9.9.9"
////    ip = "8.8.8.8"
//    val obj = IP(ip)
//    val location = obj.Locate()
//    println(location)
//}