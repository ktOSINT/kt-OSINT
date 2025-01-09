package io.github.ktosint

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.request.*
import kotlinx.coroutines.runBlocking
import org.jetbrains.annotations.TestOnly
import org.jsoup.Jsoup
import org.jsoup.nodes.Document

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

    fun Shodan(): Map<String, Any?> {
        var hostname = "Unknown"
        var country = "Unknown"
        var city = "Unknown"
        var organization = "Unknown"
        var isp = "Unknown"
        var asn = "Unknown"
        var lastSeen = "Unknown"
        var tags: List<String>? = null
        var openPorts = mutableMapOf<Int, String>()

        val doc: Document = Jsoup.connect("https://www.shodan.io/host/$ip").get()

        val td = doc.getElementsByTag("td")
        for (i in td) {
            if (i.text() == "Hostnames") {
                hostname = i.parent()!!.allElements[2].text()
            } else if (i.text() == "Country") {
                country = i.parent()!!.allElements[2].text()
            } else if (i.text() == "City") {
                city = i.parent()!!.allElements[2].text()
            } else if (i.text() == "Organization") {
                organization = i.parent()!!.allElements[2].text()
            } else if (i.text() == "ISP") {
                isp = i.parent()!!.allElements[2].text()
            } else if (i.text() == "ASN") {
                asn = i.parent()!!.allElements[2].text()
            }
        }

        val gridHeading = doc.getElementsByClass("grid-heading")
        for (i in gridHeading) {
            if (i.text().startsWith("Last Seen:")) {
                lastSeen = i.text().split(": ")[1]
            } else if (i.text() == "Tags:") {
                val elements = i.parent()!!.allElements
                var texts = mutableListOf<String>()
                for (el in elements.slice(3..<elements.size)) {
                    texts += el.text()
                }
                tags = texts.toList()
            }
        }

        val portsList = doc.getElementById("ports")!!.children()
        for (i in portsList) {
            val port = i.text()
            val h6 = doc.getElementById(port)
                ?: continue
            val parent = h6.parent()!!.allElements
            val text = parent.select("pre")[portsList.indexOf(i) * 2 + 1].text()
            openPorts += port.toInt() to text
        }

        return mapOf(
            "hostname" to hostname,
            "country" to country,
            "city" to city,
            "organization" to organization,
            "isp" to isp,
            "asn" to asn,
            "last-seen" to lastSeen,
            "tags" to tags,
            "open-ports" to openPorts.toMap()
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
//    val shodan = obj.Shodan()
//    println(shodan)
//}