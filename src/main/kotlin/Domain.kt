package io.github.ktosint

import com.beust.klaxon.JsonObject
import com.beust.klaxon.Parser
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.coroutines.runBlocking
import org.jetbrains.annotations.TestOnly

class Domain(val domain: String) {
    fun Dossier(): Map<String, Any?> {
        val final = mutableMapOf<String, Any?>(
            "addresses" to arrayOf<String>(),
            "domainWhois" to null,
            "networkWhois" to null,
            "dnsRecords" to arrayOf<Map<String, Any>>()
        )

        // dnsRecords
        val dns: HttpResponse
        runBlocking {
            val client = HttpClient(CIO)
            dns = client.get("https://dns.google/resolve") {
                parameter("name", domain)
                parameter("type", "*")
            }
            for (i in (Parser.default().parse(StringBuilder(dns.body<String>())) as JsonObject).array<JsonObject>("Answer")!!) {
                final["dnsRecords"] = (final["dnsRecords"] as Array<Map<String, Any>>) + mapOf(
                    "type" to i.int("type")!!,
                    "data" to i.string("data")!!,
                    "ttl" to i.int("TTL")!!
                )
            }
        }

        // addresses
        for (i in final["dnsRecords"] as Array<Map<String, Any>>) {
            if (i["type"] == 1 || i["type"] == 28) {
                final["addresses"] = final["addresses"] as Array<String> + i["data"] as String
            }
        }

        // domainWhois
        val whoisRes: HttpResponse
        val whois: String
        runBlocking {
            val client = HttpClient(CIO)
            whoisRes = client.submitForm(
                "https://whois-webform.markmonitor.com/whois/request",
                formParameters = parameters {
                    append("btn", "getWhois")
                    append("domain", domain)
                    append("email", "")
                }
            )
            whois = (Parser.default().parse(StringBuilder(whoisRes.body<String>())) as JsonObject).string("whois")!!.replace("<br>", "\n")
        }
        final["domainWhois"] = whois

        // networkWhois
        val nwhoisRes: HttpResponse
        val nwhois: String
        runBlocking {
            val client = HttpClient(CIO)
            val res = client.submitForm(
                "https://whois.arin.net/ui/query.do",
                formParameters = parameters {
                    append("xslt", "https://localhost:8080/ui/arin.xsl")
                    append("flushCache", "false")
                    append("queryinput", (final["addresses"] as Array<String>)[0])
                    append("whoisSubmitButton", "")
                }
            ) {
                headers {
                    append("Accept", "application/json")
                }
            }
            val link = if ("?" in res.headers["Location"]!!) res.headers["Location"]!!.replace("?", ".txt?") else res.headers["Location"]!! + ".txt"
            nwhoisRes = client.get(link)
            nwhois = nwhoisRes.body()
        }
        val iter = nwhois.split("\n")
        var new = ""
        for (i in iter) {
            if ("#" !in i) {
                new += i + "\n"
            }
        }
        while ("\n\n\n" in new) {
            new = new.replace("\n\n\n", "\n\n")
        }
        while (new.startsWith("\n") || new.endsWith("\n")) {
            new = new.removeSurrounding("\n")
        }
        final["networkWhois"] = new

        return final.toMap()
    }
}

//@TestOnly
//fun main() {
//    val domain = "google.com"
//    val obj = Domain(domain)
//    val dossier = obj.Dossier()
//    println(dossier)
//}