package io.github.ktosint

import com.beust.klaxon.JsonObject
import com.beust.klaxon.Parser
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.network.sockets.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.utils.io.errors.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import org.jetbrains.annotations.TestOnly
import java.io.EOFException
import java.nio.channels.UnresolvedAddressException
import java.util.concurrent.CancellationException

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

    @Deprecated("This function is extremely slow and still pretty inaccurate. It is deprecated as of its launch but does technically work.")
    fun XRay(loops: Int = 5): Array<String> {
        var found = arrayOf<String>()
        val wordlist: List<String>
        runBlocking {
            val client = HttpClient(CIO)
            val res = client.get("https://github.com/evilsocket/xray/raw/refs/heads/master/wordlists/default.lst")
            wordlist = res.body<String>().split("\n")
        }


        var c = 0


        runBlocking {
            withTimeoutOrNull(loops * 30000L) {
                for (i in wordlist) {
                    launch {
                        var r = 0
                        val link = "https://${i.removePrefix("#")}${if (i != "" && i != "#") "." else ""}$domain/"
                        do {
                            try {
                                if (i == "*") { // this address makes no sense... its not valid syntax?? why is it in the wordlist
                                    return@launch
                                }

                                val client = HttpClient(CIO)
                                val res: HttpResponse
                                res = client.get(link)

                                if (!res.status.toString().startsWith("4")) {
                                    r = 0
                                    found += link
                                }
                            } catch (e: Exception) {
                                if (e is UnresolvedAddressException || (e is IOException && "TLSException" in e.toString()) || e is EOFException || (e is IOException && "aborted by the software in your host machine" in e.toString()) || e is SendCountExceedException) {
                                    c += 1
                                    r = 0
                                } else if (e is ConnectTimeoutException || e is HttpRequestTimeoutException || e is ClosedReceiveChannelException) {
                                    r += 1
                                } else if (e is CancellationException) {
                                    return@launch
                                } else {
                                    println("exception caught: $e")
                                }
                            }
                        } while (r in 1..<loops)
                        c += 1
                    }
                }
            }
        }

        println("checked $c addresses")

        return found
    }
}

//@TestOnly
//fun main() {
//    val domain = "google.com"
//    val obj = Domain(domain)
//    val dossier = obj.Dossier()
//    println(dossier)
//    val xray = obj.XRay()
//    println(xray.toList())
//}