package io.github.ktosint

import com.beust.klaxon.JsonObject
import com.beust.klaxon.Parser
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.utils.io.*
import io.ktor.utils.io.core.*
import kotlinx.coroutines.*
import org.jetbrains.annotations.TestOnly
import java.net.Socket
import java.security.MessageDigest
import kotlin.io.use
import kotlin.text.StringBuilder
import kotlin.text.toByteArray

class Email(var email: String) {
    init {
        Regex("^((?!\\.)[\\w\\-_.]*[^.])(@\\w+)(\\.\\w+(\\.\\w+)?[^.\\W])\$").matchEntire(email)
            ?: throw IllegalArgumentException("Email passed was not the correct format.")
    }

    private fun smtpNmap(hosts: Array<String>): Boolean {
        val ports = listOf(25, 587, 465, 2525)
        var foundPort: Int? = null
        runBlocking {
            for (host in hosts) {
                for (port in ports) {
                    launch(Dispatchers.IO) {
                        try {
                            val socket = Socket(host, port)
                            foundPort = port
                            socket.close()
                        } catch (e: Exception) {
                            return@launch
                        }
                    }
                }
            }
        }
        return foundPort != null
    }

    private fun String.sha256(): String {
        return MessageDigest
            .getInstance("SHA-256")
            .digest(this.toByteArray())
            .fold("", { str, it -> str + "%02x".format(it) })
    }

    private fun hash(plaintext: String): String {
        return ("databreach.com-" + plaintext.lowercase()).sha256().slice(0..27)
    }

    private suspend fun ByteReadChannel.toHex(): String {
        val builder = StringBuilder()
        while (!this.isClosedForRead) {
            val packet = this.readRemaining(DEFAULT_BUFFER_SIZE.toLong())
            packet.readBytes().forEach { byte ->
                builder.append(byte.toInt().and(0xFF).toString(16).padStart(2, '0'))
            }
        }
        return builder.toString()
    }

    fun Reacher(): MutableMap<String, Any?> {
        val final: MutableMap<String, Any?> = mutableMapOf(
            "isReachable" to null,
            "misc" to mutableMapOf(
                "isDisposable" to null,
                "isRoleAccount" to null
            ),
            "mx" to mutableMapOf(
                "acceptsMail" to null,
                "records" to null
            ),
            "smtp" to mutableMapOf(
                "serverReachable" to null,
                "canConnectSMTP" to null
            ),
            "syntax" to mutableMapOf(
                "address" to email,
                "domain" to email.split("@")[1],
                "username" to email.split("@")[0]
            )
        )

        // mx
        val res: HttpResponse
        val mxRecords: JsonObject
        runBlocking {
            val client = HttpClient(CIO)
            res = client.get("https://dns.google/resolve?name=${(final["syntax"] as Map<String, Map<String, Any?>>)["domain"]}&type=MX")
            mxRecords = Parser.default().parse(StringBuilder(res.body<String>())) as JsonObject
        }
        var tempArray = arrayOf<String>()
        for (i in mxRecords.array<JsonObject>("Answer")!!) {
            tempArray = tempArray.plus(i.string("data")!!.split(" ")[1])
        }
        (final["mx"] as MutableMap<String, Any?>)["records"] = tempArray
        (final["mx"] as MutableMap<String, Any?>)["acceptsMail"] = tempArray.isNotEmpty()

        // misc
        val disposableRes: HttpResponse
        val blacklist: List<String>
        runBlocking {
            val client = HttpClient(CIO)
            disposableRes = client.get("https://raw.githubusercontent.com/FGRibreau/mailchecker/refs/heads/master/list.txt")
            blacklist = disposableRes.body<String>().split("\n")
        }
        val isDisposable = (final["syntax"] as Map<String, Map<String, Any?>>)["domain"].toString() in blacklist
        (final["misc"] as MutableMap<String, Any?>)["isDisposable"] = isDisposable
        val roleRes: HttpResponse
        var roleNames = listOf<String>()
        runBlocking {
            val client = HttpClient(CIO)
            roleRes = client.get("https://raw.githubusercontent.com/mixmaxhq/role-based-email-addresses/refs/heads/master/index.js")
            for (i in roleRes.body<String>().split("\n")) {
                if ("'" in i) {
                    roleNames = roleNames.plus(i.split("'")[1])
                }
            }
        }
        (final["misc"] as MutableMap<String, Any?>)["isRoleAccount"] = (final["syntax"] as Map<String, Map<String, Any?>>)["username"].toString() in roleNames

        // smtp
        var reachable = false
        runBlocking {
            for (i in tempArray) {
                launch(Dispatchers.IO) {
                    val test = Runtime.getRuntime().exec("ping $i").inputStream.bufferedReader()
                        .use { it.readText() }
                    if ("Reply" in test) {
                        reachable = true
                        return@launch
                    } else if ("failed" in test) {
                        return@launch
                    } else {
                        throw Error("Ping error - full details of request below\n$test")
                    }
                }
            }
        }
        (final["smtp"] as MutableMap<String, Any?>)["serverReachable"] = reachable
        val found = smtpNmap(tempArray)
        (final["smtp"] as MutableMap<String, Any?>)["canConnectSMTP"] = found

        // reachable
        var status = "safe"
        if (isDisposable || (final["syntax"] as Map<String, Map<String, Any?>>)["username"].toString() in roleNames) status = "risky"
        if (!found) status = "invalid"
        final["isReachable"] = status

        return final
    }

    fun MBoxValid(key: String): JsonObject {
        /**
         * Get API key here: https://www.mailboxvalidator.com/plans#api
         * The free plan includes 300 queries per month
         */
        val res: HttpResponse
        val data: JsonObject
        runBlocking {
            val client = HttpClient(CIO)
            res = client.get("https://api.mailboxvalidator.com/v2/validation/single") {
                parameter("email", email)
                parameter("key", key)
            }
            val sb = StringBuilder()
            sb.append(res.body<String>())
            data = Parser.default().parse(sb) as JsonObject
        }
        if (data.obj("error") == null) {
            return data
        } else {
            throw IllegalArgumentException("Key was not valid")
        }
    }

    fun HaveIBeenPwned(): Array<String> {
        val hashed = hash("email:$email")
        val res: HttpResponse
        val data: String
        runBlocking {
            val client = HttpClient(CIO)
            res = client.get("https://hashes.databreach.com/v2/${hashed.slice(0..4)}") {
                headers {
                    append(HttpHeaders.Accept, "*/*")
                    append(HttpHeaders.AcceptLanguage, "en-US,en;q=0.9")
                    append("dnt", "1")
                    append(HttpHeaders.Origin, "https://databreach.com")
                    append("Priority", "u=1, i")
                    append(HttpHeaders.Referrer, "https://databreach.com/")
                    append("sec-ch-ua", "\"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"")
                    append("sec-ch-ua-mobile", "?0")
                    append("sec-ch-ua-platform", "\"Windows\"")
                    append("sec-fetch-dest", "empty")
                    append("sec-fetch-mode", "cors")
                    append("sec-fetch-site", "same-site")
                    append(HttpHeaders.UserAgent, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
                }
            }
            data = res.bodyAsChannel().toHex()
        }

        val lookFor = "0" + hashed.slice(5..27)
        var index = 0
        var done = false
        var foundInts = arrayOf<Int>()
        while (!done) {
            val find = data.findAnyOf(listOf(lookFor), index + 1)
            if (find == null) {
                done = true
            } else {
                foundInts += data.slice(find.first + lookFor.length..find.first + lookFor.length + 3).toInt(16)
                index = find.first
            }
        }

        // get the link of breach.js (which is now card.js as of coding??)
        val indexHTML: HttpResponse
        val indexHTMLBody: String
        val indexJS: HttpResponse
        val indexJSBody: String
        val cardJS: HttpResponse
        val cardJSBody: String
        runBlocking {
            val client = HttpClient(CIO)

            indexHTML = client.get("https://databreach.com/")
            indexHTMLBody = indexHTML.body()

            var importIndex = indexHTMLBody.findAnyOf(listOf("import * as route1 from \"/assets/index"))
            val indexJSURL = indexHTMLBody.slice(importIndex!!.first + "import * as route1 from \"".length..<indexHTMLBody.findAnyOf(listOf("\";"), importIndex.first)!!.first)
            indexJS = client.get("https://databreach.com$indexJSURL")
            indexJSBody = indexJS.body()

            importIndex = indexJSBody.findAnyOf(listOf("from\"./card-"))
            val breachJSURL = indexJSBody.slice(importIndex!!.first + "from\".".length..<indexJSBody.findAnyOf(listOf("\";"), importIndex.first)!!.first)
            cardJS = client.get("https://databreach.com/assets$breachJSURL")
            cardJSBody = cardJS.body()
        }

        var found = arrayOf<String>()
        for (i in foundInts) {
            val startIndex = cardJSBody.findAnyOf(listOf(",$i:{", "{$i:{"))!!.first
            found += cardJSBody.slice(startIndex + ",$i:".length..<cardJSBody.findAnyOf(listOf("icon:!0}"), startIndex)!!.first + "icon:!0}".length)
        }

        return found
    }
}

//@TestOnly
//fun main() {
//    val email = "someone@gmail.com"
//    val obj = Email(email)
////    val final = obj.Reacher()
////    println(final)
////    val mbv = obj.MBoxValid(key = "ENTER_API_KEY_HERE")
////    println(mbv.toString())
//    val hibp = obj.HaveIBeenPwned()
//    println(hibp.toList())
//}