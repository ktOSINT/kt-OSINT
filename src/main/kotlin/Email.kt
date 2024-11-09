package io.github.ktosint

import com.beust.klaxon.JsonObject
import com.beust.klaxon.Parser
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import kotlinx.coroutines.*
import org.jetbrains.annotations.TestOnly
import java.net.Socket
import kotlin.text.StringBuilder

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
        /*
        Get API key here: https://www.mailboxvalidator.com/plans#api
        The free plan includes 300 queries per month
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
}

@TestOnly
fun main() {
    val email = "someone@gmail.com"
    val obj = Email(email)
    val final = obj.Reacher()
    println(final)
    val mbv = obj.MBoxValid(key = "ENTER_API_KEY_HERE")
    println(mbv.toString())
}