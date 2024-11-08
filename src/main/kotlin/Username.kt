package io.github.ktosint

import com.beust.klaxon.JsonArray
import com.beust.klaxon.JsonObject
import com.beust.klaxon.Parser
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.jetbrains.annotations.TestOnly
import java.net.URLEncoder


class Username(var username: String) {
    init {
        if (username.isEmpty()) {
            throw IllegalArgumentException("Username cannot be empty")
        } else {
            username = URLEncoder.encode(username, "UTF-8")
        }
    }

    fun SearchSites(log: Boolean = false): Array<Array<Array<String>>> {
        val data: JsonArray<JsonObject> = Parser.default().parse("./src/main/resources/data/username-searches.json") as JsonArray<JsonObject>

        var found: Array<Array<String>> = arrayOf()
        var notFound: Array<Array<String>> = arrayOf()

        runBlocking {
            for (i in data) {
                launch {
                    try {
                        val res: HttpResponse

                        val client = HttpClient(CIO)
                        res = client.get(i.string("url")!!.replace("{account}", username))

                        val accepted: Boolean


                        accepted = if (i.int("t-code") != i.int("f-code") && (res.status.value == i.int("t-code") || res.status.value == i.int("f-code"))) {
                            res.status.value == i.int("t-code")
                        } else if (i.string("t-body").toString() in res.body<String>() || i.string("f-body").toString() in res.body<String>()) {
                            i.string("t-body").toString() in res.body<String>()
                        } else {
                            val debugBody = res.body<String>()
                            if (log) println("Unknown response to ${i.string("name")} $debugBody")
                            return@launch
                        }

                        if (accepted) {
                            if (log) println("Found an account: ${i.string("name")} - ${i.string("url")!!.replace("{account}", username)}")
                            found += arrayOf(
                                i.string("name")!!,
                                i.string("url")!!.replace("{account}", username)
                            )
                        } else {
                            if (log) println("No account found: ${i.string("name")}")
                            notFound += arrayOf(
                                i.string("name")!!,
                                i.string("url")!!.replace("{account}", username)
                            )
                        }
                    } catch (error: Exception) {
                        print(error.toString())
                        return@launch
                    }
                }
            }
        }

        return arrayOf(found, notFound)
    }
}

//@TestOnly
//fun main() {
//    val username = "EvokerKing"
//    val obj = Username(username)
//    var f: Array<Array<Array<String>>>
//    val found = obj.SearchSites(true)
//    f = found
//    print("Found: ")
//    for (i in f[0]) {
//        print("${i[0]}, ")
//    }
//    print("\nNot Found: ")
//    for (i in f[1]) {
//        print("${i[0]}, ")
//    }
//}