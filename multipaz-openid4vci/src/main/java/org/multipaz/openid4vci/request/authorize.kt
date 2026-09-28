package org.multipaz.openid4vci.request

import io.ktor.utils.io.readAvailable
import java.io.ByteArrayOutputStream
import io.ktor.http.content.PartData
import io.ktor.http.content.forEachPart
import io.ktor.server.request.receiveMultipart
import io.ktor.client.HttpClient
import io.ktor.client.request.headers
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.readRawBytes
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.http.encodeURLParameter
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respondText
import io.ktor.utils.io.CancellationException
import kotlin.time.Instant
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.multipaz.cbor.Cbor
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.EcCurve
import org.multipaz.document.NameSpacedData
import org.multipaz.documenttype.knowntypes.EUPersonalID
import org.multipaz.webtoken.buildJwt
import org.multipaz.verifier.Openid4VpVerifierModel
import org.multipaz.openid4vci.credential.CredentialFactoryRegistry
import org.multipaz.openid4vci.util.AUTHZ_REQ
import org.multipaz.openid4vci.util.DrivingPrivilege
import org.multipaz.openid4vci.util.IssuanceState
import org.multipaz.openid4vci.util.MdlApplicant
import org.multipaz.openid4vci.util.MdlApplicantRepository
import org.multipaz.openid4vci.util.MULTIPAZ_PRE_AUTHORIZE_URI
import org.multipaz.openid4vci.util.OAUTH_REQUEST_URI_PREFIX
import org.multipaz.openid4vci.util.OPENID4VP_REQUEST_URI_PREFIX
import org.multipaz.openid4vci.util.OpaqueIdType
import org.multipaz.openid4vci.util.codeToId
import org.multipaz.server.common.getBaseUrl
import org.multipaz.openid4vci.util.getReaderIdentity
import org.multipaz.openid4vci.util.getSystemOfRecordUrl
import org.multipaz.openid4vci.util.idToCode
import org.multipaz.openid4vci.util.parseTxKind
import org.multipaz.rpc.backend.BackendEnvironment
import org.multipaz.rpc.backend.Resources
import org.multipaz.rpc.handler.InvalidRequestException
import org.multipaz.server.enrollment.ServerIdentity
import org.multipaz.server.enrollment.getServerIdentity
import org.multipaz.util.Logger
import org.multipaz.util.toBase64Url
import java.net.URI
import kotlin.collections.component1
import kotlin.collections.component2
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

private const val TAG = "authorize"

/** Amount of time that the user has to authorize themselves */
private val AUTHORIZATION_TIMEOUT = 20.minutes

suspend fun authorizeGet(call: ApplicationCall) {
    val queryParameters = call.request.queryParameters
    val requestUri = queryParameters["request_uri"] ?: ""
    val id = if (requestUri.startsWith(OAUTH_REQUEST_URI_PREFIX)) {
        val code = requestUri.substring(OAUTH_REQUEST_URI_PREFIX.length)
        codeToId(OpaqueIdType.PAR_CODE, code)
    } else if (requestUri.startsWith(OPENID4VP_REQUEST_URI_PREFIX)) {
        // Request a presentation using openid4vp
        getOpenid4Vp(requestUri.substring(OPENID4VP_REQUEST_URI_PREFIX.length), call)
        return
    } else if (requestUri == MULTIPAZ_PRE_AUTHORIZE_URI) {
        val configurationId = queryParameters["configuration_id"]
            ?: throw InvalidRequestException("'configuration_id' parameter is required")
        val registry = BackendEnvironment.getInterface(CredentialFactoryRegistry::class)!!
        val factory = registry.byId[configurationId]
            ?: throw InvalidRequestException("invalid 'configuration_id' parameter")
        val txCodeSpec = parseTxKind(
            txKind = queryParameters["tx_kind"],
            txPrompt = queryParameters["tx_prompt"]
        )
        val urlSchema = queryParameters["url_schema"]
        // Create a new session
        IssuanceState.createIssuanceState(
            issuanceState = IssuanceState(
                clientId = null,
                scope = factory.scope,
                clientAttestationKey = null,
                dpopKey = null,
                redirectUri = null,
                codeChallenge = null,
                configurationId = configurationId,
                txCodeSpec = txCodeSpec,
                urlSchema = urlSchema
            ),
            expiration = Clock.System.now() + AUTHORIZATION_TIMEOUT
        )
    } else {
        throw InvalidRequestException("Invalid or missing 'request_uri' parameter")
    }
    val systemOfRecordUrl = BackendEnvironment.getSystemOfRecordUrl()
    if (systemOfRecordUrl != null) {
        authorizeUsingSystemOfRecord(id, systemOfRecordUrl, call)
    } else {
        // Create a simple web page for the user to authorize the credential issuance.
        getHtml(id, AUTHORIZATION_TIMEOUT, call)
    }
}

internal data class RecordsClient(
    val signingKey: AsymmetricKey
)

private suspend fun authorizeUsingSystemOfRecord(
    id: String,
    systemOfRecordUrl: String,
    call: ApplicationCall
) {
    val state = IssuanceState.getIssuanceState(id)
    val codeVerifier = Random.nextBytes(32)
    state.systemOfRecordCodeVerifier = ByteString(codeVerifier)
    val codeChallenge = Crypto.digest(
        Algorithm.SHA256,
        codeVerifier.toBase64Url().encodeToByteArray()
    ).toBase64Url()
    val redirectUrl = BackendEnvironment.getBaseUrl() + "/finish_authorization"
    val baseUrl = BackendEnvironment.getBaseUrl()
    val clientAssertion = createJwtClientAssertion(systemOfRecordUrl, baseUrl)
    val req = buildMap {
        put("scope", state.scope)
        put("client_assertion", clientAssertion)
        put("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
        put("response_type", "code")
        put("code_challenge_method", "S256")
        put("redirect_uri", redirectUrl)
        put("code_challenge", codeChallenge)
        put("client_id", baseUrl)
        put("state", idToCode(OpaqueIdType.RECORDS_STATE, id, 10.minutes))
    }
    val httpClient = BackendEnvironment.getInterface(HttpClient::class)!!
    val response = httpClient.post("$systemOfRecordUrl/par") {
        headers {
            append("Content-Type", "application/x-www-form-urlencoded")
        }
        setBody(req.map { (name, value) ->
            name.encodeURLParameter() + "=" + value.encodeURLParameter()
        }.joinToString("&"))
    }
    val responseText = response.readRawBytes().decodeToString()
    if (response.status != HttpStatusCode.Created) {
        Logger.e(TAG, "PAR request error: ${response.status}: $responseText")
        throw IllegalStateException("System-of-Record: PAR request error")
    }
    val parsedResponse = Json.parseToJsonElement(responseText).jsonObject
    val requestUri = parsedResponse["request_uri"]!!.jsonPrimitive.content
    IssuanceState.updateIssuanceState(
        issuanceStateId = id,
        issuanceState = state,
        expiration = Clock.System.now() + AUTHORIZATION_TIMEOUT
    )
    call.respondRedirect(buildString {
        append(systemOfRecordUrl)
        append("/authorize?clientId=")
        append(baseUrl.encodeURLParameter())
        append("&request_uri=")
        append(requestUri.encodeURLParameter())
    })
}

private suspend fun createJwtClientAssertion(
    aud: String,
    clientId: String
): String = buildJwt(
        type = "JWT",
        key = getServerIdentity(ServerIdentity.RECORDS_CLIENT),
        expiresIn = 5.minutes
    ) {
        put("jti", Random.nextBytes(18).toBase64Url())
        put("iss", clientId)
        put("sub", clientId) // RFC 7523 Section 3, item 2.B
        put("aud", aud)
    }

private suspend fun getHtml(id: String, expiresIn: Duration, call: ApplicationCall) {
    val resources = BackendEnvironment.getInterface(Resources::class)!!
    val authorizationCode = idToCode(OpaqueIdType.AUTHORIZATION_STATE, id, expiresIn)
    val pidReadingCode = idToCode(OpaqueIdType.PID_READING, id, expiresIn)
    val authorizeHtml = resources.getStringResource("authorize.html")!!
    call.respondText(
        text = authorizeHtml
            .replace("\$authorizationCode", authorizationCode)
            .replace("\$pidReadingCode", pidReadingCode),
        contentType = ContentType.Text.Html
    )
}

private suspend fun getOpenid4Vp(code: String, call: ApplicationCall) {
    val timeout = 5.minutes
    val id = codeToId(OpaqueIdType.OPENID4VP_CODE, code)
    val stateRef = idToCode(OpaqueIdType.OPENID4VP_STATE, id, timeout)
    val baseUrl = BackendEnvironment.getBaseUrl()
    val responseUri = "$baseUrl/openid4vp_response"
    val state = IssuanceState.getIssuanceState(id)
    val model = Openid4VpVerifierModel(
        clientId = "redirect_uri:$responseUri",
        ephemeralPrivateKey = Crypto.createEcPrivateKey(EcCurve.P256)
    )
    state.openid4VpVerifierModel = model
    val jwt = state.openid4VpVerifierModel!!.makeRequest(
        state = stateRef,
        responseUri = responseUri,
        responseMode = "direct_post.jwt",
        readerIdentity = getReaderIdentity(),
        requests = mapOf(
            "pid" to EUPersonalID.getDocumentType().cannedRequests.first { it.id == "full" }
        )
    )
    IssuanceState.updateIssuanceState(id, state, expiration = Clock.System.now() + timeout)
    call.respondText(
        text = jwt,
        contentType = AUTHZ_REQ
    )
}

/**
 * Handle user's authorization and redirect to `finish_authorization` endpoint.
 */
suspend fun authorizePost(call: ApplicationCall) {

    var portraitBytes: ByteArray? = null

    val parameters = Parameters.build {

        val multipart = call.receiveMultipart()

        multipart.forEachPart { part ->

            when (part) {

                is PartData.FormItem -> {
                    val name = part.name

                    if (name != null) {
                        append(name, part.value)
                    }
                }

                is PartData.FileItem -> {

                    if (part.name == "portrait") {
                        val channel = part.provider()
                        val buffer = ByteArray(64 * 1024)
                        val output = ByteArrayOutputStream()

                        while (true) {
                            val count = channel.readAvailable(buffer)

                            if (count == -1) {
                                break
                            }

                            if (count > 0) {
                                output.write(buffer, 0, count)
                            }
                        }

                        portraitBytes = output.toByteArray()
                    }
                }

                else -> {
                    // Ignore unsupported multipart parts
                }
            }

            part.dispose()
        }
    }

    val code = parameters["authorizationCode"]
        ?: throw InvalidRequestException("'authorizationCode' missing")
    val id = codeToId(OpaqueIdType.AUTHORIZATION_STATE, code)
    val timeout = 5.minutes
    val stateCode = idToCode(OpaqueIdType.ISSUER_STATE, id, timeout)

    try {
        val state = IssuanceState.getIssuanceState(id)
        val data = NameSpacedData.Builder()
        val baseUrl = BackendEnvironment.getBaseUrl()
        val pidData = parameters["pidData"]
        if (pidData != null) {
            val baseUri = URI(baseUrl)
            val origin = baseUri.scheme + "://" + baseUri.authority
            val credMap = state.openid4VpVerifierModel!!.processResponse(
                origin,
                pidData
            )
            state.openid4VpVerifierModel = null

            when (val presentation = credMap["pid"]!!) {
                is Openid4VpVerifierModel.MdocPresentation -> {
                    for (document in presentation.deviceResponse.documents) {
                        document.issuerNamespaces.data.forEach { (namespaceName, issuerSignedItemsMap) ->
                            issuerSignedItemsMap.forEach { (dataElementName, issuerSignedItem) ->
                                data.putEntry(
                                    namespaceName,
                                    dataElementName,
                                    Cbor.encode(issuerSignedItem.dataElementValue)
                                )
                            }
                        }
                    }
                }

                is Openid4VpVerifierModel.SdJwtPresentation -> {
                    TODO()
                }
            }
        } else {
                // No external system of record.
   	        // Create an applicant record locally for development/testing.
    		val mode = parameters["mode"]
                ?: throw InvalidRequestException("'mode' missing")

            val applicant = when (mode) {

                "fake" -> createFakeMdlApplicant(parameters)

                "user" -> createUserMdlApplicant(
                    parameters,
                    portraitBytes
                )

                else -> throw InvalidRequestException("Invalid authorization mode")
            }

            val applicantId = MdlApplicantRepository.create(applicant)
            state.applicantId = applicantId
        }

        state.authorized = Clock.System.now()

        Logger.i(
            TAG,
            "Authorization completed: " +
                "mode=${parameters["mode"]}, " +
                "clientId=${state.clientId}, " +
                "redirectUri=${state.redirectUri}, " +
                "applicantId=${state.applicantId}"
        )

        IssuanceState.updateIssuanceState(
            id,
            state,
            Clock.System.now() + timeout
        )

        call.respondRedirect("finish_authorization?state=$stateCode")
    } catch (err: CancellationException) {
        throw err
    } catch (err: Exception) {
        val (error, description) = when (err) {
            is InvalidRequestException -> Pair("invalid_request", err.message)
            is AuthorizationFailed -> Pair("authorization_failed", "Invalid credentials")
            else -> Pair("internal",
                (err::class.simpleName ?: "Unknown") + ": " + err.message)
        }
        Logger.e(TAG, "$error: $description", err)
        call.respondRedirect(buildString {
            append("finish_authorization?state=")
            append(stateCode)
            append("&error=")
            append(error)
            if (description != null) {
                append("&error_description=")
                append(description.encodeURLParameter())
            }
        })
    }
}
private suspend fun createFakeMdlApplicant(
    parameters: Parameters
): MdlApplicant {

    val resources = BackendEnvironment
        .getInterface(Resources::class)!!

    return MdlApplicant(
        givenName = "Max",
        familyName = "Mustermann",
        birthDate = "1995-05-10",

        portrait = ByteString(
            resources.getRawResource("female.jpg")!!.toByteArray()
        ),

        documentNumber = "DL-DEMO-0001",
        issueDate = "2026-01-01",
        expiryDate = "2036-01-01",

        issuingAuthority = "Demo Driving Licence Authority",
        issuingCountry = "DE",

        drivingPrivileges = listOf(
            DrivingPrivilege(
                vehicleCategoryCode = "B",
                issueDate = "2026-01-01",
                expiryDate = "2036-01-01"
            )
        )
    )
}
private suspend fun createUserMdlApplicant(
    parameters: Parameters,
    portraitBytes: ByteArray?
): MdlApplicant {

    val givenName = parameters["given_name"]
        ?: throw InvalidRequestException("'given_name' missing")

    val familyName = parameters["family_name"]
        ?: throw InvalidRequestException("'family_name' missing")

    val birthDate = parameters["birth_date"]
        ?: throw InvalidRequestException("'birth_date' missing")

    val documentNumber = parameters["document_number"]
        ?: throw InvalidRequestException("'document_number' missing")

    val issueDate = parameters["issue_date"]
        ?: throw InvalidRequestException("'issue_date' missing")

    val expiryDate = parameters["expiry_date"]
        ?: throw InvalidRequestException("'expiry_date' missing")

    val issuingAuthority = parameters["issuing_authority"]
        ?: throw InvalidRequestException("'issuing_authority' missing")

    val issuingCountry = parameters["issuing_country"]
        ?: throw InvalidRequestException("'issuing_country' missing")

    val privilegeCodes = parameters.getAll("driving_privileges")
        ?: emptyList()

    if (privilegeCodes.isEmpty()) {
        throw InvalidRequestException(
            "At least one driving privilege is required"
        )
    }

    val portrait = ByteString(
    portraitBytes
        ?: throw InvalidRequestException("'portrait' missing")
    )

    val drivingPrivileges = privilegeCodes.map { categoryCode ->
        DrivingPrivilege(
            vehicleCategoryCode = categoryCode,
            issueDate = issueDate,
            expiryDate = expiryDate
        )
    }

    return MdlApplicant(
        givenName = givenName,
        familyName = familyName,
        birthDate = birthDate,

        portrait = portrait,

        documentNumber = documentNumber,
        issueDate = issueDate,
        expiryDate = expiryDate,

        issuingAuthority = issuingAuthority,
        issuingCountry = issuingCountry,

        drivingPrivileges = drivingPrivileges
    )
}
private class AuthorizationFailed: Exception("Authorization failed")
