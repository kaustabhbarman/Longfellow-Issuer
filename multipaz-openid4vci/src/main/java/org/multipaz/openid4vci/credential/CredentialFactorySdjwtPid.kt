package org.multipaz.openid4vci.credential

import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.datetime.DateTimeUnit
import kotlinx.datetime.TimeZone
import kotlinx.datetime.atStartOfDayIn
import kotlinx.datetime.plus
import kotlinx.datetime.toLocalDateTime
import kotlinx.datetime.yearsUntil
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.CborDouble
import org.multipaz.cbor.CborFloat
import org.multipaz.cbor.CborInt
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.IndefLengthBstr
import org.multipaz.cbor.IndefLengthTstr
import org.multipaz.cbor.Simple
import org.multipaz.cbor.Tagged
import org.multipaz.cbor.Tstr
import org.multipaz.crypto.EcPublicKey
import org.multipaz.documenttype.DocumentAttributeType
import org.multipaz.documenttype.knowntypes.EUPersonalID
import org.multipaz.openid4vci.util.CredentialId
import org.multipaz.provisioning.CredentialFormat
import org.multipaz.revocation.RevocationStatus
import org.multipaz.rpc.backend.BackendEnvironment
import org.multipaz.rpc.backend.Resources
import org.multipaz.sdjwt.SdJwt
import org.multipaz.server.common.getBaseUrl
import org.multipaz.util.Logger
import org.multipaz.util.toBase64Url
import kotlin.collections.List
import kotlin.collections.component1
import kotlin.collections.component2
import kotlin.collections.iterator
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days

/**
 * [CredentialFactory] for [EUPersonalID] credentials in IETF SD-JWT format.
 */
class CredentialFactorySdjwtPid : CredentialFactory {
    override val configurationId: String
        get() = "pid_sd_jwt"

    override val scope: String
        get() = "core"

    override val format
        get() = FORMAT

    override val requireKeyAttestation: Boolean get() = true

    override val proofSigningAlgorithms: List<String>
        get() = CredentialFactory.DEFAULT_PROOF_SIGNING_ALGORITHMS

    override val cryptographicBindingMethods: List<String>
        get() = listOf("jwk")

    override val name: String
        get() = "Personal ID"

    override val logo: String
        get() = "card-pid.png"

    override suspend fun mint(
        systemOfRecordData: DataItem,
        authenticationKey: EcPublicKey?,
        credentialId: CredentialId,
    ): MintedCredential {
        check(authenticationKey != null)

        val coreData = systemOfRecordData["core"]
        val dateOfBirth = coreData["birth_date"].asDateString

        val documentType = EUPersonalID.getDocumentType().jsonDocumentType!!

        val resources = BackendEnvironment.getInterface(Resources::class)!!
        val now = Clock.System.now()

        val timeZone = TimeZone.currentSystemDefault()
        val dateOfBirthInstant = dateOfBirth.atStartOfDayIn(timeZone)

        val identityAttributes = buildJsonObject {
            put("given_name", coreData["given_name"].asTstr)
            put("family_name", coreData["family_name"].asTstr)

            val added = mutableSetOf("birthdate", "given_name", "family_name", "picture")
            put("birthdate", dateOfBirth.toString())

            if (coreData.hasKey("portrait")) {
                put("picture", coreData["portrait"].asBstr.toBase64Url())
            } else {
                val bytes = resources.getRawResource("female.jpg")!!
                put("picture", bytes.toByteArray().toBase64Url())
            }

            if (coreData.hasKey("utopia_id_number")) {
                put("personal_administrative_number",
                    coreData["utopia_id_number"].asTstr)
                added.add("personal_administrative_number")
            }

            // Names at birth: SD-JWT uses different claim names
            // Names at birth: SD-JWT uses different claim names
            if (coreData.hasKey("family_name_birth")) {
                put("birth_family_name", coreData["family_name_birth"].asTstr)
                added.add("birth_family_name")
            }

            if (coreData.hasKey("given_name_birth")) {
                put("birth_given_name", coreData["given_name_birth"].asTstr)
                added.add("birth_given_name")
            }

            // Place of birth: SD-JWT represents this as a nested object
            val hasBirthPlace =
                coreData.hasKey("birth_country") ||
                coreData.hasKey("birth_state") ||
                coreData.hasKey("birth_city")

            if (hasBirthPlace) {
                putJsonObject("place_of_birth") {
                    if (coreData.hasKey("birth_country")) {
                        put("country", coreData["birth_country"].asTstr)
                    }
                    if (coreData.hasKey("birth_state")) {
                        put("region", coreData["birth_state"].asTstr)
                    }
                    if (coreData.hasKey("birth_city")) {
                        put("locality", coreData["birth_city"].asTstr)
                    }
                }
                added.add("place_of_birth")
            }

            // Address: SD-JWT uses a nested address object
            val hasAddress =
                coreData.hasKey("resident_address") ||
                coreData.hasKey("resident_country") ||
                coreData.hasKey("resident_state") ||
                coreData.hasKey("resident_city") ||
                coreData.hasKey("resident_postal_code") ||
                coreData.hasKey("resident_street") ||
                coreData.hasKey("resident_house_number")

            if (hasAddress) {
                putJsonObject("address") {
                    if (coreData.hasKey("resident_address")) {
                        put("formatted", coreData["resident_address"].asTstr)
                    }
                    if (coreData.hasKey("resident_country")) {
                        put("country", coreData["resident_country"].asTstr)
                    }
                    if (coreData.hasKey("resident_state")) {
                        put("region", coreData["resident_state"].asTstr)
                    }
                    if (coreData.hasKey("resident_city")) {
                        put("locality", coreData["resident_city"].asTstr)
                    }
                    if (coreData.hasKey("resident_postal_code")) {
                        put("postal_code", coreData["resident_postal_code"].asTstr)
                    }

                    val street = if (coreData.hasKey("resident_street")) {
                        coreData["resident_street"].asTstr
                    } else {
                        null
                    }

                    val houseNumber = if (coreData.hasKey("resident_house_number")) {
                        coreData["resident_house_number"].asTstr
                    } else {
                        null
                    }

                    when {
                        street != null && houseNumber != null ->
                            put("street_address", "$street $houseNumber")
                        street != null ->
                            put("street_address", street)
                        houseNumber != null ->
                            put("street_address", houseNumber)
                    }
                }
                added.add("address")
            }

            // SD-JWT uses nationalities as a JSON array
            if (coreData.hasKey("nationality")) {
                put(
                    "nationalities",
                    buildJsonArray {
                        for (nationality in coreData["nationality"].asArray) {
                            add(JsonPrimitive(nationality.asTstr))
                        }
                    }
                )
                added.add("nationalities")
            }

            // Date claim names differ in SD-JWT
            if (coreData.hasKey("issuance_date")) {
                put("date_of_issuance", coreData["issuance_date"].asDateString.toString())
                added.add("date_of_issuance")
            }

            if (coreData.hasKey("expiry_date")) {
                put("date_of_expiry", coreData["expiry_date"].asDateString.toString())
                added.add("date_of_expiry")
            }

            // Contact claim names differ in SD-JWT
            if (coreData.hasKey("email_address")) {
                put("email", coreData["email_address"].asTstr)
                added.add("email")
            }

            if (coreData.hasKey("mobile_phone_number")) {
                put("phone_number", coreData["mobile_phone_number"].asTstr)
                added.add("phone_number")
            }
            // Transfer core fields that have counterparts in the PID credential
            for ((nameItem, value) in coreData.asMap) {
                val name = nameItem.asTstr
                val attribute = documentType.claims[name]
                if (!added.contains(name) && attribute != null) {
                    val typeMatches = when (attribute.type) {
                        DocumentAttributeType.Blob, DocumentAttributeType.Picture ->
                            value is Bstr || value is IndefLengthBstr
                        DocumentAttributeType.Boolean ->
                            value == Simple.TRUE || value == Simple.FALSE
                        DocumentAttributeType.String, is DocumentAttributeType.StringOptions ->
                            value is Tstr || value is IndefLengthTstr
                        DocumentAttributeType.Number, is DocumentAttributeType.IntegerOptions ->
                            value is CborInt || value is CborFloat || value is CborDouble
                        DocumentAttributeType.Date ->
                            value is Tagged && value.tagNumber == Tagged.FULL_DATE_STRING
                        DocumentAttributeType.DateTime ->
                            value is Tagged && value.tagNumber == Tagged.DATE_TIME_STRING
                        is DocumentAttributeType.ComplexType -> true
                    }
                    if (typeMatches) {
                        put(name, value.toJson())
                    } else {
                        Logger.e(TAG, "Skipped '$name': type mismatch")
                    }
                }
            }

            // Values derived from the birth_date
            put("age_in_years", dateOfBirth.yearsUntil(now.toLocalDateTime(timeZone).date))
            put("age_birth_year", dateOfBirth.year)
            putJsonObject("age_equal_or_over") {
                for (age in listOf(14, 18, 21)) {
                    val isOver = now > dateOfBirthInstant.plus(age, DateTimeUnit.YEAR, timeZone)
                    put(age.toString(), isOver)
                }
            }
            added.addAll(listOf("age_in_years", "age_birth_year", "age_equal_or_over"))

            // Add all mandatory elements for completeness.
            for ((elementName, data) in documentType.claims) {
                if (!added.contains(elementName)) {
                    data.sampleValueJson?.let { put(elementName, it) }
                }
            }

        }

        val timeSigned = now
        val validFrom = Clock.System.now()
        val validUntil = validFrom + 30.days
        val issuer = BackendEnvironment.getBaseUrl()

        val baseUrl = BackendEnvironment.getBaseUrl()
        val revocationStatus = RevocationStatus.StatusList(
            idx = credentialId.index,
            uri = "$baseUrl/status_list/${credentialId.bucket}",
            certificate = null
        )

        val sdJwt = SdJwt.create(
            issuerKey = getSigningKey(),
            kbKey = authenticationKey,
            claims = identityAttributes,
            nonSdClaims = buildJsonObject {
                put("iss", issuer)
                put("vct", documentType.vct)
                put("iat", timeSigned.epochSeconds)
                put("nbf", validFrom.epochSeconds)
                put("exp", validUntil.epochSeconds)
                put("status", revocationStatus.toJson())
            }
        )

        return MintedCredential(
            credential = sdJwt.compactSerialization,
            creation = validFrom,
            expiration = validUntil
        )
    }

    override suspend fun display(systemOfRecordData: DataItem): CredentialDisplay =
        CredentialDisplay.create(systemOfRecordData, "credential_pid")

    companion object {
        private val FORMAT = CredentialFormat.SdJwt(EUPersonalID.EUPID_VCT)
        private const val TAG = "CredentialFactorySdjwtPid"
    }
}