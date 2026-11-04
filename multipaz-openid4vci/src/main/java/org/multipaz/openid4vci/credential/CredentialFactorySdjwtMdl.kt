package org.multipaz.openid4vci.credential

import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.DataItem
import org.multipaz.crypto.EcPublicKey
import org.multipaz.openid4vci.util.CredentialId
import org.multipaz.provisioning.CredentialFormat
import org.multipaz.revocation.RevocationStatus
import org.multipaz.rpc.backend.BackendEnvironment
import org.multipaz.rpc.backend.Resources
import org.multipaz.sdjwt.SdJwt
import org.multipaz.server.common.getBaseUrl
import org.multipaz.util.toBase64Url
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days

/**
 * Prototype CredentialFactory for Driving Licence credentials in SD-JWT format.
 *
 * The VCT used here is project-specific. It is not an official mDL SD-JWT VCT.
 */
class CredentialFactorySdjwtMdl : CredentialFactory {

    override val configurationId: String
        get() = "mDL_sd_jwt"

    override val scope: String
        get() = "mDL"

    override val format
        get() = FORMAT

    override val requireKeyAttestation: Boolean
        get() = true

    override val proofSigningAlgorithms: List<String>
        get() = CredentialFactory.DEFAULT_PROOF_SIGNING_ALGORITHMS

    override val cryptographicBindingMethods: List<String>
        get() = listOf("jwk")

    override val name: String
        get() = "Driving Licence"

    override val logo: String
        get() = "card-mdl.png"

    override suspend fun mint(
        systemOfRecordData: DataItem,
        authenticationKey: EcPublicKey?,
        credentialId: CredentialId
    ): MintedCredential {
        check(authenticationKey != null)

        val coreData = systemOfRecordData["core"]
        val records = systemOfRecordData["records"]

        if (!records.hasKey("mDL")) {
            throw IllegalArgumentException("No driver's license was issued to this person")
        }

        val mdlData = records["mDL"].asMap.values.firstOrNull()
            ?: throw IllegalArgumentException("Driving Licence record is empty")

        val resources = BackendEnvironment.getInterface(Resources::class)!!
        val now = Clock.System.now()
        val validFrom = now
        val validUntil = validFrom + 30.days
        val issuer = BackendEnvironment.getBaseUrl()
        val baseUrl = BackendEnvironment.getBaseUrl()

        val revocationStatus = RevocationStatus.StatusList(
            idx = credentialId.index,
            uri = "$baseUrl/status_list/${credentialId.bucket}",
            certificate = null
        )

        val identityAttributes = buildJsonObject {
            // Identity fields from the issuer's core record.
            if (coreData.hasKey("given_name")) {
                put("given_name", coreData["given_name"].asTstr)
            }

            if (coreData.hasKey("family_name")) {
                put("family_name", coreData["family_name"].asTstr)
            }

            if (coreData.hasKey("birth_date")) {
                put("birthdate", coreData["birth_date"].asDateString.toString())
            }

            // Include a portrait if present; otherwise use the existing demo portrait.
            if (coreData.hasKey("portrait")) {
                put("picture", coreData["portrait"].asBstr.toBase64Url())
            } else if (mdlData.hasKey("portrait")) {
                put("picture", mdlData["portrait"].asBstr.toBase64Url())
            } else {
                val bytes = resources.getRawResource("female.jpg")!!
                put("picture", bytes.toByteArray().toBase64Url())
            }

            // Driving Licence document details.
            if (mdlData.hasKey("document_number")) {
                put("document_number", mdlData["document_number"].asTstr)
            }

            if (mdlData.hasKey("issue_date")) {
                put("issue_date", mdlData["issue_date"].asDateString.toString())
            }

            if (mdlData.hasKey("expiry_date")) {
                put("expiry_date", mdlData["expiry_date"].asDateString.toString())
            }

            if (mdlData.hasKey("issuing_authority")) {
                put("issuing_authority", mdlData["issuing_authority"].asTstr)
            }

            if (mdlData.hasKey("issuing_country")) {
                put("issuing_country", mdlData["issuing_country"].asTstr)
            }

            // Driving privileges are represented as a JSON array.
            if (mdlData.hasKey("driving_privileges")) {
                put("driving_privileges", buildJsonArray {
                    for (privilege in mdlData["driving_privileges"].asArray) {
                        add(buildJsonObject {
                            if (privilege.hasKey("vehicle_category_code")) {
                                put(
                                    "vehicle_category_code",
                                    privilege["vehicle_category_code"].asTstr
                                )
                            }

                            if (privilege.hasKey("issue_date")) {
                                put(
                                    "issue_date",
                                    privilege["issue_date"].asDateString.toString()
                                )
                            }

                            if (privilege.hasKey("expiry_date")) {
                                put(
                                    "expiry_date",
                                    privilege["expiry_date"].asDateString.toString()
                                )
                            }
                        })
                    }
                })
            }
        }

        val sdJwt = SdJwt.create(
            issuerKey = getSigningKey(),
            kbKey = authenticationKey,
            claims = identityAttributes,
            nonSdClaims = buildJsonObject {
                put("iss", issuer)
                put("vct", MDL_SD_JWT_VCT)
                put("iat", now.epochSeconds)
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
        CredentialDisplay.create(systemOfRecordData, "credential_mdl")

    companion object {
        /**
         * Prototype VCT for this issuer's SD-JWT Driving Licence.
         * Replace with a stable, published VCT before interoperability testing.
         */
        private const val MDL_SD_JWT_VCT =
            "https://issuer.example.org/credentials/mDL-sd-jwt"

        private val FORMAT = CredentialFormat.SdJwt(MDL_SD_JWT_VCT)
    }
}