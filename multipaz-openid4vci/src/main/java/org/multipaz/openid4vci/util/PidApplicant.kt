package org.multipaz.openid4vci.util

import kotlinx.io.bytestring.ByteString
import org.multipaz.cbor.annotation.CborSerializable

@CborSerializable
data class PidApplicant(
    val givenName: String,
    val familyName: String,
    val birthDate: String,
    val personalIdNumber: String,
    val portrait: ByteString?,

    // Additional PID attributes
    val familyNameBirth: String? = null,
    val givenNameBirth: String? = null,

    val birthPlace: String? = null,
    val birthCountry: String? = null,
    val birthState: String? = null,
    val birthCity: String? = null,

    val address: String? = null,
    val residentCountry: String? = null,
    val residentState: String? = null,
    val residentCity: String? = null,
    val residentPostalCode: String? = null,
    val residentStreet: String? = null,
    val residentHouseNumber: String? = null,

    // ISO/IEC 5218 numeric sex code
    val sex: Int? = null,

    val nationality: String? = null,
    val issuanceDate: String? = null,
    val expiryDate: String? = null,
    val issuingAuthority: String? = null,
    val documentNumber: String? = null,
    val issuingJurisdiction: String? = null,
    val issuingCountry: String? = null,

    val emailAddress: String? = null,
    val mobilePhoneNumber: String? = null
) {
    companion object
}