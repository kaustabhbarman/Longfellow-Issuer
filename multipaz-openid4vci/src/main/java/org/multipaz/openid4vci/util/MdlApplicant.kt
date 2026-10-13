package org.multipaz.openid4vci.util

import kotlinx.io.bytestring.ByteString
import org.multipaz.cbor.annotation.CborSerializable

@CborSerializable
data class DrivingPrivilege(
    val vehicleCategoryCode: String,
    val issueDate: String,
    val expiryDate: String
) {
    companion object
}

@CborSerializable
data class MdlApplicant(
    val givenName: String,
    val familyName: String,
    val birthDate: String,

    val portrait: ByteString,

    val documentNumber: String,
    val issueDate: String,
    val expiryDate: String,

    val issuingAuthority: String,
    val issuingCountry: String,

    val drivingPrivileges: List<DrivingPrivilege>
) {
    companion object
}
