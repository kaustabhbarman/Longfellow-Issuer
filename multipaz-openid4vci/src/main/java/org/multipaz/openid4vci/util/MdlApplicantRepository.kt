package org.multipaz.openid4vci.util

import kotlinx.io.bytestring.ByteString
import org.multipaz.rpc.backend.BackendEnvironment
import org.multipaz.rpc.backend.getTable
import org.multipaz.storage.StorageTableSpec

object MdlApplicantRepository {

    private val tableSpec = StorageTableSpec(
        name = "OID4VCIMdlApplicant",
        supportPartitions = false,
        supportExpiration = false
    )

    suspend fun create(applicant: MdlApplicant): String {
        return BackendEnvironment.getTable(tableSpec).insert(
            key = null,
            data = ByteString(applicant.toCbor())
        )
    }

    suspend fun get(applicantId: String): MdlApplicant {
        val data = BackendEnvironment.getTable(tableSpec).get(applicantId)
            ?: throw IllegalStateException("Unknown applicant: $applicantId")

        return MdlApplicant.fromCbor(data.toByteArray())
    }

    suspend fun update(
        applicantId: String,
        applicant: MdlApplicant
    ) {
        BackendEnvironment.getTable(tableSpec).update(
            key = applicantId,
            data = ByteString(applicant.toCbor())
        )
    }
}
