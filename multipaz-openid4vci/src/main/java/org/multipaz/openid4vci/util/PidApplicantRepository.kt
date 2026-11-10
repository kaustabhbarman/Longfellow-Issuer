package org.multipaz.openid4vci.util

import kotlinx.io.bytestring.ByteString
import org.multipaz.rpc.backend.BackendEnvironment
import org.multipaz.rpc.backend.getTable
import org.multipaz.storage.StorageTableSpec

object PidApplicantRepository {

    private val tableSpec = StorageTableSpec(
        name = "OID4VCIPidApplicant",
        supportPartitions = false,
        supportExpiration = false
    )

    suspend fun create(applicant: PidApplicant): String {
        return BackendEnvironment.getTable(tableSpec).insert(
            key = null,
            data = ByteString(applicant.toCbor())
        )
    }

    suspend fun get(applicantId: String): PidApplicant {
        val data = BackendEnvironment.getTable(tableSpec).get(applicantId)
            ?: throw IllegalStateException("Unknown PID applicant: $applicantId")

        return PidApplicant.fromCbor(data.toByteArray())
    }

    suspend fun update(
        applicantId: String,
        applicant: PidApplicant
    ) {
        BackendEnvironment.getTable(tableSpec).update(
            key = applicantId,
            data = ByteString(applicant.toCbor())
        )
    }
}
