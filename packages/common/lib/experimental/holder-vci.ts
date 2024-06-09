/**
 * Experimental support not following the VCI spec to have the holder actually (re)sign the issued credential and return it to the issuer
 */
import * as process from 'node:process';

export const EXPERIMENTAL_SUBJECT_PROOF_MODE_ENABLED = process.env.EXPERIMENTAL_SUBJECT_PROOF_MODE?.trim().toLowerCase() === 'true';

export type SubjectProofMode = 'proof_chain' | 'proof_set' | 'proof_replace';

export type SubjectProofNotificationEventsSupported =
  | 'credential_accepted_holder_signed'
  | 'credential_deleted_holder_signed'
  | 'credential_accepted';

export interface ExperimentalSubjectIssuance {
  credential_subject_issuance?: {
    subject_proof_mode: SubjectProofMode;
    notifications_events_supported: Array<SubjectProofNotificationEventsSupported>;
  };
}
