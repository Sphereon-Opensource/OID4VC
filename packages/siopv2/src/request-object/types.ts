import { ClaimPayloadCommonOpts, RequestObjectPayloadOpts } from '../authorization-request';
import { ExternalSignature, InternalSignature, NoSignature, ObjectBy, SuppliedSignature } from '../types';

export interface RequestObjectOpts<CT extends ClaimPayloadCommonOpts> extends ObjectBy {
  payload?: RequestObjectPayloadOpts<CT>; // for pass by value
  signature: InternalSignature | ExternalSignature | SuppliedSignature | NoSignature; // Whether no withSignature is being used, internal (access to private key), or external (hosted using authentication), or supplied (callback supplied)
}
