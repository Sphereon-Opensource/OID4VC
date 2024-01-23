import { CredentialResponse, OpenIDResponse } from '../types';

import { post } from './HttpUtils';

export function isDeferredCredentialResponse(credentialResponse: OpenIDResponse<CredentialResponse>) {
  const orig = credentialResponse.successBody;
  // Specs mention 202, but some implementations like EBSI return 200
  return credentialResponse.origResponse.status % 200 <= 2 && !!orig && !orig.credential && (!!orig.acceptance_token || !!orig.transaction_id);
}
function assertNonFatalError(credentialResponse: OpenIDResponse<CredentialResponse>) {
  if (credentialResponse.origResponse.status === 400 && credentialResponse.errorBody?.error) {
    if (credentialResponse.errorBody.error === 'invalid_transaction_id' || credentialResponse.errorBody.error.includes('acceptance_token')) {
      throw Error('Invalid transaction id. Probably the deferred credential request expired');
    }
  }
}

export function isDeferredCredentialIssuancePending(credentialResponse: OpenIDResponse<CredentialResponse>) {
  if (isDeferredCredentialResponse(credentialResponse)) {
    return !!credentialResponse?.successBody?.transaction_id ?? !!credentialResponse?.successBody?.acceptance_token;
  }
  if (credentialResponse.origResponse.status === 400 && credentialResponse.errorBody?.error) {
    if (credentialResponse.errorBody.error === 'issuance_pending') {
      return true;
    } else if (credentialResponse.errorBody.error_description?.toLowerCase().includes('not available yet')) {
      return true;
    }
  }
  return false;
}

function sleep(ms: number) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

export async function acquireDeferredCredential({
  bearerToken,
  transactionId,
  deferredCredentialEndpoint,
  deferredCredentialIntervalInMS,
  deferredCredentialAwait,
}: {
  bearerToken: string;
  transactionId?: string;
  deferredCredentialIntervalInMS?: number;
  deferredCredentialAwait?: boolean;
  deferredCredentialEndpoint: string;
}): Promise<OpenIDResponse<CredentialResponse>> {
  let credentialResponse: OpenIDResponse<CredentialResponse> = await acquireDeferredCredentialImpl({
    bearerToken,
    transactionId,
    deferredCredentialEndpoint,
  });

  const DEFAULT_SLEEP_IN_MS = 5000;
  while (!credentialResponse.successBody?.credential && deferredCredentialAwait) {
    assertNonFatalError(credentialResponse);
    const pending = isDeferredCredentialIssuancePending(credentialResponse);
    console.log(`Issuance still pending?: ${pending}`);
    if (!pending) {
      throw Error(`Issuance isn't pending anymore: ${credentialResponse}`);
    }

    await sleep(deferredCredentialIntervalInMS ?? DEFAULT_SLEEP_IN_MS);
    credentialResponse = await acquireDeferredCredentialImpl({ bearerToken, transactionId, deferredCredentialEndpoint });
  }
  return credentialResponse;
}

async function acquireDeferredCredentialImpl({
  bearerToken,
  transactionId,
  deferredCredentialEndpoint,
}: {
  bearerToken: string;
  transactionId?: string;
  deferredCredentialEndpoint: string;
}): Promise<OpenIDResponse<CredentialResponse>> {
  const response: OpenIDResponse<CredentialResponse> = await post(
    deferredCredentialEndpoint,
    JSON.stringify(transactionId ? { transaction_id: transactionId } : ''),
    { bearerToken },
  );
  console.log(JSON.stringify(response, null, 2));
  assertNonFatalError(response);

  return response;
}
