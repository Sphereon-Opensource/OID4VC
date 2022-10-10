import { CredentialResponse, CredentialResponseError } from './CredentialResponse';
import { postWithBearerToken } from './functions/HttpUtils';
import { CredentialFormat, CredentialType, ProofOfPossesion } from './types';

export interface CredentialRequest {
  //TODO: handling list is out of scope for now
  type: CredentialType | CredentialType[];
  //TODO: handling list is out of scope for now
  format: CredentialFormat | CredentialFormat[];
  proof: ProofOfPossesion;
}

async function sendCredentialRequest(
  request: CredentialRequest,
  url: string,
  token: string
): Promise<CredentialResponse | CredentialResponseError> {
  try {
    const response = await postWithBearerToken(url, request, token);
    //TODO: remove this in the future
    console.log(response);
    return response.json();
  } catch (e) {
    //TODO: remove this in the future
    console.log(e);
    return e;
  }
}
