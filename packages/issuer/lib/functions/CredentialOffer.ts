import {
  CredentialFormatEnum,
  CredentialIssuerMetadataSupportedCredentials,
  encodeJsonAsURI,
  IssuerMetadata,
  TokenErrorResponse,
} from '@sphereon/openid4vci-common'
import { v4 as uuidv4 } from 'uuid'

export function createCredentialOfferDeeplink(preAuthorizedCode: string, issuerMetadata: IssuerMetadata): string {
  // openid-credential-offer://credential_offer=%7B%22credential_issuer%22:%22https://credential-issuer.example.com
  // %22,%22credentials%22:%5B%7B%22format%22:%22jwt_vc_json%22,%22types%22:%5B%22VerifiableCr
  // edential%22,%22UniversityDegreeCredential%22%5D%7D%5D,%22issuer_state%22:%22eyJhbGciOiJSU0Et...
  // FYUaBy%22%7D
  if (!preAuthorizedCode) {
    throw new Error(TokenErrorResponse.invalid_request)
  }

  const types: string[] = []
  issuerMetadata.credentials_supported.map((cs) => {
    if (cs.format != CredentialFormatEnum.mso_mdoc) types.push(...(cs['types' as keyof CredentialIssuerMetadataSupportedCredentials] as string[]))
  })
  return `openid-credential-offer://?credential_offer=${encodeJsonAsURI({
    credential_issuer: issuerMetadata.credential_issuer,
    credentials: {
      format: issuerMetadata.credentials_supported.map((cs) => cs.format),
      types: types,
      //fixme: @nklomp I've placed this here for now, but later we need to have the concept of sessions and in there we have to keep track of the id
      issuer_state: uuidv4(),
    },
    grants: {
      authorization_code: preAuthorizedCode,
    },
  })}`
}
