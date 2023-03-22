import {OIDCVCIVersion, URLSchemes} from "@sphereon/openid4vci-common";

export function discoverOIDCVCIVersion(credentialOfferURI: string): OIDCVCIVersion {
  if (credentialOfferURI.startsWith(URLSchemes.INITIATE_ISSUANCE)) {
    return OIDCVCIVersion.VER_9;
  } else if (credentialOfferURI.startsWith(URLSchemes.CREDENTIAL_OFFER)) {
    return OIDCVCIVersion.VER_11
  }

  throw Error('unexpected version')
}
