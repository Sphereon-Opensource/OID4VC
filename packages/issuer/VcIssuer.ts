import { ICredentialIssuerMetadataParametersV1_11 } from "./types/IVcIssuer";

export class VcIssuer {
  _issuerMetadata: ICredentialIssuerMetadataParametersV1_11;

  constructor(issuerMetadata: ICredentialIssuerMetadataParametersV1_11) {
    this._issuerMetadata = issuerMetadata;
  }

  public getIssuerMetadata() {
    return this._issuerMetadata;
  }
}
