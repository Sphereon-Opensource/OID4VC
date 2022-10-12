import { ClaimFormat } from '@sphereon/ssi-types';

import { VcIssuanceClient } from './VcIssuanceClient';

export default class VcIssuanceClientBuilder {
  credentialRequestUrl: string;
  credentialType: string | string[];
  format: ClaimFormat | ClaimFormat[];

  withCredentialRequestUrl(credentialRequestUrl: string): VcIssuanceClientBuilder {
    this.credentialRequestUrl = credentialRequestUrl;
    return this;
  }

  withCredentialType(credentialType: string | string[]): VcIssuanceClientBuilder {
    this.credentialType = credentialType;
    return this;
  }

  withFormat(format: ClaimFormat | ClaimFormat[]): VcIssuanceClientBuilder {
    this.format = format;
    return this;
  }

  build(): VcIssuanceClient {
    return new VcIssuanceClient({ builder: this });
  }
}
