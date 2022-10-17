import { CredentialFormat } from '@sphereon/ssi-types';

import { CredentialRequestClient } from './CredentialRequestClient';
import { convertURIToJsonObject } from './functions';
import { IssuanceInitiationRequestPayload } from './types';

export default class CredentialRequestClientBuilder {
  credentialRequestUrl: string;
  credentialType: string | string[];
  format: CredentialFormat | CredentialFormat[];

  public static fromIssuanceInitiationURI(issuanceInitiation: string): CredentialRequestClientBuilder {
    return CredentialRequestClientBuilder.fromIssuanceInitiationRequest(
      convertURIToJsonObject(issuanceInitiation, {
        arrayTypeProperties: ['credential_type'],
        requiredProperties: ['issuer', 'credential_type'],
      }) as IssuanceInitiationRequestPayload
    );
  }

  public static fromIssuanceInitiationRequest(issuanceInitiation: IssuanceInitiationRequestPayload): CredentialRequestClientBuilder {
    const builder = new CredentialRequestClientBuilder();
    builder.withCredentialRequestUrl(issuanceInitiation.issuer);
    builder.withCredentialType(issuanceInitiation.credential_type);
    return builder;
  }

  public withCredentialRequestUrl(credentialRequestUrl: string): CredentialRequestClientBuilder {
    this.credentialRequestUrl = credentialRequestUrl;
    return this;
  }

  public withCredentialType(credentialType: string | string[]): CredentialRequestClientBuilder {
    this.credentialType = credentialType;
    return this;
  }

  public withFormat(format: CredentialFormat | CredentialFormat[]): CredentialRequestClientBuilder {
    this.format = format;
    return this;
  }

  public build(): CredentialRequestClient {
    return new CredentialRequestClient(this);
  }
}
