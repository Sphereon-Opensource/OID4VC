import {
  CredentialOfferRequestWithBaseUrl,
  determineSpecVersionFromOffer,
  EndpointMetadata,
  OpenId4VCIVersion,
  UniformCredentialOfferRequest,
} from '@sphereon/oid4vci-common';

import { CredentialOfferClient } from './CredentialOfferClient';
import { CredentialRequestClientBuilderV1_0_11 } from './CredentialRequestClientBuilderV1_0_11';
import { CredentialRequestClientBuilderV1_0_13 } from './CredentialRequestClientBuilderV1_0_13';

export class CredentialRequestClientBuilder {
  public static fromCredentialIssuer({
    credentialIssuer,
    metadata,
    version,
    credentialIdentifier,
    credentialTypes,
  }: {
    credentialIssuer: string;
    metadata?: EndpointMetadata;
    version?: OpenId4VCIVersion;
    credentialIdentifier?: string;
    credentialTypes?: string | string[];
  }): CredentialRequestClientBuilderV1_0_13 | CredentialRequestClientBuilderV1_0_11 {
    const specVersion = version ? version : OpenId4VCIVersion.VER_1_0_13;
    if (specVersion >= OpenId4VCIVersion.VER_1_0_13) {
      return CredentialRequestClientBuilderV1_0_13.fromCredentialIssuer({
        credentialIssuer,
        metadata,
        version,
        credentialIdentifier,
        credentialTypes,
      });
    } else {
      if (!credentialTypes || credentialTypes.length === 0) {
        throw new Error('CredentialTypes must be provided for v1_0_11');
      }
      return CredentialRequestClientBuilderV1_0_11.fromCredentialIssuer({ credentialIssuer, metadata, version, credentialTypes });
    }
  }

  public static async fromURI({
    uri,
    metadata,
  }: {
    uri: string;
    metadata?: EndpointMetadata;
  }): Promise<CredentialRequestClientBuilderV1_0_11 | CredentialRequestClientBuilderV1_0_13> {
    const offer = await CredentialOfferClient.fromURI(uri);
    return CredentialRequestClientBuilder.fromCredentialOfferRequest({ request: offer, ...offer, metadata, version: offer.version });
  }

  public static fromCredentialOfferRequest(opts: {
    request: UniformCredentialOfferRequest;
    scheme?: string;
    baseUrl?: string;
    version?: OpenId4VCIVersion;
    metadata?: EndpointMetadata;
  }): CredentialRequestClientBuilderV1_0_11 | CredentialRequestClientBuilderV1_0_13 {
    const { request } = opts;
    const version = opts.version ?? request.version ?? determineSpecVersionFromOffer(request.original_credential_offer);
    if (version < OpenId4VCIVersion.VER_1_0_13) {
      return CredentialRequestClientBuilderV1_0_11.fromCredentialOfferRequest(opts);
    }
    return CredentialRequestClientBuilderV1_0_13.fromCredentialOfferRequest(opts);
  }

  public static fromCredentialOffer({
    credentialOffer,
    metadata,
  }: {
    credentialOffer: CredentialOfferRequestWithBaseUrl;
    metadata?: EndpointMetadata;
  }): CredentialRequestClientBuilderV1_0_11 | CredentialRequestClientBuilderV1_0_13 {
    const version = determineSpecVersionFromOffer(credentialOffer.credential_offer);
    if (version < OpenId4VCIVersion.VER_1_0_13) {
      return CredentialRequestClientBuilderV1_0_11.fromCredentialOffer({
        credentialOffer,
        metadata,
      });
    }
    return CredentialRequestClientBuilderV1_0_13.fromCredentialOffer({
      credentialOffer,
      metadata,
    });
  }
}
