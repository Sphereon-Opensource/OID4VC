import {
  CredentialOfferPayload,
  CredentialOfferPayloadV1_0_09,
  CredentialOfferPayloadV1_0_11,
  CredentialOfferRequestWithBaseUrl,
  CredentialOfferV1_0_11,
  determineSpecVersionFromURI,
  OpenId4VCIVersion,
  OpenIDResponse,
} from '@sphereon/oid4vci-common';
import Debug from 'debug';

import { convertJsonToURI, convertURIToJsonObject, getJson } from './functions';

const debug = Debug('sphereon:openid4vci:initiation');

export class CredentialOffer {
  public static async fromURI(uri: string, opts?: { resolve?: boolean }): Promise<CredentialOfferRequestWithBaseUrl> {
    debug(`Credential Offer URI: ${uri}`);
    if (!uri.includes('?')) {
      debug(`Invalid Credential Offer URI: ${uri}`);
      throw Error('Invalid Credential Offer Request');
    }
    const baseUrl = uri.split('?')[0];
    const version = determineSpecVersionFromURI(uri);
    let credentialOfferPayload: CredentialOfferPayload;
    if (version < OpenId4VCIVersion.VER_1_0_11) {
      credentialOfferPayload = convertURIToJsonObject(uri, {
        arrayTypeProperties: ['credential_type'],
        requiredProperties: uri.includes('credential_offer_uri=') ? ['credential_offer_uri'] : ['issuer', 'credential_type'],
      }) as CredentialOfferPayloadV1_0_09;
    } else {
      const credentialOffer = convertURIToJsonObject(uri, {
        arrayTypeProperties: ['credentials'],
        requiredProperties: uri.includes('credential_offer_uri=') ? ['credential_offer_uri'] : ['credential_offer'],
      }) as CredentialOfferV1_0_11;
      if (credentialOffer.credential_offer) {
        credentialOfferPayload = credentialOffer.credential_offer as CredentialOfferPayloadV1_0_11;
      } else if (credentialOffer.credential_offer_uri) {
        if (opts && opts.resolve === false) {
          throw Error(
            'Resolution of credential offer URIs has been explicitly disabled, but we received a URI: ' + credentialOffer.credential_offer_uri
          );
        }
        const response = (await getJson(credentialOffer.credential_offer_uri)) as OpenIDResponse<CredentialOfferPayloadV1_0_11>;
        if (!response || !response.successBody) {
          throw Error(`Could not get credential offer from uri: ${credentialOffer.credential_offer_uri}: ${JSON.stringify(response?.errorBody)}`);
        }
        credentialOfferPayload = response.successBody;
      } else {
        throw Error('Either a credential_offer or credential_offer_uri should be present in ' + uri);
      }
    }

    const request =
      version < OpenId4VCIVersion.VER_1_0_11.valueOf()
        ? (credentialOfferPayload as CredentialOfferPayloadV1_0_09)
        : (credentialOfferPayload as CredentialOfferPayloadV1_0_11);

    return {
      baseUrl,
      request,
      version,
    };
  }

  public static toURI(uri: CredentialOfferRequestWithBaseUrl, opts?: { version?: OpenId4VCIVersion }): string {
    const version = opts?.version ?? uri.version;
    const request = uri.request;
    let baseUrl = uri.baseUrl;
    let param: string | undefined;

    if (version >= OpenId4VCIVersion.VER_1_0_11) {
      // v11 changed from encoding every param to a encoded json object with a credential_offer param key
      if (!baseUrl.includes('?')) {
        param = 'credential_offer';
      } else {
        const split = baseUrl.split('?');
        if (split.length > 1 && split[1] !== '') {
          if (baseUrl.endsWith('&')) {
            param = 'credential_offer';
          } else if (!baseUrl.endsWith('=')) {
            baseUrl += `&`;
            param = 'credential_offer';
          }
        }
      }
    }
    return convertJsonToURI(request, {
      baseUrl,
      arrayTypeProperties: ['credential_type'],
      uriTypeProperties: ['issuer', 'credential_type'],
      param,
      version,
    });
  }
}
