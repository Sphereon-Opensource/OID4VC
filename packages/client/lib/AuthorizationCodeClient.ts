import {
  AuthorizationDetails,
  AuthorizationRequestOpts,
  CodeChallengeMethod,
  convertJsonToURI,
  CreateRequestObjectMode,
  CredentialConfigurationSupportedV1_0_13,
  CredentialOfferPayloadV1_0_13,
  CredentialOfferRequestWithBaseUrl,
  determineSpecVersionFromOffer,
  EndpointMetadataResultV1_0_13,
  formPost,
  JsonURIMode,
  Jwt,
  OID4VCICredentialFormat,
  OpenId4VCIVersion,
  PARMode,
  PKCEOpts,
  PushedAuthorizationResponse,
  RequestObjectOpts,
  ResponseType,
} from '@sphereon/oid4vci-common';
import Debug from 'debug';

import { ProofOfPossessionBuilder } from './ProofOfPossessionBuilder';

const debug = Debug('sphereon:oid4vci');

export async function createSignedAuthRequestWhenNeeded(requestObject: Record<string, any>, opts: RequestObjectOpts & { aud?: string }) {
  if (opts.requestObjectMode === CreateRequestObjectMode.REQUEST_URI) {
    throw Error(`Request Object Mode ${opts.requestObjectMode} is not supported yet`);
  } else if (opts.requestObjectMode === CreateRequestObjectMode.REQUEST_OBJECT) {
    if (typeof opts.signCallbacks?.signCallback !== 'function') {
      throw Error(`No request object sign callback found, whilst request object mode was set to ${opts.requestObjectMode}`);
    } else if (!opts.kid) {
      throw Error(`No kid found, whilst request object mode was set to ${opts.requestObjectMode}`);
    }
    let client_metadata: any;
    if (opts.clientMetadata || opts.jwksUri) {
      client_metadata = opts.clientMetadata ?? {};
      if (opts.jwksUri) {
        client_metadata['jwks_uri'] = opts.jwksUri;
      }
    }
    let authorization_details = requestObject['authorization_details'];
    if (typeof authorization_details === 'string') {
      authorization_details = JSON.parse(requestObject.authorization_details);
    }
    if (!requestObject.aud && opts.aud) {
      requestObject.aud = opts.aud;
    }
    const iss = requestObject.iss ?? opts.iss ?? requestObject.client_id;

    const jwt: Jwt = {
      header: { alg: 'ES256', kid: opts.kid, typ: 'JWT' },
      payload: { ...requestObject, iss, authorization_details, ...(client_metadata && { client_metadata }) },
    };
    const pop = await ProofOfPossessionBuilder.fromJwt({
      jwt,
      callbacks: opts.signCallbacks,
      version: OpenId4VCIVersion.VER_1_0_11,
      mode: 'JWT',
    }).build();
    requestObject['request'] = pop.jwt;
  }
}
function filterSupportedCredentials(
  credentialOffer: CredentialOfferPayloadV1_0_13,
  credentialsSupported?: Record<string, CredentialConfigurationSupportedV1_0_13>,
): (CredentialConfigurationSupportedV1_0_13 & { configuration_id: string })[] {
  if (!credentialOffer.credential_configuration_ids || !credentialsSupported) {
    return [];
  }
  return Object.entries(credentialsSupported)
    .filter((entry) => credentialOffer.credential_configuration_ids?.includes(entry[0]))
    .map((entry) => {
      return { ...entry[1], configuration_id: entry[0] };
    });
}

export const createAuthorizationRequestUrl = async ({
  pkce,
  endpointMetadata,
  authorizationRequest,
  credentialOffer,
  credentialConfigurationSupported,
  clientId,
  version,
}: {
  pkce: PKCEOpts;
  endpointMetadata: EndpointMetadataResultV1_0_13;
  authorizationRequest: AuthorizationRequestOpts;
  credentialOffer?: CredentialOfferRequestWithBaseUrl;
  credentialConfigurationSupported?: Record<string, CredentialConfigurationSupportedV1_0_13>;
  clientId?: string;
  version?: OpenId4VCIVersion;
}): Promise<string> => {
  function removeDisplayAndValueTypes(obj: any): void {
    for (const prop in obj) {
      if (['display', 'value_type'].includes(prop)) {
        delete obj[prop];
      } else if (typeof obj[prop] === 'object') {
        removeDisplayAndValueTypes(obj[prop]);
      }
    }
  }

  const { redirectUri, requestObjectOpts = { requestObjectMode: CreateRequestObjectMode.NONE } } = authorizationRequest;
  const client_id = clientId ?? authorizationRequest.clientId;

  let { scope, authorizationDetails } = authorizationRequest;
  const parMode = endpointMetadata?.credentialIssuerMetadata?.require_pushed_authorization_requests
    ? PARMode.REQUIRE
    : (authorizationRequest.parMode ?? (client_id ? PARMode.AUTO : PARMode.NEVER));
  // Scope and authorization_details can be used in the same authorization request
  // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rar-23#name-relationship-to-scope-param
  if (!scope && !authorizationDetails) {
    if (!credentialOffer) {
      throw Error('Please provide a scope or authorization_details if no credential offer is present');
    }
    if ('credentials' in credentialOffer.credential_offer) {
      throw new Error('CredentialOffer format is wrong.');
    }
    const ver = version ?? determineSpecVersionFromOffer(credentialOffer.credential_offer) ?? OpenId4VCIVersion.VER_1_0_13;
    const creds =
      ver === OpenId4VCIVersion.VER_1_0_13
        ? filterSupportedCredentials(credentialOffer.credential_offer as CredentialOfferPayloadV1_0_13, credentialConfigurationSupported)
        : [];

    // FIXME: complains about VCT for sd-jwt
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    authorizationDetails = creds.flatMap((cred) => {
      const locations = [credentialOffer?.credential_offer.credential_issuer ?? endpointMetadata.issuer];
      const credential_configuration_id: string | undefined = cred.configuration_id;
      const vct: string | undefined = cred.vct;
      let format: OID4VCICredentialFormat | undefined;

      if (!credential_configuration_id) {
        format = cred.format;
      }
      if (!credential_configuration_id && !cred.format) {
        throw Error('format is required in authorization details');
      }

      const meta: any = {};
      const credential_definition = cred.credential_definition;
      if (credential_definition?.type && !format) {
        // ype: OPTIONAL. Array as defined in Appendix A.1.1.2. This claim contains the type values the Wallet requests authorization for at the Credential Issuer. It MUST be present if the claim format is present in the root of the authorization details object. It MUST not be present otherwise.
        // It meens we have a config_id, already mapping it to an explicit format and types
        delete credential_definition.type;
      }
      if (credential_definition.credentialSubject) {
        removeDisplayAndValueTypes(credential_definition.credentialSubject);
      }

      return {
        type: 'openid_credential',
        ...meta,
        locations,
        ...(credential_definition && { credential_definition }),
        ...(credential_configuration_id && { credential_configuration_id }),
        ...(format && { format }),
        ...(vct && { vct }),
        ...(cred.claims && { claims: removeDisplayAndValueTypes(JSON.parse(JSON.stringify(cred.claims))) }),
      } as AuthorizationDetails;
    });
    if (!authorizationDetails || authorizationDetails.length === 0) {
      throw Error(`Could not create authorization details from credential offer. Please pass in explicit details`);
    }
  }
  if (!endpointMetadata?.authorization_endpoint) {
    throw Error('Server metadata does not contain authorization endpoint');
  }
  const parEndpoint = endpointMetadata.credentialIssuerMetadata?.pushed_authorization_request_endpoint;

  // add 'openid' scope if not present
  if (!scope?.includes('openid')) {
    scope = ['openid', scope].filter((s) => !!s).join(' ');
  }

  let queryObj: Record<string, any> | PushedAuthorizationResponse = {
    response_type: ResponseType.AUTH_CODE,
    ...(!pkce.disabled && {
      code_challenge_method: pkce.codeChallengeMethod ?? CodeChallengeMethod.S256,
      code_challenge: pkce.codeChallenge,
    }),
    authorization_details: JSON.stringify(handleAuthorizationDetails(endpointMetadata, authorizationDetails)),
    ...(redirectUri && { redirect_uri: redirectUri }),
    ...(client_id && { client_id }),
    ...(credentialOffer?.issuerState && { issuer_state: credentialOffer.issuerState }),
    scope,
  };

  if (!parEndpoint && parMode === PARMode.REQUIRE) {
    throw Error(`PAR mode is set to required by Authorization Server does not support PAR!`);
  } else if (parEndpoint && parMode !== PARMode.NEVER) {
    debug(`USING PAR with endpoint ${parEndpoint}`);
    const parResponse = await formPost<PushedAuthorizationResponse>(
      parEndpoint,
      convertJsonToURI(queryObj, {
        mode: JsonURIMode.X_FORM_WWW_URLENCODED,
        uriTypeProperties: ['client_id', 'request_uri', 'redirect_uri', 'scope', 'authorization_details', 'issuer_state'],
      }),
      { contentType: 'application/x-www-form-urlencoded', accept: 'application/json' },
    );
    if (parResponse.errorBody || !parResponse.successBody) {
      console.log(JSON.stringify(parResponse.errorBody));
      console.log('Falling back to regular request URI, since PAR failed');
      if (parMode === PARMode.REQUIRE) {
        throw Error(`PAR error: ${parResponse.origResponse.statusText}`);
      }
    } else {
      debug(`PAR response: ${JSON.stringify(parResponse.successBody, null, 2)}`);
      queryObj = { /*response_type: ResponseType.AUTH_CODE,*/ client_id, request_uri: parResponse.successBody.request_uri };
    }
  }
  await createSignedAuthRequestWhenNeeded(queryObj, { ...requestObjectOpts, aud: endpointMetadata.authorization_server });

  debug(`Object that will become query params: ` + JSON.stringify(queryObj, null, 2));
  const url = convertJsonToURI(queryObj, {
    baseUrl: endpointMetadata.authorization_endpoint,
    uriTypeProperties: ['client_id', 'request_uri', 'redirect_uri', 'scope', 'authorization_details', 'issuer_state'],
    // arrayTypeProperties: ['authorization_details'],
    mode: JsonURIMode.X_FORM_WWW_URLENCODED,
    // We do not add the version here, as this always needs to be form encoded
  });
  debug(`Authorization Request URL: ${url}`);
  return url;
};

const handleAuthorizationDetails = (
  endpointMetadata: EndpointMetadataResultV1_0_13,
  authorizationDetails?: AuthorizationDetails | AuthorizationDetails[],
): AuthorizationDetails | AuthorizationDetails[] | undefined => {
  if (authorizationDetails) {
    if (typeof authorizationDetails === 'string') {
      // backwards compat for older versions of the lib
      return authorizationDetails;
    }
    if (Array.isArray(authorizationDetails)) {
      return authorizationDetails
        .filter((value) => typeof value !== 'string')
        .map((value) => handleLocations(endpointMetadata, typeof value === 'string' ? value : { ...value }));
    } else {
      return handleLocations(endpointMetadata, { ...authorizationDetails });
    }
  }
  return authorizationDetails;
};

const handleLocations = (endpointMetadata: EndpointMetadataResultV1_0_13, authorizationDetails: AuthorizationDetails) => {
  if (typeof authorizationDetails === 'string') {
    // backwards compat for older versions of the lib
    return authorizationDetails;
  }
  if (authorizationDetails && (endpointMetadata.credentialIssuerMetadata?.authorization_server || endpointMetadata.authorization_endpoint)) {
    if (authorizationDetails.locations) {
      if (Array.isArray(authorizationDetails.locations)) {
        authorizationDetails.locations.push(endpointMetadata.issuer);
      } else {
        authorizationDetails.locations = [authorizationDetails.locations as string, endpointMetadata.issuer];
      }
    } else {
      authorizationDetails.locations = [endpointMetadata.issuer];
    }
  }
  return authorizationDetails;
};
