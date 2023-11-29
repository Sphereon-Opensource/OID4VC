<h1 align="center">
  <br>
  <a href="https://www.sphereon.com"><img src="https://sphereon.com/content/themes/sphereon/assets/img/logo.svg" alt="Sphereon" width="400"></a>
    <br>OpenID for Verifiable Credential Issuance - Client 
  <br>
</h1>

[![CI](https://github.com/Sphereon-Opensource/openid4vci-client/actions/workflows/main.yml/badge.svg)](https://github.com/Sphereon-Opensource/openid4vci-client/actions/workflows/main.yml) [![codecov](https://codecov.io/gh/Sphereon-Opensource/openid4vci-client/branch/develop/graph/badge.svg)](https://codecov.io/gh/Sphereon-Opensource/openid4vci-client) [![NPM Version](https://img.shields.io/npm/v/@sphereon/oid4vci-client.svg)](https://npm.im/@sphereon/oid4vci-client)

_IMPORTANT this package is in an early development stage and currently only supports the pre-authorized code flow of
OpenID4VCI!_

# Background

A client to request and receive Verifiable Credentials using
the [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) (
OpenID4VCI) specification for receiving Verifiable Credentials as a holder/subject.

OpenID4VCI defines an API designated as Credential Endpoint that is used to issue verifiable credentials and
corresponding OAuth 2.0 based authorization mechanisms (see [RFC6749]) that a Wallet uses to obtain authorization to
receive verifiable credentials. W3C formats as well as other Credential formats are supported. This allows existing
OAuth 2.0 deployments and OpenID Connect OPs (see [OpenID.Core]) to extend their service and become Credential Issuers.
It also allows new applications built using Verifiable Credentials to utilize OAuth 2.0 as integration and
interoperability layer. This package provides holder/wallet support to interact with OpenID4VCI capable Issuer systems.

# Flows

The spec lists 2 flows. Currently only one is supported!

## Authorized Code Flow

This flow isn't supported yet!

## Pre-authorized Code Flow

The pre-authorized code flow assumes the user is using an out-of-band mechanism outside the issuance flow to
authenticate first.

The below diagram shows the steps involved in the pre-authorized code flow. Note that wallet inner functionalities (like
saving VCs) are out of scope for this library.

![Flow diagram](https://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/Sphereon-Opensource/OID4VCI-client/develop/docs/preauthorized-code-flow.puml)

# OpenID4VCI Client

The OpenID4VCI client is the main client you typically will want to use. It combines several lower level classes into a
client you can use to finish the pre-authorized code flows.

## Initiating the client

This initiates the client using a URI obtained from the Issuer using a link (URL) or QR code typically. We are also
already fetching the Server Metadata

```typescript
import { OpenID4VCIClient } from '@sphereon/oid4vci-client';

// The client is initiated from a URI. This URI is provided by the Issuer, typically as a URL or QR code.
const client = await OpenID4VCIClient.fromURI({
  uri: 'openid-initiate-issuance://?issuer=https%3A%2F%2Fissuer.research.identiproof.io&credential_type=OpenBadgeCredentialUrl&pre-authorized_code=4jLs9xZHEfqcoow0kHE7d1a8hUk6Sy-5bVSV2MqBUGUgiFFQi-ImL62T-FmLIo8hKA1UdMPH0lM1xAgcFkJfxIw9L-lI3mVs0hRT8YVwsEM1ma6N3wzuCdwtMU4bcwKp&user_pin_required=true',
  kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21#key-1', // Our DID.  You can defer this also to when the acquireCredential method is called
  alg: Alg.ES256, // The signing Algorithm we will use. You can defer this also to when the acquireCredential method is called
  clientId: 'test-clientId', // The clientId if the Authrozation Service requires it.  If a clientId is needed you can defer this also to when the acquireAccessToken method is called
  retrieveServerMetadata: true, // Already retrieve the server metadata. Can also be done afterwards by invoking a method yourself.
});

console.log(client.getIssuer()); // https://issuer.research.identiproof.io
console.log(client.getCredentialEndpoint()); // https://issuer.research.identiproof.io/credential
console.log(client.getAccessTokenEndpoint()); // https://auth.research.identiproof.io/oauth2/token
```

## Server metadata

The OID4VCI Server metadata contains information about token endpoints, credential endpoints, as well as additional
information about supported Credentials, and their cryptographic suites and formats.
The code above already retrieved the metadata, so it will not be fetched again, and this method places the data in another variable. If you however have not used
the `retrieveServerMetadata` option, you can use this method to fetch it from the Issuer:

```typescript
const metadata = await client.retrieveServerMetadata();
```

## Access token from Authorization Server

Next we need to get an Access token from the OAuth2 Authorization Server using the token endpoint. This endpoint is
found from the metadata if the server supports it. Otherwise a default location based on the issuer value from the
Initiate Issuance Request is used.

```typescript
const accessToken = await client.acquireAccessToken({ pin: '1234' });
console.log(accessToken);
/**
 * {
 *   access_token: 'ey6546.546654.64565',
 *   authorization_pending: false,
 *   c_nonce: 'c_nonce2022101300',
 *   c_nonce_expires_in: 2025101300,
 *   interval: 2025101300,
 *   token_type: 'Bearer',
 * }
 */
```

## Getting the credential

Now it is time to get the credential. In order to achieve this, we will be using the metadata together with the access
token, but first we will have to create a so-called Proof of Possession. Please see
the [Proof of Posession](#proof-of-possession) chapter for more information.

The Proof of Possession using a signature callback function. The example uses the `jose` library.

```typescript
import * as jose from 'jose';
import { DIDDocument } from 'did-resolver';

const { privateKey, publicKey } = await jose.generateKeyPair('ES256');

// Must be JWS
async function signCallback(args: Jwt, kid: string): Promise<string> {
  return await new jose.SignJWT({ ...args.payload })
    .setProtectedHeader({ alg: args.header.alg })
    .setIssuedAt()
    .setIssuer(kid)
    .setAudience(args.payload.aud)
    .setExpirationTime('2h')
    .sign(privateKey);
}

const callbacks: ProofOfPossessionCallbacks<DIDDocument> = {
  signCallback,
};
```

Now it is time to get the actual credential

```typescript
const credentialResponse = await client.acquireCredentials({
  credentialTypes: 'OpenBadgeCredential',
  proofCallbacks: callbacks,
  format: 'jwt_vc_json',
  alg: Alg.ES256K,
  kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21#keys-1',
});
console.log(credentialResponse.credential);
// JWT format. (LDP / JSON-LD ('ldp_vc' / 'jwt_vc_json-ld') is also supported by the client)
// eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sImlkIjoiaHR0cDovL2V4YW1wbGUuZWR1L2NyZWRlbnRpYWxzLzM3MzIiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVW5pdmVyc2l0eURlZ3JlZUNyZWRlbnRpYWwiXSwiaXNzdWVyIjoiaHR0cHM6Ly9leGFtcGxlLmVkdS9pc3N1ZXJzLzU2NTA0OSIsImlzc3VhbmNlRGF0ZSI6IjIwMTAtMDEtMDFUMDA6MDA6MDBaIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEiLCJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMifX19LCJpc3MiOiJodHRwczovL2V4YW1wbGUuZWR1L2lzc3VlcnMvNTY1MDQ5IiwibmJmIjoxMjYyMzA0MDAwLCJqdGkiOiJodHRwOi8vZXhhbXBsZS5lZHUvY3JlZGVudGlhbHMvMzczMiIsInN1YiI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMSJ9.z5vgMTK1nfizNCg5N-niCOL3WUIAL7nXy-nGhDZYO_-PNGeE-0djCpWAMH8fD8eWSID5PfkPBYkx_dfLJnQ7NA
```

# Using individual classes and methods instead of the client

Instead of using the OpenID4VCI Client, you can also use the separate classes if you want. This typically gives you a
bit more control and options, at the expense of a bit more complexity.

## Issuance Initiation

Issuance is started from a so-called Issuance Initiation Request by the Issuer. This typically is URI, exposed
as a link or a QR code. You can call the `CredentialOffer.fromURI(uri)` method to parse the URI into a Json object
containing the baseUrl and a `uri` JSON object

```typescript
import { CredentialOffer } from '@sphereon/oid4vci-client';

const initiationURI =
  'https://issuer.example.com?issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FdriverLicense&op_state=eyJhbGciOiJSU0Et...FYUaBy';

const initiationRequestWithUrl = CredentialOffer.fromURI(initiationURI);
console.log(initiationRequestWithUrl);

/**
 * {
 *    "baseUrl": "https://server.example.com",
 *    "request": {
 *      "credential_type": [
 *        "https://did.example.org/healthCard",
 *        "https://did.example.org/driverLicense"
 *      ],
 *      "issuer": "https://server.example.com",
 *      "op_state": "eyJhbGciOiJSU0Et...FYUaBy"
 *    },
 *   "version": 9
 * }
 */
```

## Getting OpenID4VCI Server and OIDC/OAuth2 metadata

The OpenID4VCI spec defines a server metadata object that contains information about the issuer and the credentials they
support. Next to this predefined endpoint there are also the well-known locations for OpenID Connect Discovery
configuration and
Oauth2 Authorization Server configuration. These contain for instance the token endpoints.
The MetadataClient checks the OpenID4VCI well-known location for the medata and existence of a token endpoint. If the
OpenID4VCI well-known location is not found, the OIDC/OAuth2 well-known locations will be tried:

Example:

```typescript
import { MetadataClient } from '@sphereon/oid4vci-client';

const metadata = await MetadataClient.retrieveAllMetadataFromCredentialOffer(initiationRequestWithUrl);

console.log(metadata);
/**
 * {
 *  issuer: 'https://server.example.com',
 *  credential_endpoint: 'https://server.example.com/credential',
 *  token_endpoint: 'https://server.example.com/token',
 *  jwks_uri: 'https://server.example.com/jwks',
 *  grant_types_supported: ['urn:ietf:params:oauth:grant-type:pre-authorized_code'],
 *  credentials_supported: {
 *   OpenBadgeCredential: {
 *     formats: {
 *       jwt_vc: {
 *         types: [
 *           'https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential',
 *           'https://w3id.org/ngi/OpenBadgeExtendedCredential',
 *         ],
 *         binding_methods_supported: ['did'],
 *         cryptographic_suites_supported: ['ES256'],
 *       },
 *     },
 *   },
 *  },
 * }
 */
```

## Acquiring the Access Token

Now you will need to get an access token from the oAuth2 Authorization Server (AS), using some values from
the `IssuanceInitiationRequestPayloadV9` payload.
For now, you can use the issuer hostname for the AS, as there is no way to know the AS from the Issuance Initiation for
known until the
following [OpenID Ticket](https://bitbucket.org/openid/connect/issues/1632/issuer-metadata-clarification-needed) is
resolved. So the token endpoint would become https://<issuer-hostname>/token.
The library allows to pass in a different value for the AS token endpoint as well, so you already can use a different AS
if you know the AS upfront. If no AS is provided the issuer value from the Issuance Initiation Request will be used.

```typescript
import { AccessTokenClient, AuthorizationServerOpts } from '@sphereon/oid4vci-client';

const clientId = 'abcd'; // This can be a random value or a clientId assigned by the Authorization Server (depends on the environment)
const pin = 1234; // A pincode which is shown out of band typically. Only use when the pin-code is required from the Issuance Initiation object.

// Allows to override the Authorization Server and provide other AS options. By default the issuer value will be used
const asOpts: AuthorizationServerOpts = {
  clientId,
};

const accessTokenResponse = AccessTokenClient.acquireAccessTokenUsingRequest({
  credentialOffer,
  asOpts,
  pin,
  metadata,
});
console.log(accessTokenResponse);
/**
 * {
 *      access_token: "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ"
 *      token_type: "bearer",
 *      expires_in: 86400
 * }
 */
```

# Proof of Possession

Part of OpenID4VCI is the holder showing that they are in possession of a certain key, associated with the DID that will
be the subject of the to be issued Verifiable Credential.
This proof of possession will be created using a DID, it's associated keypair and the `ProofOfPossessionBuilder` class.
This Builder can be initiated from a JWT object if you want to create a JWT yourself, or it can be build using the
Initiate Issuance Request, Server metadata and some methods from the builder. Both approaches need a callback function
to sign the JWT and optionally a callback to verify the JWT.
The signature of the callback functions you need to implement are:

```typescript
export type JWTSignerCallback = (jwt: Jwt, kid: string) => Promise<string>;
export type JWTVerifyCallback = (args: { jwt: string; kid: string }) => Promise<void>;
```

This is an example of the signature callback function created using the `jose` library.

```typescript
import { Jwt } from '@sphereon/oid4vci-client';

const { privateKey, publicKey } = await jose.generateKeyPair('ES256');

// Must be JWS
async function signCallback(args: Jwt, kid: string): Promise<string> {
  return await new jose.SignJWT({ ...args.payload })
    .setProtectedHeader({ alg: args.header.alg })
    .setIssuedAt()
    .setIssuer(kid)
    .setAudience(args.payload.aud)
    .setExpirationTime('2h')
    .sign(keypair.privateKey);
}
```

Alongside signing, you can optionally provide another callback function for verifying the created signature with
populating `verifyCallback`. The method is expected to throw errors in case problems with the JWT or it's signature are
found.
below is an example of such method. This example (like the previous one) uses `jose` to verify the jwt.

```typescript
async function verifyCallback(args: { jwt: string; kid: string }): Promise<void> {
  await jose.compactVerify(args.jwt, keypair.publicKey);
}
```

Some important interface around Proof of Possession:

```typescript
export enum Alg {
  EdDSA = 'EdDSA',
  ES256 = 'ES256',
  ES256K = 'ES256K',
}

export interface JWTHeader {
  alg: Alg; // REQUIRED by the JWT signer
  typ?: string; //JWT always
  kid?: string; // CONDITIONAL. JWT header containing the key ID. If the Credential shall be bound to a DID, the kid refers to a DID URL which identifies a particular key in the DID Document that the Credential shall be bound to. MUST NOT be present if jwk or x5c is present.
  jwk?: JWK; // CONDITIONAL. JWT header containing the key material the new Credential shall be bound to. MUST NOT be present if kid or x5c is present.
  x5c?: string[]; // CONDITIONAL. JWT header containing a certificate or certificate chain corresponding to the key used to sign the JWT. This element may be used to convey a key attestation. In such a case, the actual key certificate will contain attributes related to the key properties. MUST NOT be present if kid or jwk is present.
}

export interface JWTPayload {
  iss?: string; // REQUIRED (string). The value of this claim MUST be the client_id of the client making the credential request.
  aud?: string; // REQUIRED (string). The value of this claim MUST be the issuer URL of credential issuer.
  iat?: number; // REQUIRED (number). The value of this claim MUST be the time at which the proof was issued using the syntax defined in [RFC7519].
  nonce?: string; // REQUIRED (string). The value type of this claim MUST be a string, where the value is a c_nonce provided by the credential issuer. //TODO: Marked as required not present in NGI flow
  jti?: string; // A new nonce chosen by the wallet. Used to prevent replay
  exp?: number; // Not longer than 5 minutes
}

export interface Jwt {
  header?: JWTHeader;
  payload?: JWTPayload;
}
```

The arguments requested by `jose` and `@sphereon/oid4vci-client`

```typescript
import { Jwt, ProofOfPossessionCallbacks } from '@sphereon/oid4vci-client';

const callbacks: ProofOfPossessionCallbacks = {
  signCallback,
  verifyCallback,
};

const keyPair = await jose.generateKeyPair('ES256');
```

### Using the builder from metadata and access token response

Normally you would use the Proof of Possession builder using the server metadata and access token response together with
the callbacks. There is however the possibility to use a JWT directly, which will be explained in the next section.

```typescript
import { ProofOfPossessionBuilder } from '@sphereon/oid4vci-client';

const proofInput: ProofOfPossession = await ProofOfPossessionBuilder.fromAccessTokenResponse({
  accessTokenResponse,
  callbacks,
})
  .withEndpointMetadata(metadata)
  .withClientId('s6BhdRkqt3')
  .withKid('did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1')
  .build();
console.log(proofInput);
// {
//   "proof_type": "jwt",
//   "jwt": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMS9rZXlzLzEifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE2NTkxNDU5MjQsIm5vbmNlIjoidFppZ25zbkZicCJ9.btetOcsJ_VOePkwlFf2kyxm6hEUvPRimf3M-Dn3Lmzcmt5QiPToXNWxe_0fEJlRf4Ith55YGB43ScBe6ScZmD1gfLELYQF7LLg97yYlx_Iu8RLA2dS_7EWzLD3ZIzyUGf_uMq3HwXGJKL-ihroRpRBvxRLdZCy-j62nAzoTsBnlr6n79VjkGtlxIjN_CLGIQBhc3du3enghY6N4s3oXFrxWMl7UzGKdjCYN6vSagDb0MURjdiDCsK_yX4NyNd0nGpxqGhVgMpuhqEcqyU0qWPyHF-swtGG5JVAOJGd_YkJS5vbia8UdyOJXnAAdEE1E62a2yUPahNDxMh1iIpS0WO7y6QexWXdb5fmnWDst89T3ELS8Hj2Vzsw1XPyk9XR9JmiDzmEZdH05Wf4M9pXUG4-8_7StB6Lxc7_xDJdk6JPbzFgAIhJa4F_3rfPuwMseSEQvD6bDFowkIiUpt1vXGGVjVm3N4I4Th4_A2QpW4mDzcTKoZq9MKlDGXeLQBtiKXmqs10Jvzpp3O7kBwH7Qm6VUdBxk_-wsWplUZC4IvCfv23hy2SyFnh5zC6Wtw3UcbrSH6LcD7g-RNTKe4fRekyDxqLRdEm60BOozgBoTNhnetCrQ3e7HrApj9EP0vqNyXdtGGWCA011HVDnz6lVzf5yijJB8hOPpkgYGRmHdRQwI"
// }
```

### Using the builder with a self-created JWT

You can build/create a JWT yourself. You would still use the callbacks to sign the JWT. Please be aware that you will
have to use the `c_nonce` value from the Access Token response as `nonce` value!. You can provide another nonce using
the `jti` property.

```typescript
import { Jwt, ProofOfPossessionBuilder, ProofOfPossessionCallbacks } from '@sphereon/oid4vci-client';

const callbacks: ProofOfPossessionCallbacks = {
  signCallback,
  verifyCallback,
};

const keyPair = await jose.generateKeyPair('ES256');

// If you directly want to use a JWT, instead of using method on the ProofOfPossessionBuilder you can create JWT:
const jwt: Jwt = {
  header: { alg: Alg.ES256, kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21#1', typ: Typ.JWT },
  payload: { iss: 's6BhdRkqt3', nonce: 'tZignsnFbp', jti: 'tZignsnFbp223', aud: 'https://issuer.example.com' },
};

const proofInput: ProofOfPossession = await ProofOfPossessionBuilder.fromJwt({
  jwt,
  callbacks,
}).build();
console.log(proofInput);
// {
//   "proof_type": "jwt",
//   "jwt": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMS9rZXlzLzEifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE2NTkxNDU5MjQsIm5vbmNlIjoidFppZ25zbkZicCJ9.btetOcsJ_VOePkwlFf2kyxm6hEUvPRimf3M-Dn3Lmzcmt5QiPToXNWxe_0fEJlRf4Ith55YGB43ScBe6ScZmD1gfLELYQF7LLg97yYlx_Iu8RLA2dS_7EWzLD3ZIzyUGf_uMq3HwXGJKL-ihroRpRBvxRLdZCy-j62nAzoTsBnlr6n79VjkGtlxIjN_CLGIQBhc3du3enghY6N4s3oXFrxWMl7UzGKdjCYN6vSagDb0MURjdiDCsK_yX4NyNd0nGpxqGhVgMpuhqEcqyU0qWPyHF-swtGG5JVAOJGd_YkJS5vbia8UdyOJXnAAdEE1E62a2yUPahNDxMh1iIpS0WO7y6QexWXdb5fmnWDst89T3ELS8Hj2Vzsw1XPyk9XR9JmiDzmEZdH05Wf4M9pXUG4-8_7StB6Lxc7_xDJdk6JPbzFgAIhJa4F_3rfPuwMseSEQvD6bDFowkIiUpt1vXGGVjVm3N4I4Th4_A2QpW4mDzcTKoZq9MKlDGXeLQBtiKXmqs10Jvzpp3O7kBwH7Qm6VUdBxk_-wsWplUZC4IvCfv23hy2SyFnh5zC6Wtw3UcbrSH6LcD7g-RNTKe4fRekyDxqLRdEm60BOozgBoTNhnetCrQ3e7HrApj9EP0vqNyXdtGGWCA011HVDnz6lVzf5yijJB8hOPpkgYGRmHdRQwI"
// }
```

## Credential Issuance

Now it is time to request the actual Credential(s) from the Issuer. The example uses a DID:JWK. The DID:JWK should match
the keypair created earlier.

```typescript
import { CredentialRequestClientBuilder, CredentialResponse, ProofOfPossessionArgs } from '@sphereon/oid4vci-client';

const credentialRequestClient = CredentialRequestClientBuilder.fromCredentialOfferRequest(initiationRequestWithUrl, metadata).build();

// In 1 step:
const credentialResponse: CredentialResponse = await credentialRequestClient.acquireCredentialsUsingProof({
  proofInput,
  credentialType: 'OpenBadgeCredential', // Needs to match a type from the Initiate Issance Request!
  format: 'jwt_vc', // Allows us to override the format
});

// Or in 2 steps:
// const credentialRequest: CredentialRequest = await credentialRequestClient.createCredentialRequest(proofOpts, { format: 'jwt_vc' }) // Allows us to override the format
// const credentialResponse: CredentialResponse = await credentialRequestClient.acquireCredentialsUsingRequest(credentialRequest)
```

# Helper Functions

Several utility functions are available

## convertJsonToURI:

Converts a Json object or string into an URI:

```typescript
import { convertJsonToURI } from '@sphereon/oid4vci-client';

const encodedURI = convertJsonToURI(
  {
    issuer: 'https://server.example.com',
    credential_type: ['https://did.example.org/healthCard', 'https://did.example1.org/driverLicense'],
    op_state: 'eyJhbGciOiJSU0Et...FYUaBy',
  },
  {
    arrayTypeProperties: ['credential_type'],
    urlTypeProperties: ['issuer', 'credential_type'],
  },
);
console.log(encodedURI);
// issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FdriverLicense&op_state=eyJhbGciOiJSU0Et...FYUaBy
```

## convertURIToJsonObject:

Converts a URI into a Json object with URL decoded properties. Allows to provide which potential duplicate keys need to
be converted into an array.

```typescript
import { convertURIToJsonObject } from '@sphereon/oid4vci-client';

const decodedJson = convertURIToJsonObject(
  'issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FdriverLicense&op_state=eyJhbGciOiJSU0Et...FYUaBy',
  {
    arrayTypeProperties: ['credential_type'],
    requiredProperties: ['issuer', 'credential_type'],
  },
);
console.log(decodedJson);
// {
//   issuer: 'https://server.example.com',
//   credential_type: ['https://did.example.org/healthCard', 'https://did.example1.org/driverLicense'],
//   op_state: 'eyJhbGciOiJSU0Et...FYUaBy'
// }
```

## determineSpecVersionFromURI(uri: string): OpenId4VCIVersion

```typescript
const CREDENTIAL_OFFER_URI =
  'openid-credential-offer://?' +
  'credential_offer=%7B%22credential_issuer%22:%22https://credential-issuer.example.com%22,%22credentials%22:%5B%7B%22format%22:%22jwt_vc_json%22,%22types%22:%5B%22VerifiableCredential%22,%22UniversityDegreeCredential%22%5D%7D%5D,%22issuer_state%22:%22eyJhbGciOiJSU0Et...FYUaBy%22%7D';

const openId4VCIVersion = determineSpecVersionFromURI(CREDENTIAL_OFFER_URI);
console.log(openId4VCIVersion);

/**
 * 11
 */
```
