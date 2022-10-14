<h1 align="center">
  <br>
  <a href="https://www.sphereon.com"><img src="https://sphereon.com/content/themes/sphereon/assets/img/logo.svg" alt="Sphereon" width="400"></a>
    <br>OpenID for Verifiable Credential Issuance - Client 
  <br>
</h1>

_IMPORTANT it still in development and it's not fully functional_

### Background 

A client to request and receive Verifiable Credentials using OID4VCI.

This library is based on [openid-4-verifiable-credential-issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) for requesting Verifiable Credentials.

### Flow
#### Pre-authorized Code Flow
The below diagram shows the steps involved in this flow. Note that wallet inner functionalities (like saving VCs) are out of scope of this library. Also This library doesn't involve any functionalities of a VC Issuer
![Flow diagram](https://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/Sphereon-Opensource/OIDC4VCI-client/develop/docs/preauthorized-code-flow.puml)

### Interfaces

```typescript
export interface IssuanceInitiationRequestPayload {
  issuer: string, //REQUIRED The issuer URL of the Credential issuer, the Wallet is requested to obtain one or more Credentials from.
  credential_type: string[] | string, //REQUIRED A JSON string denoting the type of the Credential the Wallet shall request
  pre_authorized_code?: string, //CONDITIONAL The code representing the issuer's authorization for the Wallet to obtain Credentials of a certain type. This code MUST be short lived and single-use. MUST be present in a pre-authorized code flow.
  user_pin_required?: boolean, //OPTIONAL Boolean value specifying whether the issuer expects presentation of a user PIN along with the Token Request in a pre-authorized code flow. Default is false.
  op_state?: string //OPTIONAL String value created by the Credential Issuer and opaque to the Wallet that is used to bind the sub-sequent authentication request with the Credential Issuer to a context set up during previous steps
}

export interface CredentialRequest {
  type: string | string[];
  format: CredentialFormat | CredentialFormat[];
  proof: ProofOfPossession;
}

export interface CredentialResponse {
  credential: W3CVerifiableCredential;
  format: CredentialFormat;
}

export interface CredentialResponseError {
  error: CredentialResponseErrorCode;
  error_description?: string;
  error_uri?: string;
}
```

### Functions

### Usage

#### encodeJsonAsURI:

Encodes a Json object created based on `IssuanceInitiationRequestPayload` interface into an URI:

```typescript
const encodedUri = encodeJsonAsURI({
      issuer: 'https://server.example.com',
      credential_type: 'https://did.example.org/healthCard',
      op_state: 'eyJhbGciOiJSU0Et...FYUaBy'
    }, {
      urlTypeProperties: ['issuer', 'credential_type']
    })
console.log(encodedUri)
// issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&op_state=eyJhbGciOiJSU0Et...FYUaBy
```

```typescript
const encodedURI = encodeJsonAsURI(
    {
      issuer: 'https://server.example.com',
      credential_type: ['https://did.example.org/healthCard', 'https://did.example1.org/driverLicense'],
      op_state: 'eyJhbGciOiJSU0Et...FYUaBy'
    },
    {
      arrayTypeProperties: ['credential_type'],
      urlTypeProperties: ['issuer', 'credential_type']
    })
console.log(encodedURI)
// issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FdriverLicense&op_state=eyJhbGciOiJSU0Et...FYUaBy
```

#### decodeURIAsJson:

Decodes URI into a Json object:

```typescript
const decodedJson = decodeURIAsJson('issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&op_state=eyJhbGciOiJSU0Et...FYUaBy', {
  duplicatedProperties: ['credential_type'],
  requiredProperties: ['issuer', 'credential_type']
})
console.log(decodedJson)
// console.log(decodedURI)
// {
//   issuer: 'https://server.example.com',
//   credential_type: 'https://did.example.org/healthCard',
//   op_state: 'eyJhbGciOiJSU0Et...FYUaBy'
// }
```

```typescript
const decodedJson = decodeJsonAsURI('issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FdriverLicense&op_state=eyJhbGciOiJSU0Et...FYUaBy', 
    {
      duplicatedProperties: ['credential_type'],
      requiredProperties: ['issuer', 'credential_type']
    })
// console.log(decodedJson)
// {
//   issuer: 'https://server.example.com',
//   credential_type: ['https://did.example.org/healthCard', 'https://did.example1.org/driverLicense'],
//   op_state: 'eyJhbGciOiJSU0Et...FYUaBy'
// }
```

#### parseURI:

Parses the URI without decoding it

```typescript
 const parsedURI = parseURI('issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FdriverLicense&op_state=eyJhbGciOiJSU0Et...FYUaBy')
 console.log(parsedURI)
// {
//   "issuer": "https%3A%2F%2Fserver%2Eexample%2Ecom", 
//   "credential_type": [
//     "https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard",
//     "https%3A%2F%2Fdid%2Eexample%2Eorg%2FdriverLicense"
//   ],
//   "op_state": "eyJhbGciOiJSU0Et...FYUaBy"
// }
```
* NOTE: The input may contain duplicated keys, that will result in an array

#### customEncodeURIComponent

Encodes chars that are not encoded by default

```typescript
const encodedURI = customEncodeURIComponent('https://server.example.com', /\./g);
console.log(encodedURI)
// 'https%253A%252F%252Fserver%252Eexample%252Ecom'
```
#### createProofOfPossession

Creates the ProofOfPossession object and JWT signature

The callback function created using `jose`

```typescript
// Must be JWS
const signJWT = async (args: JWTSignerArgs): Promise<string> => {
  const { header, payload, keyPair } = args
  return await new jose.CompactSign(u8a.fromString(JSON.stringify({ ...payload })))
  // Only ES256 and EdDSA are supported
  .setProtectedHeader({ ...header, alg: args.header.alg })
  .sign(keyPair.privateKey)
}
```

```typescript
const verifyJWT = async (args: { jws: string | Uint8Array, key: KeyLike | Uint8Array, options?: VerifyOptions }): Promise<void> => {
  // Throws an exception if JWT is not valid
  await jose.compactVerify(args.jws, args.key, args.options)
}
```

The arguments requested by `jose` and `oidc4vci`

```typescript
const keyPair = await jose.generateKeyPair("ES256")

const jwtArgs: JWTSignerArgs = {
  header: {
    alg: "ES256",
    kid: "did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1"
  },
  payload: {
    iss: "s6BhdRkqt3",
    aud: "https://server.example.com",
    iat: 1659145924,
    nonce: "tZignsnFbp"
  },
  privateKey: keyPair.privateKey,
  publicKey: keyPair.publicKey
}
```

The actual method call

```typescript
const proof: ProofOfPossession = await vcIssuanceClient.createProofOfPossession({
      jwtSignerArgs: jwtArgs,
      jwtSignerCallback: (args) => signJWT(args),
      jwtVerifyCallback: (args) => verifyJWT(args)
    })
console.log(proof)
// {
//   "proof_type": "jwt",
//     "jwt": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMS9rZXlzLzEifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE2NTkxNDU5MjQsIm5vbmNlIjoidFppZ25zbkZicCJ9.btetOcsJ_VOePkwlFf2kyxm6hEUvPRimf3M-Dn3Lmzcmt5QiPToXNWxe_0fEJlRf4Ith55YGB43ScBe6ScZmD1gfLELYQF7LLg97yYlx_Iu8RLA2dS_7EWzLD3ZIzyUGf_uMq3HwXGJKL-ihroRpRBvxRLdZCy-j62nAzoTsBnlr6n79VjkGtlxIjN_CLGIQBhc3du3enghY6N4s3oXFrxWMl7UzGKdjCYN6vSagDb0MURjdiDCsK_yX4NyNd0nGpxqGhVgMpuhqEcqyU0qWPyHF-swtGG5JVAOJGd_YkJS5vbia8UdyOJXnAAdEE1E62a2yUPahNDxMh1iIpS0WO7y6QexWXdb5fmnWDst89T3ELS8Hj2Vzsw1XPyk9XR9JmiDzmEZdH05Wf4M9pXUG4-8_7StB6Lxc7_xDJdk6JPbzFgAIhJa4F_3rfPuwMseSEQvD6bDFowkIiUpt1vXGGVjVm3N4I4Th4_A2QpW4mDzcTKoZq9MKlDGXeLQBtiKXmqs10Jvzpp3O7kBwH7Qm6VUdBxk_-wsWplUZC4IvCfv23hy2SyFnh5zC6Wtw3UcbrSH6LcD7g-RNTKe4fRekyDxqLRdEm60BOozgBoTNhnetCrQ3e7HrApj9EP0vqNyXdtGGWCA011HVDnz6lVzf5yijJB8hOPpkgYGRmHdRQwI"
// }
```