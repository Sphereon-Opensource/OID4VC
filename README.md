<h1 align="center">
  <br>
  <a href="https://www.sphereon.com"><img src="https://sphereon.com/content/themes/sphereon/assets/img/logo.svg" alt="Sphereon" width="400"></a>
    <br>OpenID for Verifiable Credential Issuance - Client 
  <br>
</h1>

_IMPORTANT it still in development and it's not fully functional_

### Background 

A client to request and receive Verifiable Credentials using Oidc4vci

This library is based on [openid-4-verifiable-credential-issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) for requesting Verifiable Credentials.

### Flow
#### Pre-authorized Code Flow
The below diagram shows the steps involved in this flow. Note that wallet inner functionalities (like saving VCs) are out of scope of this library. Also This library doesn't involve any functionalities of a VC Issuer
![Flow diagram](https://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/Sphereon-Opensource/OIDC4VCI-client/develop/docs/preauthorized-code-flow.puml)

### Interfaces

```typescript
export interface IssuanceInitiationRequestParams {
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

```typescript
export function encodeJsonAsURI(json: IssuanceInitiationRequestPayload[] | IssuanceInitiationRequestPayload) {
  if (!Array.isArray(json)) {
    return encodeJsonObjectAsURI(json);
  }
  return json.map((j) => encodeJsonObjectAsURI(j)).join('&');
}

function encodeJsonObjectAsURI(json: IssuanceInitiationRequestPayload) {
  if (typeof json === 'string') {
    return encodeJsonObjectAsURI(JSON.parse(json));
  }

  const results = [];

  function encodeAndStripWhitespace(key: string) {
    return encodeURIComponent(key.replace(' ', ''));
  }

  for (const [key, value] of Object.entries(json)) {
    if (!value) {
      continue;
    }
    const isBool = typeof value == 'boolean';
    const isNumber = typeof value == 'number';
    const isString = typeof value == 'string';
    let encoded;
    if (isBool || isNumber) {
      encoded = `${encodeAndStripWhitespace(key)}=${value}`;
    } else if (isString) {
      encoded = `${encodeAndStripWhitespace(key)}=${encodeURIComponent(value)}`;
    } else {
      encoded = `${encodeAndStripWhitespace(key)}=${encodeURIComponent(JSON.stringify(value))}`;
    }
    results.push(encoded);
  }
  return results.join('&');
}
```

#### Usage

```typescript
const encodedURI = encodeJsonAsURI([
    {
      issuer: 'https://server.example.com',
      credential_type: 'https://did.example.org/healthCard',
      op_state: 'eyJhbGciOiJSU0Et...FYUaBy'
    },
    {
      issuer: 'https://server.example1.com',
      credential_type: 'https://did.example1.org/healthCard',
      op_state: 'eyJhbGciOiJSU0Et...FYUaBy'
    }

    //  console.log(encodedURI)
    // 'issuer=https%3A%2F%2Fserver.example.com&credential_type=https%3A%2F%2Fdid.example.org%2FhealthCard&op_state=eyJhbGciOiJSU0Et...FYUaBy&issuer=https%3A%2F%2Fserver.example1.com&credential_type=https%3A%2F%2Fdid.example1.org%2FhealthCard&op_state=eyJhbGciOiJSU0Et...FYUaBy'
```

* NOTE: The input may be a single object or an array

```typescript
export function decodeUriAsJson(uri: string) {
  if (!uri || !uri.includes('issuer') || !uri.includes('credential_type')) {
    throw new Error(BAD_PARAMS);
  }
  const parts = new URLSearchParams(uri);
  const entries = Array.from(parts.entries());
  const jsonArray = [];
  let json: unknown = {};
  for (const [key, value] of entries) {
    if (Object.prototype.hasOwnProperty.call(json, key)) {
      jsonArray.push(json);
      json = {};
    }
    json[key] = value;
  }
  jsonArray.push(json);
  const result = jsonArray.map((o) => decodeJsonProperty(o));
  return result.length < 2 ? result[0] : result;
}
```

#### Usage

```typescript
const decodedJson = decodeUriAsJson('issuer=https%253A%252F%252Fserver%252Eexample%252Ecom&credential_type=https%253A%252F%252Fdid%252Eexample%252Eorg%252FhealthCard&op_state=eyJhbGciOiJSU0Et...FYUaBy&issuer=https%253A%252F%252Fserver%252Eexample1%252Ecom&credential_type=https%253A%252F%252Fdid%252Eexample1%252Eorg%252FhealthCard&op_state=eyJhbGciOiJSU0Et...FYUaBy')
// console.log(decodedJson)
// [
//     {
//       issuer: 'https://server.example.com',
//           credential_type: 'https://did.example.org/healthCard',
//         op_state: 'eyJhbGciOiJSU0Et...FYUaBy'
//     },
//     {
//       issuer: 'https://server.example1.com',
//           credential_type: 'https://did.example1.org/healthCard',
//         op_state: 'eyJhbGciOiJSU0Et...FYUaBy'
//     },
// ]
```
* NOTE: The input may contain duplicated keys, that will result in an array
