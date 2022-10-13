<h1 align="center">
  <br>
  <a href="https://www.sphereon.com"><img src="https://sphereon.com/content/themes/sphereon/assets/img/logo.svg" alt="Sphereon" width="400"></a>
    <br>OIDC4VCI-CLIENT 
    <br>A client to request and receive Verifiable Credentials using Oidc4vci
  <br>
</h1>

_IMPORTANT it still in development and it's not fully functional_

### Interfaces

```typescript
export interface IssuanceInitiationRequestPayload {
  issuer: string, //REQUIRED The issuer URL of the Credential issuer, the Wallet is requested to obtain one or more Credentials from.
  credential_type: string[], //REQUIRED A JSON string denoting the type of the Credential the Wallet shall request
  pre_authorized_code?: string, //CONDITIONAL The code representing the issuer's authorization for the Wallet to obtain Credentials of a certain type. This code MUST be short lived and single-use. MUST be present in a pre-authorized code flow.
  user_pin_required?: boolean, //OPTIONAL Boolean value specifying whether the issuer expects presentation of a user PIN along with the Token Request in a pre-authorized code flow. Default is false.
  op_state?: string //OPTIONAL String value created by the Credential Issuer and opaque to the Wallet that is used to bind the sub-sequent authentication request with the Credential Issuer to a context set up during previous steps
}
```

### Functions

### Usage

#### encodeJsonAsURI:

Encodes a Json object created based on `IssuanceInitiationRequestPayload` interface into an URI:

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
const decodedJson = decodeJsonAsURI('issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FdriverLicense&op_state=eyJhbGciOiJSU0Et...FYUaBy', 
    {
      duplicatedProperties: ['credential_type'],
      requiredProperties: ['issuer', 'credential_type']
    })
// console.log(decodedJson)
// {
//   issuer: 'https://server.example.com',
//       credential_type: ['https://did.example.org/healthCard', 'https://did.example1.org/driverLicense'],
//     op_state: 'eyJhbGciOiJSU0Et...FYUaBy'
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

#### customEncodeURIComponent

Encodes chars that are not encoded by default

```typescript
const encodedURI = customEncodeURIComponent('https://server.example.com', /\./g);
console.log(encodedURI)
// 'https%253A%252F%252Fserver%252Eexample%252Ecom'
```