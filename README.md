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
  credential_type: string[] | string, //REQUIRED A JSON string denoting the type of the Credential the Wallet shall request
  pre_authorized_code?: string, //CONDITIONAL The code representing the issuer's authorization for the Wallet to obtain Credentials of a certain type. This code MUST be short lived and single-use. MUST be present in a pre-authorized code flow.
  user_pin_required?: boolean, //OPTIONAL Boolean value specifying whether the issuer expects presentation of a user PIN along with the Token Request in a pre-authorized code flow. Default is false.
  op_state?: string //OPTIONAL String value created by the Credential Issuer and opaque to the Wallet that is used to bind the sub-sequent authentication request with the Credential Issuer to a context set up during previous steps
}
```

### Functions

### Usage

```typescript
const encodedURI = encodeJsonAsURI({
  issuer: 'https://server.example.com',
  credential_type: 'https://did.example.org/healthCard',
  op_state: 'eyJhbGciOiJSU0Et...FYUaBy'
})
console.log(encodedURI)
// issuer=https%253A%252F%252Fserver%252Eexample%252Ecom&credential_type=https%253A%252F%252Fdid%252Eexample%252Eorg%252FhealthCard&op_state=eyJhbGciOiJSU0Et...FYUaBy
```

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
    },
    ])
console.log(encodedURI)
// issuer=https%253A%252F%252Fserver%252Eexample%252Ecom&credential_type=https%253A%252F%252Fdid%252Eexample%252Eorg%252FhealthCard&op_state=eyJhbGciOiJSU0Et...FYUaBy&issuer=https%253A%252F%252Fserver%252Eexample%252Ecom&credential_type=https%253A%252F%252Fdid%252Eexample%252Eorg%252FhealthCard&op_state=eyJhbGciOiJSU0Et...FYUaBy
```

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
