# Creating a credential offer

Please see the below payload descriptions to create a credential offer. Both pre-authorized code grants as well as authorization-code grants are
supported.
You provide these in the `credential_offer` payload. You also have to provide the `credential_issuer`. The reason is that the agent can support
multiple issuers at the same time.

The default endpoint is enabled at:
https://agent/webapp/credential-offers
The path is configurable when creating the issuer. By default all "admin" endpoint can be found under the path "/webapp". These endpoints should be
IP/network protected typically, as well as authentication should be enabled for them. If not anyone would be able to create a session!

The create credential offer request follows the below interface and needs to be provided in the body of the POST request to the URL above.

`scheme` can be used for instance when targeting web based wallets (https) instead of deeplinks (openid-credential-offer)

```typescript
export interface CredentialOfferRESTRequest {
  baseUri?: string
  scheme?: string
  pinLength?: number
  qrCodeOpts?: QRCodeOpts
  /**
   * This is just a type alias for `any`. The idea is that the data already is the form of a JSON-LD credential
   * Optional storage that can help the credential Data Supplier. For instance to store credential input data during offer creation, if no additional data can be supplied later on
   */
  credentialDataSupplierInput?: CredentialDataSupplierInput
}

export interface CredentialOfferPayloadV1_0_13 {
  /**
   * REQUIRED. The URL of the Credential Issuer, as defined in Section 11.2.1, from which the Wallet is requested to
   * obtain one or more Credentials. The Wallet uses it to obtain the Credential Issuer's Metadata following the steps
   * defined in Section 11.2.2.
   */
  credential_issuer: string

  /**
   *  REQUIRED. Array of unique strings that each identify one of the keys in the name/value pairs stored in
   *  the credential_configurations_supported Credential Issuer metadata. The Wallet uses these string values
   *  to obtain the respective object that contains information about the Credential being offered as defined
   *  in Section 11.2.3. For example, these string values can be used to obtain scope values to be used in
   *  the Authorization Request.
   */
  credential_configuration_ids: string[]
  /**
   * OPTIONAL. A JSON object indicating to the Wallet the Grant Types the Credential Issuer's AS is prepared
   * to process for this credential offer. Every grant is represented by a key and an object.
   * The key value is the Grant Type identifier, the object MAY contain parameters either determining the way
   * the Wallet MUST use the particular grant and/or parameters the Wallet MUST send with the respective request(s).
   * If grants is not present or empty, the Wallet MUST determine the Grant Types the Credential Issuer's AS supports
   * using the respective metadata. When multiple grants are present, it's at the Wallet's discretion which one to use.
   */
  grants?: Grant

  /**
   * Some implementations might include a client_id in the offer. For instance EBSI in a same-device flow. (Cross-device tucks it in the state JWT)
   */
  client_id?: string
}
```

## Pre-authorized code and Authorization code grant

The `grants` object above needs to conform to the below interface. Either an authorization_code pre-authorized_code or both can be used. You however
cannot skip both.

Whenever a pre-authorized_code is being used, it is assumed that the Credential Issuer is creating the offer in an environment where the user/holder
has already authenticated somehow. We advice to use Transaction/PIN codes to prevent session hijacking to a certain extend, as that is very easy to
accomplish in a cross-device context where QR code are being used and where the assumption is that the user was already authenticated.
Please be aware that the current agent does not support Authorization Code yet unfortunately. We expect to add that support soon.

Although you can provide an optional authorization_server, currently only the built-in authorization server can be used. Once we added support for
external authorization servers and authorization code support on the issuer side, you will be able to use this.

Although it is technically possible to re-use the same pre-authorization_code for multiple offers, we would not advice it and suggest to always create
a unique code per offer. Reason is that the issuer has an internal state where it keeps track of the progress. This for instance can be used by the
status endpoint, to have a web-app/frontend application track progress and notify a user.

```typescript
export interface Grant {
  authorization_code?: GrantAuthorizationCode
  'urn:ietf:params:oauth:grant-type:pre-authorized_code'?: GrantUrnIetf
}

export interface GrantAuthorizationCode {
  /**
   * OPTIONAL. String value created by the Credential Issuer and opaque to the Wallet that is used to bind the subsequent
   * Authorization Request with the Credential Issuer to a context set up during previous steps.
   */
  issuer_state?: string

  // v12 feature
  /**
   * OPTIONAL string that the Wallet can use to identify the Authorization Server to use with this grant type when authorization_servers parameter in the Credential Issuer metadata has multiple entries. MUST NOT be used otherwise. The value of this parameter MUST match with one of the values in the authorization_servers array obtained from the Credential Issuer metadata
   */
  authorization_server?: string
}

export interface GrantUrnIetf {
  /**
   * REQUIRED. The code representing the Credential Issuer's authorization for the Wallet to obtain Credentials of a certain type.
   */
  'pre-authorized_code': string

  // v13
  /**
   * OPTIONAL. Object specifying whether the Authorization Server expects presentation of a Transaction Code by the
   * End-User along with the Token Request in a Pre-Authorized Code Flow. If the Authorization Server does not expect a
   * Transaction Code, this object is absent; this is the default. The Transaction Code is intended to bind the Pre-Authorized
   * Code to a certain transaction to prevent replay of this code by an attacker that, for example, scanned the QR code while
   * standing behind the legitimate End-User. It is RECOMMENDED to send the Transaction Code via a separate channel. If the Wallet
   * decides to use the Pre-Authorized Code Flow, the Transaction Code value MUST be sent in the tx_code parameter with
   * the respective Token Request as defined in Section 6.1. If no length or description is given, this object may be empty,
   * indicating that a Transaction Code is required.
   */
  tx_code?: TxCode

  // v12, v13
  /**
   * OPTIONAL. The minimum amount of time in seconds that the Wallet SHOULD wait between polling requests to the token endpoint (in case the Authorization Server responds with error code authorization_pending - see Section 6.3). If no value is provided, Wallets MUST use 5 as the default.
   */
  interval?: number

  // v12, v13 feature
  /**
   * OPTIONAL string that the Wallet can use to identify the Authorization Server to use with this grant type when authorization_servers parameter in the Credential Issuer metadata has multiple entries. MUST NOT be used otherwise. The value of this parameter MUST match with one of the values in the authorization_servers array obtained from the Credential Issuer metadata
   */
  authorization_server?: string

  // v12 and below feature
  /**
   * OPTIONAL. Boolean value specifying whether the AS
   * expects presentation of the End-User PIN along with the Token Request
   * in a Pre-Authorized Code Flow. Default is false. This PIN is intended
   * to bind the Pre-Authorized Code to a certain transaction to prevent
   * replay of this code by an attacker that, for example, scanned the QR
   * code while standing behind the legitimate End-User. It is RECOMMENDED
   * to send a PIN via a separate channel. If the Wallet decides to use
   * the Pre-Authorized Code Flow, a PIN value MUST be sent in
   * the user_pin parameter with the respective Token Request.
   */
  user_pin_required?: boolean
}

export interface TxCode {
  /**
   * OPTIONAL. String specifying the input character set. Possible values are numeric (only digits) and text (any characters). The default is numeric.
   */
  input_mode?: InputCharSet

  /**
   * OPTIONAL. Integer specifying the length of the Transaction Code. This helps the Wallet to render the input screen and improve the user experience.
   */
  length?: number

  /**
   * OPTIONAL. String containing guidance for the Holder of the Wallet on how to obtain the Transaction Code, e.g.,
   * describing over which communication channel it is delivered. The Wallet is RECOMMENDED to display this description
   * next to the Transaction Code input screen to improve the user experience. The length of the string MUST NOT exceed
   * 300 characters. The description does not support internationalization, however the Issuer MAY detect the Holder's
   * language by previous communication or an HTTP Accept-Language header within an HTTP GET request for a Credential Offer URI.
   */
  description?: string
}
```

## Credential data supplier

The credential data supplier allows you to supply data during creation of the credential offer. This data is then stored in the session, and will be
re-used once the credential is issued.
Sometimes you might not know the input data yet at this point, or you want to make sure that the wallet actually is able to get to the issuance stage
of the process. That is why soon there will also be support using a web-hook, that is called during the issuance phase. The webhook will get most
session data and then is expected to conform to the data supplier interface as well. Providing all the input data for the credential.

## Resulting credential offer response

The response after creating the credential offer can used in a webapp/frontend to create a (deep)link for a same device flow, or a QR code for a
cross-device flow. The `uri` property is the URI you can use in a QR code or as a link. The `qrCodeDataUri`
is a image-data URI you can use to create an inline QR code image. The response contains this value provided that the request contained QR code
options.

```typescript
export type CreateCredentialOfferURIResult = {
  uri: string
  qrCodeDataUri?: string
  session: CredentialOfferSession
  userPin?: string
  txCode?: TxCode
}
```

## QR code image is part of the offer response

You can decide whether you want to create a QR code yourself based on the credential offer response, or whether you want the create Credential Offer
endpoint to create a QR code image for
you. This is controlled by providing the `qrCodeOpts` object in the `CredentialOfferRESTRequest`

```typescript
export interface QRCodeOpts {
  /**
   * Size of the QR code in pixel.
   *
   * @defaultValue 400
   */
  size?: number

  /**
   * Size of margins around the QR code body in pixel.
   *
   * @defaultValue 20
   */
  margin?: number

  /**
   * Error correction level of the QR code.
   *
   * Accepts a value provided by _QRErrorCorrectLevel_.
   *
   * For more information, please refer to [https://www.qrcode.com/en/about/error_correction.html](https://www.qrcode.com/en/about/error_correction.html).
   *
   * @defaultValue 0
   */
  correctLevel?: number

  /**
   * **This is an advanced option.**
   *
   * Specify the mask pattern to be used in QR code encoding.
   *
   * Accepts a value provided by _QRMaskPattern_.
   *
   * To find out all eight mask patterns, please refer to [https://en.wikipedia.org/wiki/File:QR_Code_Mask_Patterns.svg](https://en.wikipedia.org/wiki/File:QR_Code_Mask_Patterns.svg)
   *
   * For more information, please refer to [https://en.wikiversity.org/wiki/Reed%E2%80%93Solomon_codes_for_coders#Masking](https://en.wikiversity.org/wiki/Reed%E2%80%93Solomon_codes_for_coders#Masking).
   */
  maskPattern?: number

  /**
   * **This is an advanced option.**
   *
   * Specify the version to be used in QR code encoding.
   *
   * Accepts an integer in range [1, 40].
   *
   * For more information, please refer to [https://www.qrcode.com/en/about/version.html](https://www.qrcode.com/en/about/version.html).
   */
  version?: number

  /**
   * Options to control components in the QR code.
   *
   * @deafultValue undefined
   */
  components?: ComponentOptions

  /**
   * Color of the blocks on the QR code.
   *
   * Accepts a CSS &lt;color&gt;.
   *
   * For more information about CSS &lt;color&gt;, please refer to [https://developer.mozilla.org/en-US/docs/Web/CSS/color_value](https://developer.mozilla.org/en-US/docs/Web/CSS/color_value).
   *
   * @defaultValue "#000000"
   */
  colorDark?: string

  /**
   * Color of the empty areas on the QR code.
   *
   * Accepts a CSS &lt;color&gt;.
   *
   * For more information about CSS &lt;color&gt;, please refer to [https://developer.mozilla.org/en-US/docs/Web/CSS/color_value](https://developer.mozilla.org/en-US/docs/Web/CSS/color_value).
   *
   * @defaultValue "#ffffff"
   */
  colorLight?: string

  /**
   * Automatically calculate the _colorLight_ value from the QR code's background.
   *
   * @defaultValue true
   */
  autoColor?: boolean

  /**
   * Background image to be used in the QR code.
   *
   * Accepts a `data:` string in web browsers or a Buffer in Node.js.
   *
   * @defaultValue undefined
   */
  backgroundImage?: string | Buffer

  /**
   * Color of the dimming mask above the background image.
   *
   * Accepts a CSS &lt;color&gt;.
   *
   * For more information about CSS &lt;color&gt;, please refer to [https://developer.mozilla.org/en-US/docs/Web/CSS/color_value](https://developer.mozilla.org/en-US/docs/Web/CSS/color_value).
   *
   * @defaultValue "rgba(0, 0, 0, 0)"
   */
  backgroundDimming?: string

  /**
   * GIF background image to be used in the QR code.
   *
   * @defaultValue undefined
   */
  gifBackground?: ArrayBuffer

  /**
   * Use a white margin instead of a transparent one which reveals the background of the QR code on margins.
   *
   * @defaultValue true
   */
  whiteMargin?: boolean

  /**
   * Logo image to be displayed at the center of the QR code.
   *
   * Accepts a `data:` string in web browsers or a Buffer in Node.js.
   *
   * When set to `undefined` or `null`, the logo is disabled.
   *
   * @defaultValue undefined
   */
  logoImage?: string | Buffer

  /**
   * Ratio of the logo size to the QR code size.
   *
   * @defaultValue 0.2
   */
  logoScale?: number

  /**
   * Size of margins around the logo image in pixels.
   *
   * @defaultValue 6
   */
  logoMargin?: number

  /**
   * Corner radius of the logo image in pixels.
   *
   * @defaultValue 8
   */
  logoCornerRadius?: number

  /**
   * @deprecated
   *
   * Ratio of the real size to the full size of the blocks.
   *
   * This can be helpful when you want to make more parts of the background visible.
   *
   * @deafultValue 0.4
   */
  dotScale?: number
}
```

## Example create credential offer request and response

Create offer example request. This example uses an optional template configured on the issuer, to convert the keys into a JSON-LD credential object

```json
{
  "credential_configuration_ids": ["Omzetbelasting"],
  "grants": {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "bzCzhpkwFBHPyTF9u6Rfdz",
      "tx_code": {
        "input_mode": "numeric",
        "length": 4
      }
    }
  },
  "credentialDataSupplierInput": {
    "naam": "Example",
    "rsin": "RSIN-1234",
    "btwId": "BTW-5678",
    "obNummer": "OB-abcd"
  }
}
```

Credential offer response:

```json
{
  "uri": "openid-credential-offer://?credential_offer=%7B%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22bzCzhpkwFBHPyTF9u6Rfdz%22%2C%22tx_code%22%3A%7B%22input_mode%22%3A%22numeric%22%2C%22length%22%3A4%7D%7D%7D%2C%22credential_configuration_ids%22%3A%5B%22Omzetbelasting%22%5D%2C%22credential_issuer%22%3A%22https%3A%2F%2Fagent.issuer.bd.demo.sphereon.com%22%7D",
  "txCode": {
    "input_mode": "numeric",
    "length": 4
  },
  "userPin": "0151",
  "pinLength": 4
}
```

# Track credential issuance status (session)

You can track the status of the credential issuance, using the following endpoint:
https://agent/webapp/credential-offer-status

You will need to send a POST request, with in the body an `id` value that corresponds to the `issuer_state` or `pre-authorized_code` value you
provided when creating the offer.

example request:

```json
{
  "id": "bzCzhpkwFBHPyTF9u6Rfdz"
}
```

example response:

```json
{
  "createdAt": 1721768181938,
  "lastUpdatedAt": 1721768181938,
  "status": "OFFER_CREATED"
}
```

The potential status values are:

```typescript
export enum IssueStatus {
  OFFER_CREATED = 'OFFER_CREATED',
  ACCESS_TOKEN_REQUESTED = 'ACCESS_TOKEN_REQUESTED', // Optional state, given the token endpoint could also be on a separate AS
  ACCESS_TOKEN_CREATED = 'ACCESS_TOKEN_CREATED', // Optional state, given the token endpoint could also be on a separate AS
  CREDENTIAL_REQUEST_RECEIVED = 'CREDENTIAL_REQUEST_RECEIVED', // Credential request received. Next state would either be error or issued
  CREDENTIAL_ISSUED = 'CREDENTIAL_ISSUED',
  ERROR = 'ERROR',
}
```

The whole status response:

```typescript
export interface IssueStatusResponse {
  createdAt: number
  lastUpdatedAt: number
  status: IssueStatus
  error?: string
  clientId?: string
}
```
