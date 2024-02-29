# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# [0.10.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.9.0...v0.10.0) (2024-02-29)

**Note:** Version bump only for package @sphereon/oid4vci-client

# [0.9.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.8.1...v0.9.0) (2024-02-16)

### Bug Fixes

- Add back jwt_vc format support for older versions ([9f06ab1](https://github.com/Sphereon-Opensource/OID4VCI/commit/9f06ab1e0efef89848fb6e6a2b80ed874717e580))
- Do not set a default redirect_uri, unless no authorization request options are set at all ([6c96089](https://github.com/Sphereon-Opensource/OID4VCI/commit/6c96089f1d328c60cd040f34a3d06ae3b0df392b))
- Do not set default client_id ([7a1afbc](https://github.com/Sphereon-Opensource/OID4VCI/commit/7a1afbcee3de7c7b0dbe3e32330f0a96e1dcfa1e))
- Do not sort credential types, as issuers might rely on their order ([59fba74](https://github.com/Sphereon-Opensource/OID4VCI/commit/59fba745091ef0c69a46aed1a4f7faec2416c2bd))
- the client_id used in the auth request was not taken into account when requesting access token ([2bc039c](https://github.com/Sphereon-Opensource/OID4VCI/commit/2bc039c66666d4acf59cebdddfd0b46ad795e0bc))

### Features

- Add deferred support ([99dc87d](https://github.com/Sphereon-Opensource/OID4VCI/commit/99dc87d3748cb1f71aa67237b28b6c4bb667eb29))
- Add EBSI support ([7577e3d](https://github.com/Sphereon-Opensource/OID4VCI/commit/7577e3d8a4818fe0955fce944220d6fb415a58a7))
- Add initial support for creating a client without credential offer ([13659a7](https://github.com/Sphereon-Opensource/OID4VCI/commit/13659a7b82789cc0f011d3c056ced13b3cbed290))
- add sd-jwt issuer support and e2e test ([951bf2c](https://github.com/Sphereon-Opensource/OID4VCI/commit/951bf2cb20d0a2a085a8a346d1ed519c71e31a07))
- add sd-jwt support ([a37ef06](https://github.com/Sphereon-Opensource/OID4VCI/commit/a37ef06d38fdc7a6d5acc372cd2da8935b4c414e))
- Add support to get a client id from an offer, and from state JWTs. EBSI for instance is using this ([f089116](https://github.com/Sphereon-Opensource/OID4VCI/commit/f0891164a7a6863940c264afa386144a1e4ac19a))
- added state recovery ([8ee6584](https://github.com/Sphereon-Opensource/OID4VCI/commit/8ee65844ca5d95030aa34b2a41077628ef1754f0))
- Allow to create an authorization request URL when initiating the OID4VCI client ([84ea215](https://github.com/Sphereon-Opensource/OID4VCI/commit/84ea215c10da042417dabc1d30b2e3898b635bab))
- Allow to set the clientId at a later point on the VCI client ([042b183](https://github.com/Sphereon-Opensource/OID4VCI/commit/042b183c0df91946905a6049145aa4ec16d62849))
- EBSI compatibility ([c44107f](https://github.com/Sphereon-Opensource/OID4VCI/commit/c44107f580744292a987ba2cda5795e443aaa9df))
- Make sure redirect_uri is the same for authorization and token endpoint when used and made redirect_uri optional. The redirect_uri is automatically passed to the token request in case one was used for authorization ([394fcb7](https://github.com/Sphereon-Opensource/OID4VCI/commit/394fcb71d1ac9557685e323e6b8bf4afa7d1b910))
- PAR improvements ([99f55c2](https://github.com/Sphereon-Opensource/OID4VCI/commit/99f55c23e907022954b0eb169e276f3ef9ffb8ae))
- PKCE support improvements. ([5d5cb06](https://github.com/Sphereon-Opensource/OID4VCI/commit/5d5cb060fda0790641c1b0d8d513af16ac041970))
- Support sd-jwt 0.2.0 library ([77c9c24](https://github.com/Sphereon-Opensource/OID4VCI/commit/77c9c246ac994dff1b0ca80eb42819bf9bb1844a))

## [0.8.1](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.7.3...v0.8.1) (2023-10-14)

**Note:** Version bump only for package @sphereon/oid4vci-client

## [0.7.3](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.7.2...v0.7.3) (2023-09-30)

**Note:** Version bump only for package @sphereon/oid4vci-client

## [0.7.2](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.7.1...v0.7.2) (2023-09-28)

### Bug Fixes

- id lookup against server metadata not working ([592ec4b](https://github.com/Sphereon-Opensource/OID4VCI/commit/592ec4b837898eb3022d19479d79b6065e7a0d9e))

## [0.7.1](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.7.0...v0.7.1) (2023-09-28)

### Bug Fixes

- Better match credential offer types and formats onto issuer metadata ([4044c21](https://github.com/Sphereon-Opensource/OID4VCI/commit/4044c2175b4cbee16f44c8bb5499bba249ca4993))
- clearinterval ([214e3c6](https://github.com/Sphereon-Opensource/OID4VCI/commit/214e3c6d7ced9b27c50186db8ed876330230a6a5))
- relax auth_endpoint handling. Doesn't have to be available when doing pre-auth flow. Client handles errors anyway in case of auth/par flow ([ce39958](https://github.com/Sphereon-Opensource/OID4VCI/commit/ce39958f21f82243f26111fd14bd2443517eef9c))
- relax auth_endpoint handling. Doesn't have to be available when doing pre-auth flow. Client handles errors anyway in case of auth/par flow ([cb5f9c1](https://github.com/Sphereon-Opensource/OID4VCI/commit/cb5f9c1c12285508c6d403814d032e8883a59e7d))

# [0.7.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.6.0...v0.7.0) (2023-08-19)

### Bug Fixes

- Revise well-known metadata retrieval for OID4VCI, OAuth 2.0 and OIDC. fixes [#62](https://github.com/Sphereon-Opensource/OID4VCI/issues/62) ([a750cc7](https://github.com/Sphereon-Opensource/OID4VCI/commit/a750cc76e084f12aeb58f2b1ac44b1bb5e69b5ae))

### Features

- Integrate ssi-express-support to allow for future authn/authz. Also moved endpoints to functions, so solutions can include their own set of endpoints ([c749aba](https://github.com/Sphereon-Opensource/OID4VCI/commit/c749ababd4bec567d6aeeda49b76f195ec792201))

# [0.6.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.4.0...v0.6.0) (2023-06-24)

### Bug Fixes

- added a couple of todos for handling v11, plus changed the getIssuer method to throw exception if nothing is found, and some other pr notes ([091786e](https://github.com/Sphereon-Opensource/OID4VCI/commit/091786e31246da16f6c9385fc13e7fd3e01664dc))
- added CredentialOffer to exports of client ([5cc5ab1](https://github.com/Sphereon-Opensource/OID4VCI/commit/5cc5ab10a4b5eb9c1741dc639f08d3613f9f45ea))
- added disable eslint comments in three places ([0e3ffdb](https://github.com/Sphereon-Opensource/OID4VCI/commit/0e3ffdb3a434e142d3bd8d0e04ca0b2b0f8f73e3))
- deleted wrong import and fixed the usage ([fc17946](https://github.com/Sphereon-Opensource/OID4VCI/commit/fc179469fa0d1b3669c454632aef03fa0f8d4119))
- Many v11 fixes on server and client side ([08be1ed](https://github.com/Sphereon-Opensource/OID4VCI/commit/08be1ed009fb80e910cffa2e4cf376758798b27e))
- PAR objects where in the wrong locations and one had a wrong name ([24f98e7](https://github.com/Sphereon-Opensource/OID4VCI/commit/24f98e75137cf70595753cbcf77159584d7ebe08))
- prettier, plus some type casting in test/mock files for v9 ([162af38](https://github.com/Sphereon-Opensource/OID4VCI/commit/162af3828b3dc826dc3cd5adffe3dab61925ad33))
- rename jwt_vc_json_ld to jwt_vc_json-ld ([a366bef](https://github.com/Sphereon-Opensource/OID4VCI/commit/a366bef5a7bda052de6ffa201186e02b70447a79))

### Features

- Add support for alg, kid, did, did document to Jwt Verification callback so we can ensure to set proper values in the resulting VC. ([62dd947](https://github.com/Sphereon-Opensource/OID4VCI/commit/62dd947d0e09360719e6f704db33d766dff2363a))
- Add supported flow type detection ([100f9e6](https://github.com/Sphereon-Opensource/OID4VCI/commit/100f9e6ccd7c53353f2876be81df4d6e3f7efde4))
- Add VCI Issuer ([5cab075](https://github.com/Sphereon-Opensource/OID4VCI/commit/5cab07534e7a8b340f7a05343f56fbf091d64738))
- added better support (and distinction) for types v1.0.09 and v1.0.11 ([f311258](https://github.com/Sphereon-Opensource/OID4VCI/commit/f31125865a3d63ce7719f790fc5ac74fea7f9ade))
- Added new mock data from actual issuers, fixed a small bug with v1_0_08 types, updated v1_0_08 types to support data from jff issuers ([a6b1eea](https://github.com/Sphereon-Opensource/OID4VCI/commit/a6b1eeaabc0f34cc13a79cf967a8c35a6d8dc7f5))
- Added new tests for CredentialRequestClient plus fixed a problem with CredentialOfferUtil. a CredentialRequest can have no issuer field ([50f2292](https://github.com/Sphereon-Opensource/OID4VCI/commit/50f22928426761cc3bf5d973d1f15fea407a9175))
- added support for v8 in our types (partially) to make old logics work ([4b5abf1](https://github.com/Sphereon-Opensource/OID4VCI/commit/4b5abf16507bcde0d696ea3948f816d9a2de13c4))
- added VcIssuer and builders related to that ([c2592a8](https://github.com/Sphereon-Opensource/OID4VCI/commit/c2592a8846061c5791050a76e522f50e21f617de))
- Issuer credential offer and more fixes/features ([0bbe17c](https://github.com/Sphereon-Opensource/OID4VCI/commit/0bbe17c13de4df95e2fd79b3470a746cc7a5374a))
- Translate v8 credentials_supported to v11 ([b06fa22](https://github.com/Sphereon-Opensource/OID4VCI/commit/b06fa221bed33e69aa76ae0234779f80314f2887))

# Release Notes

## v0.4.0 - 2023-03-17

Adds initial support for the Authorized Code flow (auth request, server metadata, scopes, thanks to @karimStekelenburg. Be aware that not everything in the Authorized code flow is supported yet.

- Added:
  - Add initial support for Authorized Code flow, thanks to @karimStekelenburg.
  - Add method to encode the initiation url

## v0.3.6 - 2023-01-12

Content-type fixes and allow localhost urls

- Fixes:

  - Re-add the content-type headers, inadvertently removed in the previous version. Added logic for corner-cases
  - Re-add sss-types ad dependency as it seems it is needed at runtime.
  - Allow localhost as a valid URL

- Changed:
  - Require http(s) schemes for URLs
  - Update to ssi-types from current develop branch, instead of a unstable/feature branch

## v0.3.5 - 2023-01-10

HTTP mediatype fix and HTTP response NodeJS16+ fix

- Fixes:

  - The central HTTP client method incorrectly used an array instead of an object/record when no custom headers where supplied, resulting in incorrect headers. Fixed thanks to @karimStekelenburg from our friends at @animo
  - Fix HTTP response handling for newer NodeJS >=16 not cloning the response, used for debug/log purposes.

- Changed:
  - Moved SSI-types to a dev dependency

## v0.3.4 - 2022-11-24

Release with support for the pre-authorized code flow only!

- Fixes:
  - Matching server metadata on Initiation Request types wasn't working

## v0.3.3 - 2022-11-24

Discard release because of a merge problem.

## v0.3.2 - 2022-11-21

Release with support for the pre-authorized code flow only!

- Changed:

  - renamed `jwtArgs` to `jwt` in the callback type
  - Documentation updates/fixes

- Fixes:
  - The acquireCredential in the OpenID4VCIClient was not using the access token, resulting in auth issues.

## v0.3.1 - 2022-11-20

Release with support for the pre-authorized code flow only!

- Added:

  - Allow deferring to set the kid, alg to the acquire credential method, to allow inspecting the Initiation Initiation and metadata first
  - Allow deferring setting the clientId to the acquire access token, to allow inspecting the Issuer first
  - Add methods to get supported credentials, optionally restricted to the Initiate Issuance Request types
  - Relax c_nonce handling, as some Issuers do not implement it.

- Fixes:
  - Missing some exports

## v0.3.0 - 2022-11-19

Release with support for the pre-authorized code flow only!

**WARNING: The package has been renamed to @sphereon/oid4vci-client!**

- Added:

  - Single main OpenID4VCI Client, not requiring implementation to have to use the low level classes/methods

- Fixes:
  - Several fixes and improvements

## v0.2.0 - 2022-11-04

Release with support for the pre-authorized code flow only.

Expect breaking changes in the future, as this package still is undergoing heavy development.

- Added:
  - Support for well-known OID4VCI, oAuth2 and OpenID metadata
- Fixes:
  - Several fixes related to pincode handling
  - Overall fixes

## v0.1.0 - 2022-10-18

Initial release with support for the pre-authorized code flow only.

Expect breaking changes in the future, as this package still is undergoing heavy development.
