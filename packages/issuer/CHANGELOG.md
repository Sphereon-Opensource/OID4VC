# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## [0.10.3](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.10.2...v0.10.3) (2024-04-25)

### Bug Fixes

- Fix iat expiration check ([1260291](https://github.com/Sphereon-Opensource/OID4VCI/commit/126029124ee0c566eeaab60993a65da5afa9ab31))
- issuance and expiration sometimes used milliseconds instead of seconds ([afc2a8a](https://github.com/Sphereon-Opensource/OID4VCI/commit/afc2a8a9171bae7e30ed7c7d9bd094d8cbd49b80))
- seconds to ms ([cbd60a6](https://github.com/Sphereon-Opensource/OID4VCI/commit/cbd60a6b6e91d645d03da73ef47c69b4add63e38))

## [0.10.2](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.10.1...v0.10.2) (2024-03-13)

### Bug Fixes

- token expiry ([fb641b5](https://github.com/Sphereon-Opensource/OID4VCI/commit/fb641b54e860237f0130b352055297ee45073586))
- use seconds for all expires in values ([39bde8f](https://github.com/Sphereon-Opensource/OID4VCI/commit/39bde8f835a96509727f54cbdf2d4db9fa08df8b))

## [0.10.1](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.10.0...v0.10.1) (2024-03-12)

### Bug Fixes

- await session state updates ([963fb88](https://github.com/Sphereon-Opensource/OID4VCI/commit/963fb88201af15ccfce189bb3ac7eedc846833d0))

# [0.10.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.9.0...v0.10.0) (2024-02-29)

### Features

- Open the signing algorithm list in the credential issuance process, refs [#88](https://github.com/Sphereon-Opensource/OID4VCI/issues/88) ([d9b17af](https://github.com/Sphereon-Opensource/OID4VCI/commit/d9b17af8098f55b688891de5e536fa95560ef8af))

# [0.9.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.8.1...v0.9.0) (2024-02-16)

### Bug Fixes

- Add back jwt_vc format support for older versions ([9f06ab1](https://github.com/Sphereon-Opensource/OID4VCI/commit/9f06ab1e0efef89848fb6e6a2b80ed874717e580))
- add sd-jwt to issuer callback ([93b1242](https://github.com/Sphereon-Opensource/OID4VCI/commit/93b1242d99dc21400c337b2f552a9f2da9da375c))
- disable awesome-qr in rn ([3daf0d3](https://github.com/Sphereon-Opensource/OID4VCI/commit/3daf0d3e59b37c8ac91aa050b3a7cf1ff49cbfc3))
- **sd-jwt:** cnf instead of kid ([510a4e8](https://github.com/Sphereon-Opensource/OID4VCI/commit/510a4e856c14d5daf933b60ba6d945deadf68d1c))

### Features

- Add EBSI support ([7577e3d](https://github.com/Sphereon-Opensource/OID4VCI/commit/7577e3d8a4818fe0955fce944220d6fb415a58a7))
- add sd-jwt issuer support and e2e test ([951bf2c](https://github.com/Sphereon-Opensource/OID4VCI/commit/951bf2cb20d0a2a085a8a346d1ed519c71e31a07))
- add sd-jwt support ([a37ef06](https://github.com/Sphereon-Opensource/OID4VCI/commit/a37ef06d38fdc7a6d5acc372cd2da8935b4c414e))
- ldp issuance ([bf8865a](https://github.com/Sphereon-Opensource/OID4VCI/commit/bf8865a93ebf7b1f3150da815137e2b945e3e8ec))
- Support sd-jwt 0.2.0 library ([77c9c24](https://github.com/Sphereon-Opensource/OID4VCI/commit/77c9c246ac994dff1b0ca80eb42819bf9bb1844a))

## [0.8.1](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.7.3...v0.8.1) (2023-10-14)

**Note:** Version bump only for package @sphereon/oid4vci-issuer

## [0.7.3](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.7.2...v0.7.3) (2023-09-30)

**Note:** Version bump only for package @sphereon/oid4vci-issuer

## [0.7.2](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.7.1...v0.7.2) (2023-09-28)

**Note:** Version bump only for package @sphereon/oid4vci-issuer

## [0.7.1](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.7.0...v0.7.1) (2023-09-28)

### Bug Fixes

- Better match credential offer types and formats onto issuer metadata ([4044c21](https://github.com/Sphereon-Opensource/OID4VCI/commit/4044c2175b4cbee16f44c8bb5499bba249ca4993))
- clearinterval ([214e3c6](https://github.com/Sphereon-Opensource/OID4VCI/commit/214e3c6d7ced9b27c50186db8ed876330230a6a5))

# [0.7.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.6.0...v0.7.0) (2023-08-19)

### Features

- Integrate ssi-express-support to allow for future authn/authz. Also moved endpoints to functions, so solutions can include their own set of endpoints ([c749aba](https://github.com/Sphereon-Opensource/OID4VCI/commit/c749ababd4bec567d6aeeda49b76f195ec792201))

# [0.6.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.4.0...v0.6.0) (2023-06-24)

### Bug Fixes

- Many v11 fixes on server and client side ([08be1ed](https://github.com/Sphereon-Opensource/OID4VCI/commit/08be1ed009fb80e910cffa2e4cf376758798b27e))
- rename jwt_vc_json_ld to jwt_vc_json-ld ([a366bef](https://github.com/Sphereon-Opensource/OID4VCI/commit/a366bef5a7bda052de6ffa201186e02b70447a79))

### Features

- Add status support to sessions ([02c7eaf](https://github.com/Sphereon-Opensource/OID4VCI/commit/02c7eaf69af441e15c6302a9c0f2874d54066b32))
- Add support for alg, kid, did, did document to Jwt Verification callback so we can ensure to set proper values in the resulting VC. ([62dd947](https://github.com/Sphereon-Opensource/OID4VCI/commit/62dd947d0e09360719e6f704db33d766dff2363a))
- Add support for background_image for credentials ([a3c2561](https://github.com/Sphereon-Opensource/OID4VCI/commit/a3c2561c7596ad7303467528d92cdaa033c7af94))
- Add supported flow type detection ([100f9e6](https://github.com/Sphereon-Opensource/OID4VCI/commit/100f9e6ccd7c53353f2876be81df4d6e3f7efde4))
- Add VCI Issuer ([5cab075](https://github.com/Sphereon-Opensource/OID4VCI/commit/5cab07534e7a8b340f7a05343f56fbf091d64738))
- added (issuer) state to options for createCredentialOfferDeeplink ([bd1569c](https://github.com/Sphereon-Opensource/OID4VCI/commit/bd1569c8b8b1404d90db822ecc8925a2485e46ba))
- added api.ts for all the rest apis of the issuer ([907c05e](https://github.com/Sphereon-Opensource/OID4VCI/commit/907c05efc2045d2b4faec14a206214ae17f91e1d))
- added callback function for issuing credentials ([c478788](https://github.com/Sphereon-Opensource/OID4VCI/commit/c478788d3d3d2414073eedddd9d43cc3d593ee1b))
- added issuer callback to arguments of the issuer builder ([ed4fe7c](https://github.com/Sphereon-Opensource/OID4VCI/commit/ed4fe7cff1f717d5b667da70d43b58d04651334d))
- added optional issuer callback to parameters of issueCredentialFromIssueRequest ([a7a9e4a](https://github.com/Sphereon-Opensource/OID4VCI/commit/a7a9e4a99d41fa3647482372b36d23c1595ae80f))
- added support for creating credentialOffer deeplink based on a uri ([6822dfe](https://github.com/Sphereon-Opensource/OID4VCI/commit/6822dfec553f1ff6957bedb7875fa4d40a57c06e))
- added support for creating offer deeplink from object and test it. plus some refactors ([a87dcb1](https://github.com/Sphereon-Opensource/OID4VCI/commit/a87dcb1ec10ea26a221d61ec0ffd4b4e098a594f))
- added support for v8 in our types (partially) to make old logics work ([4b5abf1](https://github.com/Sphereon-Opensource/OID4VCI/commit/4b5abf16507bcde0d696ea3948f816d9a2de13c4))
- added VcIssuer and builders related to that ([c2592a8](https://github.com/Sphereon-Opensource/OID4VCI/commit/c2592a8846061c5791050a76e522f50e21f617de))
- Ass support to provide credential input data to the issuer whilst creating the offer to be used with a credential data supplier ([03d3e46](https://github.com/Sphereon-Opensource/OID4VCI/commit/03d3e46ab44b2e924320b6aed213c88d2ad161db))
- beside the 'with' methods in the builder which will replace existing configuration for that field, I've added 'add' methods to add to existing configuration ([9d42152](https://github.com/Sphereon-Opensource/OID4VCI/commit/9d42152536fd6617bd5d8944fc6b07cb0e709473))
- created another module for rest api and moved the dependencies from issuer module to issuer-rest ([38849af](https://github.com/Sphereon-Opensource/OID4VCI/commit/38849afcc1fab1f679719bbd762316cec91af0ff))
- Issuer credential offer and more fixes/features ([0bbe17c](https://github.com/Sphereon-Opensource/OID4VCI/commit/0bbe17c13de4df95e2fd79b3470a746cc7a5374a))
- Support data supplier callback ([1c49cc8](https://github.com/Sphereon-Opensource/OID4VCI/commit/1c49cc80cfd83115956c7e9a040e12e814724e72))
