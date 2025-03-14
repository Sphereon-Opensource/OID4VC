# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# [0.17.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.16.0...v0.17.0) (2025-03-14)

### Bug Fixes

- access token client_id not always set ([4b09936](https://github.com/Sphereon-Opensource/OID4VCI/commit/4b09936ab1488eb1155f874deeb11e0afa9f5a01))
- access token client_id not always set ([a3ef03e](https://github.com/Sphereon-Opensource/OID4VCI/commit/a3ef03ece421423373cb23cee3625f1d01c4e951))
- Fix for when credential_configuration_ids is being used together with credentials_supported ([f696867](https://github.com/Sphereon-Opensource/OID4VCI/commit/f6968677ccd10c2ce8eb8484443971102547e8a2))
- fix single vp_token being send is an array ([e496ca2](https://github.com/Sphereon-Opensource/OID4VCI/commit/e496ca259319f2f6fa327cf0efe71e0a8f0dc5f1))
- offer creation improvements ([a0f5326](https://github.com/Sphereon-Opensource/OID4VCI/commit/a0f53268bbf356d5c58eadf5dc29a5c91189a264))
- session and state to correlationId mapping bugfixes ([c9b4d6f](https://github.com/Sphereon-Opensource/OID4VCI/commit/c9b4d6f8df62a11d6235d75bee63deb352f66926))
- update deps ([ca61afe](https://github.com/Sphereon-Opensource/OID4VCI/commit/ca61afe183f8387e591a17dbb9de894c1f1aad0e))

### Features

- Add expiration to offers ([bbd8d7e](https://github.com/Sphereon-Opensource/OID4VCI/commit/bbd8d7e08b2061048d7d4439eb6af5f4890bd61f))
- added support for first party applications ([9c273b9](https://github.com/Sphereon-Opensource/OID4VCI/commit/9c273b94a5373f9949b0d717e151e9f378307a3f))
- allow additional claims in access token ([1f73783](https://github.com/Sphereon-Opensource/OID4VCI/commit/1f73783e860edf330e25213fb8d84dd2cb5e1d76))
- Allow REST API and client to set client_id and other params ([16a7a2c](https://github.com/Sphereon-Opensource/OID4VCI/commit/16a7a2cdcd83711c8362c40e138235581fce8963))
- Expose DPoP support also to main clients, instead of only to the access token client and credential request client ([e2cc7f6](https://github.com/Sphereon-Opensource/OID4VCI/commit/e2cc7f6abf553a705786d9c3fdc9aa28e53cac1c))
- Improvements to by reference offers. Also allow setting a correlationId on an offer ([1020d26](https://github.com/Sphereon-Opensource/OID4VCI/commit/1020d266634e0b12e54f66c37cd5470789940087))
- mdoc credential issuance ([86f6d4a](https://github.com/Sphereon-Opensource/OID4VCI/commit/86f6d4a1e81f826ceb5c51530131be0895dfa6b9))
- MWALL-715 Add support for external AS ([914d198](https://github.com/Sphereon-Opensource/OID4VCI/commit/914d198c99df94c84ea83520e767b6b557ecd717))
- MWALL-715 Create notification endpoint logic in Issuer ([2dff0df](https://github.com/Sphereon-Opensource/OID4VCI/commit/2dff0df4f3d9c0943b9e93ea2c9666fab43747c2))
- OID4VCI Rest API session improvements and delete endpoint ([0936d5d](https://github.com/Sphereon-Opensource/OID4VCI/commit/0936d5d67b9baa392396dd5fa632df3106524aa0))
- Pass in issuer_state to regular state in auth code flow, so we get a better integration with any external OIDC solution ([5b1178d](https://github.com/Sphereon-Opensource/OID4VCI/commit/5b1178dc2770e2dc6c9fd2fe98c5fe40ddb937b1))
- Pass in issuer_state to regular state in auth code flow, so we get a better integration with any external OIDC solution ([09cbd0d](https://github.com/Sphereon-Opensource/OID4VCI/commit/09cbd0d62014b6e0c8a5d367f5f95d040e5d67c4))
- Pass in issuer_state to regular state in auth code flow, so we get a better integration with any external OIDC solution ([e6222ff](https://github.com/Sphereon-Opensource/OID4VCI/commit/e6222ffb602993d376254f0e3f44e7f90eff0e3b))

# [0.16.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.15.1...v0.16.0) (2024-08-02)

### Bug Fixes

- remove bug for txCode ([57ca020](https://github.com/Sphereon-Opensource/OID4VCI/commit/57ca0203bb9f90bb9e9b21e22aa5bc492bfcff4c))
- rename common to oid4vc-common ([d89ac4f](https://github.com/Sphereon-Opensource/OID4VCI/commit/d89ac4f4956e69dad5274b197912485665aeb97c))

### Features

- create common package ([d5b4b75](https://github.com/Sphereon-Opensource/OID4VCI/commit/d5b4b75f036edcf8082e062214c036c9be934071))
- dpop support ([9202667](https://github.com/Sphereon-Opensource/OID4VCI/commit/92026678c745b770957f5bae290ae7b456601fd2))

## [0.15.1](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.15.0...v0.15.1) (2024-07-23)

### Bug Fixes

- oid4vci draft 13 typing ([6d0bfc9](https://github.com/Sphereon-Opensource/OID4VCI/commit/6d0bfc9227b1120913b773904ef991757cb9282a))
- txCode fixes [#117](https://github.com/Sphereon-Opensource/OID4VCI/issues/117) ([7d17d13](https://github.com/Sphereon-Opensource/OID4VCI/commit/7d17d13d3485c5b6b55ef876eba8f09c9f7a788b))

# [0.15.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.14.0...v0.15.0) (2024-07-15)

**Note:** Version bump only for package @sphereon/oid4vci-issuer

# [0.14.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.13.0...v0.14.0) (2024-07-06)

### Bug Fixes

- hasher dependency and token request assert vci11/13 ([81bf769](https://github.com/Sphereon-Opensource/OID4VCI/commit/81bf7692bd7721a7542c82d60fa2c01d7ce2d7b1))
- undo tx_code changes ([7888a14](https://github.com/Sphereon-Opensource/OID4VCI/commit/7888a148a8d1c41103fde35dd065ef84c4a17c2b))
- update tx_code check ([3b0971d](https://github.com/Sphereon-Opensource/OID4VCI/commit/3b0971db8302a977550b403e6611ec53be34f1dd))

### Features

- Enable tx_code support for the issuer, and properly handle both the old userPin and tx_code on the client side. fixes [#117](https://github.com/Sphereon-Opensource/OID4VCI/issues/117) ([e54071c](https://github.com/Sphereon-Opensource/OID4VCI/commit/e54071c65b00ef921acafa2c2c73707a3bc33a44))

# [0.13.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.12.0...v0.13.0) (2024-07-03)

### Bug Fixes

- Make sure we use 'JWT' as typ instead of the lower case version as suggested in the JWT RFC. ([1ff4e40](https://github.com/Sphereon-Opensource/OID4VCI/commit/1ff4e40cefb183072951e3ede3f8b3a5842d645a))

### Features

- added x5c support and made sure that we support request-responses without dids ([27bc1d9](https://github.com/Sphereon-Opensource/OID4VCI/commit/27bc1d9522fa74d8016dced63fa415efb6c4eebc))

# [0.12.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.10.3...v0.12.0) (2024-06-19)

### Bug Fixes

- (WIP) fixed all the build errors ([e522a3d](https://github.com/Sphereon-Opensource/OID4VCI/commit/e522a3dd5821fb710211e35c8871f89772b672a0))
- (WIP) refactored and fixed build. still have to fix 33 test cases that are failing ([ff88a64](https://github.com/Sphereon-Opensource/OID4VCI/commit/ff88a647574baa9813939c296342cc112d00237f))
- (WIP) refactored and fixed build. still have to fix 8 test cases that are failing ([d8c2c4f](https://github.com/Sphereon-Opensource/OID4VCI/commit/d8c2c4fa8d73ea14a0faa823a394cde23733db8f))
- changed the accepting type in VcIssuer ([125cb81](https://github.com/Sphereon-Opensource/OID4VCI/commit/125cb81b28ec153046fb7b8378e49bca43e2d96e))
- Ensure we have a single client that handles both v13 and v11 and lower ([eadbba0](https://github.com/Sphereon-Opensource/OID4VCI/commit/eadbba03ddb6e9e32b69bb3a4d9eb9ca8ac2d260))
- fixed createCredentialOfferURI signature ([2856644](https://github.com/Sphereon-Opensource/OID4VCI/commit/2856644324e3e65a2b6899c127f425e79599255b))
- fixed some issue in the IssuerMetadataUtils ([8a6c16f](https://github.com/Sphereon-Opensource/OID4VCI/commit/8a6c16f39fdee838d935edbc46c6842b628f08b7))
- fixed test type mismatch ([215227e](https://github.com/Sphereon-Opensource/OID4VCI/commit/215227efa09088957f4d57dd47654fa1ff9ff78a))
- fixed test type mismatch ([ca32202](https://github.com/Sphereon-Opensource/OID4VCI/commit/ca3220215a46f514f3a1b271cfd22505ee2e6ad0))
- fixed tests plus prettier ([fc8cdf0](https://github.com/Sphereon-Opensource/OID4VCI/commit/fc8cdf08fa315419d8eaa6a51db68ad5d3fe9305))
- fixed the logic in creating credentialOffer uri ([53bce06](https://github.com/Sphereon-Opensource/OID4VCI/commit/53bce06da7ea9e0cec545d5da7f4585fe67be050))
- fixes after merge with CWALL-199 ([af967a9](https://github.com/Sphereon-Opensource/OID4VCI/commit/af967a96370f6dce8b9afad296fc2ff1c557dd84))
- for pin in IssuerTokenServer ([354e8ad](https://github.com/Sphereon-Opensource/OID4VCI/commit/354e8adace36ef57f684ec8f69ce7cca56632198))
- MetadataClient for version 13 and added better type distinction. added credential_definition to credential metadata of v13 ([e39bf71](https://github.com/Sphereon-Opensource/OID4VCI/commit/e39bf71625c2a66821061ece7625f0b08f1c0ad2))

### Features

- Add wallet signing support to VCI and notification support ([c4d3483](https://github.com/Sphereon-Opensource/OID4VCI/commit/c4d34836fb4923c98e7743221978c902c8427f2a))
- added setDefaultTokenEndpoint to VcIssuer constructor ([f16affc](https://github.com/Sphereon-Opensource/OID4VCI/commit/f16affc7a77847e24443930b0dd8f87f5533b61a))
- added setDefaultTokenEndpoint to VcIssuerBuilder ([96608ec](https://github.com/Sphereon-Opensource/OID4VCI/commit/96608ec72dcbf1f66e30b1ead8d363836db5d7d3))
- created special type for CredentialRequest v1_0_13 and fixed the tests for it ([25a6051](https://github.com/Sphereon-Opensource/OID4VCI/commit/25a6051ed0bb096c2249f24cd054c1a7aec97f61))

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
