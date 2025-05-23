# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# [0.19.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.17.0...v0.19.0) (2025-05-22)


### Features

* add biome ([b8ff6cb](https://github.com/Sphereon-Opensource/OID4VC/commit/b8ff6cb8c7ca78acfc2dffab080ac03ea24ee8d5))
* add biome ([d92e50e](https://github.com/Sphereon-Opensource/OID4VC/commit/d92e50eb349a07f6c76d012ece5e88473b2406c5))
* move from jest to vitest ([6188f4a](https://github.com/Sphereon-Opensource/OID4VC/commit/6188f4a58493429d9ec2581eb587d61e5d91ad64))
* Project is now ESM by default, bundled as CJS as well ([af84cc5](https://github.com/Sphereon-Opensource/OID4VC/commit/af84cc5d0d775d9e76ce49695fd7b0b67d98a9dd))





# [0.17.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.16.0...v0.17.0) (2025-03-14)

### Bug Fixes

- access token client_id not always set ([4b09936](https://github.com/Sphereon-Opensource/OID4VC/commit/4b09936ab1488eb1155f874deeb11e0afa9f5a01))
- Disable token endpoint in case asClientMetadata is found ([362da1a](https://github.com/Sphereon-Opensource/OID4VC/commit/362da1a1180be9d0eed81bf53a7da54e42ddd0c4))
- Fix disabled AS assertion by looking at configured AS ([1e5b251](https://github.com/Sphereon-Opensource/OID4VC/commit/1e5b251d38856db4d6dca9ec5f69ead9235cce63))
- Fix for when credential_configuration_ids is being used together with credentials_supported ([f696867](https://github.com/Sphereon-Opensource/OID4VC/commit/f6968677ccd10c2ce8eb8484443971102547e8a2))
- fix single vp_token being send is an array ([e496ca2](https://github.com/Sphereon-Opensource/OID4VC/commit/e496ca259319f2f6fa327cf0efe71e0a8f0dc5f1))
- session and state to correlationId mapping bugfixes ([c9b4d6f](https://github.com/Sphereon-Opensource/OID4VC/commit/c9b4d6f8df62a11d6235d75bee63deb352f66926))
- update deps ([ca61afe](https://github.com/Sphereon-Opensource/OID4VC/commit/ca61afe183f8387e591a17dbb9de894c1f1aad0e))

### Features

- Add expiration to offers ([bbd8d7e](https://github.com/Sphereon-Opensource/OID4VC/commit/bbd8d7e08b2061048d7d4439eb6af5f4890bd61f))
- added support for first party applications ([9c273b9](https://github.com/Sphereon-Opensource/OID4VC/commit/9c273b94a5373f9949b0d717e151e9f378307a3f))
- Allow REST API and client to set client_id and other params ([16a7a2c](https://github.com/Sphereon-Opensource/OID4VC/commit/16a7a2cdcd83711c8362c40e138235581fce8963))
- Expose DPoP support also to main clients, instead of only to the access token client and credential request client ([e2cc7f6](https://github.com/Sphereon-Opensource/OID4VC/commit/e2cc7f6abf553a705786d9c3fdc9aa28e53cac1c))
- Improvements to by reference offers. Also allow setting a correlationId on an offer ([1020d26](https://github.com/Sphereon-Opensource/OID4VC/commit/1020d266634e0b12e54f66c37cd5470789940087))
- MWALL-715 Add support for external AS ([914d198](https://github.com/Sphereon-Opensource/OID4VC/commit/914d198c99df94c84ea83520e767b6b557ecd717))
- MWALL-715 Create notification endpoint logic in Issuer ([2dff0df](https://github.com/Sphereon-Opensource/OID4VC/commit/2dff0df4f3d9c0943b9e93ea2c9666fab43747c2))
- OID4VCI Rest API session improvements and delete endpoint ([0936d5d](https://github.com/Sphereon-Opensource/OID4VC/commit/0936d5d67b9baa392396dd5fa632df3106524aa0))
- Pass in issuer_state to regular state in auth code flow, so we get a better integration with any external OIDC solution ([e6222ff](https://github.com/Sphereon-Opensource/OID4VC/commit/e6222ffb602993d376254f0e3f44e7f90eff0e3b))

# [0.16.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.15.1...v0.16.0) (2024-08-02)

### Bug Fixes

- rename common to oid4vc-common ([d89ac4f](https://github.com/Sphereon-Opensource/OID4VC/commit/d89ac4f4956e69dad5274b197912485665aeb97c))

### Features

- address feedback part 2 ([01f6d4d](https://github.com/Sphereon-Opensource/OID4VC/commit/01f6d4d7884c7f49f4395f7ec9ba12ee9b0a8668))
- create common package ([d5b4b75](https://github.com/Sphereon-Opensource/OID4VC/commit/d5b4b75f036edcf8082e062214c036c9be934071))
- dpop support ([9202667](https://github.com/Sphereon-Opensource/OID4VC/commit/92026678c745b770957f5bae290ae7b456601fd2))
- incorporate feedback and fix tests ([c7c6af4](https://github.com/Sphereon-Opensource/OID4VC/commit/c7c6af464d9fda53b86c3095feca5705df9e92cc))

## [0.15.1](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.15.0...v0.15.1) (2024-07-23)

### Bug Fixes

- txCode fixes [#117](https://github.com/Sphereon-Opensource/OID4VC/issues/117) ([7d17d13](https://github.com/Sphereon-Opensource/OID4VC/commit/7d17d13d3485c5b6b55ef876eba8f09c9f7a788b))

# [0.15.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.14.0...v0.15.0) (2024-07-15)

**Note:** Version bump only for package @sphereon/oid4vci-issuer-server

# [0.14.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.13.0...v0.14.0) (2024-07-06)

### Features

- Enable tx_code support for the issuer, and properly handle both the old userPin and tx_code on the client side. fixes [#117](https://github.com/Sphereon-Opensource/OID4VC/issues/117) ([e54071c](https://github.com/Sphereon-Opensource/OID4VC/commit/e54071c65b00ef921acafa2c2c73707a3bc33a44))

# [0.13.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.12.0...v0.13.0) (2024-07-03)

**Note:** Version bump only for package @sphereon/oid4vci-issuer-server

# [0.12.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.10.3...v0.12.0) (2024-06-19)

### Bug Fixes

- (WIP) fixed all the build errors ([e522a3d](https://github.com/Sphereon-Opensource/OID4VC/commit/e522a3dd5821fb710211e35c8871f89772b672a0))
- (WIP) refactored and fixed build. still have to fix 33 test cases that are failing ([ff88a64](https://github.com/Sphereon-Opensource/OID4VC/commit/ff88a647574baa9813939c296342cc112d00237f))
- (WIP) refactored and fixed build. still have to fix 8 test cases that are failing ([d8c2c4f](https://github.com/Sphereon-Opensource/OID4VC/commit/d8c2c4fa8d73ea14a0faa823a394cde23733db8f))
- (WIP) refactored and fixed parts of the logic for v1_0_13. ([06117c0](https://github.com/Sphereon-Opensource/OID4VC/commit/06117c0fd9a06170284ce5a89075d5b12fcd7d7b))
- (WIP) skipped failing tests and made comment to fix them ([16f1673](https://github.com/Sphereon-Opensource/OID4VC/commit/16f1673bd30b43ce1b9209650e7b6be5e1f2c237))
- Ensure we have a single client that handles both v13 and v11 and lower ([eadbba0](https://github.com/Sphereon-Opensource/OID4VC/commit/eadbba03ddb6e9e32b69bb3a4d9eb9ca8ac2d260))
- fixed ClientIssuerIT.spec ([c5be065](https://github.com/Sphereon-Opensource/OID4VC/commit/c5be06583048dd8b1e80e60eb1b290c07e0e5bc9))
- fixed some test cases ([ccac046](https://github.com/Sphereon-Opensource/OID4VC/commit/ccac04640a7fc950d8e2f98d932acdf2f896a791))
- fixed test type mismatch ([ca32202](https://github.com/Sphereon-Opensource/OID4VC/commit/ca3220215a46f514f3a1b271cfd22505ee2e6ad0))
- fixed tests plus prettier ([fc8cdf0](https://github.com/Sphereon-Opensource/OID4VC/commit/fc8cdf08fa315419d8eaa6a51db68ad5d3fe9305))
- fixed the failing test for the credentialOfferUri ([a8ac2e3](https://github.com/Sphereon-Opensource/OID4VC/commit/a8ac2e3421009189580c2098c1d8f96038914447))
- for pin in IssuerTokenServer ([354e8ad](https://github.com/Sphereon-Opensource/OID4VC/commit/354e8adace36ef57f684ec8f69ce7cca56632198))
- MetadataClient for version 13 and added better type distinction. added credential_definition to credential metadata of v13 ([e39bf71](https://github.com/Sphereon-Opensource/OID4VC/commit/e39bf71625c2a66821061ece7625f0b08f1c0ad2))

### Features

- Add wallet signing support to VCI and notification support ([c4d3483](https://github.com/Sphereon-Opensource/OID4VC/commit/c4d34836fb4923c98e7743221978c902c8427f2a))
- added setDefaultTokenEndpoint to VcIssuerBuilder ([96608ec](https://github.com/Sphereon-Opensource/OID4VC/commit/96608ec72dcbf1f66e30b1ead8d363836db5d7d3))
- added token_endpoint to the metadata ([72f2988](https://github.com/Sphereon-Opensource/OID4VC/commit/72f2988a0837e53f0a01cc40b88fdeb2f948627a))
- created special type for CredentialRequest v1_0_13 and fixed the tests for it ([25a6051](https://github.com/Sphereon-Opensource/OID4VC/commit/25a6051ed0bb096c2249f24cd054c1a7aec97f61))

## [0.10.3](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.10.2...v0.10.3) (2024-04-25)

### Bug Fixes

- issuance and expiration sometimes used milliseconds instead of seconds ([afc2a8a](https://github.com/Sphereon-Opensource/OID4VC/commit/afc2a8a9171bae7e30ed7c7d9bd094d8cbd49b80))

## [0.10.2](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.10.1...v0.10.2) (2024-03-13)

### Bug Fixes

- use seconds for all expires in values ([39bde8f](https://github.com/Sphereon-Opensource/OID4VC/commit/39bde8f835a96509727f54cbdf2d4db9fa08df8b))

## [0.10.1](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.10.0...v0.10.1) (2024-03-12)

**Note:** Version bump only for package @sphereon/oid4vci-issuer-server

# [0.10.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.9.0...v0.10.0) (2024-02-29)

**Note:** Version bump only for package @sphereon/oid4vci-issuer-server

# [0.9.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.8.1...v0.9.0) (2024-02-16)

### Bug Fixes

- Add back jwt_vc format support for older versions ([9f06ab1](https://github.com/Sphereon-Opensource/OID4VC/commit/9f06ab1e0efef89848fb6e6a2b80ed874717e580))
- opts passed to getCredentialOfferEndpoint() ([923b8b4](https://github.com/Sphereon-Opensource/OID4VC/commit/923b8b4a74394788a8756211d1491612e20f2a9f))

### Features

- add sd-jwt support ([a37ef06](https://github.com/Sphereon-Opensource/OID4VC/commit/a37ef06d38fdc7a6d5acc372cd2da8935b4c414e))
- Allow to create an authorization request URL when initiating the OID4VCI client ([84ea215](https://github.com/Sphereon-Opensource/OID4VC/commit/84ea215c10da042417dabc1d30b2e3898b635bab))
- Support sd-jwt 0.2.0 library ([77c9c24](https://github.com/Sphereon-Opensource/OID4VC/commit/77c9c246ac994dff1b0ca80eb42819bf9bb1844a))

## [0.8.1](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.7.3...v0.8.1) (2023-10-14)

**Note:** Version bump only for package @sphereon/oid4vci-issuer-server

## [0.7.3](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.7.2...v0.7.3) (2023-09-30)

### Bug Fixes

- allow token endpoint to be defined in metadata without triggering logic for external AS ([d99304c](https://github.com/Sphereon-Opensource/OID4VC/commit/d99304cd02b92974785f516e8bd82900cc3e0925))

## [0.7.2](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.7.1...v0.7.2) (2023-09-28)

**Note:** Version bump only for package @sphereon/oid4vci-issuer-server

## [0.7.1](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.7.0...v0.7.1) (2023-09-28)

### Bug Fixes

- Better match credential offer types and formats onto issuer metadata ([4044c21](https://github.com/Sphereon-Opensource/OID4VC/commit/4044c2175b4cbee16f44c8bb5499bba249ca4993))

# [0.7.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.6.0...v0.7.0) (2023-08-19)

### Bug Fixes

- Revise well-known metadata retrieval for OID4VCI, OAuth 2.0 and OIDC. fixes [#62](https://github.com/Sphereon-Opensource/OID4VC/issues/62) ([a750cc7](https://github.com/Sphereon-Opensource/OID4VC/commit/a750cc76e084f12aeb58f2b1ac44b1bb5e69b5ae))

### Features

- Integrate ssi-express-support to allow for future authn/authz. Also moved endpoints to functions, so solutions can include their own set of endpoints ([c749aba](https://github.com/Sphereon-Opensource/OID4VC/commit/c749ababd4bec567d6aeeda49b76f195ec792201))

# [0.6.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.4.0...v0.6.0) (2023-06-24)

### Bug Fixes

- Fix issue with deleting session when imported in other projects ([4656c29](https://github.com/Sphereon-Opensource/OID4VC/commit/4656c292cf68c141e0facb852ff97947bd38dfa3))
- Many v11 fixes on server and client side ([08be1ed](https://github.com/Sphereon-Opensource/OID4VC/commit/08be1ed009fb80e910cffa2e4cf376758798b27e))
- prettier, plus some type casting in test/mock files for v9 ([162af38](https://github.com/Sphereon-Opensource/OID4VC/commit/162af3828b3dc826dc3cd5adffe3dab61925ad33))

### Features

- Add status support to sessions ([02c7eaf](https://github.com/Sphereon-Opensource/OID4VC/commit/02c7eaf69af441e15c6302a9c0f2874d54066b32))
- Add support for alg, kid, did, did document to Jwt Verification callback so we can ensure to set proper values in the resulting VC. ([62dd947](https://github.com/Sphereon-Opensource/OID4VC/commit/62dd947d0e09360719e6f704db33d766dff2363a))
- Add supported flow type detection ([100f9e6](https://github.com/Sphereon-Opensource/OID4VC/commit/100f9e6ccd7c53353f2876be81df4d6e3f7efde4))
- Add VCI Issuer ([5cab075](https://github.com/Sphereon-Opensource/OID4VC/commit/5cab07534e7a8b340f7a05343f56fbf091d64738))
- added optional issuer callback to parameters of issueCredentialFromIssueRequest ([a7a9e4a](https://github.com/Sphereon-Opensource/OID4VC/commit/a7a9e4a99d41fa3647482372b36d23c1595ae80f))
- added support for creating offer deeplink from object and test it. plus some refactors ([a87dcb1](https://github.com/Sphereon-Opensource/OID4VC/commit/a87dcb1ec10ea26a221d61ec0ffd4b4e098a594f))
- Ass support to provide credential input data to the issuer whilst creating the offer to be used with a credential data supplier ([03d3e46](https://github.com/Sphereon-Opensource/OID4VC/commit/03d3e46ab44b2e924320b6aed213c88d2ad161db))
- created another module for rest api and moved the dependencies from issuer module to issuer-rest ([38849af](https://github.com/Sphereon-Opensource/OID4VC/commit/38849afcc1fab1f679719bbd762316cec91af0ff))
- Issuer credential offer and more fixes/features ([0bbe17c](https://github.com/Sphereon-Opensource/OID4VC/commit/0bbe17c13de4df95e2fd79b3470a746cc7a5374a))
- Support data supplier callback ([1c49cc8](https://github.com/Sphereon-Opensource/OID4VC/commit/1c49cc80cfd83115956c7e9a040e12e814724e72))
