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

- add a test file to jarm ([1309fb7](https://github.com/Sphereon-Opensource/OID4VC/commit/1309fb791b4757a339e1d2bc263191a6f89e518c))
- feedback ([b119275](https://github.com/Sphereon-Opensource/OID4VC/commit/b1192751c7d72890bfb4d7822c10f39e24830422))
- session and state to correlationId mapping bugfixes ([c9b4d6f](https://github.com/Sphereon-Opensource/OID4VC/commit/c9b4d6f8df62a11d6235d75bee63deb352f66926))

### Features

- add jarm package ([4cb9259](https://github.com/Sphereon-Opensource/OID4VC/commit/4cb9259a5bb015a8ffca63d2873cc0baae2b1b8e))
- add jarm package ([9d6f07a](https://github.com/Sphereon-Opensource/OID4VC/commit/9d6f07a2e5ec282b1ffe6716786c80394395598d))
- mso mdoc handling ([d88df4f](https://github.com/Sphereon-Opensource/OID4VC/commit/d88df4fc9f4a704f9c4cf208a0b302dca4fc2d29))
- validate jarm metadata ([348d5bc](https://github.com/Sphereon-Opensource/OID4VC/commit/348d5bc05224afd54bfda03960a7599817fbc9d7))

# [0.16.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.15.1...v0.16.0) (2024-08-02)

### Bug Fixes

- add some dpop unit tests ([c24a898](https://github.com/Sphereon-Opensource/OID4VC/commit/c24a8985b8c788c5947b9493c1d74185a419d7f9))
- jwk thumprint using crypto.subtle ([56a291c](https://github.com/Sphereon-Opensource/OID4VC/commit/56a291c2a59c2966fdf428d7cf7e2e69389fd38b))
- nits ([1a54e69](https://github.com/Sphereon-Opensource/OID4VC/commit/1a54e6966da62e4796640dd73393fd0fdc5c76b4))
- prettier + eslint ([57c7592](https://github.com/Sphereon-Opensource/OID4VC/commit/57c7592f1cd787321d8ded8c89013076b428a9c8))
- rename common to oid4vc-common ([d89ac4f](https://github.com/Sphereon-Opensource/OID4VC/commit/d89ac4f4956e69dad5274b197912485665aeb97c))
- some last nits ([3c71599](https://github.com/Sphereon-Opensource/OID4VC/commit/3c715992fe8c52e32147c3bc0aaf7c2ea8fb9741))

### Features

- add additional dpop retry mechanisms ([a102854](https://github.com/Sphereon-Opensource/OID4VC/commit/a1028540432115f26677a860bf6bac10e630a1d9))
- address feedback part 2 ([01f6d4d](https://github.com/Sphereon-Opensource/OID4VC/commit/01f6d4d7884c7f49f4395f7ec9ba12ee9b0a8668))
- create common package ([d5b4b75](https://github.com/Sphereon-Opensource/OID4VC/commit/d5b4b75f036edcf8082e062214c036c9be934071))
- dpop support ([9202667](https://github.com/Sphereon-Opensource/OID4VC/commit/92026678c745b770957f5bae290ae7b456601fd2))
- incorporate feedback and fix tests ([c7c6af4](https://github.com/Sphereon-Opensource/OID4VC/commit/c7c6af464d9fda53b86c3095feca5705df9e92cc))
- incorporate feedback part1 ([f30475a](https://github.com/Sphereon-Opensource/OID4VC/commit/f30475a8c98f869ffe82e67f59231a4faf182a98))
- rename common to oid4vci-common ([9efbf32](https://github.com/Sphereon-Opensource/OID4VC/commit/9efbf32a68ae8b9b91be23c2fb07138181fe5af4))

## [0.15.1](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.15.0...v0.15.1) (2024-07-23)

### Bug Fixes

- oid4vci draft 13 typing ([6d0bfc9](https://github.com/Sphereon-Opensource/OID4VC/commit/6d0bfc9227b1120913b773904ef991757cb9282a))

# [0.15.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.14.0...v0.15.0) (2024-07-15)

### Features

- did-auth-siop-adapter ([32ec2fc](https://github.com/Sphereon-Opensource/OID4VC/commit/32ec2fc27a22cd069dc12fe011debef7f870cf5d))

# [0.14.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.13.0...v0.14.0) (2024-07-06)

### Features

- Enable tx_code support for the issuer, and properly handle both the old userPin and tx_code on the client side. fixes [#117](https://github.com/Sphereon-Opensource/OID4VC/issues/117) ([e54071c](https://github.com/Sphereon-Opensource/OID4VC/commit/e54071c65b00ef921acafa2c2c73707a3bc33a44))

# [0.13.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.12.0...v0.13.0) (2024-07-03)

### Bug Fixes

- Make sure we use 'JWT' as typ instead of the lower case version as suggested in the JWT RFC. ([1ff4e40](https://github.com/Sphereon-Opensource/OID4VC/commit/1ff4e40cefb183072951e3ede3f8b3a5842d645a))

### Features

- add get types from offer function to get the types from multiple versions of credential offers ([b966d8c](https://github.com/Sphereon-Opensource/OID4VC/commit/b966d8c75bb3df36e816706b961e749b86ae1586))
- Add support for jwt-bearer client assertions in access token ([ab4905c](https://github.com/Sphereon-Opensource/OID4VC/commit/ab4905ce7b4465b0c8adce6140209fb2c39f1469))
- added a facade for CredentialRequestClientBuilder and adjusted the tests ([30cddd3](https://github.com/Sphereon-Opensource/OID4VC/commit/30cddd3af544e97047d27f48d1d76ce16f80a79b))
- added x5c support and made sure that we support request-responses without dids ([27bc1d9](https://github.com/Sphereon-Opensource/OID4VC/commit/27bc1d9522fa74d8016dced63fa415efb6c4eebc))
- Allow to pass in custom access token request params ([1a469f9](https://github.com/Sphereon-Opensource/OID4VC/commit/1a469f9f1f07dc54facf831b3336eb706cb0fe7a))

# [0.12.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.10.3...v0.12.0) (2024-06-19)

### Bug Fixes

- (WIP) fixed all the build errors ([e522a3d](https://github.com/Sphereon-Opensource/OID4VC/commit/e522a3dd5821fb710211e35c8871f89772b672a0))
- (WIP) refactored and fixed build. still have to fix 33 test cases that are failing ([ff88a64](https://github.com/Sphereon-Opensource/OID4VC/commit/ff88a647574baa9813939c296342cc112d00237f))
- (WIP) refactored and fixed build. still have to fix 8 test cases that are failing ([d8c2c4f](https://github.com/Sphereon-Opensource/OID4VC/commit/d8c2c4fa8d73ea14a0faa823a394cde23733db8f))
- (WIP) refactored and fixed parts of the logic for v1_0_13. ([06117c0](https://github.com/Sphereon-Opensource/OID4VC/commit/06117c0fd9a06170284ce5a89075d5b12fcd7d7b))
- added back optional vct to CredentialConfigurationSupportedV1_0_13 for sd-jwt ([88341ef](https://github.com/Sphereon-Opensource/OID4VC/commit/88341ef186c5c2842bf16729ab5c02fae9f22999))
- added back the isEbsi function to the new version's OpenID4VCIClient ([479bea7](https://github.com/Sphereon-Opensource/OID4VC/commit/479bea791e2d82a1e564e08a569f4caf205e1cc1))
- added generic union types for frequently used types ([72474d6](https://github.com/Sphereon-Opensource/OID4VC/commit/72474d6b95d58914d31ee36875feace8f0432942))
- added generic union types for frequently used types ([f10d0b2](https://github.com/Sphereon-Opensource/OID4VC/commit/f10d0b22c4a1c4f6d57fe21d5a7d659f35a3fc27))
- Ensure we have a single client that handles both v13 and v11 and lower ([eadbba0](https://github.com/Sphereon-Opensource/OID4VC/commit/eadbba03ddb6e9e32b69bb3a4d9eb9ca8ac2d260))
- fixed some issue in the IssuerMetadataUtils ([8a6c16f](https://github.com/Sphereon-Opensource/OID4VC/commit/8a6c16f39fdee838d935edbc46c6842b628f08b7))
- fixed some issue in the IssuerMetadataUtils plus added some unittests for it ([d348641](https://github.com/Sphereon-Opensource/OID4VC/commit/d348641523d786d354fff3dfe75dbdda18e2d550))
- fixed type mismatch in some files ([a2b3c22](https://github.com/Sphereon-Opensource/OID4VC/commit/a2b3c2294331bceea8c39228b9b3da1c385d01cd))
- fixes after merge with CWALL-199 ([af967a9](https://github.com/Sphereon-Opensource/OID4VC/commit/af967a96370f6dce8b9afad296fc2ff1c557dd84))
- fixes for PAR. Several things were missing, wrong. Higly likely this is a problem for non PAR flows as well ([9ed5064](https://github.com/Sphereon-Opensource/OID4VC/commit/9ed506466413b6fdb5df7bff50accf3a7a1ad874))
- MetadataClient for version 13 and added better type distinction. added credential_definition to credential metadata of v13 ([e39bf71](https://github.com/Sphereon-Opensource/OID4VC/commit/e39bf71625c2a66821061ece7625f0b08f1c0ad2))
- set client_id on authorization url ([04e7cb8](https://github.com/Sphereon-Opensource/OID4VC/commit/04e7cb8d60bddca7cea7d8ec04f3072ef989a2c3))

### Features

- Add wallet signing support to VCI and notification support ([c4d3483](https://github.com/Sphereon-Opensource/OID4VC/commit/c4d34836fb4923c98e7743221978c902c8427f2a))
- created special type for CredentialRequest v1_0_13 and fixed the tests for it ([25a6051](https://github.com/Sphereon-Opensource/OID4VC/commit/25a6051ed0bb096c2249f24cd054c1a7aec97f61))
- expose functions for experimental subject issuer support ([c4adecc](https://github.com/Sphereon-Opensource/OID4VC/commit/c4adeccdbde6b42a7df85dfbdcb821f2fab8b819))
- Unify how we get types from different spec versions ([449364b](https://github.com/Sphereon-Opensource/OID4VC/commit/449364b49db4eaf5b847d5124687f9a3cd4bbc40))

## [0.10.3](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.10.2...v0.10.3) (2024-04-25)

**Note:** Version bump only for package @sphereon/oid4vci-common

## [0.10.1](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.10.0...v0.10.1) (2024-03-12)

### Bug Fixes

- type for cred request ldp ([dbbe447](https://github.com/Sphereon-Opensource/OID4VC/commit/dbbe44784f60234897c1b9ccdac09259a1226066))

# [0.10.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.9.0...v0.10.0) (2024-02-29)

### Bug Fixes

- enum type ([c39d8e1](https://github.com/Sphereon-Opensource/OID4VC/commit/c39d8e1d0b10f6f683dbd229c14e6299a9163e1c))
- Extend Alg enum to allow for more algorithms. refs [#88](https://github.com/Sphereon-Opensource/OID4VC/issues/88) ([6e76f57](https://github.com/Sphereon-Opensource/OID4VC/commit/6e76f5759d2cf989f246ed8a4d45e6c5bd2cb06f))

### Features

- Open the signing algorithm list in the credential issuance process, refs [#88](https://github.com/Sphereon-Opensource/OID4VC/issues/88) ([d9b17af](https://github.com/Sphereon-Opensource/OID4VC/commit/d9b17af8098f55b688891de5e536fa95560ef8af))

# [0.9.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.8.1...v0.9.0) (2024-02-16)

### Bug Fixes

- Add back jwt_vc format support for older versions ([9f06ab1](https://github.com/Sphereon-Opensource/OID4VC/commit/9f06ab1e0efef89848fb6e6a2b80ed874717e580))
- Do not set a default redirect_uri, unless no authorization request options are set at all ([6c96089](https://github.com/Sphereon-Opensource/OID4VC/commit/6c96089f1d328c60cd040f34a3d06ae3b0df392b))
- Do not set default client_id ([7a1afbc](https://github.com/Sphereon-Opensource/OID4VC/commit/7a1afbcee3de7c7b0dbe3e32330f0a96e1dcfa1e))
- Fix uri to json conversion when no required params are provided ([36a70ca](https://github.com/Sphereon-Opensource/OID4VC/commit/36a70ca634c1caf92555745108ea07c35570b423))

### Features

- Add deferred support ([99dc87d](https://github.com/Sphereon-Opensource/OID4VC/commit/99dc87d3748cb1f71aa67237b28b6c4bb667eb29))
- add sd-jwt support ([a37ef06](https://github.com/Sphereon-Opensource/OID4VC/commit/a37ef06d38fdc7a6d5acc372cd2da8935b4c414e))
- Add support to get a client id from an offer, and from state JWTs. EBSI for instance is using this ([f089116](https://github.com/Sphereon-Opensource/OID4VC/commit/f0891164a7a6863940c264afa386144a1e4ac19a))
- Allow to create an authorization request URL when initiating the OID4VCI client ([84ea215](https://github.com/Sphereon-Opensource/OID4VC/commit/84ea215c10da042417dabc1d30b2e3898b635bab))
- PAR improvements ([99f55c2](https://github.com/Sphereon-Opensource/OID4VC/commit/99f55c23e907022954b0eb169e276f3ef9ffb8ae))
- PKCE support improvements. ([5d5cb06](https://github.com/Sphereon-Opensource/OID4VC/commit/5d5cb060fda0790641c1b0d8d513af16ac041970))
- Support sd-jwt 0.2.0 library ([77c9c24](https://github.com/Sphereon-Opensource/OID4VC/commit/77c9c246ac994dff1b0ca80eb42819bf9bb1844a))

## [0.8.1](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.7.3...v0.8.1) (2023-10-14)

**Note:** Version bump only for package @sphereon/oid4vci-common

## [0.7.3](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.7.2...v0.7.3) (2023-09-30)

**Note:** Version bump only for package @sphereon/oid4vci-common

## [0.7.2](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.7.1...v0.7.2) (2023-09-28)

### Bug Fixes

- id lookup against server metadata not working ([592ec4b](https://github.com/Sphereon-Opensource/OID4VC/commit/592ec4b837898eb3022d19479d79b6065e7a0d9e))

## [0.7.1](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.7.0...v0.7.1) (2023-09-28)

### Bug Fixes

- Better match credential offer types and formats onto issuer metadata ([4044c21](https://github.com/Sphereon-Opensource/OID4VC/commit/4044c2175b4cbee16f44c8bb5499bba249ca4993))
- Fix credential offer matching against metadata ([3c23bab](https://github.com/Sphereon-Opensource/OID4VC/commit/3c23bab83569e04a4b5846fed83ce00d68e8ddce))
- Fix credential offer matching against metadata ([b79027f](https://github.com/Sphereon-Opensource/OID4VC/commit/b79027fe601ecccb1373ba399419e14f5ec2d7ff))
- relax auth_endpoint handling. Doesn't have to be available when doing pre-auth flow. Client handles errors anyway in case of auth/par flow ([cb5f9c1](https://github.com/Sphereon-Opensource/OID4VC/commit/cb5f9c1c12285508c6d403814d032e8883a59e7d))

# [0.7.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.6.0...v0.7.0) (2023-08-19)

### Bug Fixes

- fix credential request properties ([0037025](https://github.com/Sphereon-Opensource/OID4VC/commit/0037025ef27d3a1fa7c68954b1f87e660ef0c82c))
- Revise well-known metadata retrieval for OID4VCI, OAuth 2.0 and OIDC. fixes [#62](https://github.com/Sphereon-Opensource/OID4VC/issues/62) ([a750cc7](https://github.com/Sphereon-Opensource/OID4VC/commit/a750cc76e084f12aeb58f2b1ac44b1bb5e69b5ae))

### Features

- Integrate ssi-express-support to allow for future authn/authz. Also moved endpoints to functions, so solutions can include their own set of endpoints ([c749aba](https://github.com/Sphereon-Opensource/OID4VC/commit/c749ababd4bec567d6aeeda49b76f195ec792201))

# [0.6.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.4.0...v0.6.0) (2023-06-24)

### Bug Fixes

- added a couple of todos for handling v11, plus changed the getIssuer method to throw exception if nothing is found, and some other pr notes ([091786e](https://github.com/Sphereon-Opensource/OID4VC/commit/091786e31246da16f6c9385fc13e7fd3e01664dc))
- added disable eslint comments in three places ([0e3ffdb](https://github.com/Sphereon-Opensource/OID4VC/commit/0e3ffdb3a434e142d3bd8d0e04ca0b2b0f8f73e3))
- made v1_0.09 types strict and added a few utility methods to it for ease of access ([9391f31](https://github.com/Sphereon-Opensource/OID4VC/commit/9391f317ee41068b823901036c3ac7d4b33ce6dd))
- Many v11 fixes on server and client side ([08be1ed](https://github.com/Sphereon-Opensource/OID4VC/commit/08be1ed009fb80e910cffa2e4cf376758798b27e))
- PAR objects where in the wrong locations and one had a wrong name ([24f98e7](https://github.com/Sphereon-Opensource/OID4VC/commit/24f98e75137cf70595753cbcf77159584d7ebe08))
- prettier, plus some type casting in test/mock files for v9 ([162af38](https://github.com/Sphereon-Opensource/OID4VC/commit/162af3828b3dc826dc3cd5adffe3dab61925ad33))
- removed type support for mso_mdoc ([867073c](https://github.com/Sphereon-Opensource/OID4VC/commit/867073ccf3612e6ad869dbc662c791b292fe06ca))
- rename jwt_vc_json_ld to jwt_vc_json-ld ([a366bef](https://github.com/Sphereon-Opensource/OID4VC/commit/a366bef5a7bda052de6ffa201186e02b70447a79))

### Features

- Add status support to sessions ([02c7eaf](https://github.com/Sphereon-Opensource/OID4VC/commit/02c7eaf69af441e15c6302a9c0f2874d54066b32))
- Add support for alg, kid, did, did document to Jwt Verification callback so we can ensure to set proper values in the resulting VC. ([62dd947](https://github.com/Sphereon-Opensource/OID4VC/commit/62dd947d0e09360719e6f704db33d766dff2363a))
- Add support for background_image for credentials ([a3c2561](https://github.com/Sphereon-Opensource/OID4VC/commit/a3c2561c7596ad7303467528d92cdaa033c7af94))
- Add supported flow type detection ([100f9e6](https://github.com/Sphereon-Opensource/OID4VC/commit/100f9e6ccd7c53353f2876be81df4d6e3f7efde4))
- Add VCI Issuer ([5cab075](https://github.com/Sphereon-Opensource/OID4VC/commit/5cab07534e7a8b340f7a05343f56fbf091d64738))
- added better support (and distinction) for types v1.0.09 and v1.0.11 ([f311258](https://github.com/Sphereon-Opensource/OID4VC/commit/f31125865a3d63ce7719f790fc5ac74fea7f9ade))
- added callback function for issuing credentials ([c478788](https://github.com/Sphereon-Opensource/OID4VC/commit/c478788d3d3d2414073eedddd9d43cc3d593ee1b))
- added error code invalid_scope ([e7864d9](https://github.com/Sphereon-Opensource/OID4VC/commit/e7864d96476ae8ff21867646c0943975b773d7d5))
- Added new mock data from actual issuers, fixed a small bug with v1_0_08 types, updated v1_0_08 types to support data from jff issuers ([a6b1eea](https://github.com/Sphereon-Opensource/OID4VC/commit/a6b1eeaabc0f34cc13a79cf967a8c35a6d8dc7f5))
- Added new tests for CredentialRequestClient plus fixed a problem with CredentialOfferUtil. a CredentialRequest can have no issuer field ([50f2292](https://github.com/Sphereon-Opensource/OID4VC/commit/50f22928426761cc3bf5d973d1f15fea407a9175))
- added support for creating offer deeplink from object and test it. plus some refactors ([a87dcb1](https://github.com/Sphereon-Opensource/OID4VC/commit/a87dcb1ec10ea26a221d61ec0ffd4b4e098a594f))
- added support for v8 in our types (partially) to make old logics work ([4b5abf1](https://github.com/Sphereon-Opensource/OID4VC/commit/4b5abf16507bcde0d696ea3948f816d9a2de13c4))
- added utility method for recognizing v1.0.11 objects ([ed6436e](https://github.com/Sphereon-Opensource/OID4VC/commit/ed6436e3bd22307fe9f7b4411ff3c8086ddb940c))
- added VcIssuer and builders related to that ([c2592a8](https://github.com/Sphereon-Opensource/OID4VC/commit/c2592a8846061c5791050a76e522f50e21f617de))
- Ass support to provide credential input data to the issuer whilst creating the offer to be used with a credential data supplier ([03d3e46](https://github.com/Sphereon-Opensource/OID4VC/commit/03d3e46ab44b2e924320b6aed213c88d2ad161db))
- Issuer credential offer and more fixes/features ([0bbe17c](https://github.com/Sphereon-Opensource/OID4VC/commit/0bbe17c13de4df95e2fd79b3470a746cc7a5374a))
- Support data supplier callback ([1c49cc8](https://github.com/Sphereon-Opensource/OID4VC/commit/1c49cc80cfd83115956c7e9a040e12e814724e72))
- Translate v8 credentials_supported to v11 ([b06fa22](https://github.com/Sphereon-Opensource/OID4VC/commit/b06fa221bed33e69aa76ae0234779f80314f2887))
