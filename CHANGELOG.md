# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# [0.15.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.14.0...v0.15.0) (2024-07-15)

### Bug Fixes

- add openid federation jwtVerifier ([a5755ff](https://github.com/Sphereon-Opensource/OID4VCI/commit/a5755ffc5244f1ae72d9ad160c2271de07202ac1))
- build ([2da9205](https://github.com/Sphereon-Opensource/OID4VCI/commit/2da92051cb6387e6c10dd0ff2767aeeddab17dd9))
- build ([84aba5e](https://github.com/Sphereon-Opensource/OID4VCI/commit/84aba5e7cc9aca7b597f24c907dc717be45768d7))
- remove outdated docs ([31731e7](https://github.com/Sphereon-Opensource/OID4VCI/commit/31731e7628a93a1f749600ee138d2470a5048353))
- siop-oid4vp build order ([dacf629](https://github.com/Sphereon-Opensource/OID4VCI/commit/dacf629be63f130c0f027deea6dfdc988eaa3c1b))

### Features

- add siop-oid4vp package ([6bc76dd](https://github.com/Sphereon-Opensource/OID4VCI/commit/6bc76dd2e4843e0acf07fc44c4c0c247496d1973))
- did-auth-siop-adapter ([32ec2fc](https://github.com/Sphereon-Opensource/OID4VCI/commit/32ec2fc27a22cd069dc12fe011debef7f870cf5d))
- update pnpm-lock.yaml ([158fb23](https://github.com/Sphereon-Opensource/OID4VCI/commit/158fb23152a5f8e891cbaeb5904947bb1cacf13e))

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
- test added ([f655bf0](https://github.com/Sphereon-Opensource/OID4VCI/commit/f655bf063128e94e0f6e4b54a2437ea975bc0d34))
- test added ([19b0704](https://github.com/Sphereon-Opensource/OID4VCI/commit/19b07046aaf213c3feb4f4b8c61f4eb97f8504cc))

### Features

- add get types from offer function to get the types from multiple versions of credential offers ([b966d8c](https://github.com/Sphereon-Opensource/OID4VCI/commit/b966d8c75bb3df36e816706b961e749b86ae1586))
- Add support for jwt-bearer client assertions in access token ([ab4905c](https://github.com/Sphereon-Opensource/OID4VCI/commit/ab4905ce7b4465b0c8adce6140209fb2c39f1469))
- added a facade for CredentialRequestClientBuilder and adjusted the tests ([30cddd3](https://github.com/Sphereon-Opensource/OID4VCI/commit/30cddd3af544e97047d27f48d1d76ce16f80a79b))
- added mock data for metadata draft 13 and added some tests for it ([5439a02](https://github.com/Sphereon-Opensource/OID4VCI/commit/5439a02483c16666629912152dd3618536f51bf2))
- added x5c support and made sure that we support request-responses without dids ([27bc1d9](https://github.com/Sphereon-Opensource/OID4VCI/commit/27bc1d9522fa74d8016dced63fa415efb6c4eebc))
- Allow to pass in custom access token request params ([1a469f9](https://github.com/Sphereon-Opensource/OID4VCI/commit/1a469f9f1f07dc54facf831b3336eb706cb0fe7a))

# [0.12.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.10.3...v0.12.0) (2024-06-19)

### Bug Fixes

- (WIP) fixed all the build errors ([e522a3d](https://github.com/Sphereon-Opensource/OID4VCI/commit/e522a3dd5821fb710211e35c8871f89772b672a0))
- (WIP) refactored and fixed build. still have to fix 33 test cases that are failing ([ff88a64](https://github.com/Sphereon-Opensource/OID4VCI/commit/ff88a647574baa9813939c296342cc112d00237f))
- (WIP) refactored and fixed build. still have to fix 8 test cases that are failing ([d8c2c4f](https://github.com/Sphereon-Opensource/OID4VCI/commit/d8c2c4fa8d73ea14a0faa823a394cde23733db8f))
- (WIP) refactored and fixed parts of the logic for v1_0_13. ([06117c0](https://github.com/Sphereon-Opensource/OID4VCI/commit/06117c0fd9a06170284ce5a89075d5b12fcd7d7b))
- (WIP) skipped failing tests and made comment to fix them ([16f1673](https://github.com/Sphereon-Opensource/OID4VCI/commit/16f1673bd30b43ce1b9209650e7b6be5e1f2c237))
- add back missing authz url getter ([6870fce](https://github.com/Sphereon-Opensource/OID4VCI/commit/6870fcead5921ca1cddef5fb418b8e3a2976e1e4))
- added back optional vct to CredentialConfigurationSupportedV1_0_13 for sd-jwt ([88341ef](https://github.com/Sphereon-Opensource/OID4VCI/commit/88341ef186c5c2842bf16729ab5c02fae9f22999))
- added back the isEbsi function to the new version's OpenID4VCIClient ([479bea7](https://github.com/Sphereon-Opensource/OID4VCI/commit/479bea791e2d82a1e564e08a569f4caf205e1cc1))
- added generic union types for frequently used types ([72474d6](https://github.com/Sphereon-Opensource/OID4VCI/commit/72474d6b95d58914d31ee36875feace8f0432942))
- added generic union types for frequently used types ([f10d0b2](https://github.com/Sphereon-Opensource/OID4VCI/commit/f10d0b22c4a1c4f6d57fe21d5a7d659f35a3fc27))
- allow to set client_id ([d51bf25](https://github.com/Sphereon-Opensource/OID4VCI/commit/d51bf2530e0a352ad3a7bfd12977ae6bc8001deb))
- changed the accepting type in VcIssuer ([125cb81](https://github.com/Sphereon-Opensource/OID4VCI/commit/125cb81b28ec153046fb7b8378e49bca43e2d96e))
- changed the if param in the assertAlphanumericPin ([5655859](https://github.com/Sphereon-Opensource/OID4VCI/commit/5655859121ed166a7190845083b9b26a8ea485ce))
- changed the logic for pin validation ([b8bb359](https://github.com/Sphereon-Opensource/OID4VCI/commit/b8bb3591ea704a777cfe057920edc8cd61faf3ef))
- Comparison of request subject signing with response was not normalized for a comparison ([cd72dc6](https://github.com/Sphereon-Opensource/OID4VCI/commit/cd72dc698108cb1baca9e00c37aa4e6b519a6985))
- Ensure we have a single client that handles both v13 and v11 and lower ([eadbba0](https://github.com/Sphereon-Opensource/OID4VCI/commit/eadbba03ddb6e9e32b69bb3a4d9eb9ca8ac2d260))
- fixed ClientIssuerIT.spec ([c5be065](https://github.com/Sphereon-Opensource/OID4VCI/commit/c5be06583048dd8b1e80e60eb1b290c07e0e5bc9))
- fixed createCredentialOfferURI signature ([2856644](https://github.com/Sphereon-Opensource/OID4VCI/commit/2856644324e3e65a2b6899c127f425e79599255b))
- fixed failing test cases ([690b02b](https://github.com/Sphereon-Opensource/OID4VCI/commit/690b02b655ef021355870dd92605dc15f2d8ac06))
- fixed sd jwt test with version 13 ([dcf7439](https://github.com/Sphereon-Opensource/OID4VCI/commit/dcf743945bcd53436e0758b1604e2a31d37a39fe))
- fixed some issue in the IssuerMetadataUtils ([8a6c16f](https://github.com/Sphereon-Opensource/OID4VCI/commit/8a6c16f39fdee838d935edbc46c6842b628f08b7))
- fixed some issue in the IssuerMetadataUtils plus added some unittests for it ([d348641](https://github.com/Sphereon-Opensource/OID4VCI/commit/d348641523d786d354fff3dfe75dbdda18e2d550))
- fixed some test cases ([ccac046](https://github.com/Sphereon-Opensource/OID4VCI/commit/ccac04640a7fc950d8e2f98d932acdf2f896a791))
- fixed test type mismatch ([215227e](https://github.com/Sphereon-Opensource/OID4VCI/commit/215227efa09088957f4d57dd47654fa1ff9ff78a))
- fixed test type mismatch ([ca32202](https://github.com/Sphereon-Opensource/OID4VCI/commit/ca3220215a46f514f3a1b271cfd22505ee2e6ad0))
- fixed tests plus prettier ([fc8cdf0](https://github.com/Sphereon-Opensource/OID4VCI/commit/fc8cdf08fa315419d8eaa6a51db68ad5d3fe9305))
- fixed the failing test for the credentialOfferUri ([a8ac2e3](https://github.com/Sphereon-Opensource/OID4VCI/commit/a8ac2e3421009189580c2098c1d8f96038914447))
- fixed the logic in creating credentialOffer uri ([53bce06](https://github.com/Sphereon-Opensource/OID4VCI/commit/53bce06da7ea9e0cec545d5da7f4585fe67be050))
- fixed the regex for pin ([d3b2f0c](https://github.com/Sphereon-Opensource/OID4VCI/commit/d3b2f0c23b74ceb031d1e812847c9bf20ee17ae5))
- fixed type mismatch in some files ([a2b3c22](https://github.com/Sphereon-Opensource/OID4VCI/commit/a2b3c2294331bceea8c39228b9b3da1c385d01cd))
- fixes after merge with CWALL-199 ([af967a9](https://github.com/Sphereon-Opensource/OID4VCI/commit/af967a96370f6dce8b9afad296fc2ff1c557dd84))
- fixes for PAR. Several things were missing, wrong. Higly likely this is a problem for non PAR flows as well ([9ed5064](https://github.com/Sphereon-Opensource/OID4VCI/commit/9ed506466413b6fdb5df7bff50accf3a7a1ad874))
- for pin in IssuerTokenServer ([354e8ad](https://github.com/Sphereon-Opensource/OID4VCI/commit/354e8adace36ef57f684ec8f69ce7cca56632198))
- MetadataClient for version 13 and added better type distinction. added credential_definition to credential metadata of v13 ([e39bf71](https://github.com/Sphereon-Opensource/OID4VCI/commit/e39bf71625c2a66821061ece7625f0b08f1c0ad2))
- No response type set on authz code after using PAR ([5da243e](https://github.com/Sphereon-Opensource/OID4VCI/commit/5da243e85207919d51b4af6b364fc2250a90bb09))
- set client_id on authorization url ([599ca9e](https://github.com/Sphereon-Opensource/OID4VCI/commit/599ca9ecec502738e227c9175663cd9814ac1d39))
- set client_id on authorization url ([04e7cb8](https://github.com/Sphereon-Opensource/OID4VCI/commit/04e7cb8d60bddca7cea7d8ec04f3072ef989a2c3))

### Features

- Add wallet signing support to VCI and notification support ([c4d3483](https://github.com/Sphereon-Opensource/OID4VCI/commit/c4d34836fb4923c98e7743221978c902c8427f2a))
- added setDefaultTokenEndpoint to VcIssuer constructor ([f16affc](https://github.com/Sphereon-Opensource/OID4VCI/commit/f16affc7a77847e24443930b0dd8f87f5533b61a))
- added setDefaultTokenEndpoint to VcIssuerBuilder ([96608ec](https://github.com/Sphereon-Opensource/OID4VCI/commit/96608ec72dcbf1f66e30b1ead8d363836db5d7d3))
- added token_endpoint to the metadata ([72f2988](https://github.com/Sphereon-Opensource/OID4VCI/commit/72f2988a0837e53f0a01cc40b88fdeb2f948627a))
- created special type for CredentialRequest v1_0_13 and fixed the tests for it ([25a6051](https://github.com/Sphereon-Opensource/OID4VCI/commit/25a6051ed0bb096c2249f24cd054c1a7aec97f61))
- expose functions for experimental subject issuer support ([c4adecc](https://github.com/Sphereon-Opensource/OID4VCI/commit/c4adeccdbde6b42a7df85dfbdcb821f2fab8b819))
- Unify how we get types from different spec versions ([449364b](https://github.com/Sphereon-Opensource/OID4VCI/commit/449364b49db4eaf5b847d5124687f9a3cd4bbc40))

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
- type for cred request ldp ([dbbe447](https://github.com/Sphereon-Opensource/OID4VCI/commit/dbbe44784f60234897c1b9ccdac09259a1226066))

# [0.10.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.9.0...v0.10.0) (2024-02-29)

### Bug Fixes

- enum type ([c39d8e1](https://github.com/Sphereon-Opensource/OID4VCI/commit/c39d8e1d0b10f6f683dbd229c14e6299a9163e1c))
- Extend Alg enum to allow for more algorithms. refs [#88](https://github.com/Sphereon-Opensource/OID4VCI/issues/88) ([6e76f57](https://github.com/Sphereon-Opensource/OID4VCI/commit/6e76f5759d2cf989f246ed8a4d45e6c5bd2cb06f))

### Features

- Open the signing algorithm list in the credential issuance process, refs [#88](https://github.com/Sphereon-Opensource/OID4VCI/issues/88) ([d9b17af](https://github.com/Sphereon-Opensource/OID4VCI/commit/d9b17af8098f55b688891de5e536fa95560ef8af))

# [0.9.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.8.1...v0.9.0) (2024-02-16)

### Bug Fixes

- Add back jwt_vc format support for older versions ([9f06ab1](https://github.com/Sphereon-Opensource/OID4VCI/commit/9f06ab1e0efef89848fb6e6a2b80ed874717e580))
- add sd-jwt to issuer callback ([93b1242](https://github.com/Sphereon-Opensource/OID4VCI/commit/93b1242d99dc21400c337b2f552a9f2da9da375c))
- disable awesome-qr in rn ([3daf0d3](https://github.com/Sphereon-Opensource/OID4VCI/commit/3daf0d3e59b37c8ac91aa050b3a7cf1ff49cbfc3))
- Do not set a default redirect_uri, unless no authorization request options are set at all ([6c96089](https://github.com/Sphereon-Opensource/OID4VCI/commit/6c96089f1d328c60cd040f34a3d06ae3b0df392b))
- Do not set default client_id ([7a1afbc](https://github.com/Sphereon-Opensource/OID4VCI/commit/7a1afbcee3de7c7b0dbe3e32330f0a96e1dcfa1e))
- Do not sort credential types, as issuers might rely on their order ([59fba74](https://github.com/Sphereon-Opensource/OID4VCI/commit/59fba745091ef0c69a46aed1a4f7faec2416c2bd))
- Fix uri to json conversion when no required params are provided ([36a70ca](https://github.com/Sphereon-Opensource/OID4VCI/commit/36a70ca634c1caf92555745108ea07c35570b423))
- opts passed to getCredentialOfferEndpoint() ([923b8b4](https://github.com/Sphereon-Opensource/OID4VCI/commit/923b8b4a74394788a8756211d1491612e20f2a9f))
- **sd-jwt:** cnf instead of kid ([510a4e8](https://github.com/Sphereon-Opensource/OID4VCI/commit/510a4e856c14d5daf933b60ba6d945deadf68d1c))
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
- ldp issuance ([bf8865a](https://github.com/Sphereon-Opensource/OID4VCI/commit/bf8865a93ebf7b1f3150da815137e2b945e3e8ec))
- Make sure redirect_uri is the same for authorization and token endpoint when used and made redirect_uri optional. The redirect_uri is automatically passed to the token request in case one was used for authorization ([394fcb7](https://github.com/Sphereon-Opensource/OID4VCI/commit/394fcb71d1ac9557685e323e6b8bf4afa7d1b910))
- PAR improvements ([99f55c2](https://github.com/Sphereon-Opensource/OID4VCI/commit/99f55c23e907022954b0eb169e276f3ef9ffb8ae))
- PKCE support improvements. ([5d5cb06](https://github.com/Sphereon-Opensource/OID4VCI/commit/5d5cb060fda0790641c1b0d8d513af16ac041970))
- Support sd-jwt 0.2.0 library ([77c9c24](https://github.com/Sphereon-Opensource/OID4VCI/commit/77c9c246ac994dff1b0ca80eb42819bf9bb1844a))

## [0.8.1](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.7.3...v0.8.1) (2023-10-14)

### Features

- Allow for authorized code flows. Removes the param to determine the flow, as that is determined from the credential offer itself ([a78e1fc](https://github.com/Sphereon-Opensource/OID4VCI/commit/a78e1fc25e717cb240f2d753632595474f9b64da))
- Allow for authorized code flows. Removes the param to determine the flow, as that is determined from the credential offer itself. Thanks to https://github.com/linasi for the PR ([861ee87](https://github.com/Sphereon-Opensource/OID4VCI/commit/861ee87e190d023df84d726e0d860a4621698967))

## [0.7.3](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.7.2...v0.7.3) (2023-09-30)

### Bug Fixes

- allow token endpoint to be defined in metadata without triggering logic for external AS ([d99304c](https://github.com/Sphereon-Opensource/OID4VCI/commit/d99304cd02b92974785f516e8bd82900cc3e0925))

## [0.7.2](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.7.1...v0.7.2) (2023-09-28)

### Bug Fixes

- id lookup against server metadata not working ([592ec4b](https://github.com/Sphereon-Opensource/OID4VCI/commit/592ec4b837898eb3022d19479d79b6065e7a0d9e))

## [0.7.1](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.7.0...v0.7.1) (2023-09-28)

### Bug Fixes

- Better match credential offer types and formats onto issuer metadata ([4044c21](https://github.com/Sphereon-Opensource/OID4VCI/commit/4044c2175b4cbee16f44c8bb5499bba249ca4993))
- clearinterval ([214e3c6](https://github.com/Sphereon-Opensource/OID4VCI/commit/214e3c6d7ced9b27c50186db8ed876330230a6a5))
- Fix credential offer matching against metadata ([3c23bab](https://github.com/Sphereon-Opensource/OID4VCI/commit/3c23bab83569e04a4b5846fed83ce00d68e8ddce))
- Fix credential offer matching against metadata ([b79027f](https://github.com/Sphereon-Opensource/OID4VCI/commit/b79027fe601ecccb1373ba399419e14f5ec2d7ff))
- relax auth_endpoint handling. Doesn't have to be available when doing pre-auth flow. Client handles errors anyway in case of auth/par flow ([ce39958](https://github.com/Sphereon-Opensource/OID4VCI/commit/ce39958f21f82243f26111fd14bd2443517eef9c))
- relax auth_endpoint handling. Doesn't have to be available when doing pre-auth flow. Client handles errors anyway in case of auth/par flow ([cb5f9c1](https://github.com/Sphereon-Opensource/OID4VCI/commit/cb5f9c1c12285508c6d403814d032e8883a59e7d))

# [0.7.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.6.0...v0.7.0) (2023-08-19)

### Bug Fixes

- fix credential request properties ([0037025](https://github.com/Sphereon-Opensource/OID4VCI/commit/0037025ef27d3a1fa7c68954b1f87e660ef0c82c))
- Revise well-known metadata retrieval for OID4VCI, OAuth 2.0 and OIDC. fixes [#62](https://github.com/Sphereon-Opensource/OID4VCI/issues/62) ([a750cc7](https://github.com/Sphereon-Opensource/OID4VCI/commit/a750cc76e084f12aeb58f2b1ac44b1bb5e69b5ae))

### Features

- Integrate ssi-express-support to allow for future authn/authz. Also moved endpoints to functions, so solutions can include their own set of endpoints ([c749aba](https://github.com/Sphereon-Opensource/OID4VCI/commit/c749ababd4bec567d6aeeda49b76f195ec792201))

# [0.6.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.4.0...v0.6.0) (2023-06-24)

### Bug Fixes

- added a couple of todos for handling v11, plus changed the getIssuer method to throw exception if nothing is found, and some other pr notes ([091786e](https://github.com/Sphereon-Opensource/OID4VCI/commit/091786e31246da16f6c9385fc13e7fd3e01664dc))
- added CredentialOffer to exports of client ([5cc5ab1](https://github.com/Sphereon-Opensource/OID4VCI/commit/5cc5ab10a4b5eb9c1741dc639f08d3613f9f45ea))
- added disable eslint comments in three places ([0e3ffdb](https://github.com/Sphereon-Opensource/OID4VCI/commit/0e3ffdb3a434e142d3bd8d0e04ca0b2b0f8f73e3))
- deleted wrong import and fixed the usage ([fc17946](https://github.com/Sphereon-Opensource/OID4VCI/commit/fc179469fa0d1b3669c454632aef03fa0f8d4119))
- Fix issue with deleting session when imported in other projects ([4656c29](https://github.com/Sphereon-Opensource/OID4VCI/commit/4656c292cf68c141e0facb852ff97947bd38dfa3))
- made v1_0.09 types strict and added a few utility methods to it for ease of access ([9391f31](https://github.com/Sphereon-Opensource/OID4VCI/commit/9391f317ee41068b823901036c3ac7d4b33ce6dd))
- Many v11 fixes on server and client side ([08be1ed](https://github.com/Sphereon-Opensource/OID4VCI/commit/08be1ed009fb80e910cffa2e4cf376758798b27e))
- PAR objects where in the wrong locations and one had a wrong name ([24f98e7](https://github.com/Sphereon-Opensource/OID4VCI/commit/24f98e75137cf70595753cbcf77159584d7ebe08))
- prettier, plus some type casting in test/mock files for v9 ([162af38](https://github.com/Sphereon-Opensource/OID4VCI/commit/162af3828b3dc826dc3cd5adffe3dab61925ad33))
- removed type support for mso_mdoc ([867073c](https://github.com/Sphereon-Opensource/OID4VCI/commit/867073ccf3612e6ad869dbc662c791b292fe06ca))
- rename jwt_vc_json_ld to jwt_vc_json-ld ([a366bef](https://github.com/Sphereon-Opensource/OID4VCI/commit/a366bef5a7bda052de6ffa201186e02b70447a79))

### Features

- Add status support to sessions ([a1fa6a4](https://github.com/Sphereon-Opensource/OID4VCI/commit/a1fa6a4c569c36951e1a7cedb632aa0b22104448))
- Add status support to sessions ([02c7eaf](https://github.com/Sphereon-Opensource/OID4VCI/commit/02c7eaf69af441e15c6302a9c0f2874d54066b32))
- Add support for alg, kid, did, did document to Jwt Verification callback so we can ensure to set proper values in the resulting VC. ([62dd947](https://github.com/Sphereon-Opensource/OID4VCI/commit/62dd947d0e09360719e6f704db33d766dff2363a))
- Add support for background_image for credentials ([a3c2561](https://github.com/Sphereon-Opensource/OID4VCI/commit/a3c2561c7596ad7303467528d92cdaa033c7af94))
- Add supported flow type detection ([100f9e6](https://github.com/Sphereon-Opensource/OID4VCI/commit/100f9e6ccd7c53353f2876be81df4d6e3f7efde4))
- Add VCI Issuer ([5cab075](https://github.com/Sphereon-Opensource/OID4VCI/commit/5cab07534e7a8b340f7a05343f56fbf091d64738))
- added (issuer) state to options for createCredentialOfferDeeplink ([bd1569c](https://github.com/Sphereon-Opensource/OID4VCI/commit/bd1569c8b8b1404d90db822ecc8925a2485e46ba))
- added api.ts for all the rest apis of the issuer ([907c05e](https://github.com/Sphereon-Opensource/OID4VCI/commit/907c05efc2045d2b4faec14a206214ae17f91e1d))
- added better support (and distinction) for types v1.0.09 and v1.0.11 ([f311258](https://github.com/Sphereon-Opensource/OID4VCI/commit/f31125865a3d63ce7719f790fc5ac74fea7f9ade))
- added callback function for issuing credentials ([c478788](https://github.com/Sphereon-Opensource/OID4VCI/commit/c478788d3d3d2414073eedddd9d43cc3d593ee1b))
- added error code invalid_scope ([e7864d9](https://github.com/Sphereon-Opensource/OID4VCI/commit/e7864d96476ae8ff21867646c0943975b773d7d5))
- added issuer callback to arguments of the issuer builder ([ed4fe7c](https://github.com/Sphereon-Opensource/OID4VCI/commit/ed4fe7cff1f717d5b667da70d43b58d04651334d))
- Added new mock data from actual issuers, fixed a small bug with v1_0_08 types, updated v1_0_08 types to support data from jff issuers ([a6b1eea](https://github.com/Sphereon-Opensource/OID4VCI/commit/a6b1eeaabc0f34cc13a79cf967a8c35a6d8dc7f5))
- Added new tests for CredentialRequestClient plus fixed a problem with CredentialOfferUtil. a CredentialRequest can have no issuer field ([50f2292](https://github.com/Sphereon-Opensource/OID4VCI/commit/50f22928426761cc3bf5d973d1f15fea407a9175))
- added optional issuer callback to parameters of issueCredentialFromIssueRequest ([a7a9e4a](https://github.com/Sphereon-Opensource/OID4VCI/commit/a7a9e4a99d41fa3647482372b36d23c1595ae80f))
- added support for creating credentialOffer deeplink based on a uri ([6822dfe](https://github.com/Sphereon-Opensource/OID4VCI/commit/6822dfec553f1ff6957bedb7875fa4d40a57c06e))
- added support for creating offer deeplink from object and test it. plus some refactors ([a87dcb1](https://github.com/Sphereon-Opensource/OID4VCI/commit/a87dcb1ec10ea26a221d61ec0ffd4b4e098a594f))
- added support for v8 in our types (partially) to make old logics work ([4b5abf1](https://github.com/Sphereon-Opensource/OID4VCI/commit/4b5abf16507bcde0d696ea3948f816d9a2de13c4))
- added utility method for recognizing v1.0.11 objects ([ed6436e](https://github.com/Sphereon-Opensource/OID4VCI/commit/ed6436e3bd22307fe9f7b4411ff3c8086ddb940c))
- added VcIssuer and builders related to that ([c2592a8](https://github.com/Sphereon-Opensource/OID4VCI/commit/c2592a8846061c5791050a76e522f50e21f617de))
- Ass support to provide credential input data to the issuer whilst creating the offer to be used with a credential data supplier ([03d3e46](https://github.com/Sphereon-Opensource/OID4VCI/commit/03d3e46ab44b2e924320b6aed213c88d2ad161db))
- beside the 'with' methods in the builder which will replace existing configuration for that field, I've added 'add' methods to add to existing configuration ([9d42152](https://github.com/Sphereon-Opensource/OID4VCI/commit/9d42152536fd6617bd5d8944fc6b07cb0e709473))
- created another module for rest api and moved the dependencies from issuer module to issuer-rest ([38849af](https://github.com/Sphereon-Opensource/OID4VCI/commit/38849afcc1fab1f679719bbd762316cec91af0ff))
- Issuer credential offer and more fixes/features ([0bbe17c](https://github.com/Sphereon-Opensource/OID4VCI/commit/0bbe17c13de4df95e2fd79b3470a746cc7a5374a))
- Support data supplier callback ([1c49cc8](https://github.com/Sphereon-Opensource/OID4VCI/commit/1c49cc80cfd83115956c7e9a040e12e814724e72))
- Translate v8 credentials_supported to v11 ([b06fa22](https://github.com/Sphereon-Opensource/OID4VCI/commit/b06fa221bed33e69aa76ae0234779f80314f2887))
