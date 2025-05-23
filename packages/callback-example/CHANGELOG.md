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

- Fix for when credential_configuration_ids is being used together with credentials_supported ([f696867](https://github.com/Sphereon-Opensource/OID4VC/commit/f6968677ccd10c2ce8eb8484443971102547e8a2))
- fix single vp_token being send is an array ([e496ca2](https://github.com/Sphereon-Opensource/OID4VC/commit/e496ca259319f2f6fa327cf0efe71e0a8f0dc5f1))
- session and state to correlationId mapping bugfixes ([c9b4d6f](https://github.com/Sphereon-Opensource/OID4VC/commit/c9b4d6f8df62a11d6235d75bee63deb352f66926))
- update deps ([ca61afe](https://github.com/Sphereon-Opensource/OID4VC/commit/ca61afe183f8387e591a17dbb9de894c1f1aad0e))

### Features

- Expose DPoP support also to main clients, instead of only to the access token client and credential request client ([e2cc7f6](https://github.com/Sphereon-Opensource/OID4VC/commit/e2cc7f6abf553a705786d9c3fdc9aa28e53cac1c))

# [0.16.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.15.1...v0.16.0) (2024-08-02)

### Bug Fixes

- rename common to oid4vc-common ([d89ac4f](https://github.com/Sphereon-Opensource/OID4VC/commit/d89ac4f4956e69dad5274b197912485665aeb97c))

### Features

- create common package ([d5b4b75](https://github.com/Sphereon-Opensource/OID4VC/commit/d5b4b75f036edcf8082e062214c036c9be934071))

## [0.15.1](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.15.0...v0.15.1) (2024-07-23)

**Note:** Version bump only for package @sphereon/oid4vci-callback-example

# [0.15.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.14.0...v0.15.0) (2024-07-15)

**Note:** Version bump only for package @sphereon/oid4vci-callback-example

# [0.14.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.13.0...v0.14.0) (2024-07-06)

### Features

- Enable tx_code support for the issuer, and properly handle both the old userPin and tx_code on the client side. fixes [#117](https://github.com/Sphereon-Opensource/OID4VC/issues/117) ([e54071c](https://github.com/Sphereon-Opensource/OID4VC/commit/e54071c65b00ef921acafa2c2c73707a3bc33a44))

# [0.13.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.12.0...v0.13.0) (2024-07-03)

### Bug Fixes

- Make sure we use 'JWT' as typ instead of the lower case version as suggested in the JWT RFC. ([1ff4e40](https://github.com/Sphereon-Opensource/OID4VC/commit/1ff4e40cefb183072951e3ede3f8b3a5842d645a))
- test added ([19b0704](https://github.com/Sphereon-Opensource/OID4VC/commit/19b07046aaf213c3feb4f4b8c61f4eb97f8504cc))

### Features

- added a facade for CredentialRequestClientBuilder and adjusted the tests ([30cddd3](https://github.com/Sphereon-Opensource/OID4VC/commit/30cddd3af544e97047d27f48d1d76ce16f80a79b))

# [0.12.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.10.3...v0.12.0) (2024-06-19)

### Bug Fixes

- (WIP) fixed all the build errors ([e522a3d](https://github.com/Sphereon-Opensource/OID4VC/commit/e522a3dd5821fb710211e35c8871f89772b672a0))
- (WIP) refactored and fixed build. still have to fix 33 test cases that are failing ([ff88a64](https://github.com/Sphereon-Opensource/OID4VC/commit/ff88a647574baa9813939c296342cc112d00237f))
- (WIP) refactored and fixed build. still have to fix 8 test cases that are failing ([d8c2c4f](https://github.com/Sphereon-Opensource/OID4VC/commit/d8c2c4fa8d73ea14a0faa823a394cde23733db8f))
- (WIP) refactored and fixed parts of the logic for v1_0_13. ([06117c0](https://github.com/Sphereon-Opensource/OID4VC/commit/06117c0fd9a06170284ce5a89075d5b12fcd7d7b))
- fixed some test cases ([ccac046](https://github.com/Sphereon-Opensource/OID4VC/commit/ccac04640a7fc950d8e2f98d932acdf2f896a791))
- fixes for PAR. Several things were missing, wrong. Higly likely this is a problem for non PAR flows as well ([9ed5064](https://github.com/Sphereon-Opensource/OID4VC/commit/9ed506466413b6fdb5df7bff50accf3a7a1ad874))
- MetadataClient for version 13 and added better type distinction. added credential_definition to credential metadata of v13 ([e39bf71](https://github.com/Sphereon-Opensource/OID4VC/commit/e39bf71625c2a66821061ece7625f0b08f1c0ad2))

### Features

- Add wallet signing support to VCI and notification support ([c4d3483](https://github.com/Sphereon-Opensource/OID4VC/commit/c4d34836fb4923c98e7743221978c902c8427f2a))
- created special type for CredentialRequest v1_0_13 and fixed the tests for it ([25a6051](https://github.com/Sphereon-Opensource/OID4VC/commit/25a6051ed0bb096c2249f24cd054c1a7aec97f61))

## [0.10.3](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.10.2...v0.10.3) (2024-04-25)

### Bug Fixes

- issuance and expiration sometimes used milliseconds instead of seconds ([afc2a8a](https://github.com/Sphereon-Opensource/OID4VC/commit/afc2a8a9171bae7e30ed7c7d9bd094d8cbd49b80))

## [0.10.2](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.10.1...v0.10.2) (2024-03-13)

### Bug Fixes

- use seconds for all expires in values ([39bde8f](https://github.com/Sphereon-Opensource/OID4VC/commit/39bde8f835a96509727f54cbdf2d4db9fa08df8b))

## [0.10.1](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.10.0...v0.10.1) (2024-03-12)

### Bug Fixes

- await session state updates ([963fb88](https://github.com/Sphereon-Opensource/OID4VC/commit/963fb88201af15ccfce189bb3ac7eedc846833d0))

# [0.10.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.9.0...v0.10.0) (2024-02-29)

**Note:** Version bump only for package @sphereon/oid4vci-callback-example

# [0.9.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.8.1...v0.9.0) (2024-02-16)

### Bug Fixes

- add sd-jwt to issuer callback ([93b1242](https://github.com/Sphereon-Opensource/OID4VC/commit/93b1242d99dc21400c337b2f552a9f2da9da375c))

### Features

- add sd-jwt support ([a37ef06](https://github.com/Sphereon-Opensource/OID4VC/commit/a37ef06d38fdc7a6d5acc372cd2da8935b4c414e))
- Support sd-jwt 0.2.0 library ([77c9c24](https://github.com/Sphereon-Opensource/OID4VC/commit/77c9c246ac994dff1b0ca80eb42819bf9bb1844a))

## [0.8.1](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.7.3...v0.8.1) (2023-10-14)

**Note:** Version bump only for package @sphereon/oid4vci-callback-example

## [0.7.3](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.7.2...v0.7.3) (2023-09-30)

**Note:** Version bump only for package @sphereon/oid4vci-callback-example

## [0.7.2](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.7.1...v0.7.2) (2023-09-28)

**Note:** Version bump only for package @sphereon/oid4vci-callback-example

## [0.7.1](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.7.0...v0.7.1) (2023-09-28)

### Bug Fixes

- Better match credential offer types and formats onto issuer metadata ([4044c21](https://github.com/Sphereon-Opensource/OID4VC/commit/4044c2175b4cbee16f44c8bb5499bba249ca4993))

# [0.7.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.6.0...v0.7.0) (2023-08-19)

### Features

- Integrate ssi-express-support to allow for future authn/authz. Also moved endpoints to functions, so solutions can include their own set of endpoints ([c749aba](https://github.com/Sphereon-Opensource/OID4VC/commit/c749ababd4bec567d6aeeda49b76f195ec792201))

# [0.6.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.4.0...v0.6.0) (2023-06-24)

### Bug Fixes

- Many v11 fixes on server and client side ([08be1ed](https://github.com/Sphereon-Opensource/OID4VC/commit/08be1ed009fb80e910cffa2e4cf376758798b27e))

### Features

- Add status support to sessions ([a1fa6a4](https://github.com/Sphereon-Opensource/OID4VC/commit/a1fa6a4c569c36951e1a7cedb632aa0b22104448))
- Add support for alg, kid, did, did document to Jwt Verification callback so we can ensure to set proper values in the resulting VC. ([62dd947](https://github.com/Sphereon-Opensource/OID4VC/commit/62dd947d0e09360719e6f704db33d766dff2363a))
- Add VCI Issuer ([5cab075](https://github.com/Sphereon-Opensource/OID4VC/commit/5cab07534e7a8b340f7a05343f56fbf091d64738))
- Issuer credential offer and more fixes/features ([0bbe17c](https://github.com/Sphereon-Opensource/OID4VC/commit/0bbe17c13de4df95e2fd79b3470a746cc7a5374a))
- Support data supplier callback ([1c49cc8](https://github.com/Sphereon-Opensource/OID4VC/commit/1c49cc80cfd83115956c7e9a040e12e814724e72))
