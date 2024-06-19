# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# [0.12.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.10.3...v0.12.0) (2024-06-19)

### Bug Fixes

- (WIP) fixed all the build errors ([e522a3d](https://github.com/Sphereon-Opensource/OID4VCI/commit/e522a3dd5821fb710211e35c8871f89772b672a0))
- (WIP) refactored and fixed build. still have to fix 33 test cases that are failing ([ff88a64](https://github.com/Sphereon-Opensource/OID4VCI/commit/ff88a647574baa9813939c296342cc112d00237f))
- (WIP) refactored and fixed build. still have to fix 8 test cases that are failing ([d8c2c4f](https://github.com/Sphereon-Opensource/OID4VCI/commit/d8c2c4fa8d73ea14a0faa823a394cde23733db8f))
- (WIP) refactored and fixed parts of the logic for v1_0_13. ([06117c0](https://github.com/Sphereon-Opensource/OID4VCI/commit/06117c0fd9a06170284ce5a89075d5b12fcd7d7b))
- fixed some test cases ([ccac046](https://github.com/Sphereon-Opensource/OID4VCI/commit/ccac04640a7fc950d8e2f98d932acdf2f896a791))
- fixes for PAR. Several things were missing, wrong. Higly likely this is a problem for non PAR flows as well ([9ed5064](https://github.com/Sphereon-Opensource/OID4VCI/commit/9ed506466413b6fdb5df7bff50accf3a7a1ad874))
- MetadataClient for version 13 and added better type distinction. added credential_definition to credential metadata of v13 ([e39bf71](https://github.com/Sphereon-Opensource/OID4VCI/commit/e39bf71625c2a66821061ece7625f0b08f1c0ad2))

### Features

- Add wallet signing support to VCI and notification support ([c4d3483](https://github.com/Sphereon-Opensource/OID4VCI/commit/c4d34836fb4923c98e7743221978c902c8427f2a))
- created special type for CredentialRequest v1_0_13 and fixed the tests for it ([25a6051](https://github.com/Sphereon-Opensource/OID4VCI/commit/25a6051ed0bb096c2249f24cd054c1a7aec97f61))

## [0.10.3](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.10.2...v0.10.3) (2024-04-25)

### Bug Fixes

- issuance and expiration sometimes used milliseconds instead of seconds ([afc2a8a](https://github.com/Sphereon-Opensource/OID4VCI/commit/afc2a8a9171bae7e30ed7c7d9bd094d8cbd49b80))

## [0.10.2](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.10.1...v0.10.2) (2024-03-13)

### Bug Fixes

- use seconds for all expires in values ([39bde8f](https://github.com/Sphereon-Opensource/OID4VCI/commit/39bde8f835a96509727f54cbdf2d4db9fa08df8b))

## [0.10.1](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.10.0...v0.10.1) (2024-03-12)

### Bug Fixes

- await session state updates ([963fb88](https://github.com/Sphereon-Opensource/OID4VCI/commit/963fb88201af15ccfce189bb3ac7eedc846833d0))

# [0.10.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.9.0...v0.10.0) (2024-02-29)

**Note:** Version bump only for package @sphereon/oid4vci-callback-example

# [0.9.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.8.1...v0.9.0) (2024-02-16)

### Bug Fixes

- add sd-jwt to issuer callback ([93b1242](https://github.com/Sphereon-Opensource/OID4VCI/commit/93b1242d99dc21400c337b2f552a9f2da9da375c))

### Features

- add sd-jwt support ([a37ef06](https://github.com/Sphereon-Opensource/OID4VCI/commit/a37ef06d38fdc7a6d5acc372cd2da8935b4c414e))
- Support sd-jwt 0.2.0 library ([77c9c24](https://github.com/Sphereon-Opensource/OID4VCI/commit/77c9c246ac994dff1b0ca80eb42819bf9bb1844a))

## [0.8.1](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.7.3...v0.8.1) (2023-10-14)

**Note:** Version bump only for package @sphereon/oid4vci-callback-example

## [0.7.3](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.7.2...v0.7.3) (2023-09-30)

**Note:** Version bump only for package @sphereon/oid4vci-callback-example

## [0.7.2](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.7.1...v0.7.2) (2023-09-28)

**Note:** Version bump only for package @sphereon/oid4vci-callback-example

## [0.7.1](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.7.0...v0.7.1) (2023-09-28)

### Bug Fixes

- Better match credential offer types and formats onto issuer metadata ([4044c21](https://github.com/Sphereon-Opensource/OID4VCI/commit/4044c2175b4cbee16f44c8bb5499bba249ca4993))

# [0.7.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.6.0...v0.7.0) (2023-08-19)

### Features

- Integrate ssi-express-support to allow for future authn/authz. Also moved endpoints to functions, so solutions can include their own set of endpoints ([c749aba](https://github.com/Sphereon-Opensource/OID4VCI/commit/c749ababd4bec567d6aeeda49b76f195ec792201))

# [0.6.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.4.0...v0.6.0) (2023-06-24)

### Bug Fixes

- Many v11 fixes on server and client side ([08be1ed](https://github.com/Sphereon-Opensource/OID4VCI/commit/08be1ed009fb80e910cffa2e4cf376758798b27e))

### Features

- Add status support to sessions ([a1fa6a4](https://github.com/Sphereon-Opensource/OID4VCI/commit/a1fa6a4c569c36951e1a7cedb632aa0b22104448))
- Add support for alg, kid, did, did document to Jwt Verification callback so we can ensure to set proper values in the resulting VC. ([62dd947](https://github.com/Sphereon-Opensource/OID4VCI/commit/62dd947d0e09360719e6f704db33d766dff2363a))
- Add VCI Issuer ([5cab075](https://github.com/Sphereon-Opensource/OID4VCI/commit/5cab07534e7a8b340f7a05343f56fbf091d64738))
- Issuer credential offer and more fixes/features ([0bbe17c](https://github.com/Sphereon-Opensource/OID4VCI/commit/0bbe17c13de4df95e2fd79b3470a746cc7a5374a))
- Support data supplier callback ([1c49cc8](https://github.com/Sphereon-Opensource/OID4VCI/commit/1c49cc80cfd83115956c7e9a040e12e814724e72))
