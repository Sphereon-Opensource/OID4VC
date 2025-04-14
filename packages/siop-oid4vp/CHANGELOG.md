# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# [0.17.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.16.0...v0.17.0) (2025-03-14)

### Bug Fixes

- changes for oid4vc conformance tests ([aa56dbf](https://github.com/Sphereon-Opensource/OID4VC/commit/aa56dbfc49b46fc559f4e4d2affcb20ddd91a525))
- check if oid4vp defined ([c654a7b](https://github.com/Sphereon-Opensource/OID4VC/commit/c654a7bce3dd659d48d7cf3fdfa5d6f23b23a3f4))
- client_id_scheme & default scope handling ([c559618](https://github.com/Sphereon-Opensource/OID4VC/commit/c559618a3ef78e50a312757de02cfa1468493e82))
- Codecov ([36c7e09](https://github.com/Sphereon-Opensource/OID4VC/commit/36c7e096161d6c4495a3d5d531c5418138e6c061))
- dcql alpha ([6ff3355](https://github.com/Sphereon-Opensource/OID4VC/commit/6ff33553305bf59f7a55259ab7d63ae5398c37fa))
- feedback ([413ecb9](https://github.com/Sphereon-Opensource/OID4VC/commit/413ecb9af2fa4010ef177272d320045f6148747f))
- feedback ([b119275](https://github.com/Sphereon-Opensource/OID4VC/commit/b1192751c7d72890bfb4d7822c10f39e24830422))
- Fix for when credential_configuration_ids is being used together with credentials_supported ([f696867](https://github.com/Sphereon-Opensource/OID4VC/commit/f6968677ccd10c2ce8eb8484443971102547e8a2))
- fix single vp_token being send is an array ([e496ca2](https://github.com/Sphereon-Opensource/OID4VC/commit/e496ca259319f2f6fa327cf0efe71e0a8f0dc5f1))
- fixed LanguageTagUtils tests ([2a5e3a6](https://github.com/Sphereon-Opensource/OID4VC/commit/2a5e3a606954745069345b1c7a3e1664b30bdded))
- fixed LanguageTagUtils to only process field names if it has a mapping ([e0c592e](https://github.com/Sphereon-Opensource/OID4VC/commit/e0c592efe26742ab02d35bf39f2d450c1c51c13a))
- format ([688fb6d](https://github.com/Sphereon-Opensource/OID4VC/commit/688fb6d81c414b865fcef6ae2a1fe9b40c5d1782))
- missing export ([e520711](https://github.com/Sphereon-Opensource/OID4VC/commit/e520711491a1a1d847061f0cf3c49d7947dc6d2e))
- remove mdoc ([4d8859e](https://github.com/Sphereon-Opensource/OID4VC/commit/4d8859e0317759d36b348357ef28715ad2a515f3))
- session and state to correlationId mapping bugfixes ([c9b4d6f](https://github.com/Sphereon-Opensource/OID4VC/commit/c9b4d6f8df62a11d6235d75bee63deb352f66926))
- small fixes for siop-oid4vp package ([8584d76](https://github.com/Sphereon-Opensource/OID4VC/commit/8584d766c065672bbd70c1c916bfb506b1004b53))
- small fixes for siop-oid4vp package ([5aeff03](https://github.com/Sphereon-Opensource/OID4VC/commit/5aeff03cce285d29c105aeca2c234269ca4999e2))
- small fixes for siop-oid4vp package ([5ccb87c](https://github.com/Sphereon-Opensource/OID4VC/commit/5ccb87c1edae6ced9ba3d067c222ebc7f8f963ce))
- some nits ([ac9ead6](https://github.com/Sphereon-Opensource/OID4VC/commit/ac9ead6d8d216a7e0cf09c6bf76e1ee410e3727c))
- test ([2c1a354](https://github.com/Sphereon-Opensource/OID4VC/commit/2c1a354044b84b0883f3e89e1344753853f4a3cf))
- test for nonce ([f9b1bdf](https://github.com/Sphereon-Opensource/OID4VC/commit/f9b1bdfe5681ed81bc0287f066f4f8792c36a715))
- update ([9ff62bd](https://github.com/Sphereon-Opensource/OID4VC/commit/9ff62bd5127a69f33a158fe8f0be21ca9820879a))
- update dcql and incorporate feedback ([76be4cc](https://github.com/Sphereon-Opensource/OID4VC/commit/76be4cc85ae2be951574385ba9a6f0aa1c62d18f))
- update deps ([ca61afe](https://github.com/Sphereon-Opensource/OID4VC/commit/ca61afe183f8387e591a17dbb9de894c1f1aad0e))
- update jarm ([7b54fae](https://github.com/Sphereon-Opensource/OID4VC/commit/7b54fae2c09cbe1208d34148c2e17e2043c34739))
- use error reason if provided ([5f2b3f2](https://github.com/Sphereon-Opensource/OID4VC/commit/5f2b3f2a547504a5ecea0411b8ed3a4af8f4e798))

### Features

- add aud/response_uri to request object, and client_id to the request ([400df29](https://github.com/Sphereon-Opensource/OID4VC/commit/400df29061a93b46149ab1744998b592e36b399f))
- add jarm package ([4cb9259](https://github.com/Sphereon-Opensource/OID4VC/commit/4cb9259a5bb015a8ffca63d2873cc0baae2b1b8e))
- add things ([6ad4d89](https://github.com/Sphereon-Opensource/OID4VC/commit/6ad4d89e6ad97b4d4d1155722e71477e36decc59))
- added DynamicRegistrationClientMetadata type and extended existing metadata for issuer and rp ([97b8779](https://github.com/Sphereon-Opensource/OID4VC/commit/97b87795b893eaede336387af9a209338da00213))
- added support for first party applications ([9c273b9](https://github.com/Sphereon-Opensource/OID4VC/commit/9c273b94a5373f9949b0d717e151e9f378307a3f))
- Allow to acquire credentials without using a proof for V13. This is rare and has to be supported by the issuer. For instance when using DPop and authorization code ([2f1fcee](https://github.com/Sphereon-Opensource/OID4VC/commit/2f1fcee8ba67229f037d5387be73fb9ab0d998d1))
- changed the default uri scheme to openid4vp ([e9dd686](https://github.com/Sphereon-Opensource/OID4VC/commit/e9dd686c508547eee9b1aa1bbca24bfc58eba0a7))
- dcql alpha ([dc1c318](https://github.com/Sphereon-Opensource/OID4VC/commit/dc1c318fa130dc7fec493b82f69a1f563f62713c))
- dcql alpha ([4b7e8ae](https://github.com/Sphereon-Opensource/OID4VC/commit/4b7e8aecba5825cdee14fe12b50e9dc57f64d9ab))
- Improve create jarm response callback to also include clientMetadata, to make it easier for implementers to extract the enc jwks themselves ([e71cd2d](https://github.com/Sphereon-Opensource/OID4VC/commit/e71cd2dff5ad696cbc7ca6a7f6d8cb6640674739))
- jarm alpha ([cc55d5e](https://github.com/Sphereon-Opensource/OID4VC/commit/cc55d5e8256fcb884e28b1847033c534e31f6d76))
- jarm alpha ([703e09e](https://github.com/Sphereon-Opensource/OID4VC/commit/703e09e8c869bd37d52aba01a2e8ca5b2adeb5a8))
- mso mdoc handling ([d88df4f](https://github.com/Sphereon-Opensource/OID4VC/commit/d88df4fc9f4a704f9c4cf208a0b302dca4fc2d29))
- MWALL-715 Create notification endpoint logic in Issuer ([2dff0df](https://github.com/Sphereon-Opensource/OID4VC/commit/2dff0df4f3d9c0943b9e93ea2c9666fab43747c2))
- OID4VCI Rest API session improvements and delete endpoint ([0936d5d](https://github.com/Sphereon-Opensource/OID4VC/commit/0936d5d67b9baa392396dd5fa632df3106524aa0))
- support exchanges with multiple vps ([5d5b0d7](https://github.com/Sphereon-Opensource/OID4VC/commit/5d5b0d7277c121a51f2db1acc10c475d4a8b4d9d))
- update dcql ([ad19797](https://github.com/Sphereon-Opensource/OID4VC/commit/ad19797805d68855d902afcf586d521927654adc))
- update dcql ([d7cc1e7](https://github.com/Sphereon-Opensource/OID4VC/commit/d7cc1e7342280370e9a4bef023e1b88ac735f412))
- update dcql lib ([6d94367](https://github.com/Sphereon-Opensource/OID4VC/commit/6d94367ad7c64a6ca4e170b54cd83e7e490b8d6b))
- validate jarm metadata ([348d5bc](https://github.com/Sphereon-Opensource/OID4VC/commit/348d5bc05224afd54bfda03960a7599817fbc9d7))

### Reverts

- Revert "chore: disable mattr tests due to 502 bad gateway" ([9a526e2](https://github.com/Sphereon-Opensource/OID4VC/commit/9a526e222e4d6eedd5a9841f800e7b3973f65046))
- Revert "chore: disable AuthenticationResponse tests due to 502 bad gateway" ([8ae6c46](https://github.com/Sphereon-Opensource/OID4VC/commit/8ae6c4678795eed20d207e0c8be982b8ebe9fefe))

# [0.16.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.15.1...v0.16.0) (2024-08-02)

### Bug Fixes

- jwk thumprint using crypto.subtle ([56a291c](https://github.com/Sphereon-Opensource/OID4VC/commit/56a291c2a59c2966fdf428d7cf7e2e69389fd38b))
- nits ([1a54e69](https://github.com/Sphereon-Opensource/OID4VC/commit/1a54e6966da62e4796640dd73393fd0fdc5c76b4))
- redirect uri should not be set with direct_post ([42c8ddd](https://github.com/Sphereon-Opensource/OID4VC/commit/42c8dddf8c0ec76de98052198a27fe4409903918))
- rename common to oid4vc-common ([d89ac4f](https://github.com/Sphereon-Opensource/OID4VC/commit/d89ac4f4956e69dad5274b197912485665aeb97c))
- some imports ([5034468](https://github.com/Sphereon-Opensource/OID4VC/commit/5034468ab464f39e0c82cf09af8605d23d1f81f6))

### Features

- create common package ([d5b4b75](https://github.com/Sphereon-Opensource/OID4VC/commit/d5b4b75f036edcf8082e062214c036c9be934071))
- incorporate feedback part1 ([f30475a](https://github.com/Sphereon-Opensource/OID4VC/commit/f30475a8c98f869ffe82e67f59231a4faf182a98))

## [0.15.1](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.15.0...v0.15.1) (2024-07-23)

### Bug Fixes

- oid4vci draft 13 typing ([6d0bfc9](https://github.com/Sphereon-Opensource/OID4VC/commit/6d0bfc9227b1120913b773904ef991757cb9282a))

# [0.15.0](https://github.com/Sphereon-Opensource/OID4VC/compare/v0.14.0...v0.15.0) (2024-07-15)

### Bug Fixes

- add openid federation jwtVerifier ([a5755ff](https://github.com/Sphereon-Opensource/OID4VC/commit/a5755ffc5244f1ae72d9ad160c2271de07202ac1))
- build ([2da9205](https://github.com/Sphereon-Opensource/OID4VC/commit/2da92051cb6387e6c10dd0ff2767aeeddab17dd9))
- build ([84aba5e](https://github.com/Sphereon-Opensource/OID4VC/commit/84aba5e7cc9aca7b597f24c907dc717be45768d7))
- remove outdated docs ([31731e7](https://github.com/Sphereon-Opensource/OID4VC/commit/31731e7628a93a1f749600ee138d2470a5048353))
- siop-oid4vp build order ([dacf629](https://github.com/Sphereon-Opensource/OID4VC/commit/dacf629be63f130c0f027deea6dfdc988eaa3c1b))

### Features

- add siop-oid4vp package ([6bc76dd](https://github.com/Sphereon-Opensource/OID4VC/commit/6bc76dd2e4843e0acf07fc44c4c0c247496d1973))
- did-auth-siop-adapter ([32ec2fc](https://github.com/Sphereon-Opensource/OID4VC/commit/32ec2fc27a22cd069dc12fe011debef7f870cf5d))

# Release Notes

The DID Auth SIOP typescript library is still in an beta state at this point. Please note that the interfaces might
still change a bit as the software still is in active development.

## 0.6.5

- Added:
  - Initial support for OID4VP draft 20
  - Removed did-jwt and did-resolver dependencies
  - Support for pluggable signing and verification methods
  - Remove Signature Types
  - Remove Verification Method Types
  - This PR provides verification and signing 'adapters' for x5c, jwk, and did protected jwts (x5c, and jwk functionality was not present/possible previously)

## 0.6.4 - 2024-04-24

- Fixed:
  - Success event was emitted even though presentation verification callback failed
  - Always verify nonces, extract them from VP
- Updated:
  - Update to latest @sphereon/ssi-types

## 0.6.3 - 2024-03-20

- Updated:
  - Update to latest @sphereon/ssi-types, including the latest @sd-jwt packages

## 0.6.2 - 2024-03-04

- Fixed:
  - RP kept stale options to create the request object, resulting in recreation of the same request object over and over

## 0.6.0 - 2024-02-29

- Added:
  - Initial support for SIOPv2 draft 11
  - Initial support for OID4VP draft 18
  - SD-JWT support
  - Partial support for http(s) client_ids instead of DIDs. No validation for keys in this case yet though!
  - Convert presentation submissions that inadvertently come in from external OPs as a string instead of an object
  - Allow id-token only handling
  - Allow vp-token only handling
  - EBSI support
- Fixed:
  - issue with determining whether a Presentation Definition reference has been used
  - vp_token handling and nonce management was incorrect in certain cases (for instance when no id token is used)
  - Make sure a presentation verification callback result throws an error if it does not verify
  - Do not put VP token in the id token as default for spec versions above v10 if no explicit location is provided
  - Several small fixes

## 0.4.2 - 2023-10-01

Fixed an issue with did:key resolution used in Veramo

- Fixed:
  - Fixed an issue with did:key resolution from Veramo. The driver requires a mediaType which according to the spec is
    optional. We now always set it as it doesn't hurt to begin with.

## 0.4.1 - 2023-10-01

Fixed not being able to configure the resolver for well-known DIDs

- Fixed:
  - Well-known DIDs did not use a configured DID resolver and thus always used the universal resolver, which has
    issues quite often.

## 0.4.0 - 2023-09-28

- Fixed:

  - Claims are not required in the auth request
  - State is not required in payloads
  - We didn't handle merging of verification options present on an object and passed in as argument nicely

- Updated:

  - Updated to another JSONPath implementation for improved security `@astronautlabs/jsonpath`
  - Better error handling and logging in the session manager
  - Allow for numbers in the scheme thus supporting openid4vp://

- Added:
  - Allow to pass additional claims as verified data in the authorization response. Which can be handy in case you
    want to extract data from a VP and pass that to the app that uses this library

## v0.3.1 - 2023-05-17

Bugfix release, fixing RPBuilder export and a client_id bug when not explicitly provided to the RP.

- Fixed:
  - Changed RPBuilder default export to a named export
  - Fix #54. The client_id took the whole registration object, instead of the client_id in case it was not provided
    explicitly
- Updated:
  - SSI-types have been updated to the latest version.

## v0.3.0 - 2023-04-30

This release contains many breaking changes. Sorry for these, but this library still is in active development, as
reflected by the major version still being 0.
A lot of code has been refactored. Now certain classes have state, instead of passing around objects between static
methods.

- Added:
  - Allow to restrict selecting VCs against Formats not communicated in a presentation definition. For instance useful
    for filtering against a OID4VP RP, which signals support for certain Formats, but uses a definition which does not
    include this information
  - Allow to restrict selecting VCs against DID methods not communicated in a presentation definition. For instance
    useful
    for filtering against a OID4VP RP, which signals support for certain DID methods, but uses a definition which does
    not
    include this information
  - Allow passing in submission data separately from a VP. Again useful in a OID4VP situation, where presentation
    submission objects can be transferred next to the VP instead if in the VP
  - A simple session/state manager for the RP side. This allows to find back definitions for responses coming back in.
    As this is a library the only implementation is an in memory implementation. It is left up to implementers to
    create their persistent implementations
  - Added support for new version of the spec
  - Support for JWT VC Presentation Profile
  - Support for DID domain linkage
- Removed:
  - Several dependencies have been removed or moved to development dependencies. Mainly the cryptographic libraries
    have
    been removed
- Changed:
  - Requests and responses now contain state and can be instantiated from scratch/options or from an actual payload
  - Schema's for AJV are now compiled at build time, instead of at runtime.
- Fixed:
  - JSON-LD contexts where not always fetched correctly (Github for instance)
  - Signature callback function was not always working after creating copies of data
  - React-native not playing nicely with AJV schema's
  - JWT VCs/VPs were not always handled correctly
  - Submission data contained several errors
  - Holder was sometimes missing from the VP
  - Too many other fixes to list

## v0.2.14 - 2022-10-27

- Updated:
  - Updated some dependencies

## v0.2.13 - 2022-08-15

- Updated:
  - Updated some dependencies

## v0.2.12 - 2022-07-07

- Fixed:
  - We did not check the proper claims in an AuthResponse to determine the key type, resulting in an invalid JWT
    header
  - Removed some remnants of the DID-jwt fork

## v0.2.11 - 2022-07-01

- Updated:
  - Update to PEX 1.1.2
  - Update several other deps
- Fixed:
  - Only throw a PEX error in case PEX itself has flagged the submission to be in error
  - Use nonce from request in response if available
  - Remove DID-JWT fork as the current version supports SIOPv2 iss values

## v0.2.10 - 2022-02-25

- Added:
  - Add default resolver support to builder

## v0.2.9 - 2022-02-23

- Fixed:
  - Remove did-jwt dependency, since we use an internal fork for the time being anyway

## v0.2.7 - 2022-02-11

- Fixed:
  - Revert back to commonjs

## v0.2.6 - 2022-02-10

- Added:
  - Supplied withSignature support. Allowing to integrate withSignature callbacks, next to supplying private keys or
    using external custodial signing with authn/authz

## v0.2.5 - 2022-01-26

- Updated:
  - Update @sphereon/pex to the latest stable version v1.0.2
  - Moved did-key dep to dev dependency and changed to @digitalcredentials/did-method-key

## v0.2.4 - 2022-01-13

- Updated:
  - Update @sphereon/pex to latest stable version v1.0.1

## v0.2.3 - 2021-12-10

- Fixed:

  - Check nonce and did support first before verifying JWT

- Updated:
  - Updated PEX dependency that fixed a JSON-path bug impacting us

## v0.2.2 - 2021-11-29

- Updated:
  - Updated dependencies

## v0.2.1 - 2021-11-28

- Updated:
  - Presentation Exchange updated to latest PEX version 0.5.x. The eventual Presentation is not a VP yet (proof will
    be in next minor release)
  - Update Uni Resolver client to latest version 0.3.3

## v0.2.0 - 2021-10-06

- Added:

  - Presentation Exchange support [OpenID Connect for Verifiable
    Presentations(https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0.html)

- Fixed:
  - Many bug fixes (see git history)

## v0.1.1 - 2021-09-29

- Fixed:
  - Packaging fix for the did-jwt fork we include for now

## v0.1.0 - 2021-09-29

This is the first Alpha release of the DID Auth SIOP typescript library. Please note that the interfaces might still
change a bit as the software still is in active development.

- Alpha release:

  - Low level Auth Request and Response service classes
  - High Level OP and RP role service classes
  - Support for most of [SIOPv2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)

- Planned for Beta:
  - [Support for OpenID Connect for Verifiable Presentations](https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0.html)
