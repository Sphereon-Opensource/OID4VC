# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# [0.16.0](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.15.1...v0.16.0) (2024-08-02)

### Bug Fixes

- jwk thumprint using crypto.subtle ([56a291c](https://github.com/Sphereon-Opensource/OID4VCI/commit/56a291c2a59c2966fdf428d7cf7e2e69389fd38b))
- nits ([1a54e69](https://github.com/Sphereon-Opensource/OID4VCI/commit/1a54e6966da62e4796640dd73393fd0fdc5c76b4))
- redirect uri should not be set with direct_post ([42c8ddd](https://github.com/Sphereon-Opensource/OID4VCI/commit/42c8dddf8c0ec76de98052198a27fe4409903918))
- rename common to oid4vc-common ([d89ac4f](https://github.com/Sphereon-Opensource/OID4VCI/commit/d89ac4f4956e69dad5274b197912485665aeb97c))
- some imports ([5034468](https://github.com/Sphereon-Opensource/OID4VCI/commit/5034468ab464f39e0c82cf09af8605d23d1f81f6))

### Features

- create common package ([d5b4b75](https://github.com/Sphereon-Opensource/OID4VCI/commit/d5b4b75f036edcf8082e062214c036c9be934071))
- incorporate feedback part1 ([f30475a](https://github.com/Sphereon-Opensource/OID4VCI/commit/f30475a8c98f869ffe82e67f59231a4faf182a98))

## [0.15.1](https://github.com/Sphereon-Opensource/OID4VCI/compare/v0.15.0...v0.15.1) (2024-07-23)

### Bug Fixes

- oid4vci draft 13 typing ([6d0bfc9](https://github.com/Sphereon-Opensource/OID4VCI/commit/6d0bfc9227b1120913b773904ef991757cb9282a))

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
