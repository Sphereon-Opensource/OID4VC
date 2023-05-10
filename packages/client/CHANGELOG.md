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
