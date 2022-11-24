# Release Notes

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

**WARNING: The package has been renamed to @sphereon/openid4vci-client!**

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
