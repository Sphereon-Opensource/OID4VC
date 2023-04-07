<h1 align="center">
  <br>
  <a href="https://www.sphereon.com"><img src="https://sphereon.com/content/themes/sphereon/assets/img/logo.svg" alt="Sphereon" width="400"></a>
    <br>OpenID for Verifiable Credential Issuance - Client and Issuer
  <br>
</h1>

[![CI](https://github.com/Sphereon-Opensource/OpenID4VCI/actions/workflows/build-test-on-pr.yml/badge.svg)](https://github.com/Sphereon-Opensource/OpenID4VCI/actions/workflows/build-test-on-pr.yml) [![codecov](https://codecov.io/gh/Sphereon-Opensource/OpenID4VCI/branch/develop/graph/badge.svg)](https://codecov.io/gh/Sphereon-Opensource/OpenID4VCI) [![NPM Version](https://img.shields.io/npm/v/@sphereon/openid4vci.svg)](https://npm.im/@sphereon/openid4vci)

_IMPORTANT the packages are in an early development stage and currently only supports the pre-authorized code flow of
OpenID4VCI! Work is underway for the Authorized Flows as well, but not fully supported yet_

# Background

This is a mono-repository with a client and issuer pacakge to request and receive Verifiable Credentials using
the [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) (
OpenID4VCI) specification for receiving Verifiable Credentials as a holder/subject.

OpenID4VCI defines an API designated as Credential Endpoint that is used to issue verifiable credentials and
corresponding OAuth 2.0 based authorization mechanisms (see [RFC6749]) that a Wallet uses to obtain authorization to
receive verifiable credentials. W3C formats as well as other Credential formats are supported. This allows existing
OAuth 2.0 deployments and OpenID Connect OPs (see [OpenID.Core]) to extend their service and become Credential Issuers.
It also allows new applications built using Verifiable Credentials to utilize OAuth 2.0 as integration and
interoperability layer. This package provides holder/wallet support to interact with OpenID4VCI capable Issuer systems.

Next to the client and issuer, there is also a common package, which has all the types and payloads shared between the client and issuer.

# Packages
There are 2 main packages in this mono-repository

## OpenID4VCI Client

The OpenID4VCI client is typically used in wallet type of applications, where the user is receiving the credential(s). More info can be found in the client [README](./packages/client/README.md)

## OpenID4VCI Issuer

The OpenID4VCI issuer is used in issuer type applications, where an organization is issuiing the credential(s). More info can be found in the client [README](./packages/issuer/README.md). This package is currently undergoing development, and not ready to be used yet!


# Flows

The spec lists 2 flows:

## Authorized Code Flow

This flow isn't fully supported yet, so you might run into issues trying to use it.

## Pre-authorized Code Flow

The pre-authorized code flow assumes the user is using an out of bound mechanism outside the issuance flow to
authenticate first.

The below diagram shows the steps involved in the pre-authorized code flow. Note that wallet inner functionalities (like
saving VCs) are out of scope for this library. Also This library doesn't involve any functionalities of a VC Issuer
![Flow diagram](https://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/Sphereon-Opensource/OID4VCI-client/develop/docs/preauthorized-code-flow.puml)
