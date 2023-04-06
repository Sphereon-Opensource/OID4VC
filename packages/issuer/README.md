<h1 align="center">
  <br>
  <a href="https://www.sphereon.com"><img src="https://sphereon.com/content/themes/sphereon/assets/img/logo.svg" alt="Sphereon" width="400"></a>
    <br>OpenID for Verifiable Credential Issuance - Issuer
  <br>
</h1>

[![CI](https://github.com/Sphereon-Opensource/openid4vci-client/actions/workflows/main.yml/badge.svg)](https://github.com/Sphereon-Opensource/openid4vci-client/actions/workflows/main.yml) [![codecov](https://codecov.io/gh/Sphereon-Opensource/openid4vci-client/branch/develop/graph/badge.svg)](https://codecov.io/gh/Sphereon-Opensource/openid4vci-client) [![NPM Version](https://img.shields.io/npm/v/@sphereon/openid4vci-client.svg)](https://npm.im/@sphereon/openid4vci-client)

_IMPORTANT the packages are in an early development stage and currently only supports the pre-authorized code flow of
OpenID4VCI! Work is underway for the Authorized Flows as well, but not fully supported yet_

# Background

The OpenID4VCI issuer is used in issuer type applications, where an organization is issuing the credential(s)

## Credential Offer State Manager

The CredentialOfferState is used to track of the creation date of the credential offer:

```typescript
export interface CredentialOfferState {
  credentialOffer: CredentialOfferPayloadV1_0_11
  createdOn: number
}
```

The ICredentialOfferStateManager allows to have a custom implementation of the state manager:

```typescript
export interface ICredentialOfferStateManager {
  setState(state: string, payload: CredentialOfferState): Promise<Map<string, CredentialOfferState>>

  getState(state: string): Promise<CredentialOfferState | undefined>

  hasState(state: string): Promise<boolean>

  deleteState(state: string): Promise<boolean>

  clearExpiredStates(timestamp?: number): Promise<void> // clears all expired states compared against timestamp if provided, otherwise current timestamp

  clearAllStates(): Promise<void> // clears all states
}
```

Here is an example, an in-memory implementation of the ICredentialOfferStateManager

```typescript
export class MemoryCredentialOfferStateManager implements ICredentialOfferStateManager {
  private readonly credentialOfferStateManager: Map<string, CredentialOfferState>
  constructor() {
    this.credentialOfferStateManager = new Map()
  }

  async clearAllStates(): Promise<void> {
    this.credentialOfferStateManager.clear()
  }

  async clearExpiredStates(timestamp?: number): Promise<void> {
    const states = Array.from(this.credentialOfferStateManager.entries())
    timestamp = timestamp ?? +new Date()
    for (const [issuerState, state] of states) {
      if (state.createdOn < timestamp) {
        this.credentialOfferStateManager.delete(issuerState)
      }
    }
  }

  async deleteState(state: string): Promise<boolean> {
    return this.credentialOfferStateManager.delete(state)
  }

  async getState(state: string): Promise<CredentialOfferState | undefined> {
    return this.credentialOfferStateManager.get(state)
  }

  async hasState(state: string): Promise<boolean> {
    return this.credentialOfferStateManager.has(state)
  }

  async setState(state: string, payload: CredentialOfferState): Promise<Map<string, CredentialOfferState>> {
    return this.credentialOfferStateManager.set(state, payload)
  }
}
```

### Usage

Pass an instance of the state manager to the VC Issuer Builder

```typescript
const vcIssuer = new VcIssuerBuilder()
  .withAuthorizationServer('https://authorization-server')
  .withCredentialEndpoint('https://credential-endpoint')
  .withCredentialIssuer('https://credential-issuer')
  .withIssuerDisplay({
    name: 'example issuer',
    locale: 'en-US',
  })
  .withCredentialsSupported(credentialsSupported)
  .withInMemoryCredentialOfferStates(new MemoryCredentialOfferStateManager())
  .build()
```
