import { ServiceTypesEnum } from '@sphereon/wellknown-dids-client'

import { DIDDocument } from '../ResolverTestUtils'

export const UNIT_TEST_TIMEOUT = 90000

export const VERIFIER_LOGO_FOR_CLIENT = 'https://sphereon.com/content/themes/sphereon/assets/favicons/safari-pinned-tab.svg'

export const VERIFIER_NAME_FOR_CLIENT = 'Client Verifier Relying Party Sphereon INC'
export const VERIFIER_NAME_FOR_CLIENT_NL = ' *** dutch *** Client Verifier Relying Party Sphereon B.V.'

export const VERIFIERZ_PURPOSE_TO_VERIFY = 'To request, receive and verify your credential about the the valid subject.'
export const VERIFIERZ_PURPOSE_TO_VERIFY_NL = ' *** Dutch *** To request, receive and verify your credential about the the valid subject.'

export const DID_DOCUMENT_PUBKEY_B58: DIDDocument = {
  assertionMethod: [],
  capabilityDelegation: [],
  capabilityInvocation: [],
  keyAgreement: [],
  '@context': 'https://w3id.org/did/v1',
  id: 'did:ethr:0xE3f80bcbb360F04865AfA795B7507d384154216C',
  controller: 'did:ethr:0xE3f80bcbb360F04865AfA795B7507d384154216C',
  authentication: ['did:ethr:0xE3f80bcbb360F04865AfA795B7507d384154216C#key-1'],
  verificationMethod: [
    {
      id: 'did:ethr:0xE3f80bcbb360F04865AfA795B7507d384154216C#key-1',
      type: 'EcdsaSecp256k1VerificationKey2019',
      controller: 'did:ethr:0xE3f80bcbb360F04865AfA795B7507d384154216C',
      publicKeyBase58: 'PSPfR29Snu5yxJcLHf2t6SyJ9mttet19ECkDHr4HY3FD5YC8ZenjvspPSAGSpaQ8B8kXADV97WSd7JqaNAUTn8YG',
    },
  ],
}

export const DID_DOCUMENT_PUBKEY_JWK: DIDDocument = {
  assertionMethod: [],
  capabilityDelegation: [],
  capabilityInvocation: [],
  keyAgreement: [],
  '@context': 'https://w3id.org/did/v1',
  id: 'did:ethr:0x96e9A346905a8F8D5ee0e6BA5D13456965e74513',
  controller: 'did:ethr:0x96e9A346905a8F8D5ee0e6BA5D13456965e74513',
  authentication: ['did:ethr:0x96e9A346905a8F8D5ee0e6BA5D13456965e74513#JTa8+HgHPyId90xmMFw6KRD4YUYLosBuWJw33nAuRS0='],
  verificationMethod: [
    {
      id: 'did:ethr:0x96e9A346905a8F8D5ee0e6BA5D13456965e74513#JTa8+HgHPyId90xmMFw6KRD4YUYLosBuWJw33nAuRS0=',
      type: 'EcdsaSecp256k1VerificationKey2019',
      controller: 'did:ethr:0x96e9A346905a8F8D5ee0e6BA5D13456965e74513',
      publicKeyJwk: {
        kty: 'EC',
        crv: 'secp256k1',
        x: '62451c7a3e0c6e2276960834b79ae491ba0a366cd6a1dd814571212ffaeaaf5a',
        y: '1ede3d754090437db67eca78c1659498c9cf275d2becc19cdc8f1ef76b9d8159',
        kid: 'JTa8+HgHPyId90xmMFw6KRD4YUYLosBuWJw33nAuRS0=',
      },
    },
  ],
}

export const DID_KEY = 'did:key:z6MktwS79rvBjzRX8a8PPiURqG7HMJAfACTiozFkPJeJHRxS'

export const DID_KEY_ORIGIN = 'https://example.com'

export const DID_KEY_DOCUMENT = {
  '@context': [
    'https://www.w3.org/ns/did/v1',
    {
      Ed25519VerificationKey2018: 'https://w3id.org/security#Ed25519VerificationKey2018',
      publicKeyJwk: {
        '@id': 'https://w3id.org/security#publicKeyJwk',
        '@type': '@json',
      },
    },
  ],
  id: DID_KEY,
  verificationMethod: [
    {
      id: `${DID_KEY}#z6MktwS79rvBjzRX8a8PPiURqG7HMJAfACTiozFkPJeJHRxS`,
      type: 'Ed25519VerificationKey2018',
      controller: DID_KEY,
      publicKeyJwk: {
        kty: 'OKP',
        crv: 'Ed25519',
        x: '1ztBkC3x-8Eu8uPNTkTgH1Q0tkuO8v8RJDqfqWFl1N8',
      },
    },
  ],
  authentication: [`${DID_KEY}#z6MktwS79rvBjzRX8a8PPiURqG7HMJAfACTiozFkPJeJHRxS`],
  assertionMethod: [`${DID_KEY}#z6MktwS79rvBjzRX8a8PPiURqG7HMJAfACTiozFkPJeJHRxS`],
  service: [
    {
      id: `${DID_KEY}#z6MktwS79rvBjzRX8a8PPiURqG7HMJAfACTiozFkPJeJHRxS`,
      type: ServiceTypesEnum.LINKED_DOMAINS,
      serviceEndpoint: DID_KEY_ORIGIN,
    },
  ],
} as DIDDocument

export const VC_KEY_PAIR = {
  type: 'Ed25519VerificationKey2020',
  id: `${DID_KEY}#z6MktwS79rvBjzRX8a8PPiURqG7HMJAfACTiozFkPJeJHRxS`,
  controller: `${DID_KEY_ORIGIN}/1234`,
  publicKeyMultibase: 'z6MktwS79rvBjzRX8a8PPiURqG7HMJAfACTiozFkPJeJHRxS',
  privateKeyMultibase: 'zrv4UTisGEUxoZr1enXeC7NMVapzq48KkS1rLSpBvpTyg1v3cLo7g5SnprD1eD4bdKdYHHMu5feATzatSAkbhgXgtZU',
}

export const DID_ION =
  'did:ion:EiCMvVdXv6iL3W8i4n-LmqUhE614kX4TYxVR5kTY2QGOjg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXkxIiwicHVibGljS2V5SndrIjp7ImNydiI6InNlY3AyNTZrMSIsImt0eSI6IkVDIiwieCI6Ii1MbHNpQVk5b3JmMXpKQlJOV0NuN0RpNUpoYl8tY2xhNlY5R3pHa3FmSFUiLCJ5IjoiRXBIU25GZHQ2ZU5lRkJEZzNVNVFIVDE0TVRsNHZIc0h5NWRpWU9DWEs1TSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiIsImFzc2VydGlvbk1ldGhvZCJdLCJ0eXBlIjoiRWNkc2FTZWNwMjU2azFWZXJpZmljYXRpb25LZXkyMDE5In1dLCJzZXJ2aWNlcyI6W3siaWQiOiJsZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vbGR0ZXN0LnNwaGVyZW9uLmNvbSIsInR5cGUiOiJMaW5rZWREb21haW5zIn1dfX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlBem8wTVVZUW5HNWM0VFJKZVFsNFR5WVRrSmRyeTJoeXlQUlpENzdFQm1CdyJ9LCJzdWZmaXhEYXRhIjp7ImRlbHRhSGFzaCI6IkVpQUwtaEtrLUVsODNsRVJiZkFDUk1kSWNQVjRXWGJqZ3dsZ1ZDWTNwbDhhMGciLCJyZWNvdmVyeUNvbW1pdG1lbnQiOiJFaUItT2NSbTlTNXdhU3QxbU4zSG4zM2RnMzJKN25MOEdBVHpGQ2ZXaWdIXzh3In19'

export const DID_ION_ORIGIN = 'https://ldtest.sphereon.com'

export const DID_ION_DOCUMENT = {
  id: DID_ION,
  '@context': [
    'https://www.w3.org/ns/did/v1',
    {
      '@base': DID_ION,
    },
  ],
  service: [
    {
      id: '#ld',
      type: 'LinkedDomains',
      serviceEndpoint: DID_ION_ORIGIN,
    },
  ],
  verificationMethod: [
    {
      id: '#key1',
      controller: DID_ION,
      type: 'EcdsaSecp256k1VerificationKey2019',
      publicKeyJwk: {
        kty: 'EC',
        crv: 'secp256k1',
        x: '-LlsiAY9orf1zJBRNWCn7Di5Jhb_-cla6V9GzGkqfHU',
        y: 'EpHSnFdt6eNeFBDg3U5QHT14MTl4vHsHy5diYOCXK5M',
      },
    },
  ],
  authentication: ['#key1'],
  assertionMethod: ['#key1'],
}
