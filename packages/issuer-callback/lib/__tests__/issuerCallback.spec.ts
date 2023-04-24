import { ICredential } from '@sphereon/ssi-types'

import { generateDid, getIssuerCallback } from '../IssuerCallback'

describe('issuerCallback', () => {
  let didKey: string

  beforeAll(async () => {
    didKey = (await generateDid()).didDocument.id
  })

  it('should issue a VC', async () => {
    const credential: ICredential = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential'],
      issuer: didKey,
      credentialSubject: {},
      issuanceDate: new Date().toISOString(),
    }
    await expect(getIssuerCallback(credential)()).resolves.toEqual({
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/security/suites/ed25519-2020/v1'],
      credentialSubject: {},
      issuanceDate: expect.any(String),
      issuer: expect.stringContaining('did:key:'),
      proof: {
        created: expect.any(String),
        proofPurpose: 'assertionMethod',
        proofValue: expect.any(String),
        type: 'Ed25519Signature2020',
        verificationMethod: expect.any(String),
      },
      type: ['VerifiableCredential'],
    })
  })
})
