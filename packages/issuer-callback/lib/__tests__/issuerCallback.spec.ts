import {credentialCallback} from "../IssuerCallback";
import {ICredential} from "@sphereon/ssi-types";

describe('issuerCallback', () => {
  it('should issue a VC', async () => {

    const credential: ICredential = {
      '@context': [],
      type: ['VerifiableCredential'],
      issuer: 'did:key',
      credentialSubject: {},
      issuanceDate: new Date().toISOString()
    }
    await expect(credentialCallback({ credential })).resolves.toEqual({})
  })
})