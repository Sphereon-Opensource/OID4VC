import {
  AccessTokenResponse,
  Alg,
  EndpointMetadata,
  Jwt,
  NO_JWT_PROVIDED,
  PROOF_CANT_BE_CONSTRUCTED,
  ProofOfPossession,
  ProofOfPossessionCallbacks,
} from '@sphereon/openid4vci-common/lib';

import { createProofOfPossession } from './functions';

export class ProofOfPossessionBuilder {
  private readonly proof?: ProofOfPossession;
  private readonly callbacks?: ProofOfPossessionCallbacks;

  private kid: string;
  private clientId?: string;
  private issuer?: string;
  private jwt?: Jwt;
  private alg?: string;
  private jti?: string;
  private cNonce?: string;

  private constructor({
    proof,
    callbacks,
    jwt,
    accessTokenResponse,
  }: {
    proof?: ProofOfPossession;
    callbacks?: ProofOfPossessionCallbacks;
    accessTokenResponse?: AccessTokenResponse;
    jwt?: Jwt;
  }) {
    this.proof = proof;
    this.callbacks = callbacks;
    if (jwt) {
      this.withJwt(jwt);
    }
    if (accessTokenResponse) {
      this.withAccessTokenResponse(accessTokenResponse);
    }
  }

  static fromJwt({ jwt, callbacks }: { jwt: Jwt; callbacks: ProofOfPossessionCallbacks }): ProofOfPossessionBuilder {
    return new ProofOfPossessionBuilder({ callbacks, jwt });
  }

  static fromAccessTokenResponse({
    accessTokenResponse,
    callbacks,
  }: {
    accessTokenResponse: AccessTokenResponse;
    callbacks: ProofOfPossessionCallbacks;
  }): ProofOfPossessionBuilder {
    return new ProofOfPossessionBuilder({ callbacks, accessTokenResponse });
  }

  static fromProof(proof: ProofOfPossession): ProofOfPossessionBuilder {
    return new ProofOfPossessionBuilder({ proof });
  }

  withClientId(clientId: string): ProofOfPossessionBuilder {
    this.clientId = clientId;
    return this;
  }

  withKid(kid: string): ProofOfPossessionBuilder {
    this.kid = kid;
    return this;
  }

  withIssuer(issuer: string): ProofOfPossessionBuilder {
    this.issuer = issuer;
    return this;
  }

  withAlg(alg: Alg | string): ProofOfPossessionBuilder {
    this.alg = alg;
    return this;
  }

  withJti(jti: string): ProofOfPossessionBuilder {
    this.jti = jti;
    return this;
  }

  withAccessTokenNonce(cNonce: string): ProofOfPossessionBuilder {
    this.cNonce = cNonce;
    return this;
  }

  withAccessTokenResponse(accessToken: AccessTokenResponse): ProofOfPossessionBuilder {
    this.withAccessTokenNonce(accessToken.c_nonce);
    return this;
  }

  withEndpointMetadata(endpointMetadata: EndpointMetadata): ProofOfPossessionBuilder {
    this.withIssuer(endpointMetadata.issuer);
    return this;
  }

  withJwt(jwt: Jwt): ProofOfPossessionBuilder {
    if (!jwt) {
      throw new Error(NO_JWT_PROVIDED);
    }
    this.jwt = jwt;
    if (jwt.header) {
      this.withKid(jwt.header.kid);
      this.withAlg(jwt.header.alg);
    }
    if (jwt.payload) {
      this.withClientId(jwt.payload.iss);
      this.withIssuer(jwt.payload.aud);
      this.withJti(jwt.payload.jti);
      this.withAccessTokenNonce(jwt.payload.nonce);
    }
    return this;
  }

  public async build(): Promise<ProofOfPossession> {
    if (this.proof) {
      return Promise.resolve(this.proof);
    } else if (this.callbacks) {
      return await createProofOfPossession(
        this.callbacks,
        {
          kid: this.kid,
          jti: this.jti,
          alg: this.alg,
          issuer: this.issuer,
          clientId: this.clientId,
          nonce: this.cNonce,
        },
        this.jwt
      );
    }
    throw new Error(PROOF_CANT_BE_CONSTRUCTED);
  }
}
