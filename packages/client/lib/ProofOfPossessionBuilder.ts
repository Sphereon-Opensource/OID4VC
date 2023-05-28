import {
  AccessTokenResponse,
  Alg,
  EndpointMetadata,
  Jwt,
  NO_JWT_PROVIDED,
  OpenId4VCIVersion,
  PROOF_CANT_BE_CONSTRUCTED,
  ProofOfPossession,
  ProofOfPossessionCallbacks,
  Typ,
} from '@sphereon/oid4vci-common';

import { createProofOfPossession } from './functions';

export class ProofOfPossessionBuilder {
  private readonly proof?: ProofOfPossession;
  private readonly callbacks?: ProofOfPossessionCallbacks;

  private version: OpenId4VCIVersion;

  private kid?: string;
  private clientId?: string;
  private issuer?: string;
  private jwt?: Jwt;
  private alg?: string;
  private jti?: string;
  private cNonce?: string;
  private typ?: Typ;

  private constructor({
    proof,
    callbacks,
    jwt,
    accessTokenResponse,
    version,
  }: {
    proof?: ProofOfPossession;
    callbacks?: ProofOfPossessionCallbacks;
    accessTokenResponse?: AccessTokenResponse;
    jwt?: Jwt;
    version: OpenId4VCIVersion;
  }) {
    this.proof = proof;
    this.callbacks = callbacks;
    if (jwt) {
      this.withJwt(jwt);
    }
    if (accessTokenResponse) {
      this.withAccessTokenResponse(accessTokenResponse);
    }
    this.version = version;
  }

  static fromJwt({
    jwt,
    callbacks,
    version,
  }: {
    jwt: Jwt;
    callbacks: ProofOfPossessionCallbacks;
    version: OpenId4VCIVersion;
  }): ProofOfPossessionBuilder {
    return new ProofOfPossessionBuilder({ callbacks, jwt, version });
  }

  static fromAccessTokenResponse({
    accessTokenResponse,
    callbacks,
    version,
  }: {
    accessTokenResponse: AccessTokenResponse;
    callbacks: ProofOfPossessionCallbacks;
    version: OpenId4VCIVersion;
  }): ProofOfPossessionBuilder {
    return new ProofOfPossessionBuilder({ callbacks, accessTokenResponse, version });
  }

  static fromProof(proof: ProofOfPossession, version: OpenId4VCIVersion): ProofOfPossessionBuilder {
    return new ProofOfPossessionBuilder({ proof, version });
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

  withTyp(typ: Typ): ProofOfPossessionBuilder {
    this.typ = typ;
    return this;
  }

  withAccessTokenNonce(cNonce: string): ProofOfPossessionBuilder {
    this.cNonce = cNonce;
    return this;
  }

  withAccessTokenResponse(accessToken: AccessTokenResponse): ProofOfPossessionBuilder {
    if (accessToken.c_nonce) {
      this.withAccessTokenNonce(accessToken.c_nonce);
    }
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
    if (!jwt.header) {
      throw Error(`No JWT header present`);
    } else if (!jwt.payload) {
      throw Error(`No JWT payload present`);
    }

    if (jwt.header.kid) {
      this.withKid(jwt.header.kid);
    }
    if (jwt.header.typ) {
      this.withTyp(jwt.header.typ as Typ);
    }
    if (this.version >= OpenId4VCIVersion.VER_1_0_11) {
      this.withTyp('openid4vci-proof+jwt');
    }
    this.withAlg(jwt.header.alg);

    if (jwt.payload) {
      if (jwt.payload.iss) this.withClientId(jwt.payload.iss);
      if (jwt.payload.aud) this.withIssuer(jwt.payload.aud);
      if (jwt.payload.jti) this.withJti(jwt.payload.jti);
      if (jwt.payload.nonce) this.withAccessTokenNonce(jwt.payload.nonce);
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
          typ: this.typ ?? (this.version < OpenId4VCIVersion.VER_1_0_11 ? 'jwt' : 'openid4vci-proof+jwt'),
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
