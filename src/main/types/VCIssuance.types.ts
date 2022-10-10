export enum CredentialFormat {
  JWT_VC = 'jwt_vc',
  LDP_VC = 'ldp_vc',
}

export enum CredentialType {
  OPEN_BADGE_CREDENTIAL = 'https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential',
}

export enum ProofType {
  JWT = 'jwt',
}

export interface ProofOfPossesion {
  proof_type: ProofType;
  jws: string;
  [x: string]: any;
}
