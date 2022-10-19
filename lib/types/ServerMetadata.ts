export interface ServerMetadata {
  credential_endpoint: string;
  credentials_supported: CredentialsSupported;
  credential_issuer?: { display?: ClaimIssuerDisplay };
}

export interface CredentialsSupported {
  [x: string]: {
    display?: Display[];
    formats: Formats;
    claims: Claims;
  };
}

export interface Display {
  name: string;
  locale?: string;
  logo?: Logo;
  [x: string]: unknown;
}

export interface Logo {
  url?: string;
  alt_text?: string;
  description?: string;
  background_color?: string;
  text_color?: string;
  [x: string]: unknown;
}

export interface Claims {
  [x: string]: {
    mandatory?: boolean;
    namespace?: string;
    value_type?: string;
    display?: ClaimIssuerDisplay[];
    [x: string]: unknown;
  };
}

export enum FormatKeys {
  ldp_vc = 'ldp_vc',
  jwt_vc = 'jwt_vc',
  mdl_iso = 'mdl_iso',
  ac_vc = 'ac_vc',
}

export type Formats = {
  [x in FormatKeys]: {
    types: string[];
    cryptographic_binding_methods_supported?: string[];
    cryptographic_suites_supported?: string[];
    [x: string]: unknown;
  };
};

export type ClaimIssuerDisplay = Partial<Pick<Display, 'name' | 'locale'>> & { [x: string]: unknown };
