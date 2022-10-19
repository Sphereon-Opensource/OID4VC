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

export interface Formats {
  [x: FormatType]: {
    types: string[];
    cryptographic_binding_methods_supported?: string[];
    cryptographic_suites_supported?: string[];
    [x: string]: unknown;
  };
}

export type FormatType = 'ldp_vc' | 'jwt_vc' | 'mdl_iso' | 'ac_vc';

export type ClaimIssuerDisplay = Partial<Pick<Display, 'name' | 'locale'>> & { [x: string]: unknown };
