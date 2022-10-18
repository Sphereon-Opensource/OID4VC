export interface ErrorResponse extends Response {
  error: string;
  error_description?: string;
  error_uri?: string;
  state?: string;
}

export const PRE_AUTH_CODE_LITERAL = 'pre-authorized_code';
