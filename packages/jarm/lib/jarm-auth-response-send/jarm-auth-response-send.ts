import { appendFragmentParams, appendQueryParams } from '../utils.js'
import type { JarmResponseMode, Openid4vpJarmResponseMode } from '../v-response-mode-registry.js'
import { getJarmDefaultResponseMode, validateResponseMode } from '../v-response-mode-registry.js'
import type { ResponseTypeOut } from '../v-response-type-registry.js'

interface JarmAuthResponseSendInput {
  authRequestParams: {
    response_mode?: JarmResponseMode | Openid4vpJarmResponseMode;
    response_type: ResponseTypeOut;
  } & (
    | {
        response_uri: string;
      }
    | {
        redirect_uri: string;
      }
  );

  authResponse: string;
  state: string;
}

export const jarmAuthResponseSend = async (input: JarmAuthResponseSendInput): Promise<Response> => {
  const { authRequestParams, authResponse, state } = input;

  const responseEndpoint = 'response_uri' in authRequestParams ? new URL(authRequestParams.response_uri) : new URL(authRequestParams.redirect_uri);

  const responseMode =
    authRequestParams.response_mode && authRequestParams.response_mode !== 'jwt'
      ? authRequestParams.response_mode
      : getJarmDefaultResponseMode(authRequestParams);

  validateResponseMode({
    response_type: authRequestParams.response_type,
    response_mode: responseMode,
  });

  switch (responseMode) {
    case 'direct_post.jwt':
      return handleDirectPostJwt(responseEndpoint, authResponse, state);
    case 'query.jwt':
      return handleQueryJwt(responseEndpoint, authResponse, state);
    case 'fragment.jwt':
      return handleFragmentJwt(responseEndpoint, authResponse, state);
    case 'form_post.jwt':
      throw new Error('Not implemented. form_post.jwt is not yet supported.');
  }
};

async function handleDirectPostJwt(responseEndpoint: URL, responseJwt: string, state: string) {
  const response =  await fetch(responseEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `response=${responseJwt}&state=${state}`
  })
  return response;
}

async function handleQueryJwt(responseEndpoint: URL, responseJwt: string, state: string) {
  const responseUrl = appendQueryParams({
    url: responseEndpoint,
    params: { response: responseJwt, state },
  });

  const response = await fetch(responseUrl, { method: 'POST' });
  return response;
}

async function handleFragmentJwt(responseEndpoint: URL, responseJwt: string, state: string) {
  const responseUrl = appendFragmentParams({
    url: responseEndpoint,
    fragments: { response: responseJwt, state },
  });
  const response = await fetch(responseUrl, { method: 'POST' });
  return response;
}
