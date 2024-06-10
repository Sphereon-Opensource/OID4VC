import { NotificationErrorResponse, NotificationRequest, NotificationResult, post } from '@sphereon/oid4vci-common';

import { CredentialRequestOpts } from '../CredentialRequestClient';
import { LOG } from '../types';

export async function sendNotification(
  credentialRequestOpts: Partial<CredentialRequestOpts>,
  request: NotificationRequest,
  accessToken?: string,
): Promise<NotificationResult> {
  LOG.info(`Sending status notification event '${request.event}' for id ${request.notification_id}`);
  if (!credentialRequestOpts.notificationEndpoint) {
    throw Error(`Cannot send notification when no notification endpoint is provided`);
  }
  const token = accessToken ?? credentialRequestOpts.token;
  const response = await post<NotificationErrorResponse>(credentialRequestOpts.notificationEndpoint, JSON.stringify(request), {
    bearerToken: token,
  });
  const error = response.errorBody?.error !== undefined;
  const result = {
    error,
    response: error ? await response.errorBody?.json() : undefined,
  };
  if (error) {
    LOG.warning(
      `Notification endpoint returned an error for event '${request.event}' and id ${request.notification_id}: ${await response.errorBody?.json()}`,
    );
  } else {
    LOG.debug(`Notification endpoint returned success for event '${request.event}' and id ${request.notification_id}`);
  }
  return result;
}
