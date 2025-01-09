import { EventManager } from '@sphereon/ssi-types';

export type EventNames = CredentialOfferEventNames | NotificationStatusEventNames | LogEvents | CredentialEventNames;

export enum CredentialOfferEventNames {
  OID4VCI_OFFER_CREATED = 'OID4VCI_OFFER_CREATED',
  OID4VCI_OFFER_EXPIRED = 'OID4VCI_OFFER_EXPIRED',
  OID4VCI_OFFER_DELETED = 'OID4VCI_OFFER_DELETED',
}

export enum CredentialEventNames {
  OID4VCI_CREDENTIAL_ISSUED = 'OID4VCI_CREDENTIAL_ISSUED',
}

export enum NotificationStatusEventNames {
  OID4VCI_NOTIFICATION_RECEIVED = 'OID4VCI_NOTIFICATION_RECEIVED',
  OID4VCI_NOTIFICATION_PROCESSED = 'OID4VCI_NOTIFICATION_PROCESSED',
  OID4VCI_NOTIFICATION_ERROR = 'OID4VCI_NOTIFICATION_ERROR',
}
export type LogEvents = 'oid4vciLog';
export const EVENTS = EventManager.instance();
