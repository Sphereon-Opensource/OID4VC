import { Loggers, LogMethod } from '@sphereon/ssi-types';

export * from './Authorization.types';
export * from './CredentialIssuance.types';
export * from './Generic.types';
export * from './v1_0_08.types';
export * from './v1_0_09.types';
export * from './v1_0_11.types';
export * from './ServerMetadata';
export * from './OpenID4VCIErrors';
export * from './OpenID4VCIVersions.types';
export * from './StateManager.types';
export * from './Token.types';
export * from './QRCode.types';

export const VCI_LOGGERS = Loggers.default();
export const VCI_LOG_COMMON = VCI_LOGGERS.options('sphereon:oid4vci:common', { methods: [LogMethod.EVENT, LogMethod.DEBUG_PKG] }).get(
  'sphereon:oid4vci:common',
);
