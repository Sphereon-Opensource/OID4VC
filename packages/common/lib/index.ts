import { Loggers, LogMethod } from '@sphereon/ssi-types';

export const VCI_LOGGERS = Loggers.default();
export const VCI_LOG_COMMON = VCI_LOGGERS.options('sphereon:oid4vci:common', { methods: [LogMethod.EVENT, LogMethod.DEBUG_PKG] }).get(
  'sphereon:oid4vci:common',
);

export * from './functions';
export * from './types';
export * from './experimental/holder-vci';
export * from './events';
