import { VCI_LOGGERS } from '@sphereon/oid4vci-common';
import { ISimpleLogger, LogMethod } from '@sphereon/ssi-types';

export const LOG: ISimpleLogger<string> = VCI_LOGGERS.options('sphereon:oid4vci:client', { methods: [LogMethod.EVENT, LogMethod.DEBUG_PKG] }).get(
  'sphereon:oid4vci:client',
);
