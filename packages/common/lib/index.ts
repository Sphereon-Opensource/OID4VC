import { Loggers } from '@sphereon/ssi-types';

export const VCI_LOGGERS = Loggers.DEFAULT;
export const VCI_LOG_COMMON = VCI_LOGGERS.get('sphereon:oid4vci:common');

export * from './jwt';
export * from './dpop';

export { v4 as uuidv4 } from 'uuid';
export { defaultHasher } from './hasher';
