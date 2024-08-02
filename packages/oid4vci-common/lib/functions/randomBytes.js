'use strict';

// limit of Crypto.getRandomValues()
// https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues
const MAX_BYTES = 65536;

// Node supports requesting up to this number of bytes
// https://github.com/nodejs/node/blob/master/lib/internal/crypto/random.js#L48
const MAX_UINT32 = 4294967295;

function oldBrowser() {
  throw new Error('Secure random number generation is not supported by this browser.\nUse Chrome, Firefox or Internet Explorer 11');
}

// eslint-disable-next-line no-undef
const _global = typeof globalThis !== 'undefined' ? globalThis : global;

let crypto = _global.crypto || _global.msCrypto;
if (!crypto) {
  try {
    // eslint-disable-next-line no-undef
    crypto = require('crypto');
  } catch (err) {
    throw Error('crypto module is not available');
  }
}

if (crypto && crypto.getRandomValues) {
  // eslint-disable-next-line no-undef
  module.exports = randomBytes;
} else {
  // eslint-disable-next-line no-undef
  module.exports = oldBrowser;
}

function randomBytes(size) {
  // phantomjs needs to throw
  if (size > MAX_UINT32) throw new Error('requested too many random bytes');

  // eslint-disable-next-line no-undef
  const bytes = Buffer.allocUnsafe(size);

  if (size > 0) {
    // getRandomValues fails on IE if size == 0
    if (size > MAX_BYTES) {
      // this is the max bytes crypto.getRandomValues
      // can do at once see https://developer.mozilla.org/en-US/docs/Web/API/window.crypto.getRandomValues
      for (let generated = 0; generated < size; generated += MAX_BYTES) {
        // buffer.slice automatically checks if the end is past the end of
        // the buffer so we don't have to here
        crypto.getRandomValues(bytes.slice(generated, generated + MAX_BYTES));
      }
    } else {
      crypto.getRandomValues(bytes);
    }
  }
  return Uint8Array.from(bytes);
}

// eslint-disable-next-line no-undef
module.exports = { randomBytes };
