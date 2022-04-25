var Buffer = require('buffer').Buffer;

var ROUNDS = 32;
var DELTA = 0x9E3779B9;

/** @private */
function encipher( v, k ) {
  var y = v[0];
  var z = v[1];
  var sum = 0;
  var limit = (DELTA * ROUNDS) >>> 0;

  while ( sum !== limit ) {
    y += (((z << 4) >>> 0 ^ (z >>> 5)) + z) ^ (sum + k[sum & 3]);
    y = y >>> 0;
    sum = (sum + DELTA) >>> 0;
    z += (((y << 4) >>> 0 ^ (y >>> 5)) + y) ^ (sum + k[(sum >> 11) & 3]);
    z = z >>> 0;
  }
  v[0] = y;
  v[1] = z;
}

/** @private */
function decipher( v, k ) {
  var y = v[0];
  var z = v[1];
  var sum = (DELTA * ROUNDS) >>> 0;

  while (sum) {
    z -= (((y << 4) >>> 0 ^ (y >>> 5)) + y) ^ (sum + k[(sum >> 11) & 3]);
    z = z >>> 0;
    sum = (sum - DELTA) >>> 0;
    y -= (((z << 4) >>> 0 ^ (z >>> 5)) + z) ^ (sum + k[sum & 3]);
    y = y >>> 0;
  }
  v[0] = y;
  v[1] = z;
}

/** @private */
function encipher_cbc( v, k, iv ) {
  v[0] ^= iv[0];
  v[1] ^= iv[1];
  encipher( v, k );
  iv[0] = v[0];
  iv[1] = v[1];
}

/** @private */
function decipher_cbc( v, k, iv ) {
  var tmp = new Uint32Array(v);
  decipher( v, k );
  v[0] ^= iv[0];
  v[1] ^= iv[1];
  iv[0] = tmp[0];
  iv[1] = tmp[1];
}

/** @private */
function doBlock( method, block ,key ) {
  var k = new Uint32Array(4);
  var v = new Uint32Array(2);
  var out = Buffer.allocUnsafe(8);

  for (var i = 0; i < 4; ++i) {
    k[i] = key.readUInt32BE(i * 4);
  }
  v[0] = block.readUInt32BE(0);
  v[1] = block.readUInt32BE(4);

  method( v, k );

  out.writeUInt32BE(v[0], 0);
  out.writeUInt32BE(v[1], 4);

  return out
}

var MODES = {
  ecb: { encrypt: encipher, decrypt: decipher },
  cbc: { encrypt: encipher_cbc, decrypt: decipher_cbc }
}

/** @private */
function doBlocks( encryption, msg, key, mode, ivbuf, skippad ) {
  mode = mode || 'ecb';
  if (!ivbuf) {
    ivbuf = Buffer.allocUnsafe(8);
    ivbuf.fill(0);
  }

  var mode_ = MODES[ mode ];
  if (!mode_) {
    throw new Error('Unimplemented mode: ' + mode);
  }

  var method;
  if (encryption) {
    method = mode_.encrypt;
  } else {
    method = mode_.decrypt;
  }

  var length = msg.length;
  var pad = 8 - (length & 7);
  if ( pad == 8 ) {
	  pad = 0;
  }

  if ( skippad || ! encryption ) {
    if (pad !== 8) {
      throw new Error("Data not aligned to 8 bytes block boundary");
    }
    pad = 0;
  }

  var out = Buffer.allocUnsafe(length + pad);
  var k = new Uint32Array(4);
  var v = new Uint32Array(2);
  var iv = new Uint32Array(2);

  iv[0] = ivbuf.readUInt32BE(0);
  iv[1] = ivbuf.readUInt32BE(4);

  for (var i = 0; i < 4; ++i) {
    k[i] = key.readUInt32BE(i * 4);
  }

  var offset = 0;
  while (offset <= length) {
    if (length - offset < 8) {
      if ( skippad || ! encryption ) {
        break;
      }

      var buf = Buffer.allocUnsafe( pad );
      buf.fill( pad );

      buf = Buffer.concat([ msg.slice( offset ), buf ]);
      v[0] = buf.readUInt32BE( 0 );
      v[1] = buf.readUInt32BE( 4 );
    } else {
      v[0] = msg.readUInt32BE( offset );
      v[1] = msg.readUInt32BE( offset + 4 );
    }

    method( v, k, iv );

    out.writeUInt32BE( v[0], offset );
    out.writeUInt32BE( v[1], offset + 4 );
    offset += 8;
  }

  if ( skippad || encryption )
    return out;

  var pad = out[out.length - 1];
  return out.slice(0, out.length - pad);
}

/**
 * Encrypts single block of data using XTEA cipher.
 *
 * @param {Buffer} block  64-bit (8-bytes) block of data to encrypt
 * @param {Buffer} key    128-bit (16-bytes) encryption key
 * @returns {Buffer}  64-bit of encrypted block
 */
function encryptBlock( block, key ) {
  return doBlock( encipher, block, key );
}

/**
 * Decrypts single block of data using XTEA cipher.
 *
 * @param {Buffer} block  64-bit (8-bytes) block of data to encrypt
 * @param {Buffer} key    128-bit (16-bytes) encryption key
 * @returns {Buffer}  64-bit of encrypted block
 */
function decryptBlock( block, key ) {
  return doBlock( decipher, block, key );
}

/**
 * Encrypts data using XTEA cipher using specified block cipher mode of operation
 * and PKCS#7 padding.
 *
 * @param {Buffer} msg  Message to encrypt
 * @param {Buffer} key  128-bit encryption key (16 bytes)
 * @param {string} [mode=ecb]  Block cipher mode of operation (currently only 'ecb' or 'cbc')
 * @param {Buffer} [iv]  Optional IV
 * @param {bool}   [skippad]  Skip PKCS#7 padding postprocessing
 * @returns {Buffer}
 */
function encrypt( msg, key, mode, ivbuf, skippad ) {
  return doBlocks( true, msg, key, mode, ivbuf, skippad );
}

/**
 * Decrypts data using XTEA cipher using specified block cipher mode of operation
 * and PKCS#7 padding.
 *
 * @param {Buffer} msg  Ciphertext to decrypt
 * @param {Buffer} key  128-bit encryption key (16 bytes)
 * @param {string} [mode=ecb]  Block cipher mode of operation (currently only 'ecb' or 'cbc')
 * @param {Buffer} [iv]  Optional IV
 * @param {bool}   [skippad]  Skip PKCS#7 padding postprocessing
 * @returns {Buffer}
 */
function decrypt( msg, key, mode, ivbuf, skippad ) {
  return doBlocks( false, msg, key, mode, ivbuf, skippad );
}

exports.encryptBlock = encryptBlock
exports.decryptBlock = decryptBlock
exports.encrypt = encrypt
exports.decrypt = decrypt
// vim: ts=2 sts=2 sw=2 et
