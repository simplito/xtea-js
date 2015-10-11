XTEA
====

A pure JavaScript implementation of [XTEA] block cipher with support 
for [ECB] and [CBC] modes of operation.

The [PKCS#7] padding is used for processing data not alligned to 8-byte block size.

The [XTEA] cipher algorithm is very effective and is supported 
by PHP's [mcrypt] cryptographic extension (in contrast to XXTEA cipher) 
so you may find this module useful when you need interoperability 
between JS and PHP and don't need stronger cryptography.

API
---

This module exports four functions:

### encrypt(msg, key, [mode=ecb], [iv], [skippad])

Encrypts data using XTEA cipher using specified block cipher mode of operation
and PKCS#7 padding.

#### Params:

* **Buffer** *msg* Message to encrypt
* **Buffer** *key* 128-bit encryption key (16 bytes)
* **string** *[mode=ecb]* Block cipher mode of operation (currently only 'ecb' or 'cbc')
* **Buffer** *[iv]* Optional IV
* **bool** *[skippad]* Skip PKCS#7 padding postprocessing

#### Return:

* **Buffer** 

### decrypt(msg, key, [mode=ecb], [iv], [skippad])

Decrypts data using XTEA cipher using specified block cipher mode of operation
and PKCS#7 padding.

#### Params:

* **Buffer** *msg* Ciphertext to decrypt
* **Buffer** *key* 128-bit encryption key (16 bytes)
* **string** *[mode=ecb]* Block cipher mode of operation (currently only 'ecb' or 'cbc')
* **Buffer** *[iv]* Optional IV
* **bool** *[skippad]* Skip PKCS#7 padding postprocessing

#### Return:

* **Buffer** 

### encryptBlock( block, key )

Encrypts single block of data using XTEA cipher.

#### Params:

* **Buffer** *block* 64-bit (8-bytes) block of data to encrypt
* **Buffer** *key* 128-bit (16-bytes) encryption key

#### Return:

* **Buffer** 64-bit of encrypted block


### decryptBlock( block, key )

Decrypts single block of data using XTEA cipher.

#### Params:

* **Buffer** *block* 64-bit (8-bytes) block of data to encrypt
* **Buffer** *key* 128-bit (16-bytes) encryption key

#### Return:

* **Buffer** 64-bit of encrypted block


Example usage
-------------

```javascript
var xtea = require('xtea');

var plaintext = new Buffer('Zażółć gęślą jaźń', 'utf8');
var key = new Buffer('33fd7bd6d85ddbe134c23fcb09c37e5a', 'hex');
var ciphertext = xtea.encrypt( plaintext, key );

console.log( ciphertext.toString('hex') );
console.log( xtea.decrypt( ciphertext, key ).toString() );
```

expected output:

```
da9466824a7606cf8faa4bf462c667c1dc4a23cb508199fdd6689b5134640e09
Zażółć gęślą jaźń
```


Example PHP code
----------------

```php
function xtea_encrypt($msg, $key, $mode, $iv) {
    $pad = 8 - (strlen($msg) % 8);
    $msg .= str_repeat(chr($pad), $pad);
    return mcrypt_encrypt(MCRYPT_XTEA, $key, $msg, $mode, $iv);
}

function xtea_decrypt($msg, $key, $mode, $iv) {
    $msg = mcrypt_decrypt(MCRYPT_XTEA, $key, $msg, $mode, $iv);
    $pad = ord($msg[ strlen($msg) - 1 ]);
    return substr($msg, 0, strlen($msg) - $pad);
}
```


Running tests
-------------

Install dev dependencies and execute `npm run test`:

    $ npm install -d
    $ npm run test


\newpage

License
-------

The MIT License (MIT)

Copyright (c) 2015 Sebastian Smyczynski, Simplito Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.


[XTEA]: https://en.wikipedia.org/wiki/XTEA
[ECB]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB
[CBC]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC
[PKCS#7]: https://en.wikipedia.org/wiki/Padding_%28cryptography%29#PKCS7
[mcrypt]: http://php.net/manual/en/book.mcrypt.php
