(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
(function (process,Buffer){
/*
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
'License'); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
*/

/* Test RSA - test driver and function exerciser for RSA_WWW API Functions */

var CTX = require("../src/ctx");

var ctx = new CTX('RSA2048');

console.log('Start test RSA2048');

// Load test vectors
var vectors = require('../testVectors/RSA2048.json');

var i, j = 0,
    res;
var result;

var RAW = [];
var rng = new ctx.RAND();
rng.clean();
for (i = 0; i < 100; i++) RAW[i] = i;

rng.seed(100, RAW);

var sha = ctx.RSA.HASH_TYPE;
var message = 'Hello World\n';
var pub = new ctx.rsa_public_key(ctx.FF.FFLEN);
var priv = new ctx.rsa_private_key(ctx.FF.HFLEN);

var ML = [];
var C = [];
var S = [];

var start, end, time;
start = new Date().getTime();
console.log('Load RSA public/private key pair from test vectors');

ctx.FF.fromBytes(priv.p, new Buffer(vectors['priv.p'], "hex"));
ctx.FF.fromBytes(priv.q, new Buffer(vectors['priv.q'], "hex"));
ctx.FF.fromBytes(priv.dp, new Buffer(vectors['priv.dp'], "hex"));
ctx.FF.fromBytes(priv.dq, new Buffer(vectors['priv.dq'], "hex"));
ctx.FF.fromBytes(priv.c, new Buffer(vectors['priv.c'], "hex"));
ctx.FF.fromBytes(pub.n, new Buffer(vectors['pub.n'], "hex"));
pub.e = vectors['pub.e'];

end = new Date().getTime();
time = end - start;
console.log('Time in ms= ' + time);

var M = ctx.RSA.stringtobytes(message);
console.log('Encrypting test string');

var E = ctx.RSA.OAEP_ENCODE(sha, M, rng, null); /* OAEP encode message m to e  */
console.log('Encoding= 0x' + ctx.RSA.bytestohex(E));

console.log('Public key= 0x' + pub.n.toString());

start = new Date().getTime();
ctx.RSA.ENCRYPT(pub, E, C); /* encrypt encoded message */
end = new Date().getTime();
time = end - start;
console.log('Time in ms= ' + time);

console.log('Ciphertext= 0x' + ctx.RSA.bytestohex(C));

console.log('Decrypting test string');
start = new Date().getTime();
ctx.RSA.DECRYPT(priv, C, ML);
end = new Date().getTime();
time = end - start;
console.log('Time in ms= ' + time);

var cmp = true;
if (E.length != ML.length) cmp = false;
else {
    for (var j = 0; j < E.length; j++)
        if (E[j] != ML[j]) cmp = false;
}
if (cmp) console.log('Decryption is OK');
else {
    console.error('Decryption Failed');
    process.exit(-1);
}

var MS = ctx.RSA.OAEP_DECODE(sha, null, ML); /* OAEP decode message  */
console.log('Decoding= 0x' + ctx.RSA.bytestohex(MS));

console.log('message= ' + ctx.RSA.bytestostring(MS));

console.log('Start test RSA signature');

ctx.RSA.PKCS15(sha, M, C);

ctx.RSA.DECRYPT(priv, C, S); /* create signature in S */

console.log('Signature= 0x' + ctx.RSA.bytestohex(S));

ctx.RSA.ENCRYPT(pub, S, ML);

cmp = true;
if (C.length != ML.length) cmp = false;
else {
    for (var j = 0; j < C.length; j++)
        if (C[j] != ML[j]) cmp = false;
}
if (cmp) console.log('Signature is valid');
else {
    console.error('Signature is INVALID');
    process.exit(-1);
}
ctx.RSA.PRIVATE_KEY_KILL(priv);

console.log('SUCCESS')




var ctx1 = new CTX('RSA3072');

console.log('\n\nStart test RSA3072');

// Load test vectors
var vectors = require('../testVectors/RSA3072.json');

var i, j = 0,
    res;
var result;

var RAW = [];
var rng = new ctx1.RAND();
rng.clean();
for (i = 0; i < 100; i++) RAW[i] = i;

rng.seed(100, RAW);

var sha = ctx1.RSA.HASH_TYPE;
var message = 'Hello World\n';
var pub = new ctx1.rsa_public_key(ctx1.FF.FFLEN);
var priv = new ctx1.rsa_private_key(ctx1.FF.HFLEN);

var ML = [];
var C = [];
var S = [];

var start, end, time;
start = new Date().getTime();
console.log('Load RSA public/private key pair from test vectors');

ctx1.FF.fromBytes(priv.p, new Buffer(vectors['priv.p'], "hex"));
ctx1.FF.fromBytes(priv.q, new Buffer(vectors['priv.q'], "hex"));
ctx1.FF.fromBytes(priv.dp, new Buffer(vectors['priv.dp'], "hex"));
ctx1.FF.fromBytes(priv.dq, new Buffer(vectors['priv.dq'], "hex"));
ctx1.FF.fromBytes(priv.c, new Buffer(vectors['priv.c'], "hex"));
ctx1.FF.fromBytes(pub.n, new Buffer(vectors['pub.n'], "hex"));
pub.e = vectors['pub.e'];

end = new Date().getTime();
time = end - start;
console.log('Time in ms= ' + time);

var M = ctx1.RSA.stringtobytes(message);
console.log('Encrypting test string');

var E = ctx1.RSA.OAEP_ENCODE(sha, M, rng, null); /* OAEP encode message m to e  */
console.log('Encoding= 0x' + ctx1.RSA.bytestohex(E));

console.log('Public key= 0x' + pub.n.toString());

start = new Date().getTime();
ctx1.RSA.ENCRYPT(pub, E, C); /* encrypt encoded message */
end = new Date().getTime();
time = end - start;
console.log('Time in ms= ' + time);

console.log('Ciphertext= 0x' + ctx1.RSA.bytestohex(C));

console.log('Decrypting test string');
start = new Date().getTime();
ctx1.RSA.DECRYPT(priv, C, ML);
end = new Date().getTime();
time = end - start;
console.log('Time in ms= ' + time);

var cmp = true;
if (E.length != ML.length) cmp = false;
else {
    for (var j = 0; j < E.length; j++)
        if (E[j] != ML[j]) cmp = false;
}
if (cmp) console.log('Decryption is OK');
else {
    console.error('Decryption Failed');
    process.exit(-1);
}

var MS = ctx1.RSA.OAEP_DECODE(sha, null, ML); /* OAEP decode message  */
console.log('Decoding= 0x' + ctx1.RSA.bytestohex(MS));

console.log('message= ' + ctx1.RSA.bytestostring(MS));

console.log('Start test RSA signature');

ctx1.RSA.PKCS15(sha, M, C);

ctx1.RSA.DECRYPT(priv, C, S); /* create signature in S */

console.log('Signature= 0x' + ctx1.RSA.bytestohex(S));

ctx1.RSA.ENCRYPT(pub, S, ML);

cmp = true;
if (C.length != ML.length) cmp = false;
else {
    for (var j = 0; j < C.length; j++)
        if (C[j] != ML[j]) cmp = false;
}
if (cmp) console.log('Signature is valid');
else {
    console.error('Signature is INVALID');
    process.exit(-1);
}
ctx1.RSA.PRIVATE_KEY_KILL(priv);

console.log('SUCCESS')
}).call(this,require('_process'),require("buffer").Buffer)
},{"../src/ctx":4,"../testVectors/RSA2048.json":24,"../testVectors/RSA3072.json":25,"_process":29,"buffer":27}],2:[function(require,module,exports){
/*
	Licensed to the Apache Software Foundation (ASF) under one
	or more contributor license agreements.  See the NOTICE file
	distributed with this work for additional information
	regarding copyright ownership.  The ASF licenses this file
	to you under the Apache License, Version 2.0 (the
	"License"); you may not use this file except in compliance
	with the License.  You may obtain a copy of the License at
	
	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing,
	software distributed under the License is distributed on an
	"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
	KIND, either express or implied.  See the License for the
	specific language governing permissions and limitations
	under the License.
*/

module.exports.AES = function(ctx) {

    var AES = function() {
        this.Nk = 0;
        this.Nr = 0;
        this.mode = 0;
        this.fkey = [];
        this.rkey = [];
        this.f = [];
    };

    // AES constants

    AES.ECB = 0;
    AES.CBC = 1;
    AES.CFB1 = 2;
    AES.CFB2 = 3;
    AES.CFB4 = 5;
    AES.OFB1 = 14;
    AES.OFB2 = 15;
    AES.OFB4 = 17;
    AES.OFB8 = 21;
    AES.OFB16 = 29;
    AES.CTR1 = 30;
    AES.CTR2 = 31;
    AES.CTR4 = 33;
    AES.CTR8 = 37;
    AES.CTR16 = 45;

    AES.prototype = {
        /* reset cipher */
        reset: function(m, iv) { /* reset mode, or reset iv */
            var i;
            this.mode = m;
            for (i = 0; i < 16; i++)
                this.f[i] = 0;
            if (this.mode != AES.ECB && iv !== null)
                for (i = 0; i < 16; i++)
                    this.f[i] = iv[i];
        },

        getreg: function() {
            var ir = [];
            for (var i = 0; i < 16; i++) ir[i] = this.f[i];
            return ir;
        },

        increment: function() {
            for (var i = 0; i < 16; i++) {
                this.f[i]++;
                if ((this.f[i] & 0xff) != 0) break;
            }
        },

        /* Initialise cipher */
        init: function(m, nk, key, iv) { /* Key=16 bytes */
            /* Key Scheduler. Create expanded encryption key */
            var i, j, k, N, nr;
            var CipherKey = [];
            var b = [];
            nk /= 4;

            if (nk != 4 && nk != 6 && nk != 8) return false;

            nr = 6 + nk;

            this.Nk = nk;
            this.Nr = nr;


            this.reset(m, iv);
            N = 4 * (nr + 1);

            for (i = j = 0; i < nk; i++, j += 4) {
                for (k = 0; k < 4; k++) b[k] = key[j + k];
                CipherKey[i] = AES.pack(b);
            }
            for (i = 0; i < nk; i++) this.fkey[i] = CipherKey[i];
            for (j = nk, k = 0; j < N; j += nk, k++) {
                this.fkey[j] = this.fkey[j - nk] ^ AES.SubByte(AES.ROTL24(this.fkey[j - 1])) ^ (AES.rco[k]) & 0xff;
                for (i = 1; i < nk && (i + j) < N; i++)
                    this.fkey[i + j] = this.fkey[i + j - nk] ^ this.fkey[i + j - 1];
            }

            /* now for the expanded decrypt key in reverse order */

            for (j = 0; j < 4; j++) this.rkey[j + N - 4] = this.fkey[j];
            for (i = 4; i < N - 4; i += 4) {
                k = N - 4 - i;
                for (j = 0; j < 4; j++) this.rkey[k + j] = AES.InvMixCol(this.fkey[i + j]);
            }
            for (j = N - 4; j < N; j++) this.rkey[j - N + 4] = this.fkey[j];
        },

        /* Encrypt a single block */
        ecb_encrypt: function(buff) {
            var i, j, k;
            var t;
            var b = [];
            var p = [];
            var q = [];

            for (i = j = 0; i < 4; i++, j += 4) {
                for (k = 0; k < 4; k++) b[k] = buff[j + k];
                p[i] = AES.pack(b);
                p[i] ^= this.fkey[i];
            }

            k = 4;

            /* State alternates between p and q */
            for (i = 1; i < this.Nr; i++) {
                q[0] = this.fkey[k] ^ AES.ftable[p[0] & 0xff] ^
                    AES.ROTL8(AES.ftable[(p[1] >>> 8) & 0xff]) ^
                    AES.ROTL16(AES.ftable[(p[2] >>> 16) & 0xff]) ^
                    AES.ROTL24(AES.ftable[(p[3] >>> 24) & 0xff]);
                q[1] = this.fkey[k + 1] ^ AES.ftable[p[1] & 0xff] ^
                    AES.ROTL8(AES.ftable[(p[2] >>> 8) & 0xff]) ^
                    AES.ROTL16(AES.ftable[(p[3] >>> 16) & 0xff]) ^
                    AES.ROTL24(AES.ftable[(p[0] >>> 24) & 0xff]);
                q[2] = this.fkey[k + 2] ^ AES.ftable[p[2] & 0xff] ^
                    AES.ROTL8(AES.ftable[(p[3] >>> 8) & 0xff]) ^
                    AES.ROTL16(AES.ftable[(p[0] >>> 16) & 0xff]) ^
                    AES.ROTL24(AES.ftable[(p[1] >>> 24) & 0xff]);
                q[3] = this.fkey[k + 3] ^ AES.ftable[p[3] & 0xff] ^
                    AES.ROTL8(AES.ftable[(p[0] >>> 8) & 0xff]) ^
                    AES.ROTL16(AES.ftable[(p[1] >>> 16) & 0xff]) ^
                    AES.ROTL24(AES.ftable[(p[2] >>> 24) & 0xff]);

                k += 4;
                for (j = 0; j < 4; j++) {
                    t = p[j];
                    p[j] = q[j];
                    q[j] = t;
                }
            }

            /* Last Round */

            q[0] = this.fkey[k] ^ (AES.fbsub[p[0] & 0xff] & 0xff) ^
                AES.ROTL8(AES.fbsub[(p[1] >>> 8) & 0xff] & 0xff) ^
                AES.ROTL16(AES.fbsub[(p[2] >>> 16) & 0xff] & 0xff) ^
                AES.ROTL24(AES.fbsub[(p[3] >>> 24) & 0xff] & 0xff);

            q[1] = this.fkey[k + 1] ^ (AES.fbsub[p[1] & 0xff] & 0xff) ^
                AES.ROTL8(AES.fbsub[(p[2] >>> 8) & 0xff] & 0xff) ^
                AES.ROTL16(AES.fbsub[(p[3] >>> 16) & 0xff] & 0xff) ^
                AES.ROTL24(AES.fbsub[(p[0] >>> 24) & 0xff] & 0xff);

            q[2] = this.fkey[k + 2] ^ (AES.fbsub[p[2] & 0xff] & 0xff) ^
                AES.ROTL8(AES.fbsub[(p[3] >>> 8) & 0xff] & 0xff) ^
                AES.ROTL16(AES.fbsub[(p[0] >>> 16) & 0xff] & 0xff) ^
                AES.ROTL24(AES.fbsub[(p[1] >>> 24) & 0xff] & 0xff);

            q[3] = this.fkey[k + 3] ^ (AES.fbsub[(p[3]) & 0xff] & 0xff) ^
                AES.ROTL8(AES.fbsub[(p[0] >>> 8) & 0xff] & 0xff) ^
                AES.ROTL16(AES.fbsub[(p[1] >>> 16) & 0xff] & 0xff) ^
                AES.ROTL24(AES.fbsub[(p[2] >>> 24) & 0xff] & 0xff);

            for (i = j = 0; i < 4; i++, j += 4) {
                b = AES.unpack(q[i]);
                for (k = 0; k < 4; k++) buff[j + k] = b[k];
            }
        },

        /* Decrypt a single block */
        ecb_decrypt: function(buff) {
            var i, j, k;
            var t;
            var b = [];
            var p = [];
            var q = [];

            for (i = j = 0; i < 4; i++, j += 4) {
                for (k = 0; k < 4; k++) b[k] = buff[j + k];
                p[i] = AES.pack(b);
                p[i] ^= this.rkey[i];
            }

            k = 4;

            /* State alternates between p and q */
            for (i = 1; i < this.Nr; i++) {
                q[0] = this.rkey[k] ^ AES.rtable[p[0] & 0xff] ^
                    AES.ROTL8(AES.rtable[(p[3] >>> 8) & 0xff]) ^
                    AES.ROTL16(AES.rtable[(p[2] >>> 16) & 0xff]) ^
                    AES.ROTL24(AES.rtable[(p[1] >>> 24) & 0xff]);
                q[1] = this.rkey[k + 1] ^ AES.rtable[p[1] & 0xff] ^
                    AES.ROTL8(AES.rtable[(p[0] >>> 8) & 0xff]) ^
                    AES.ROTL16(AES.rtable[(p[3] >>> 16) & 0xff]) ^
                    AES.ROTL24(AES.rtable[(p[2] >>> 24) & 0xff]);
                q[2] = this.rkey[k + 2] ^ AES.rtable[p[2] & 0xff] ^
                    AES.ROTL8(AES.rtable[(p[1] >>> 8) & 0xff]) ^
                    AES.ROTL16(AES.rtable[(p[0] >>> 16) & 0xff]) ^
                    AES.ROTL24(AES.rtable[(p[3] >>> 24) & 0xff]);
                q[3] = this.rkey[k + 3] ^ AES.rtable[p[3] & 0xff] ^
                    AES.ROTL8(AES.rtable[(p[2] >>> 8) & 0xff]) ^
                    AES.ROTL16(AES.rtable[(p[1] >>> 16) & 0xff]) ^
                    AES.ROTL24(AES.rtable[(p[0] >>> 24) & 0xff]);

                k += 4;
                for (j = 0; j < 4; j++) {
                    t = p[j];
                    p[j] = q[j];
                    q[j] = t;
                }
            }

            /* Last Round */

            q[0] = this.rkey[k] ^ (AES.rbsub[p[0] & 0xff] & 0xff) ^
                AES.ROTL8(AES.rbsub[(p[3] >>> 8) & 0xff] & 0xff) ^
                AES.ROTL16(AES.rbsub[(p[2] >>> 16) & 0xff] & 0xff) ^
                AES.ROTL24(AES.rbsub[(p[1] >>> 24) & 0xff] & 0xff);
            q[1] = this.rkey[k + 1] ^ (AES.rbsub[p[1] & 0xff] & 0xff) ^
                AES.ROTL8(AES.rbsub[(p[0] >>> 8) & 0xff] & 0xff) ^
                AES.ROTL16(AES.rbsub[(p[3] >>> 16) & 0xff] & 0xff) ^
                AES.ROTL24(AES.rbsub[(p[2] >>> 24) & 0xff] & 0xff);
            q[2] = this.rkey[k + 2] ^ (AES.rbsub[p[2] & 0xff] & 0xff) ^
                AES.ROTL8(AES.rbsub[(p[1] >>> 8) & 0xff] & 0xff) ^
                AES.ROTL16(AES.rbsub[(p[0] >>> 16) & 0xff] & 0xff) ^
                AES.ROTL24(AES.rbsub[(p[3] >>> 24) & 0xff] & 0xff);
            q[3] = this.rkey[k + 3] ^ (AES.rbsub[p[3] & 0xff] & 0xff) ^
                AES.ROTL8(AES.rbsub[(p[2] >>> 8) & 0xff] & 0xff) ^
                AES.ROTL16(AES.rbsub[(p[1] >>> 16) & 0xff] & 0xff) ^
                AES.ROTL24(AES.rbsub[(p[0] >>> 24) & 0xff] & 0xff);

            for (i = j = 0; i < 4; i++, j += 4) {
                b = AES.unpack(q[i]);
                for (k = 0; k < 4; k++) buff[j + k] = b[k];
            }

        },

        /* Encrypt using selected mode of operation */
        encrypt: function(buff) {
            var j, bytes;
            var st = [];
            var fell_off;

            // Supported Modes of Operation 

            fell_off = 0;

            switch (this.mode) {
                case AES.ECB:
                    this.ecb_encrypt(buff);
                    return 0;
                case AES.CBC:
                    for (j = 0; j < 16; j++) buff[j] ^= this.f[j];
                    this.ecb_encrypt(buff);
                    for (j = 0; j < 16; j++) this.f[j] = buff[j];
                    return 0;

                case AES.CFB1:
                case AES.CFB2:
                case AES.CFB4:
                    bytes = this.mode - AES.CFB1 + 1;
                    for (j = 0; j < bytes; j++) fell_off = (fell_off << 8) | this.f[j];
                    for (j = 0; j < 16; j++) st[j] = this.f[j];
                    for (j = bytes; j < 16; j++) this.f[j - bytes] = this.f[j];
                    this.ecb_encrypt(st);
                    for (j = 0; j < bytes; j++) {
                        buff[j] ^= st[j];
                        this.f[16 - bytes + j] = buff[j];
                    }
                    return fell_off;

                case AES.OFB1:
                case AES.OFB2:
                case AES.OFB4:
                case AES.OFB8:
                case AES.OFB16:

                    bytes = this.mode - AES.OFB1 + 1;
                    this.ecb_encrypt(this.f);
                    for (j = 0; j < bytes; j++) buff[j] ^= this.f[j];
                    return 0;

                case AES.CTR1:
                case AES.CTR2:
                case AES.CTR4:
                case AES.CTR8:
                case AES.CTR16:

                    bytes = this.mode - AES.CTR1 + 1;
                    for (j = 0; j < 16; j++) st[j] = this.f[j];
                    this.ecb_encrypt(st);
                    for (j = 0; j < bytes; j++) buff[j] ^= st[j];
                    this.increment();

                default:
                    return 0;
            }
        },

        /* Decrypt using selected mode of operation */
        decrypt: function(buff) {
            var j, bytes;
            var st = [];
            var fell_off;

            // Supported modes of operation 
            fell_off = 0;
            switch (this.mode) {
                case AES.ECB:
                    this.ecb_decrypt(buff);
                    return 0;
                case AES.CBC:
                    for (j = 0; j < 16; j++) {
                        st[j] = this.f[j];
                        this.f[j] = buff[j];
                    }
                    this.ecb_decrypt(buff);
                    for (j = 0; j < 16; j++) {
                        buff[j] ^= st[j];
                        st[j] = 0;
                    }
                    return 0;
                case AES.CFB1:
                case AES.CFB2:
                case AES.CFB4:
                    bytes = this.mode - AES.CFB1 + 1;
                    for (j = 0; j < bytes; j++) fell_off = (fell_off << 8) | this.f[j];
                    for (j = 0; j < 16; j++) st[j] = this.f[j];
                    for (j = bytes; j < 16; j++) this.f[j - bytes] = this.f[j];
                    this.ecb_encrypt(st);
                    for (j = 0; j < bytes; j++) {
                        this.f[16 - bytes + j] = buff[j];
                        buff[j] ^= st[j];
                    }
                    return fell_off;
                case AES.OFB1:
                case AES.OFB2:
                case AES.OFB4:
                case AES.OFB8:
                case AES.OFB16:
                    bytes = this.mode - AES.OFB1 + 1;
                    this.ecb_encrypt(this.f);
                    for (j = 0; j < bytes; j++) buff[j] ^= this.f[j];
                    return 0;

                case AES.CTR1:
                case AES.CTR2:
                case AES.CTR4:
                case AES.CTR8:
                case AES.CTR16:
                    bytes = this.mode - AES.CTR1 + 1;
                    for (j = 0; j < 16; j++) st[j] = this.f[j];
                    this.ecb_encrypt(st);
                    for (j = 0; j < bytes; j++) buff[j] ^= st[j];
                    this.increment();
                default:
                    return 0;
            }
        },

        /* Clean up and delete left-overs */
        end: function() { // clean up 
            var i;
            for (i = 0; i < 4 * (this.Nr + 1); i++)
                this.fkey[i] = this.rkey[i] = 0;
            for (i = 0; i < 16; i++)
                this.f[i] = 0;
        }

    };

    /* static functions */

    AES.ROTL8 = function(x) {
        return (((x) << 8) | ((x) >>> 24));
    };

    AES.ROTL16 = function(x) {
        return (((x) << 16) | ((x) >>> 16));
    };

    AES.ROTL24 = function(x) {
        return (((x) << 24) | ((x) >>> 8));
    };

    AES.pack = function(b) { /* pack 4 bytes into a 32-bit Word */
        return (((b[3]) & 0xff) << 24) | ((b[2] & 0xff) << 16) | ((b[1] & 0xff) << 8) | (b[0] & 0xff);
    };

    AES.unpack = function(a) { /* unpack bytes from a word */
        var b = [];
        b[0] = (a & 0xff);
        b[1] = ((a >>> 8) & 0xff);
        b[2] = ((a >>> 16) & 0xff);
        b[3] = ((a >>> 24) & 0xff);
        return b;
    };

    AES.bmul = function(x, y) { /* x.y= AntiLog(Log(x) + Log(y)) */

        var ix = (x & 0xff);
        var iy = (y & 0xff);
        var lx = (AES.ltab[ix]) & 0xff;
        var ly = (AES.ltab[iy]) & 0xff;
        if (x !== 0 && y !== 0) return AES.ptab[(lx + ly) % 255];
        else return 0;
    };

    //  if (x && y) 

    AES.SubByte = function(a) {
        var b = AES.unpack(a);
        b[0] = AES.fbsub[b[0] & 0xff];
        b[1] = AES.fbsub[b[1] & 0xff];
        b[2] = AES.fbsub[b[2] & 0xff];
        b[3] = AES.fbsub[b[3] & 0xff];
        return AES.pack(b);
    };

    AES.product = function(x, y) { /* dot product of two 4-byte arrays */
        var xb = AES.unpack(x);
        var yb = AES.unpack(y);
        return (AES.bmul(xb[0], yb[0]) ^ AES.bmul(xb[1], yb[1]) ^ AES.bmul(xb[2], yb[2]) ^ AES.bmul(xb[3], yb[3])) & 0xff;
    };

    AES.InvMixCol = function(x) { /* matrix Multiplication */
        var y, m;
        var b = [];
        m = AES.pack(AES.InCo);
        b[3] = AES.product(m, x);
        m = AES.ROTL24(m);
        b[2] = AES.product(m, x);
        m = AES.ROTL24(m);
        b[1] = AES.product(m, x);
        m = AES.ROTL24(m);
        b[0] = AES.product(m, x);
        y = AES.pack(b);
        return y;
    };

    AES.InCo = [0xB, 0xD, 0x9, 0xE]; /* Inverse Coefficients */
    AES.rco = [1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47];

    AES.ptab = [
        1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53,
        95, 225, 56, 72, 216, 115, 149, 164, 247, 2, 6, 10, 30, 34, 102, 170,
        229, 52, 92, 228, 55, 89, 235, 38, 106, 190, 217, 112, 144, 171, 230, 49,
        83, 245, 4, 12, 20, 60, 68, 204, 79, 209, 104, 184, 211, 110, 178, 205,
        76, 212, 103, 169, 224, 59, 77, 215, 98, 166, 241, 8, 24, 40, 120, 136,
        131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206, 73, 219, 118, 154,
        181, 196, 87, 249, 16, 48, 80, 240, 11, 29, 39, 105, 187, 214, 97, 163,
        254, 25, 43, 125, 135, 146, 173, 236, 47, 113, 147, 174, 233, 32, 96, 160,
        251, 22, 58, 78, 210, 109, 183, 194, 93, 231, 50, 86, 250, 21, 63, 65,
        195, 94, 226, 61, 71, 201, 64, 192, 91, 237, 44, 116, 156, 191, 218, 117,
        159, 186, 213, 100, 172, 239, 42, 126, 130, 157, 188, 223, 122, 142, 137, 128,
        155, 182, 193, 88, 232, 35, 101, 175, 234, 37, 111, 177, 200, 67, 197, 84,
        252, 31, 33, 99, 165, 244, 7, 9, 27, 45, 119, 153, 176, 203, 70, 202,
        69, 207, 74, 222, 121, 139, 134, 145, 168, 227, 62, 66, 198, 81, 243, 14,
        18, 54, 90, 238, 41, 123, 141, 140, 143, 138, 133, 148, 167, 242, 13, 23,
        57, 75, 221, 124, 132, 151, 162, 253, 28, 36, 108, 180, 199, 82, 246, 1
    ];
    AES.ltab = [
        0, 255, 25, 1, 50, 2, 26, 198, 75, 199, 27, 104, 51, 238, 223, 3,
        100, 4, 224, 14, 52, 141, 129, 239, 76, 113, 8, 200, 248, 105, 28, 193,
        125, 194, 29, 181, 249, 185, 39, 106, 77, 228, 166, 114, 154, 201, 9, 120,
        101, 47, 138, 5, 33, 15, 225, 36, 18, 240, 130, 69, 53, 147, 218, 142,
        150, 143, 219, 189, 54, 208, 206, 148, 19, 92, 210, 241, 64, 70, 131, 56,
        102, 221, 253, 48, 191, 6, 139, 98, 179, 37, 226, 152, 34, 136, 145, 16,
        126, 110, 72, 195, 163, 182, 30, 66, 58, 107, 40, 84, 250, 133, 61, 186,
        43, 121, 10, 21, 155, 159, 94, 202, 78, 212, 172, 229, 243, 115, 167, 87,
        175, 88, 168, 80, 244, 234, 214, 116, 79, 174, 233, 213, 231, 230, 173, 232,
        44, 215, 117, 122, 235, 22, 11, 245, 89, 203, 95, 176, 156, 169, 81, 160,
        127, 12, 246, 111, 23, 196, 73, 236, 216, 67, 31, 45, 164, 118, 123, 183,
        204, 187, 62, 90, 251, 96, 177, 134, 59, 82, 161, 108, 170, 85, 41, 157,
        151, 178, 135, 144, 97, 190, 220, 252, 188, 149, 207, 205, 55, 63, 91, 209,
        83, 57, 132, 60, 65, 162, 109, 71, 20, 42, 158, 93, 86, 242, 211, 171,
        68, 17, 146, 217, 35, 32, 46, 137, 180, 124, 184, 38, 119, 153, 227, 165,
        103, 74, 237, 222, 197, 49, 254, 24, 13, 99, 140, 128, 192, 247, 112, 7
    ];
    AES.fbsub = [
        99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,
        202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192,
        183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21,
        4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117,
        9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132,
        83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207,
        208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168,
        81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210,
        205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115,
        96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219,
        224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121,
        231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8,
        186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138,
        112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158,
        225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223,
        140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22
    ];
    AES.rbsub = [
        82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
        124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
        84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
        8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37,
        114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146,
        108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132,
        144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6,
        208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107,
        58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115,
        150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110,
        71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27,
        252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244,
        31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
        96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
        160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
        23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125
    ];
    AES.ftable = [
        0xa56363c6, 0x847c7cf8, 0x997777ee, 0x8d7b7bf6, 0xdf2f2ff, 0xbd6b6bd6,
        0xb16f6fde, 0x54c5c591, 0x50303060, 0x3010102, 0xa96767ce, 0x7d2b2b56,
        0x19fefee7, 0x62d7d7b5, 0xe6abab4d, 0x9a7676ec, 0x45caca8f, 0x9d82821f,
        0x40c9c989, 0x877d7dfa, 0x15fafaef, 0xeb5959b2, 0xc947478e, 0xbf0f0fb,
        0xecadad41, 0x67d4d4b3, 0xfda2a25f, 0xeaafaf45, 0xbf9c9c23, 0xf7a4a453,
        0x967272e4, 0x5bc0c09b, 0xc2b7b775, 0x1cfdfde1, 0xae93933d, 0x6a26264c,
        0x5a36366c, 0x413f3f7e, 0x2f7f7f5, 0x4fcccc83, 0x5c343468, 0xf4a5a551,
        0x34e5e5d1, 0x8f1f1f9, 0x937171e2, 0x73d8d8ab, 0x53313162, 0x3f15152a,
        0xc040408, 0x52c7c795, 0x65232346, 0x5ec3c39d, 0x28181830, 0xa1969637,
        0xf05050a, 0xb59a9a2f, 0x907070e, 0x36121224, 0x9b80801b, 0x3de2e2df,
        0x26ebebcd, 0x6927274e, 0xcdb2b27f, 0x9f7575ea, 0x1b090912, 0x9e83831d,
        0x742c2c58, 0x2e1a1a34, 0x2d1b1b36, 0xb26e6edc, 0xee5a5ab4, 0xfba0a05b,
        0xf65252a4, 0x4d3b3b76, 0x61d6d6b7, 0xceb3b37d, 0x7b292952, 0x3ee3e3dd,
        0x712f2f5e, 0x97848413, 0xf55353a6, 0x68d1d1b9, 0x0, 0x2cededc1,
        0x60202040, 0x1ffcfce3, 0xc8b1b179, 0xed5b5bb6, 0xbe6a6ad4, 0x46cbcb8d,
        0xd9bebe67, 0x4b393972, 0xde4a4a94, 0xd44c4c98, 0xe85858b0, 0x4acfcf85,
        0x6bd0d0bb, 0x2aefefc5, 0xe5aaaa4f, 0x16fbfbed, 0xc5434386, 0xd74d4d9a,
        0x55333366, 0x94858511, 0xcf45458a, 0x10f9f9e9, 0x6020204, 0x817f7ffe,
        0xf05050a0, 0x443c3c78, 0xba9f9f25, 0xe3a8a84b, 0xf35151a2, 0xfea3a35d,
        0xc0404080, 0x8a8f8f05, 0xad92923f, 0xbc9d9d21, 0x48383870, 0x4f5f5f1,
        0xdfbcbc63, 0xc1b6b677, 0x75dadaaf, 0x63212142, 0x30101020, 0x1affffe5,
        0xef3f3fd, 0x6dd2d2bf, 0x4ccdcd81, 0x140c0c18, 0x35131326, 0x2fececc3,
        0xe15f5fbe, 0xa2979735, 0xcc444488, 0x3917172e, 0x57c4c493, 0xf2a7a755,
        0x827e7efc, 0x473d3d7a, 0xac6464c8, 0xe75d5dba, 0x2b191932, 0x957373e6,
        0xa06060c0, 0x98818119, 0xd14f4f9e, 0x7fdcdca3, 0x66222244, 0x7e2a2a54,
        0xab90903b, 0x8388880b, 0xca46468c, 0x29eeeec7, 0xd3b8b86b, 0x3c141428,
        0x79dedea7, 0xe25e5ebc, 0x1d0b0b16, 0x76dbdbad, 0x3be0e0db, 0x56323264,
        0x4e3a3a74, 0x1e0a0a14, 0xdb494992, 0xa06060c, 0x6c242448, 0xe45c5cb8,
        0x5dc2c29f, 0x6ed3d3bd, 0xefacac43, 0xa66262c4, 0xa8919139, 0xa4959531,
        0x37e4e4d3, 0x8b7979f2, 0x32e7e7d5, 0x43c8c88b, 0x5937376e, 0xb76d6dda,
        0x8c8d8d01, 0x64d5d5b1, 0xd24e4e9c, 0xe0a9a949, 0xb46c6cd8, 0xfa5656ac,
        0x7f4f4f3, 0x25eaeacf, 0xaf6565ca, 0x8e7a7af4, 0xe9aeae47, 0x18080810,
        0xd5baba6f, 0x887878f0, 0x6f25254a, 0x722e2e5c, 0x241c1c38, 0xf1a6a657,
        0xc7b4b473, 0x51c6c697, 0x23e8e8cb, 0x7cdddda1, 0x9c7474e8, 0x211f1f3e,
        0xdd4b4b96, 0xdcbdbd61, 0x868b8b0d, 0x858a8a0f, 0x907070e0, 0x423e3e7c,
        0xc4b5b571, 0xaa6666cc, 0xd8484890, 0x5030306, 0x1f6f6f7, 0x120e0e1c,
        0xa36161c2, 0x5f35356a, 0xf95757ae, 0xd0b9b969, 0x91868617, 0x58c1c199,
        0x271d1d3a, 0xb99e9e27, 0x38e1e1d9, 0x13f8f8eb, 0xb398982b, 0x33111122,
        0xbb6969d2, 0x70d9d9a9, 0x898e8e07, 0xa7949433, 0xb69b9b2d, 0x221e1e3c,
        0x92878715, 0x20e9e9c9, 0x49cece87, 0xff5555aa, 0x78282850, 0x7adfdfa5,
        0x8f8c8c03, 0xf8a1a159, 0x80898909, 0x170d0d1a, 0xdabfbf65, 0x31e6e6d7,
        0xc6424284, 0xb86868d0, 0xc3414182, 0xb0999929, 0x772d2d5a, 0x110f0f1e,
        0xcbb0b07b, 0xfc5454a8, 0xd6bbbb6d, 0x3a16162c
    ];
    AES.rtable = [
        0x50a7f451, 0x5365417e, 0xc3a4171a, 0x965e273a, 0xcb6bab3b, 0xf1459d1f,
        0xab58faac, 0x9303e34b, 0x55fa3020, 0xf66d76ad, 0x9176cc88, 0x254c02f5,
        0xfcd7e54f, 0xd7cb2ac5, 0x80443526, 0x8fa362b5, 0x495ab1de, 0x671bba25,
        0x980eea45, 0xe1c0fe5d, 0x2752fc3, 0x12f04c81, 0xa397468d, 0xc6f9d36b,
        0xe75f8f03, 0x959c9215, 0xeb7a6dbf, 0xda595295, 0x2d83bed4, 0xd3217458,
        0x2969e049, 0x44c8c98e, 0x6a89c275, 0x78798ef4, 0x6b3e5899, 0xdd71b927,
        0xb64fe1be, 0x17ad88f0, 0x66ac20c9, 0xb43ace7d, 0x184adf63, 0x82311ae5,
        0x60335197, 0x457f5362, 0xe07764b1, 0x84ae6bbb, 0x1ca081fe, 0x942b08f9,
        0x58684870, 0x19fd458f, 0x876cde94, 0xb7f87b52, 0x23d373ab, 0xe2024b72,
        0x578f1fe3, 0x2aab5566, 0x728ebb2, 0x3c2b52f, 0x9a7bc586, 0xa50837d3,
        0xf2872830, 0xb2a5bf23, 0xba6a0302, 0x5c8216ed, 0x2b1ccf8a, 0x92b479a7,
        0xf0f207f3, 0xa1e2694e, 0xcdf4da65, 0xd5be0506, 0x1f6234d1, 0x8afea6c4,
        0x9d532e34, 0xa055f3a2, 0x32e18a05, 0x75ebf6a4, 0x39ec830b, 0xaaef6040,
        0x69f715e, 0x51106ebd, 0xf98a213e, 0x3d06dd96, 0xae053edd, 0x46bde64d,
        0xb58d5491, 0x55dc471, 0x6fd40604, 0xff155060, 0x24fb9819, 0x97e9bdd6,
        0xcc434089, 0x779ed967, 0xbd42e8b0, 0x888b8907, 0x385b19e7, 0xdbeec879,
        0x470a7ca1, 0xe90f427c, 0xc91e84f8, 0x0, 0x83868009, 0x48ed2b32,
        0xac70111e, 0x4e725a6c, 0xfbff0efd, 0x5638850f, 0x1ed5ae3d, 0x27392d36,
        0x64d90f0a, 0x21a65c68, 0xd1545b9b, 0x3a2e3624, 0xb1670a0c, 0xfe75793,
        0xd296eeb4, 0x9e919b1b, 0x4fc5c080, 0xa220dc61, 0x694b775a, 0x161a121c,
        0xaba93e2, 0xe52aa0c0, 0x43e0223c, 0x1d171b12, 0xb0d090e, 0xadc78bf2,
        0xb9a8b62d, 0xc8a91e14, 0x8519f157, 0x4c0775af, 0xbbdd99ee, 0xfd607fa3,
        0x9f2601f7, 0xbcf5725c, 0xc53b6644, 0x347efb5b, 0x7629438b, 0xdcc623cb,
        0x68fcedb6, 0x63f1e4b8, 0xcadc31d7, 0x10856342, 0x40229713, 0x2011c684,
        0x7d244a85, 0xf83dbbd2, 0x1132f9ae, 0x6da129c7, 0x4b2f9e1d, 0xf330b2dc,
        0xec52860d, 0xd0e3c177, 0x6c16b32b, 0x99b970a9, 0xfa489411, 0x2264e947,
        0xc48cfca8, 0x1a3ff0a0, 0xd82c7d56, 0xef903322, 0xc74e4987, 0xc1d138d9,
        0xfea2ca8c, 0x360bd498, 0xcf81f5a6, 0x28de7aa5, 0x268eb7da, 0xa4bfad3f,
        0xe49d3a2c, 0xd927850, 0x9bcc5f6a, 0x62467e54, 0xc2138df6, 0xe8b8d890,
        0x5ef7392e, 0xf5afc382, 0xbe805d9f, 0x7c93d069, 0xa92dd56f, 0xb31225cf,
        0x3b99acc8, 0xa77d1810, 0x6e639ce8, 0x7bbb3bdb, 0x97826cd, 0xf418596e,
        0x1b79aec, 0xa89a4f83, 0x656e95e6, 0x7ee6ffaa, 0x8cfbc21, 0xe6e815ef,
        0xd99be7ba, 0xce366f4a, 0xd4099fea, 0xd67cb029, 0xafb2a431, 0x31233f2a,
        0x3094a5c6, 0xc066a235, 0x37bc4e74, 0xa6ca82fc, 0xb0d090e0, 0x15d8a733,
        0x4a9804f1, 0xf7daec41, 0xe50cd7f, 0x2ff69117, 0x8dd64d76, 0x4db0ef43,
        0x544daacc, 0xdf0496e4, 0xe3b5d19e, 0x1b886a4c, 0xb81f2cc1, 0x7f516546,
        0x4ea5e9d, 0x5d358c01, 0x737487fa, 0x2e410bfb, 0x5a1d67b3, 0x52d2db92,
        0x335610e9, 0x1347d66d, 0x8c61d79a, 0x7a0ca137, 0x8e14f859, 0x893c13eb,
        0xee27a9ce, 0x35c961b7, 0xede51ce1, 0x3cb1477a, 0x59dfd29c, 0x3f73f255,
        0x79ce1418, 0xbf37c773, 0xeacdf753, 0x5baafd5f, 0x146f3ddf, 0x86db4478,
        0x81f3afca, 0x3ec468b9, 0x2c342438, 0x5f40a3c2, 0x72c31d16, 0xc25e2bc,
        0x8b493c28, 0x41950dff, 0x7101a839, 0xdeb30c08, 0x9ce4b4d8, 0x90c15664,
        0x6184cb7b, 0x70b632d5, 0x745c6c48, 0x4257b8d0
    ];

    AES.ctx = ctx;
    return AES;
};
},{}],3:[function(require,module,exports){
/*
	Licensed to the Apache Software Foundation (ASF) under one
	or more contributor license agreements.  See the NOTICE file
	distributed with this work for additional information
	regarding copyright ownership.  The ASF licenses this file
	to you under the Apache License, Version 2.0 (the
	"License"); you may not use this file except in compliance
	with the License.  You may obtain a copy of the License at
	
	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing,
	software distributed under the License is distributed on an
	"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
	KIND, either express or implied.  See the License for the
	specific language governing permissions and limitations
	under the License.
*/

/* AMCL BIG number class */

module.exports.BIG = function(ctx) {

    /* General purpose Constructor */
    var BIG = function(x) {
        this.w = new Array(BIG.NLEN);
        switch (typeof(x)) {
            case "object":
                this.copy(x);
                break;
            case "number":
                this.zero();
                this.w[0] = x;
                break;
            default:
                this.zero();
        }
    };

    BIG.CHUNK = 32;
    BIG.MODBYTES = ctx.config["@NB"];
    BIG.BASEBITS = ctx.config["@BASE"];
    BIG.NLEN = (1 + (Math.floor((8 * BIG.MODBYTES - 1) / BIG.BASEBITS)));
    BIG.DNLEN = 2 * BIG.NLEN;
    BIG.BMASK = (1 << BIG.BASEBITS) - 1;
    BIG.BIGBITS = (8 * BIG.MODBYTES);
    BIG.NEXCESS = (1 << (BIG.CHUNK - BIG.BASEBITS - 1));
    BIG.MODINV = (Math.pow(2, -BIG.BASEBITS));

    BIG.prototype = {
        /* set to zero */
        zero: function() {
            for (var i = 0; i < BIG.NLEN; i++) this.w[i] = 0;
            return this;
        },
        /* set to one */
        one: function() {
            this.w[0] = 1;
            for (var i = 1; i < BIG.NLEN; i++) this.w[i] = 0;
            return this;
        },

        get: function(i) {
            return this.w[i];
        },

        set: function(i, x) {
            this.w[i] = x;
        },
        /* test for zero */
        iszilch: function() {
            for (var i = 0; i < BIG.NLEN; i++)
                if (this.w[i] !== 0) return false;
            return true;
        },
        /* test for unity */
        isunity: function() {
            for (var i = 1; i < BIG.NLEN; i++)
                if (this.w[i] !== 0) return false;
            if (this.w[0] != 1) return false;
            return true;
        },

        /* Conditional swap of two BIGs depending on d using XOR - no branches */
        cswap: function(b, d) {
            var i;
            var t, c = d;
            c = ~(c - 1);

            for (i = 0; i < BIG.NLEN; i++) {
                t = c & (this.w[i] ^ b.w[i]);
                this.w[i] ^= t;
                b.w[i] ^= t;
            }
        },

        /* Conditional move of BIG depending on d using XOR - no branches */
        cmove: function(b, d) {
            var i;
            var c = d;
            c = ~(c - 1);

            for (i = 0; i < BIG.NLEN; i++) {
                this.w[i] ^= (this.w[i] ^ b.w[i]) & c;
            }
        },

        /* copy from another BIG */
        copy: function(y) {
            for (var i = 0; i < BIG.NLEN; i++)
                this.w[i] = y.w[i];
            return this;
        },
        /* copy from bottom half of ctx.DBIG */
        hcopy: function(y) {
            for (var i = 0; i < BIG.NLEN; i++)
                this.w[i] = y.w[i];
            return this;
        },
        /* copy from ROM */
        rcopy: function(y) {
            for (var i = 0; i < BIG.NLEN; i++)
                this.w[i] = y[i];
            return this;
        },

        xortop: function(x) {
            this.w[BIG.NLEN - 1] ^= x;
        },

        ortop: function(x) {
            this.w[BIG.NLEN - 1] |= x;
        },

        /* normalise BIG - force all digits < 2^BASEBITS */
        norm: function() {
            var d, carry = 0;
            for (var i = 0; i < BIG.NLEN - 1; i++) {
                d = this.w[i] + carry;
                this.w[i] = d & BIG.BMASK;
                carry = d >> BIG.BASEBITS;
            }
            this.w[BIG.NLEN - 1] = (this.w[BIG.NLEN - 1] + carry);

            return (this.w[BIG.NLEN - 1] >> ((8 * BIG.MODBYTES) % BIG.BASEBITS));

        },
        /* quick shift right by less than a word */
        fshr: function(k) {
            var r = this.w[0] & ((1 << k) - 1); /* shifted out part */
            for (var i = 0; i < BIG.NLEN - 1; i++)
                this.w[i] = (this.w[i] >> k) | ((this.w[i + 1] << (BIG.BASEBITS - k)) & BIG.BMASK);
            this.w[BIG.NLEN - 1] = this.w[BIG.NLEN - 1] >> k;
            return r;
        },
        /* General shift right by k bits */
        shr: function(k) {
            var n = k % BIG.BASEBITS;
            var m = Math.floor(k / BIG.BASEBITS);
            for (var i = 0; i < BIG.NLEN - m - 1; i++)
                this.w[i] = (this.w[m + i] >> n) | ((this.w[m + i + 1] << (BIG.BASEBITS - n)) & BIG.BMASK);
            this.w[BIG.NLEN - m - 1] = this.w[BIG.NLEN - 1] >> n;
            for (i = BIG.NLEN - m; i < BIG.NLEN; i++) this.w[i] = 0;
            return this;
        },
        /* quick shift left by less than a word */
        fshl: function(k) {
            this.w[BIG.NLEN - 1] = ((this.w[BIG.NLEN - 1] << k)) | (this.w[BIG.NLEN - 2] >> (BIG.BASEBITS - k));
            for (var i = BIG.NLEN - 2; i > 0; i--)
                this.w[i] = ((this.w[i] << k) & BIG.BMASK) | (this.w[i - 1] >> (BIG.BASEBITS - k));
            this.w[0] = (this.w[0] << k) & BIG.BMASK;

            return (this.w[BIG.NLEN - 1] >> ((8 * BIG.MODBYTES) % BIG.BASEBITS)); /* return excess - only used in FF.java */
        },
        /* General shift left by k bits */
        shl: function(k) {
            var i, n = k % BIG.BASEBITS;
            var m = Math.floor(k / BIG.BASEBITS);

            this.w[BIG.NLEN - 1] = (this.w[BIG.NLEN - 1 - m] << n);
            if (BIG.NLEN > m + 2) this.w[BIG.NLEN - 1] |= (this.w[BIG.NLEN - m - 2] >> (BIG.BASEBITS - n));
            for (i = BIG.NLEN - 2; i > m; i--)
                this.w[i] = ((this.w[i - m] << n) & BIG.BMASK) | (this.w[i - m - 1] >> (BIG.BASEBITS - n));
            this.w[m] = (this.w[0] << n) & BIG.BMASK;
            for (i = 0; i < m; i++) this.w[i] = 0;
            return this;
        },
        /* return length in bits */
        nbits: function() {
            var bts, k = BIG.NLEN - 1;
            var c;
            this.norm();
            while (k >= 0 && this.w[k] === 0) k--;
            if (k < 0) return 0;
            bts = BIG.BASEBITS * k;
            c = this.w[k];
            while (c !== 0) {
                c = Math.floor(c / 2);
                bts++;
            }
            return bts;
        },
        /* convert this to string */
        toString: function() {
            var b;
            var s = "";
            var len = this.nbits();
            if (len % 4 === 0) len = Math.floor(len / 4);
            else {
                len = Math.floor(len / 4);
                len++;
            }
            if (len < BIG.MODBYTES * 2) len = BIG.MODBYTES * 2;
            for (var i = len - 1; i >= 0; i--) {
                b = new BIG(0);
                b.copy(this);
                b.shr(i * 4);
                s += (b.w[0] & 15).toString(16);
            }
            return s;
        },
        /* this+=y */
        add: function(y) {
            for (var i = 0; i < BIG.NLEN; i++) this.w[i] += y.w[i];
            return this;
        },
        /* return this+x */
        plus: function(x) {
            var s = new BIG(0);
            for (var i = 0; i < BIG.NLEN; i++)
                s.w[i] = this.w[i] + x.w[i];
            return s;
        },
        /* this+=i, where i is int */
        inc: function(i) {
            this.norm();
            this.w[0] += i;
            return this;
        },
        /* this-=y */
        sub: function(y) {
            for (var i = 0; i < BIG.NLEN; i++) this.w[i] -= y.w[i];
            return this;
        },

        /* reverse subtract this=x-this */
        rsub: function(x) {
            for (var i = 0; i < BIG.NLEN; i++)
                this.w[i] = x.w[i] - this.w[i];
            return this;
        },
        /* this-=i, where i is int */
        dec: function(i) {
            this.norm();
            this.w[0] -= i;
            return this;
        },
        /* return this-x */
        minus: function(x) {
            var d = new BIG(0);
            for (var i = 0; i < BIG.NLEN; i++)
                d.w[i] = this.w[i] - x.w[i];
            return d;
        },
        /* multiply by small integer */
        imul: function(c) {
            for (var i = 0; i < BIG.NLEN; i++) this.w[i] *= c;
            return this;
        },
        /* convert this BIG to byte array */
        tobytearray: function(b, n) {
            this.norm();
            var c = new BIG(0);
            c.copy(this);

            for (var i = BIG.MODBYTES - 1; i >= 0; i--) {
                b[i + n] = c.w[0] & 0xff;
                c.fshr(8);
            }
            return this;
        },
        /* convert this to byte array */
        toBytes: function(b) {
            this.tobytearray(b, 0);
        },

        /* set this[i]+=x*y+c, and return high part */
        muladd: function(x, y, c, i) {
            var prod = x * y + c + this.w[i];
            this.w[i] = prod & BIG.BMASK;
            return ((prod - this.w[i]) * BIG.MODINV);
        },
        /* multiply by larger int */
        pmul: function(c) {
            var ak, carry = 0;
            //	this.norm();
            for (var i = 0; i < BIG.NLEN; i++) {
                ak = this.w[i];
                this.w[i] = 0;
                carry = this.muladd(ak, c, carry, i);
            }
            return carry;
        },
        /* multiply by still larger int - results requires a ctx.DBIG */
        pxmul: function(c) {
            var m = new ctx.DBIG(0);
            var carry = 0;
            for (var j = 0; j < BIG.NLEN; j++)
                carry = m.muladd(this.w[j], c, carry, j);
            m.w[BIG.NLEN] = carry;
            return m;
        },
        /* divide by 3 */
        div3: function() {
            var ak, base, carry = 0;
            this.norm();
            base = (1 << BIG.BASEBITS);
            for (var i = BIG.NLEN - 1; i >= 0; i--) {
                ak = (carry * base + this.w[i]);
                this.w[i] = Math.floor(ak / 3);
                carry = ak % 3;
            }
            return carry;
        },

        /* set x = x mod 2^m */
        mod2m: function(m) {
            var i, wd, bt;
            var msk;
            wd = Math.floor(m / BIG.BASEBITS);
            bt = m % BIG.BASEBITS;
            msk = (1 << bt) - 1;
            this.w[wd] &= msk;
            for (i = wd + 1; i < BIG.NLEN; i++) this.w[i] = 0;
        },

        /* a=1/a mod 2^256. This is very fast! */
        invmod2m: function() {
            var U = new BIG(0);
            var b = new BIG(0);
            var c = new BIG(0);

            U.inc(BIG.invmod256(this.lastbits(8)));

            for (var i = 8; i < BIG.BIGBITS; i <<= 1) {
                U.norm();
                b.copy(this);
                b.mod2m(i);
                var t1 = BIG.smul(U, b);
                t1.shr(i);
                c.copy(this);
                c.shr(i);
                c.mod2m(i);

                var t2 = BIG.smul(U, c);
                t2.mod2m(i);
                t1.add(t2);
                t1.norm();
                b = BIG.smul(t1, U);
                t1.copy(b);
                t1.mod2m(i);

                t2.one();
                t2.shl(i);
                t1.rsub(t2);
                t1.norm();
                t1.shl(i);
                U.add(t1);
            }
            U.mod2m(BIG.BIGBITS);
            this.copy(U);
            this.norm();
        },

        /* reduce this mod m */
        mod: function(m) {
            var k = 0;
            var r = new BIG(0);

            this.norm();
            if (BIG.comp(this, m) < 0) return;
            do {
                m.fshl(1);
                k++;
            } while (BIG.comp(this, m) >= 0);

            while (k > 0) {
                m.fshr(1);

                r.copy(this);
                r.sub(m);
                r.norm();
                this.cmove(r, (1 - ((r.w[BIG.NLEN - 1] >> (BIG.CHUNK - 1)) & 1)));

                /*
                			if (BIG.comp(this,m)>=0)
                			{
                				this.sub(m);
                				this.norm();
                			} */
                k--;
            }
        },
        /* this/=m */
        div: function(m) {
            var k = 0;
            var d = 0;
            this.norm();
            var e = new BIG(1);
            var b = new BIG(0);
            var r = new BIG(0);
            b.copy(this);
            this.zero();

            while (BIG.comp(b, m) >= 0) {
                e.fshl(1);
                m.fshl(1);
                k++;
            }

            while (k > 0) {
                m.fshr(1);
                e.fshr(1);

                r.copy(b);
                r.sub(m);
                r.norm();
                d = (1 - ((r.w[BIG.NLEN - 1] >> (BIG.CHUNK - 1)) & 1));
                b.cmove(r, d);
                r.copy(this);
                r.add(e);
                r.norm();
                this.cmove(r, d);

                /*
                			if (BIG.comp(b,m)>=0)
                			{
                				this.add(e);
                				this.norm();
                				b.sub(m);
                				b.norm();
                			} */


                k--;
            }
        },
        /* return parity of this */
        parity: function() {
            return this.w[0] % 2;
        },
        /* return n-th bit of this */
        bit: function(n) {
            if ((this.w[Math.floor(n / BIG.BASEBITS)] & (1 << (n % BIG.BASEBITS))) > 0) return 1;
            else return 0;
        },
        /* return last n bits of this */
        lastbits: function(n) {
            var msk = (1 << n) - 1;
            this.norm();
            return (this.w[0]) & msk;
        },

        isok: function() {
            var ok = true;
            for (var i = 0; i < BIG.NLEN; i++) {
                if ((this.w[i] >> BIG.BASEBITS) != 0) ok = false;
            }
            return ok;
        },


        /* Jacobi Symbol (this/p). Returns 0, 1 or -1 */
        jacobi: function(p) {
            var n8, k, m = 0;
            var t = new BIG(0);
            var x = new BIG(0);
            var n = new BIG(0);
            var zilch = new BIG(0);
            var one = new BIG(1);
            if (p.parity() === 0 || BIG.comp(this, zilch) === 0 || BIG.comp(p, one) <= 0) return 0;
            this.norm();
            x.copy(this);
            n.copy(p);
            x.mod(p);

            while (BIG.comp(n, one) > 0) {
                if (BIG.comp(x, zilch) === 0) return 0;
                n8 = n.lastbits(3);
                k = 0;
                while (x.parity() === 0) {
                    k++;
                    x.shr(1);
                }
                if (k % 2 == 1) m += (n8 * n8 - 1) / 8;
                m += (n8 - 1) * (x.lastbits(2) - 1) / 4;
                t.copy(n);
                t.mod(x);
                n.copy(x);
                x.copy(t);
                m %= 2;

            }
            if (m === 0) return 1;
            else return -1;
        },
        /* this=1/this mod p. Binary method */
        invmodp: function(p) {
            this.mod(p);
            var u = new BIG(0);
            u.copy(this);
            var v = new BIG(0);
            v.copy(p);
            var x1 = new BIG(1);
            var x2 = new BIG(0);
            var t = new BIG(0);
            var one = new BIG(1);

            while (BIG.comp(u, one) !== 0 && BIG.comp(v, one) !== 0) {
                while (u.parity() === 0) {
                    u.shr(1);
                    if (x1.parity() !== 0) {
                        x1.add(p);
                        x1.norm();
                    }
                    x1.shr(1);
                }
                while (v.parity() === 0) {
                    v.shr(1);
                    if (x2.parity() !== 0) {
                        x2.add(p);
                        x2.norm();
                    }
                    x2.shr(1);
                }
                if (BIG.comp(u, v) >= 0) {
                    u.sub(v);
                    u.norm();
                    if (BIG.comp(x1, x2) >= 0) x1.sub(x2);
                    else {
                        t.copy(p);
                        t.sub(x2);
                        x1.add(t);
                    }
                    x1.norm();
                } else {
                    v.sub(u);
                    v.norm();
                    if (BIG.comp(x2, x1) >= 0) x2.sub(x1);
                    else {
                        t.copy(p);
                        t.sub(x1);
                        x2.add(t);
                    }
                    x2.norm();
                }
            }
            if (BIG.comp(u, one) === 0) this.copy(x1);
            else this.copy(x2);
        },
        /* return this^e mod m */
        powmod: function(e, m) {
            var bt;
            this.norm();
            e.norm();
            var a = new BIG(1);
            var z = new BIG(0);
            z.copy(e);
            var s = new BIG(0);
            s.copy(this);
            var i = 0;
            while (true) {
                i++;
                bt = z.parity();
                z.fshr(1);
                if (bt == 1) a = BIG.modmul(a, s, m);

                if (z.iszilch()) break;
                s = BIG.modsqr(s, m);
            }
            return a;
        }

    };
    /* convert from byte array to BIG */
    BIG.frombytearray = function(b, n) {
        var m = new BIG(0);

        for (var i = 0; i < BIG.MODBYTES; i++) {
            m.fshl(8);
            m.w[0] += b[i + n] & 0xff;
            //m.inc(b[i]&0xff);
        }
        return m;
    };

    BIG.fromBytes = function(b) {
        return BIG.frombytearray(b, 0);
    };

    /* return a*b where product fits a BIG */
    BIG.smul = function(a, b) {
        var carry;
        var c = new BIG(0);
        for (var i = 0; i < BIG.NLEN; i++) {
            carry = 0;
            for (var j = 0; j < BIG.NLEN; j++)
                if (i + j < BIG.NLEN) carry = c.muladd(a.w[i], b.w[j], carry, i + j);
        }
        return c;
    };
    /* Compare a and b, return 0 if a==b, -1 if a<b, +1 if a>b. Inputs must be normalised */
    BIG.comp = function(a, b) {
        for (var i = BIG.NLEN - 1; i >= 0; i--) {
            if (a.w[i] == b.w[i]) continue;
            if (a.w[i] > b.w[i]) return 1;
            else return -1;
        }
        return 0;
    };

    /* get 8*MODBYTES size random number */
    BIG.random = function(rng) {
        var m = new BIG(0);
        var i, b, j = 0,
            r = 0;

        /* generate random BIG */
        for (i = 0; i < 8 * BIG.MODBYTES; i++) {
            if (j === 0) r = rng.getByte();
            else r >>= 1;

            b = r & 1;
            m.shl(1);
            m.w[0] += b; // m.inc(b);
            j++;
            j &= 7;
        }
        return m;
    };

    /* Create random BIG in portable way, one bit at a time */
    BIG.randomnum = function(q, rng) {
        var d = new ctx.DBIG(0);
        var i, b, j = 0,
            r = 0;
        for (i = 0; i < 2 * q.nbits(); i++) {
            if (j === 0) r = rng.getByte();
            else r >>= 1;

            b = r & 1;
            d.shl(1);
            d.w[0] += b;
            j++;
            j &= 7;
        }

        var m = d.mod(q);

        return m;
    };

    /* return NAF value as +/- 1, 3 or 5. x and x3 should be normed. 
    nbs is number of bits processed, and nzs is number of trailing 0s detected */
    /*
    BIG.nafbits=function(x,x3,i)
    {
    	var n=[];
    	var nb=x3.bit(i)-x.bit(i);
    	var j;
    	n[1]=1;
    	n[0]=0;
    	if (nb===0) {n[0]=0; return n;}
    	if (i===0) {n[0]=nb; return n;}
    	if (nb>0) n[0]=1;
    	else      n[0]=(-1);

    	for (j=i-1;j>0;j--)
    	{
    		n[1]++;
    		n[0]*=2;
    		nb=x3.bit(j)-x.bit(j);
    		if (nb>0) n[0]+=1;
    		if (nb<0) n[0]-=1;
    		if (n[0]>5 || n[0]<-5) break;
    	}

    	if (n[0]%2!==0 && j!==0)
    	{ // backtrack 
    		if (nb>0) n[0]=(n[0]-1)/2;
    		if (nb<0) n[0]=(n[0]+1)/2;
    		n[1]--;
    	}
    	while (n[0]%2===0)
    	{ // remove trailing zeros 
    		n[0]/=2;
    		n[2]++;
    		n[1]--;
    	}
    	return n;
    };
    */
    /* return a*b as ctx.DBIG */
    BIG.mul = function(a, b) {
        var n, c = new ctx.DBIG(0);
        //	a.norm();
        //	b.norm();

        var d = [];
        var s, t;

        //if (!a.isok()) alert("Problem in mul a");
        //if (!b.isok()) alert("Problem in mul b");

        for (var i = 0; i < BIG.NLEN; i++)
            d[i] = a.w[i] * b.w[i];

        s = d[0];
        t = s;
        c.w[0] = t;

        for (var k = 1; k < BIG.NLEN; k++) {
            s += d[k];
            t = s;
            for (i = k; i >= 1 + Math.floor(k / 2); i--) t += (a.w[i] - a.w[k - i]) * (b.w[k - i] - b.w[i]);
            c.w[k] = t;
        }
        for (var k = BIG.NLEN; k < 2 * BIG.NLEN - 1; k++) {
            s -= d[k - BIG.NLEN];
            t = s;
            for (i = BIG.NLEN - 1; i >= 1 + Math.floor(k / 2); i--) t += (a.w[i] - a.w[k - i]) * (b.w[k - i] - b.w[i]);
            c.w[k] = t;
        }

        var co = 0;
        for (var i = 0; i < BIG.DNLEN - 1; i++) {
            n = c.w[i] + co;
            c.w[i] = n & BIG.BMASK;
            co = (n - c.w[i]) * BIG.MODINV;
        }
        c.w[BIG.DNLEN - 1] = co;


        /*
        	for (var j=0;j<BIG.NLEN;j++)
        	{
        		t=0; for (var i=0;i<=j;i++) t+=a.w[j-i]*b.w[i];
        		c.w[j]=t;
        	}
        	for (var j=BIG.NLEN;j<BIG.DNLEN-2;j++)
        	{
        		t=0; for (var i=j-BIG.NLEN+1;i<BIG.NLEN;i++) t+=a.w[j-i]*b.w[i];
        		c.w[j]=t; 
        	}
        	t=a.w[BIG.NLEN-1]*b.w[BIG.NLEN-1];
        	c.w[BIG.DNLEN-2]=t;
        	var co=0;
        	for (var i=0;i<BIG.DNLEN-1;i++)
        	{
        		n=c.w[i]+co;
        		c.w[i]=n&BIG.BMASK;
        		co=(n-c.w[i])*BIG.MODINV;
        	}
        	c.w[BIG.DNLEN-1]=co;
        */
        return c;
    };

    /* return a^2 as ctx.DBIG */
    BIG.sqr = function(a) {
        var n, c = new ctx.DBIG(0);
        //	a.norm();

        //if (!a.isok()) alert("Problem in sqr");

        c.w[0] = a.w[0] * a.w[0];

        for (var j = 1; j < BIG.NLEN - 1;) {
            t = a.w[j] * a.w[0];
            for (var i = 1; i < (j + 1) >> 1; i++) {
                t += a.w[j - i] * a.w[i];
            }
            t += t;
            c.w[j] = t;
            j++;
            t = a.w[j] * a.w[0];
            for (i = 1; i < (j + 1) >> 1; i++) {
                t += a.w[j - i] * a.w[i];
            }
            t += t;
            t += a.w[j >> 1] * a.w[j >> 1];
            c.w[j] = t;
            j++;
        }

        for (var j = BIG.NLEN - 1 + BIG.NLEN % 2; j < BIG.DNLEN - 3;) {
            t = a.w[BIG.NLEN - 1] * a.w[j - BIG.NLEN + 1];
            for (var i = j - BIG.NLEN + 2; i < (j + 1) >> 1; i++) {
                t += a.w[j - i] * a.w[i];
            }
            t += t;
            c.w[j] = t;
            j++;
            t = a.w[BIG.NLEN - 1] * a.w[j - BIG.NLEN + 1];
            for (var i = j - BIG.NLEN + 2; i < (j + 1) >> 1; i++) {
                t += a.w[j - i] * a.w[i];
            }
            t += t;
            t += a.w[j >> 1] * a.w[j >> 1];
            c.w[j] = t;
            j++;
        }

        t = a.w[BIG.NLEN - 2] * a.w[BIG.NLEN - 1];
        t += t;
        c.w[BIG.DNLEN - 3] = t;

        t = a.w[BIG.NLEN - 1] * a.w[BIG.NLEN - 1];
        c.w[BIG.DNLEN - 2] = t;

        var co = 0;
        for (var i = 0; i < BIG.DNLEN - 1; i++) {
            n = c.w[i] + co;
            c.w[i] = n & BIG.BMASK;
            co = (n - c.w[i]) * BIG.MODINV;
        }
        c.w[BIG.DNLEN - 1] = co;

        return c;
    };

    BIG.monty = function(m, nd, d) {
        var b = new BIG(0);
        var v = [];
        var dd = [];
        var s, c, t;

        t = d.w[0];
        v[0] = ((t & BIG.BMASK) * nd) & BIG.BMASK;
        t += v[0] * m.w[0];
        c = d.w[1] + (t * BIG.MODINV);
        s = 0;

        for (var k = 1; k < BIG.NLEN; k++) {
            t = c + s + v[0] * m.w[k];
            for (i = k - 1; i > Math.floor(k / 2); i--) t += (v[k - i] - v[i]) * (m.w[i] - m.w[k - i]);
            v[k] = ((t & BIG.BMASK) * nd) & BIG.BMASK;
            t += v[k] * m.w[0];
            c = (t * BIG.MODINV) + d.w[k + 1];

            dd[k] = v[k] * m.w[k];
            s += dd[k];
        }
        for (var k = BIG.NLEN; k < 2 * BIG.NLEN - 1; k++) {
            t = c + s;
            for (i = BIG.NLEN - 1; i >= 1 + Math.floor(k / 2); i--) t += (v[k - i] - v[i]) * (m.w[i] - m.w[k - i]);
            b.w[k - BIG.NLEN] = t & BIG.BMASK;
            c = ((t - b.w[k - BIG.NLEN]) * BIG.MODINV) + d.w[k + 1];

            s -= dd[k - BIG.NLEN + 1];
        }
        b.w[BIG.NLEN - 1] = c & BIG.BMASK;
        return b;
    }



    /* return a*b mod m */
    BIG.modmul = function(a, b, m) {
        a.mod(m);
        b.mod(m);
        var d = BIG.mul(a, b);
        return d.mod(m);
    };

    /* return a^2 mod m */
    BIG.modsqr = function(a, m) {
        a.mod(m);
        var d = BIG.sqr(a);
        return d.mod(m);
    };

    /* return -a mod m */
    BIG.modneg = function(a, m) {
        a.mod(m);
        return m.minus(a);
    };

    /* Arazi and Qi inversion mod 256 */
    BIG.invmod256 = function(a) {
        var U, t1, t2, b, c;
        t1 = 0;
        c = (a >> 1) & 1;
        t1 += c;
        t1 &= 1;
        t1 = 2 - t1;
        t1 <<= 1;
        U = t1 + 1;

        // i=2
        b = a & 3;
        t1 = U * b;
        t1 >>= 2;
        c = (a >> 2) & 3;
        t2 = (U * c) & 3;
        t1 += t2;
        t1 *= U;
        t1 &= 3;
        t1 = 4 - t1;
        t1 <<= 2;
        U += t1;

        // i=4
        b = a & 15;
        t1 = U * b;
        t1 >>= 4;
        c = (a >> 4) & 15;
        t2 = (U * c) & 15;
        t1 += t2;
        t1 *= U;
        t1 &= 15;
        t1 = 16 - t1;
        t1 <<= 4;
        U += t1;

        return U;
    };
    BIG.ctx = ctx;
    return BIG;
};

module.exports.DBIG = function(ctx) {

    /* AMCL double length DBIG number class */

    /* constructor */
    var DBIG = function(x) {
        this.w = [];
        this.zero();
        this.w[0] = x;
    };

    DBIG.prototype = {

        /* set this=0 */
        zero: function() {
            for (var i = 0; i < ctx.BIG.DNLEN; i++) this.w[i] = 0;
            return this;
        },

        /* set this=b */
        copy: function(b) {
            for (var i = 0; i < ctx.BIG.DNLEN; i++) this.w[i] = b.w[i];
            return this;
        },


        /* copy from ctx.BIG */
        hcopy: function(b) {
            var i;
            for (i = 0; i < ctx.BIG.NLEN; i++) this.w[i] = b.w[i];
            for (i = ctx.BIG.NLEN; i < ctx.BIG.DNLEN; i++) this.w[i] = 0;
            return this;
        },

        ucopy: function(b) {
            var i;
            for (i = 0; i < ctx.BIG.NLEN; i++) this.w[i] = 0;
            for (i = ctx.BIG.NLEN; i < ctx.BIG.DNLEN; i++) this.w[i] = b.w[i - ctx.BIG.NLEN];
            return this;
        },

        /* normalise this */
        norm: function() {
            var d, carry = 0;
            for (var i = 0; i < ctx.BIG.DNLEN - 1; i++) {
                d = this.w[i] + carry;
                this.w[i] = d & ctx.BIG.BMASK;
                carry = d >> ctx.BIG.BASEBITS;
            }
            this.w[ctx.BIG.DNLEN - 1] = (this.w[ctx.BIG.DNLEN - 1] + carry);
            return this;
        },

        /* set this[i]+=x*y+c, and return high part */
        muladd: function(x, y, c, i) {
            var prod = x * y + c + this.w[i];
            this.w[i] = prod & ctx.BIG.BMASK;
            return ((prod - this.w[i]) * ctx.BIG.MODINV);
        },

        /* shift this right by k bits */
        shr: function(k) {
            var i, n = k % ctx.BIG.BASEBITS;
            var m = Math.floor(k / ctx.BIG.BASEBITS);
            for (i = 0; i < ctx.BIG.DNLEN - m - 1; i++)
                this.w[i] = (this.w[m + i] >> n) | ((this.w[m + i + 1] << (ctx.BIG.BASEBITS - n)) & ctx.BIG.BMASK);
            this.w[ctx.BIG.DNLEN - m - 1] = this.w[ctx.BIG.DNLEN - 1] >> n;
            for (i = ctx.BIG.DNLEN - m; i < ctx.BIG.DNLEN; i++) this.w[i] = 0;
            return this;
        },

        /* shift this left by k bits */
        shl: function(k) {
            var i, n = k % ctx.BIG.BASEBITS;
            var m = Math.floor(k / ctx.BIG.BASEBITS);

            this.w[ctx.BIG.DNLEN - 1] = ((this.w[ctx.BIG.DNLEN - 1 - m] << n)) | (this.w[ctx.BIG.DNLEN - m - 2] >> (ctx.BIG.BASEBITS - n));
            for (i = ctx.BIG.DNLEN - 2; i > m; i--)
                this.w[i] = ((this.w[i - m] << n) & ctx.BIG.BMASK) | (this.w[i - m - 1] >> (ctx.BIG.BASEBITS - n));
            this.w[m] = (this.w[0] << n) & ctx.BIG.BMASK;
            for (i = 0; i < m; i++) this.w[i] = 0;
            return this;
        },

        /* Conditional move of ctx.BIG depending on d using XOR - no branches */
        cmove: function(b, d) {
            var i;
            var c = d;
            c = ~(c - 1);

            for (i = 0; i < ctx.BIG.DNLEN; i++) {
                this.w[i] ^= (this.w[i] ^ b.w[i]) & c;
            }
        },


        /* this+=x */
        add: function(x) {
            for (var i = 0; i < ctx.BIG.DNLEN; i++)
                this.w[i] += x.w[i];
        },

        /* this-=x */
        sub: function(x) {
            for (var i = 0; i < ctx.BIG.DNLEN; i++)
                this.w[i] -= x.w[i];
        },

        rsub: function(x) {
            for (var i = 0; i < ctx.BIG.DNLEN; i++)
                this.w[i] = x.w[i] - this.w[i];
        },

        /* return number of bits in this */
        nbits: function() {
            var bts, k = ctx.BIG.DNLEN - 1;
            var c;
            this.norm();
            while (k >= 0 && this.w[k] === 0) k--;
            if (k < 0) return 0;
            bts = ctx.BIG.BASEBITS * k;
            c = this.w[k];
            while (c !== 0) {
                c = Math.floor(c / 2);
                bts++;
            }
            return bts;
        },

        /* convert this to string */
        toString: function() {

            var b;
            var s = "";
            var len = this.nbits();
            if (len % 4 === 0) len = Math.floor(len / 4);
            else {
                len = Math.floor(len / 4);
                len++;
            }

            for (var i = len - 1; i >= 0; i--) {
                b = new DBIG(0);
                b.copy(this);
                b.shr(i * 4);
                s += (b.w[0] & 15).toString(16);
            }
            return s;
        },

        /* reduces this DBIG mod a ctx.BIG, and returns the ctx.BIG */
        mod: function(c) {
            var k = 0;
            this.norm();
            var m = new DBIG(0);
            var dr = new DBIG(0);
            m.hcopy(c);
            var r = new ctx.BIG(0);
            r.hcopy(this);

            if (DBIG.comp(this, m) < 0) return r;

            do {
                m.shl(1);
                k++;
            }
            while (DBIG.comp(this, m) >= 0);

            while (k > 0) {
                m.shr(1);

                dr.copy(this);
                dr.sub(m);
                dr.norm();
                this.cmove(dr, (1 - ((dr.w[ctx.BIG.DNLEN - 1] >> (ctx.BIG.CHUNK - 1)) & 1)));

                /*
                			if (DBIG.comp(this,m)>=0)
                			{
                				this.sub(m);
                				this.norm();
                			} */
                k--;
            }

            r.hcopy(this);
            return r;
        },

        /* this/=c */
        div: function(c) {
            var d = 0;
            var k = 0;
            var m = new DBIG(0);
            m.hcopy(c);
            var dr = new DBIG(0);
            var r = new ctx.BIG(0);
            var a = new ctx.BIG(0);
            var e = new ctx.BIG(1);
            this.norm();

            while (DBIG.comp(this, m) >= 0) {
                e.fshl(1);
                m.shl(1);
                k++;
            }

            while (k > 0) {
                m.shr(1);
                e.shr(1);

                dr.copy(this);
                dr.sub(m);
                dr.norm();
                d = (1 - ((dr.w[ctx.BIG.DNLEN - 1] >> (ctx.BIG.CHUNK - 1)) & 1));
                this.cmove(dr, d);
                r.copy(a);
                r.add(e);
                r.norm();
                a.cmove(r, d);
                /*
                			if (DBIG.comp(this,m)>0)
                			{
                				a.add(e);
                				a.norm();
                				this.sub(m);
                				this.norm();
                			}  */
                k--;
            }
            return a;
        },

        /* split this DBIG at position n, return higher half, keep lower half */
        split: function(n) {
            var t = new ctx.BIG(0);
            var nw, m = n % ctx.BIG.BASEBITS;
            var carry = this.w[ctx.BIG.DNLEN - 1] << (ctx.BIG.BASEBITS - m);


            for (var i = ctx.BIG.DNLEN - 2; i >= ctx.BIG.NLEN - 1; i--) {
                nw = (this.w[i] >> m) | carry;
                carry = (this.w[i] << (ctx.BIG.BASEBITS - m)) & ctx.BIG.BMASK;
                t.w[i - ctx.BIG.NLEN + 1] = nw;
            }
            this.w[ctx.BIG.NLEN - 1] &= ((1 << m) - 1);

            return t;
        }

    };

    /* Compare a and b, return 0 if a==b, -1 if a<b, +1 if a>b. Inputs must be normalised */
    DBIG.comp = function(a, b) {
        for (var i = ctx.BIG.DNLEN - 1; i >= 0; i--) {
            if (a.w[i] == b.w[i]) continue;
            if (a.w[i] > b.w[i]) return 1;
            else return -1;
        }
        return 0;
    };


    DBIG.ctx = ctx;
    return DBIG;
};
},{}],4:[function(require,module,exports){
/*
	Licensed to the Apache Software Foundation (ASF) under one
	or more contributor license agreements.  See the NOTICE file
	distributed with this work for additional information
	regarding copyright ownership.  The ASF licenses this file
	to you under the Apache License, Version 2.0 (the
	"License"); you may not use this file except in compliance
	with the License.  You may obtain a copy of the License at
	
	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing,
	software distributed under the License is distributed on an
	"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
	KIND, either express or implied.  See the License for the
	specific language governing permissions and limitations
	under the License.
*/

var romField = require('./rom_field');
var romCurve = require('./rom_curve');
var aes = require('./aes');
var gcm = require('./gcm');
var uint64 = require('./uint64');
var hash256 = require('./hash256');
var hash384 = require('./hash384');
var hash512 = require('./hash512');
var rand = require('./rand');
var big = require('./big');
var fp = require('./fp');
var ecp = require('./ecp');
var ecdh = require('./ecdh');

var ff = require('./ff');
var rsa = require('./rsa');

var fp2 = require('./fp2');
var fp4 = require('./fp4');
var fp12 = require('./fp12');
var ecp2 = require('./ecp2');
var pair = require('./pair');
var mpin = require('./mpin');

var CTXLIST = {
    "ED25519": {
        "BITS": "256",
        "FIELD": "25519",
        "CURVE": "ED25519",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 255,
        "@M8": 5,
        "@MT": 1,
        "@CT": 1,
        "@PF": 0
    },

    "C25519": {
        "BITS": "256",
        "FIELD": "25519",
        "CURVE": "C25519",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 255,
        "@M8": 5,
        "@MT": 1,
        "@CT": 2,
        "@PF": 0
    },

    "NIST256": {
        "BITS": "256",
        "FIELD": "NIST256",
        "CURVE": "NIST256",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 256,
        "@M8": 7,
        "@MT": 0,
        "@CT": 0,
        "@PF": 0
    },

    "NIST384": {
        "BITS": "384",
        "FIELD": "NIST384",
        "CURVE": "NIST384",
        "@NB": 48,
        "@BASE": 56,
        "@NBT": 384,
        "@M8": 7,
        "@MT": 0,
        "@CT": 0,
        "@PF": 0
    },

    "BRAINPOOL": {
        "BITS": "256",
        "FIELD": "BRAINPOOL",
        "CURVE": "BRAINPOOL",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 256,
        "@M8": 7,
        "@MT": 0,
        "@CT": 0,
        "@PF": 0
    },

    "ANSSI": {
        "BITS": "256",
        "FIELD": "ANSSI",
        "CURVE": "ANSSI",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 256,
        "@M8": 7,
        "@MT": 0,
        "@CT": 0,
        "@PF": 0
    },

    "HIFIVE": {
        "BITS": "336",
        "FIELD": "HIFIVE",
        "CURVE": "HIFIVE",
        "@NB": 42,
        "@BASE": 23,
        "@NBT": 336,
        "@M8": 5,
        "@MT": 1,
        "@CT": 1,
        "@PF": 0
    },

    "GOLDILOCKS": {
        "BITS": "448",
        "FIELD": "GOLDILOCKS",
        "CURVE": "GOLDILOCKS",
        "@NB": 56,
        "@BASE": 23,
        "@NBT": 448,
        "@M8": 7,
        "@MT": 2,
        "@CT": 1,
        "@PF": 0
    },

    "C41417": {
        "BITS": "416",
        "FIELD": "C41417",
        "CURVE": "C41417",
        "@NB": 52,
        "@BASE": 23,
        "@NBT": 414,
        "@M8": 7,
        "@MT": 1,
        "@CT": 1,
        "@PF": 0
    },

    "NIST521": {
        "BITS": "528",
        "FIELD": "NIST521",
        "CURVE": "NIST521",
        "@NB": 66,
        "@BASE": 23,
        "@NBT": 521,
        "@M8": 7,
        "@MT": 1,
        "@CT": 0,
        "@PF": 0
    },

    "MF254W": {
        "BITS": "256",
        "FIELD": "254MF",
        "CURVE": "MF254W",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 254,
        "@M8": 7,
        "@MT": 3,
        "@CT": 0,
        "@PF": 0
    },

    "MF254E": {
        "BITS": "256",
        "FIELD": "254MF",
        "CURVE": "MF254E",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 254,
        "@M8": 7,
        "@MT": 3,
        "@CT": 1,
        "@PF": 0
    },

    "MF254M": {
        "BITS": "256",
        "FIELD": "254MF",
        "CURVE": "MF254M",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 254,
        "@M8": 7,
        "@MT": 3,
        "@CT": 2,
        "@PF": 0
    },

    "MF256W": {
        "BITS": "256",
        "FIELD": "256MF",
        "CURVE": "MF256W",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 256,
        "@M8": 7,
        "@MT": 3,
        "@CT": 0,
        "@PF": 0
    },

    "MF256E": {
        "BITS": "256",
        "FIELD": "256MF",
        "CURVE": "MF256E",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 256,
        "@M8": 7,
        "@MT": 3,
        "@CT": 1,
        "@PF": 0
    },

    "MF256M": {
        "BITS": "256",
        "FIELD": "256MF",
        "CURVE": "MF256M",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 256,
        "@M8": 7,
        "@MT": 3,
        "@CT": 2,
        "@PF": 0
    },

    "MS255W": {
        "BITS": "256",
        "FIELD": "255MS",
        "CURVE": "MS255W",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 255,
        "@M8": 3,
        "@MT": 1,
        "@CT": 0,
        "@PF": 0
    },

    "MS255E": {
        "BITS": "256",
        "FIELD": "255MS",
        "CURVE": "MS255E",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 255,
        "@M8": 3,
        "@MT": 1,
        "@CT": 1,
        "@PF": 0
    },

    "MS255M": {
        "BITS": "256",
        "FIELD": "255MS",
        "CURVE": "MS255M",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 255,
        "@M8": 3,
        "@MT": 1,
        "@CT": 2,
        "@PF": 0
    },

    "MS256W": {
        "BITS": "256",
        "FIELD": "256MS",
        "CURVE": "MS256W",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 256,
        "@M8": 3,
        "@MT": 1,
        "@CT": 0,
        "@PF": 0
    },

    "MS256E": {
        "BITS": "256",
        "FIELD": "256MS",
        "CURVE": "MS256E",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 256,
        "@M8": 3,
        "@MT": 1,
        "@CT": 1,
        "@PF": 0
    },

    "MS256M": {
        "BITS": "256",
        "FIELD": "256MS",
        "CURVE": "MS256M",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 256,
        "@M8": 3,
        "@MT": 1,
        "@CT": 2,
        "@PF": 0
    },

    "BN254": {
        "BITS": "256",
        "FIELD": "BN254",
        "CURVE": "BN254",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 254,
        "@M8": 3,
        "@MT": 0,
        "@CT": 0,
        "@PF": 1
    },

    "BN254CX": {
        "BITS": "256",
        "FIELD": "BN254CX",
        "CURVE": "BN254CX",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 254,
        "@M8": 3,
        "@MT": 0,
        "@CT": 0,
        "@PF": 1
    },

    "BLS383": {
        "BITS": "384",
        "FIELD": "BLS383",
        "CURVE": "BLS383",
        "@NB": 48,
        "@BASE": 23,
        "@NBT": 383,
        "@M8": 3,
        "@MT": 0,
        "@CT": 0,
        "@PF": 2
    },

    "RSA2048": {
        "BITS": "1024",
        "TFF": "2048",
        "@NB": 128,
        "@BASE": 22,
        "@ML": 2,
    },

    "RSA3072": {
        "BITS": "384",
        "TFF": "3072",
        "@NB": 48,
        "@BASE": 23,
        "@ML": 8,
    },

    "RSA4096": {
        "BITS": "512",
        "TFF": "4096",
        "@NB": 64,
        "@BASE": 23,
        "@ML": 8,
    },
}

module.exports = CTXLIST;

CTX = function(input_parameter) {
    this.AES = aes.AES(this);
    this.GCM = gcm.GCM(this);
    this.UInt64 = uint64.UInt64(this);
    this.HASH256 = hash256.HASH256(this);
    this.HASH384 = hash384.HASH384(this);
    this.HASH512 = hash512.HASH512(this);
    this.RAND = rand.RAND(this);

    if (input_parameter === undefined)
        return;
    else {

        this.config = CTXLIST[input_parameter];

        // Set RSA parameters
        if (this.config['TFF'] !== undefined) {
            this.BIG = big.BIG(this);
            this.DBIG = big.DBIG(this);
            this.FF = ff.FF(this);
            this.RSA = rsa.RSA(this);
            this.rsa_public_key = rsa.rsa_public_key(this);
            this.rsa_private_key = rsa.rsa_private_key(this);
            return;
        };

        // Set Elliptic Curve parameters
        if (this.config['CURVE'] !== undefined) {

            this.ROM_CURVE = romCurve['ROM_CURVE_' + this.config['CURVE']](this);
            this.ROM_FIELD = romField['ROM_FIELD_' + this.config['FIELD']](this);
            this.BIG = big.BIG(this);
            this.DBIG = big.DBIG(this);
            this.FP = fp.FP(this);
            this.ECP = ecp.ECP(this);
            this.ECDH = ecdh.ECDH(this);

            if (this.config['@PF'] != 0) {
                this.FP2 = fp2.FP2(this);
                this.FP4 = fp4.FP4(this);
                this.FP12 = fp12.FP12(this);
                this.ECP2 = ecp2.ECP2(this);
                this.PAIR = pair.PAIR(this);
                this.MPIN = mpin.MPIN(this);
            };
            return;
        };
    };
};

module.exports = CTX;
},{"./aes":2,"./big":3,"./ecdh":5,"./ecp":6,"./ecp2":7,"./ff":8,"./fp":9,"./fp12":10,"./fp2":11,"./fp4":12,"./gcm":13,"./hash256":14,"./hash384":15,"./hash512":16,"./mpin":17,"./pair":18,"./rand":19,"./rom_curve":20,"./rom_field":21,"./rsa":22,"./uint64":23}],5:[function(require,module,exports){
/*
	Licensed to the Apache Software Foundation (ASF) under one
	or more contributor license agreements.  See the NOTICE file
	distributed with this work for additional information
	regarding copyright ownership.  The ASF licenses this file
	to you under the Apache License, Version 2.0 (the
	"License"); you may not use this file except in compliance
	with the License.  You may obtain a copy of the License at
	
	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing,
	software distributed under the License is distributed on an
	"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
	KIND, either express or implied.  See the License for the
	specific language governing permissions and limitations
	under the License.
*/

module.exports.ECDH = function(ctx) {

    var ECDH = {

        INVALID_PUBLIC_KEY: -2,
        ERROR: -3,
        INVALID: -4,
        EFS: ctx.BIG.MODBYTES,
        EGS: ctx.BIG.MODBYTES,
        EAS: 16,
        EBS: 16,
        SHA256: 32,
        SHA384: 48,
        SHA512: 64,

        HASH_TYPE: 64,

        /* Convert Integer to n-byte array */
        inttobytes: function(n, len) {
            var i;
            var b = [];

            for (i = 0; i < len; i++) b[i] = 0;
            i = len;
            while (n > 0 && i > 0) {
                i--;
                b[i] = (n & 0xff);
                n = Math.floor(n / 256);
            }
            return b;
        },

        bytestostring: function(b) {
            var s = "";
            var len = b.length;
            var ch;

            for (var i = 0; i < len; i++) {
                ch = b[i];
                s += ((ch >>> 4) & 15).toString(16);
                s += (ch & 15).toString(16);

            }
            return s;
        },

        stringtobytes: function(s) {
            var b = [];
            for (var i = 0; i < s.length; i++)
                b.push(s.charCodeAt(i));
            return b;
        },

        hashit: function(sha, A, n, B, pad) {
            var R = [];
            if (sha == this.SHA256) {
                var H = new ctx.HASH256();
                H.process_array(A);
                if (n > 0) H.process_num(n);
                if (B != null) H.process_array(B);
                R = H.hash();
            }
            if (sha == this.SHA384) {
                H = new ctx.HASH384();
                H.process_array(A);
                if (n > 0) H.process_num(n);
                if (B != null) H.process_array(B);
                R = H.hash();
            }
            if (sha == this.SHA512) {
                H = new ctx.HASH512();
                H.process_array(A);
                if (n > 0) H.process_num(n);
                if (B != null) H.process_array(B);
                R = H.hash();
            }
            if (R.length == 0) return null;

            if (pad == 0) return R;
            var W = [];
            if (pad <= sha) {
                for (var i = 0; i < pad; i++) W[i] = R[i];
            } else {
                for (var i = 0; i < sha; i++) W[i] = R[i];
                for (var i = sha; i < pad; i++) W[i] = 0;
            }
            return W;
        },

        KDF1: function(sha, Z, olen) {
            /* NOTE: the parameter olen is the length of the output K in bytes */
            var i, hlen = sha;
            var K = [];

            var B = [];
            var counter, cthreshold, k = 0;

            for (i = 0; i < K.length; i++) K[i] = 0; // redundant?

            cthreshold = Math.floor(olen / hlen);
            if (olen % hlen !== 0) cthreshold++;

            for (counter = 0; counter < cthreshold; counter++) {
                B = this.hashit(sha, Z, counter, null, 0);
                if (k + hlen > olen)
                    for (i = 0; i < olen % hlen; i++) K[k++] = B[i];
                else
                    for (i = 0; i < hlen; i++) K[k++] = B[i];
            }
            return K;
        },

        KDF2: function(sha, Z, P, olen) {
            /* NOTE: the parameter olen is the length of the output k in bytes */
            var i, hlen = sha;
            var K = [];

            var B = [];
            var counter, cthreshold, k = 0;

            for (i = 0; i < K.length; i++) K[i] = 0; // redundant?

            cthreshold = Math.floor(olen / hlen);
            if (olen % hlen !== 0) cthreshold++;

            for (counter = 1; counter <= cthreshold; counter++) {
                B = this.hashit(sha, Z, counter, P, 0);
                if (k + hlen > olen)
                    for (i = 0; i < olen % hlen; i++) K[k++] = B[i];
                else
                    for (i = 0; i < hlen; i++) K[k++] = B[i];
            }
            return K;
        },

        /* Password based Key Derivation Function */
        /* Input password p, salt s, and repeat count */
        /* Output key of length olen */

        PBKDF2: function(sha, Pass, Salt, rep, olen) {
            var i, j, k, d, opt;
            d = Math.floor(olen / sha);
            if (olen % sha !== 0) d++;
            var F = new Array(sha);
            var U = [];
            var S = [];

            var K = [];
            opt = 0;

            for (i = 1; i <= d; i++) {
                for (j = 0; j < Salt.length; j++) S[j] = Salt[j];
                var N = this.inttobytes(i, 4);
                for (j = 0; j < 4; j++) S[Salt.length + j] = N[j];
                this.HMAC(sha, S, Pass, F);
                for (j = 0; j < sha; j++) U[j] = F[j];
                for (j = 2; j <= rep; j++) {
                    this.HMAC(sha, U, Pass, U);
                    for (k = 0; k < sha; k++) F[k] ^= U[k];
                }
                for (j = 0; j < sha; j++) K[opt++] = F[j];
            }
            var key = [];
            for (i = 0; i < olen; i++) key[i] = K[i];
            return key;
        },

        HMAC: function(sha, M, K, tag) {
            /* Input is from an octet m        *
             * olen is requested output length in bytes. k is the key  *
             * The output is the calculated tag */
            var i, b;
            var B = [];
            b = 64;
            if (sha > 32) b = 128;
            var K0 = new Array(b);
            var olen = tag.length;

            //b=K0.length;
            if (olen < 4) return 0;

            for (i = 0; i < b; i++) K0[i] = 0;

            if (K.length > b) {
                B = this.hashit(sha, K, 0, null, 0);
                for (i = 0; i < sha; i++) K0[i] = B[i];
            } else
                for (i = 0; i < K.length; i++) K0[i] = K[i];

            for (i = 0; i < b; i++) K0[i] ^= 0x36;
            B = this.hashit(sha, K0, 0, M, 0);

            for (i = 0; i < b; i++) K0[i] ^= 0x6a;
            B = this.hashit(sha, K0, 0, B, olen);

            for (i = 0; i < olen; i++) tag[i] = B[i];

            return 1;
        },

        /* ctx.AES encryption/decryption */

        AES_CBC_IV0_ENCRYPT: function(K, M) { /* ctx.AES CBC encryption, with Null IV and key K */
            /* Input is from an octet string M, output is to an octet string C */
            /* Input is padded as necessary to make up a full final block */
            var a = new ctx.AES();
            var fin;
            var i, j, ipt, opt;
            var buff = [];
            /*var clen=16+(Math.floor(M.length/16))*16;*/

            var C = [];
            var padlen;

            a.init(ctx.AES.CBC, K.length, K, null);

            ipt = opt = 0;
            fin = false;
            for (;;) {
                for (i = 0; i < 16; i++) {
                    if (ipt < M.length) buff[i] = M[ipt++];
                    else {
                        fin = true;
                        break;
                    }
                }
                if (fin) break;
                a.encrypt(buff);
                for (i = 0; i < 16; i++)
                    C[opt++] = buff[i];
            }

            /* last block, filled up to i-th index */

            padlen = 16 - i;
            for (j = i; j < 16; j++) buff[j] = padlen;
            a.encrypt(buff);
            for (i = 0; i < 16; i++)
                C[opt++] = buff[i];
            a.end();
            return C;
        },

        AES_CBC_IV0_DECRYPT: function(K, C) { /* padding is removed */
            var a = new ctx.AES();
            var i, ipt, opt, ch;
            var buff = [];
            var MM = [];
            var fin, bad;
            var padlen;
            ipt = opt = 0;

            a.init(ctx.AES.CBC, K.length, K, null);

            if (C.length === 0) return [];
            ch = C[ipt++];

            fin = false;

            for (;;) {
                for (i = 0; i < 16; i++) {
                    buff[i] = ch;
                    if (ipt >= C.length) {
                        fin = true;
                        break;
                    } else ch = C[ipt++];
                }
                a.decrypt(buff);
                if (fin) break;
                for (i = 0; i < 16; i++)
                    MM[opt++] = buff[i];
            }

            a.end();
            bad = false;
            padlen = buff[15];
            if (i != 15 || padlen < 1 || padlen > 16) bad = true;
            if (padlen >= 2 && padlen <= 16)
                for (i = 16 - padlen; i < 16; i++)
                    if (buff[i] != padlen) bad = true;

            if (!bad)
                for (i = 0; i < 16 - padlen; i++)
                    MM[opt++] = buff[i];

            var M = [];
            if (bad) return M;

            for (i = 0; i < opt; i++) M[i] = MM[i];
            return M;
        },

        KEY_PAIR_GENERATE: function(RNG, S, W) {
            var r, gx, gy, s;
            var G, WP;
            var res = 0;
            //		var T=[];
            G = new ctx.ECP(0);

            gx = new ctx.BIG(0);
            gx.rcopy(ctx.ROM_CURVE.CURVE_Gx);

            if (ctx.ECP.CURVETYPE != ctx.ECP.MONTGOMERY) {
                gy = new ctx.BIG(0);
                gy.rcopy(ctx.ROM_CURVE.CURVE_Gy);
                G.setxy(gx, gy);
            } else G.setx(gx);

            r = new ctx.BIG(0);
            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            if (RNG === null) {
                s = ctx.BIG.fromBytes(S);
                s.mod(r);
            } else {
                s = ctx.BIG.randomnum(r, RNG);

                //		s.toBytes(T);
                //		for (var i=0;i<this.EGS;i++) S[i]=T[i];
            }
            //if (ROM.AES_S>0)
            //{
            //	s.mod2m(2*ROM.AES_S);
            //}
            s.toBytes(S);

            WP = G.mul(s);
            WP.toBytes(W);

            return res;
        },

        PUBLIC_KEY_VALIDATE: function(W) {
            var r;
            var WP = ctx.ECP.fromBytes(W);
            var res = 0;

            r = new ctx.BIG(0);
            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            if (WP.is_infinity()) res = this.INVALID_PUBLIC_KEY;

            if (res === 0) {

                var q = new ctx.BIG(0);
                q.rcopy(ctx.ROM_FIELD.Modulus);
                var nb = q.nbits();
                var k = new ctx.BIG(1);
                k.shl(Math.floor((nb + 4) / 2));
                k.add(q);
                k.div(r);

                while (k.parity() == 0) {
                    k.shr(1);
                    WP.dbl();
                }

                if (!k.isunity()) WP = WP.mul(k);
                if (WP.is_infinity()) res = this.INVALID_PUBLIC_KEY;

            }
            return res;
        },

        ECPSVDP_DH: function(S, WD, Z) {
            var r, s;
            var W;
            var res = 0;
            var T = [];

            s = ctx.BIG.fromBytes(S);

            W = ctx.ECP.fromBytes(WD);
            if (W.is_infinity()) res = this.ERROR;

            if (res === 0) {
                r = new ctx.BIG(0);
                r.rcopy(ctx.ROM_CURVE.CURVE_Order);
                s.mod(r);
                W = W.mul(s);
                if (W.is_infinity()) res = this.ERROR;
                else {
                    W.getX().toBytes(T);
                    for (var i = 0; i < this.EFS; i++) Z[i] = T[i];
                }
            }
            return res;
        },

        ECPSP_DSA: function(sha, RNG, S, F, C, D) {
            var T = [];
            var i, gx, gy, r, s, f, c, d, u, vx, w;
            var G, V;

            var B = this.hashit(sha, F, 0, null, ctx.BIG.MODBYTES);

            gx = new ctx.BIG(0);
            gx.rcopy(ctx.ROM_CURVE.CURVE_Gx);
            gy = new ctx.BIG(0);
            gy.rcopy(ctx.ROM_CURVE.CURVE_Gy);

            G = new ctx.ECP(0);
            G.setxy(gx, gy);
            r = new ctx.BIG(0);
            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            s = ctx.BIG.fromBytes(S);
            f = ctx.BIG.fromBytes(B);

            c = new ctx.BIG(0);
            d = new ctx.BIG(0);
            V = new ctx.ECP();

            do {
                u = ctx.BIG.randomnum(r, RNG);
                w = ctx.BIG.randomnum(r, RNG);
                //if (ROM.AES_S>0)
                //{
                //	u.mod2m(2*ROM.AES_S);
                //}				
                V.copy(G);
                V = V.mul(u);
                vx = V.getX();
                c.copy(vx);
                c.mod(r);
                if (c.iszilch()) continue;
                u = ctx.BIG.modmul(u, w, r);
                u.invmodp(r);
                d = ctx.BIG.modmul(s, c, r);
                d.add(f);
                d = ctx.BIG.modmul(d, w, r);
                d = ctx.BIG.modmul(u, d, r);
            } while (d.iszilch());

            c.toBytes(T);
            for (i = 0; i < this.EFS; i++) C[i] = T[i];
            d.toBytes(T);
            for (i = 0; i < this.EFS; i++) D[i] = T[i];
            return 0;
        },

        ECPVP_DSA: function(sha, W, F, C, D) {
            var B = [];
            var r, gx, gy, f, c, d, h2;
            var res = 0;
            var G, WP, P;

            B = this.hashit(sha, F, 0, null, ctx.BIG.MODBYTES);

            gx = new ctx.BIG(0);
            gx.rcopy(ctx.ROM_CURVE.CURVE_Gx);
            gy = new ctx.BIG(0);
            gy.rcopy(ctx.ROM_CURVE.CURVE_Gy);

            G = new ctx.ECP(0);
            G.setxy(gx, gy);
            r = new ctx.BIG(0);
            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            c = ctx.BIG.fromBytes(C);
            d = ctx.BIG.fromBytes(D);
            f = ctx.BIG.fromBytes(B);

            if (c.iszilch() || ctx.BIG.comp(c, r) >= 0 || d.iszilch() || ctx.BIG.comp(d, r) >= 0)
                res = this.INVALID;

            if (res === 0) {
                d.invmodp(r);
                f = ctx.BIG.modmul(f, d, r);
                h2 = ctx.BIG.modmul(c, d, r);

                WP = ctx.ECP.fromBytes(W);
                if (WP.is_infinity()) res = this.ERROR;
                else {
                    P = new ctx.ECP();
                    P.copy(WP);
                    P = P.mul2(h2, G, f);
                    if (P.is_infinity()) res = this.INVALID;
                    else {
                        d = P.getX();
                        d.mod(r);
                        if (ctx.BIG.comp(d, c) !== 0) res = this.INVALID;
                    }
                }
            }

            return res;
        },

        ECIES_ENCRYPT: function(sha, P1, P2, RNG, W, M, V, T) {
            var i;

            var Z = [];
            var VZ = [];
            var K1 = [];
            var K2 = [];
            var U = [];
            var C = [];

            if (this.KEY_PAIR_GENERATE(RNG, U, V) !== 0) return C;
            if (this.ECPSVDP_DH(U, W, Z) !== 0) return C;

            for (i = 0; i < 2 * this.EFS + 1; i++) VZ[i] = V[i];
            for (i = 0; i < this.EFS; i++) VZ[2 * this.EFS + 1 + i] = Z[i];


            var K = this.KDF2(sha, VZ, P1, this.EFS);

            for (i = 0; i < this.EAS; i++) {
                K1[i] = K[i];
                K2[i] = K[this.EAS + i];
            }

            C = this.AES_CBC_IV0_ENCRYPT(K1, M);

            var L2 = this.inttobytes(P2.length, 8);

            var AC = [];
            for (i = 0; i < C.length; i++) AC[i] = C[i];
            for (i = 0; i < P2.length; i++) AC[C.length + i] = P2[i];
            for (i = 0; i < 8; i++) AC[C.length + P2.length + i] = L2[i];

            this.HMAC(sha, AC, K2, T);

            return C;
        },

        ECIES_DECRYPT: function(sha, P1, P2, V, C, T, U) {

            var i;

            var Z = [];
            var VZ = [];
            var K1 = [];
            var K2 = [];
            var TAG = new Array(T.length);
            var M = [];

            if (this.ECPSVDP_DH(U, V, Z) !== 0) return M;

            for (i = 0; i < 2 * this.EFS + 1; i++) VZ[i] = V[i];
            for (i = 0; i < this.EFS; i++) VZ[2 * this.EFS + 1 + i] = Z[i];

            var K = this.KDF2(sha, VZ, P1, this.EFS);

            for (i = 0; i < this.EAS; i++) {
                K1[i] = K[i];
                K2[i] = K[this.EAS + i];
            }

            M = this.AES_CBC_IV0_DECRYPT(K1, C);

            if (M.length === 0) return M;

            var L2 = this.inttobytes(P2.length, 8);

            var AC = [];

            for (i = 0; i < C.length; i++) AC[i] = C[i];
            for (i = 0; i < P2.length; i++) AC[C.length + i] = P2[i];
            for (i = 0; i < 8; i++) AC[C.length + P2.length + i] = L2[i];

            this.HMAC(sha, AC, K2, TAG);

            var same = true;
            for (i = 0; i < T.length; i++)
                if (T[i] != TAG[i]) same = false;
            if (!same) return [];

            return M;
        }
    };
    ECDH.ctx = ctx;
    return ECDH;
};
},{}],6:[function(require,module,exports){
/*
	Licensed to the Apache Software Foundation (ASF) under one
	or more contributor license agreements.  See the NOTICE file
	distributed with this work for additional information
	regarding copyright ownership.  The ASF licenses this file
	to you under the Apache License, Version 2.0 (the
	"License"); you may not use this file except in compliance
	with the License.  You may obtain a copy of the License at
	
	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing,
	software distributed under the License is distributed on an
	"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
	KIND, either express or implied.  See the License for the
	specific language governing permissions and limitations
	under the License.
*/

/* Elliptic Curve Point class */

module.exports.ECP = function(ctx) {

    /* Constructor */
    var ECP = function() {
        this.x = new ctx.FP(0);
        this.y = new ctx.FP(1);
        this.z = new ctx.FP(1);
        this.INF = true;
    };

    ECP.WEIERSTRASS = 0;
    ECP.EDWARDS = 1;
    ECP.MONTGOMERY = 2;
    ECP.NOT = 0;
    ECP.BN = 1;
    ECP.BLS = 2;

    ECP.CURVETYPE = ctx.config["@CT"];
    ECP.CURVE_PAIRING_TYPE = ctx.config["@PF"];

    ECP.prototype = {
        /* test this=O point-at-infinity */
        is_infinity: function() {
            if (ECP.CURVETYPE == ECP.EDWARDS) {
                this.x.reduce();
                this.y.reduce();
                this.z.reduce();
                return (this.x.iszilch() && this.y.equals(this.z));
            } else return this.INF;
        },


        /* conditional swap of this and Q dependant on d */
        cswap: function(Q, d) {
            this.x.cswap(Q.x, d);
            if (ECP.CURVETYPE != ECP.MONTGOMERY) this.y.cswap(Q.y, d);
            this.z.cswap(Q.z, d);
            if (ECP.CURVETYPE != ECP.EDWARDS) {
                var bd = (d !== 0) ? true : false;
                bd = bd & (this.INF ^ Q.INF);
                this.INF ^= bd;
                Q.INF ^= bd;
            }
        },

        /* conditional move of Q to P dependant on d */
        cmove: function(Q, d) {
            this.x.cmove(Q.x, d);
            if (ECP.CURVETYPE != ECP.MONTGOMERY) this.y.cmove(Q.y, d);
            this.z.cmove(Q.z, d);
            if (ECP.CURVETYPE != ECP.EDWARDS) {
                var bd = (d !== 0) ? true : false;
                this.INF ^= (this.INF ^ Q.INF) & bd;
            }
        },

        /* Constant time select from pre-computed table */
        select: function(W, b) {
            var MP = new ECP();
            var m = b >> 31;
            var babs = (b ^ m) - m;

            babs = (babs - 1) / 2;

            this.cmove(W[0], ECP.teq(babs, 0)); // conditional move
            this.cmove(W[1], ECP.teq(babs, 1));
            this.cmove(W[2], ECP.teq(babs, 2));
            this.cmove(W[3], ECP.teq(babs, 3));
            this.cmove(W[4], ECP.teq(babs, 4));
            this.cmove(W[5], ECP.teq(babs, 5));
            this.cmove(W[6], ECP.teq(babs, 6));
            this.cmove(W[7], ECP.teq(babs, 7));

            MP.copy(this);
            MP.neg();
            this.cmove(MP, (m & 1));
        },

        /* Test P == Q */

        equals: function(Q) {
            if (this.is_infinity() && Q.is_infinity()) return true;
            if (this.is_infinity() || Q.is_infinity()) return false;
            if (ECP.CURVETYPE == ECP.WEIERSTRASS) {
                var zs2 = new ctx.FP(0);
                zs2.copy(this.z);
                zs2.sqr();
                var zo2 = new ctx.FP(0);
                zo2.copy(Q.z);
                zo2.sqr();
                var zs3 = new ctx.FP(0);
                zs3.copy(zs2);
                zs3.mul(this.z);
                var zo3 = new ctx.FP(0);
                zo3.copy(zo2);
                zo3.mul(Q.z);
                zs2.mul(Q.x);
                zo2.mul(this.x);
                if (!zs2.equals(zo2)) return false;
                zs3.mul(Q.y);
                zo3.mul(this.y);
                if (!zs3.equals(zo3)) return false;
            } else {
                var a = new ctx.FP(0);
                var b = new ctx.FP(0);
                a.copy(this.x);
                a.mul(Q.z);
                a.reduce();
                b.copy(Q.x);
                b.mul(this.z);
                b.reduce();
                if (!a.equals(b)) return false;
                if (ECP.CURVETYPE == ECP.EDWARDS) {
                    a.copy(this.y);
                    a.mul(Q.z);
                    a.reduce();
                    b.copy(Q.y);
                    b.mul(this.z);
                    b.reduce();
                    if (!a.equals(b)) return false;
                }
            }
            return true;
        },
        /* copy this=P */
        copy: function(P) {
            this.x.copy(P.x);
            if (ECP.CURVETYPE != ECP.MONTGOMERY) this.y.copy(P.y);
            this.z.copy(P.z);
            this.INF = P.INF;
        },
        /* this=-this */
        neg: function() {
            if (this.is_infinity()) return;
            if (ECP.CURVETYPE == ECP.WEIERSTRASS) {
                this.y.neg();
                this.y.norm();
            }
            if (ECP.CURVETYPE == ECP.EDWARDS) {
                this.x.neg();
                this.x.norm();
            }
            return;
        },
        /* set this=O */
        inf: function() {
            this.INF = true;
            this.x.zero();
            this.y = new ctx.FP(1);
            this.z = new ctx.FP(1);
        },
        /* set this=(x,y) where x and y are BIGs */
        setxy: function(ix, iy) {

            this.x = new ctx.FP(0);
            this.x.bcopy(ix);
            var bx = this.x.redc();

            this.y = new ctx.FP(0);
            this.y.bcopy(iy);
            this.z = new ctx.FP(1);
            var rhs = ECP.RHS(this.x);

            if (ECP.CURVETYPE == ECP.MONTGOMERY) {
                if (rhs.jacobi() == 1) this.INF = false;
                else this.inf();
            } else {
                var y2 = new ctx.FP(0);
                y2.copy(this.y);
                y2.sqr();
                if (y2.equals(rhs)) this.INF = false;
                else this.inf();

            }
        },
        /* set this=x, where x is ctx.BIG, y is derived from sign s */
        setxi: function(ix, s) {
            this.x = new ctx.FP(0);
            this.x.bcopy(ix);
            var rhs = ECP.RHS(this.x);
            this.z = new ctx.FP(1);
            if (rhs.jacobi() == 1) {
                var ny = rhs.sqrt();
                if (ny.redc().parity() != s) ny.neg();
                this.y = ny;
                this.INF = false;
            } else this.inf();
        },
        /* set this=x, y calcuated from curve equation */
        setx: function(ix) {
            this.x = new ctx.FP(0);
            this.x.bcopy(ix);
            var rhs = ECP.RHS(this.x);
            this.z = new ctx.FP(1);
            if (rhs.jacobi() == 1) {
                if (ECP.CURVETYPE != ECP.MONTGOMERY) this.y = rhs.sqrt();
                this.INF = false;
            } else this.INF = true;
        },
        /* set this to affine - from (x,y,z) to (x,y) */
        affine: function() {
            if (this.is_infinity()) return;
            var one = new ctx.FP(1);
            if (this.z.equals(one)) return;
            this.z.inverse();
            if (ECP.CURVETYPE == ECP.WEIERSTRASS) {
                var z2 = new ctx.FP(0);
                z2.copy(this.z);
                z2.sqr();
                this.x.mul(z2);
                this.x.reduce();
                this.y.mul(z2);
                this.y.mul(this.z);
                this.y.reduce();
                this.z = one;
            }
            if (ECP.CURVETYPE == ECP.EDWARDS) {
                this.x.mul(this.z);
                this.x.reduce();
                this.y.mul(this.z);
                this.y.reduce();
                this.z = one;
            }
            if (ECP.CURVETYPE == ECP.MONTGOMERY) {
                this.x.mul(this.z);
                this.x.reduce();
                this.z = one;
            }
        },
        /* extract x as ctx.BIG */
        getX: function() {
            this.affine();
            return this.x.redc();
        },
        /* extract y as ctx.BIG */
        getY: function() {
            this.affine();
            return this.y.redc();
        },

        /* get sign of Y */
        getS: function() {
            this.affine();
            var y = this.getY();
            return y.parity();
        },
        /* extract x as ctx.FP */
        getx: function() {
            return this.x;
        },
        /* extract y as ctx.FP */
        gety: function() {
            return this.y;
        },
        /* extract z as ctx.FP */
        getz: function() {
            return this.z;
        },
        /* convert to byte array */
        toBytes: function(b) {
            var i, t = [];
            if (ECP.CURVETYPE != ECP.MONTGOMERY) b[0] = 0x04;
            else b[0] = 0x02;

            this.affine();
            this.x.redc().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) b[i + 1] = t[i];
            if (ECP.CURVETYPE != ECP.MONTGOMERY) {
                this.y.redc().toBytes(t);
                for (i = 0; i < ctx.BIG.MODBYTES; i++) b[i + ctx.BIG.MODBYTES + 1] = t[i];
            }
        },
        /* convert to hex string */
        toString: function() {
            if (this.is_infinity()) return "infinity";
            this.affine();
            if (ECP.CURVETYPE == ECP.MONTGOMERY) return "(" + this.x.redc().toString() + ")";
            else return "(" + this.x.redc().toString() + "," + this.y.redc().toString() + ")";
        },

        /* this+=this */
        dbl: function() {
            if (ECP.CURVETYPE == ECP.WEIERSTRASS) {
                if (this.INF) return;
                if (this.y.iszilch()) {
                    this.inf();
                    return;
                }

                var w1 = new ctx.FP(0);
                w1.copy(this.x);
                var w6 = new ctx.FP(0);
                w6.copy(this.z);
                var w2 = new ctx.FP(0);
                var w3 = new ctx.FP(0);
                w3.copy(this.x);
                var w8 = new ctx.FP(0);
                w8.copy(this.x);

                if (ctx.ROM_CURVE.CURVE_A == -3) {
                    w6.sqr();
                    w1.copy(w6);
                    w1.neg();
                    w3.add(w1);
                    w8.add(w6);
                    w3.norm();
                    w8.norm();
                    w3.mul(w8);
                    w8.copy(w3);
                    w8.imul(3);
                } else {
                    w1.sqr();
                    w8.copy(w1);
                    w8.imul(3);
                }

                w2.copy(this.y);
                w2.sqr();

                w3.copy(this.x);
                w3.imul(4);

                //			w3.copy(this.x); 
                w3.mul(w2);
                //			w3.imul(4); //w3.norm();
                w1.copy(w3);
                w1.neg();

                //w8.norm();
                this.x.copy(w8);
                this.x.sqr();
                this.x.add(w1);
                this.x.add(w1);
                this.x.norm();

                this.z.add(this.z);
                this.z.norm();
                this.z.mul(this.y);

                //			this.z.mul(this.y);
                //			this.z.add(this.z);

                w2.add(w2);
                w2.norm();
                w2.sqr();
                w2.add(w2);
                w3.sub(this.x);
                w3.norm();
                this.y.copy(w8);
                this.y.mul(w3);
                this.y.sub(w2);
                this.y.norm();
                this.z.norm();
            }
            if (ECP.CURVETYPE == ECP.EDWARDS) {
                var C = new ctx.FP(0);
                C.copy(this.x);
                var D = new ctx.FP(0);
                D.copy(this.y);
                var H = new ctx.FP(0);
                H.copy(this.z);
                var J = new ctx.FP(0);

                this.x.mul(this.y);
                this.x.add(this.x);
                this.x.norm();
                C.sqr();
                D.sqr();
                if (ctx.ROM_CURVE.CURVE_A == -1) C.neg();
                this.y.copy(C);
                this.y.add(D);
                this.y.norm();
                H.sqr();
                H.add(H);
                this.z.copy(this.y);
                J.copy(this.y);
                J.sub(H);
                J.norm();
                this.x.mul(J);
                C.sub(D);
                C.norm();
                this.y.mul(C);
                this.z.mul(J);

                //	this.x.norm();
                //	this.y.norm();
                //	this.z.norm();
            }
            if (ECP.CURVETYPE == ECP.MONTGOMERY) {
                var A = new ctx.FP(0);
                A.copy(this.x);
                var B = new ctx.FP(0);
                B.copy(this.x);
                var AA = new ctx.FP(0);
                var BB = new ctx.FP(0);
                var C = new ctx.FP(0);

                if (this.INF) return;

                A.add(this.z);
                A.norm();
                AA.copy(A);
                AA.sqr();
                B.sub(this.z);
                B.norm();
                BB.copy(B);
                BB.sqr();
                C.copy(AA);
                C.sub(BB);
                C.norm();

                this.x.copy(AA);
                this.x.mul(BB);

                A.copy(C);
                A.imul((ctx.ROM_CURVE.CURVE_A + 2) >> 2);

                BB.add(A);
                BB.norm();
                this.z.copy(BB);
                this.z.mul(C);
                //	this.x.norm();
                //	this.z.norm();
            }
            return;
        },

        /* this+=Q */
        add: function(Q) {
            if (ECP.CURVETYPE == ECP.WEIERSTRASS) {
                if (this.INF) {
                    this.copy(Q);
                    return;
                }
                if (Q.INF) return;

                var aff = false;
                var one = new ctx.FP(1);
                if (Q.z.equals(one)) aff = true;

                var A, C;
                var B = new ctx.FP(this.z);
                var D = new ctx.FP(this.z);
                if (!aff) {
                    A = new ctx.FP(Q.z);
                    C = new ctx.FP(Q.z);

                    A.sqr();
                    B.sqr();
                    C.mul(A);
                    D.mul(B);

                    A.mul(this.x);
                    C.mul(this.y);
                } else {
                    A = new ctx.FP(this.x);
                    C = new ctx.FP(this.y);

                    B.sqr();
                    D.mul(B);
                }

                B.mul(Q.x);
                B.sub(A);
                D.mul(Q.y);
                D.sub(C);

                if (B.iszilch()) {
                    if (D.iszilch()) {
                        this.dbl();
                        return;
                    } else {
                        this.INF = true;
                        return;
                    }
                }

                if (!aff) this.z.mul(Q.z);
                this.z.mul(B);

                var e = new ctx.FP(B);
                e.sqr();
                B.mul(e);
                A.mul(e);

                e.copy(A);
                e.add(A);
                e.add(B);
                e.norm();
                D.norm();
                this.x.copy(D);
                this.x.sqr();
                this.x.sub(e);

                A.sub(this.x);
                A.norm();
                this.y.copy(A);
                this.y.mul(D);
                C.mul(B);
                this.y.sub(C);

                this.x.norm();
                this.y.norm();
                //	this.z.norm();

            }
            if (ECP.CURVETYPE == ECP.EDWARDS) {
                var b = new ctx.FP(0);
                b.rcopy(ctx.ROM_CURVE.CURVE_B);
                var A = new ctx.FP(0);
                A.copy(this.z);
                var B = new ctx.FP(0);
                var C = new ctx.FP(0);
                C.copy(this.x);
                var D = new ctx.FP(0);
                D.copy(this.y);
                var E = new ctx.FP(0);
                var F = new ctx.FP(0);
                var G = new ctx.FP(0);

                A.mul(Q.z);
                B.copy(A);
                B.sqr();
                C.mul(Q.x);
                D.mul(Q.y);

                E.copy(C);
                E.mul(D);
                E.mul(b);
                F.copy(B);
                F.sub(E);
                G.copy(B);
                G.add(E);

                if (ctx.ROM_CURVE.CURVE_A == 1) {
                    E.copy(D);
                    E.sub(C);
                }
                C.add(D);

                B.copy(this.x);
                B.add(this.y);
                D.copy(Q.x);
                D.add(Q.y);
                B.norm();
                D.norm();
                B.mul(D);
                B.sub(C);
                B.norm();
                F.norm();
                B.mul(F);
                this.x.copy(A);
                this.x.mul(B);

                G.norm();
                if (ctx.ROM_CURVE.CURVE_A == 1) {
                    E.norm();
                    C.copy(E);
                    C.mul(G);
                }
                if (ctx.ROM_CURVE.CURVE_A == -1) {
                    C.norm();
                    C.mul(G);
                }
                this.y.copy(A);
                this.y.mul(C);
                this.z.copy(F);
                this.z.mul(G);
                //	this.x.norm(); this.y.norm(); this.z.norm();
            }
            return;
        },

        /* Differential Add for Montgomery curves. this+=Q where W is this-Q and is affine. */
        dadd: function(Q, W) {
            var A = new ctx.FP(0);
            A.copy(this.x);
            var B = new ctx.FP(0);
            B.copy(this.x);
            var C = new ctx.FP(0);
            C.copy(Q.x);
            var D = new ctx.FP(0);
            D.copy(Q.x);
            var DA = new ctx.FP(0);
            var CB = new ctx.FP(0);

            A.add(this.z);
            B.sub(this.z);

            C.add(Q.z);
            D.sub(Q.z);

            D.norm();
            A.norm();
            DA.copy(D);
            DA.mul(A);
            C.norm();
            B.norm();
            CB.copy(C);
            CB.mul(B);

            A.copy(DA);
            A.add(CB);
            A.norm();
            A.sqr();
            B.copy(DA);
            B.sub(CB);
            B.norm();
            B.sqr();

            this.x.copy(A);
            this.z.copy(W.x);
            this.z.mul(B);

            if (this.z.iszilch()) this.inf();
            else this.INF = false;

            //	this.x.norm();
        },

        /* this-=Q */
        sub: function(Q) {
            Q.neg();
            this.add(Q);
            Q.neg();
        },

        /* constant time multiply by small integer of length bts - use ladder */
        pinmul: function(e, bts) {
            if (ECP.CURVETYPE == ECP.MONTGOMERY)
                return this.mul(new ctx.BIG(e));
            else {
                var nb, i, b;
                var P = new ECP();
                var R0 = new ECP();
                var R1 = new ECP();
                R1.copy(this);

                for (i = bts - 1; i >= 0; i--) {
                    b = (e >> i) & 1;
                    P.copy(R1);
                    P.add(R0);
                    R0.cswap(R1, b);
                    R1.copy(P);
                    R0.dbl();
                    R0.cswap(R1, b);
                }
                P.copy(R0);
                P.affine();
                return P;
            }
        },

        /* return e.this - SPA immune, using Ladder */

        mul: function(e) {
            if (e.iszilch() || this.is_infinity()) return new ECP();
            var P = new ECP();
            if (ECP.CURVETYPE == ECP.MONTGOMERY) { /* use ladder */
                var nb, i, b;
                var D = new ECP();
                var R0 = new ECP();
                R0.copy(this);
                var R1 = new ECP();
                R1.copy(this);
                R1.dbl();
                D.copy(this);
                D.affine();
                nb = e.nbits();
                for (i = nb - 2; i >= 0; i--) {
                    b = e.bit(i);
                    P.copy(R1);
                    P.dadd(R0, D);

                    R0.cswap(R1, b);
                    R1.copy(P);
                    R0.dbl();
                    R0.cswap(R1, b);
                }
                P.copy(R0);
            } else {
                // fixed size windows 
                var i, b, nb, m, s, ns;
                var mt = new ctx.BIG();
                var t = new ctx.BIG();
                var Q = new ECP();
                var C = new ECP();
                var W = [];
                var w = [];

                this.affine();

                // precompute table 
                Q.copy(this);
                Q.dbl();
                W[0] = new ECP();
                W[0].copy(this);

                for (i = 1; i < 8; i++) {
                    W[i] = new ECP();
                    W[i].copy(W[i - 1]);
                    W[i].add(Q);
                }

                // convert the table to affine 
                if (ECP.CURVETYPE == ECP.WEIERSTRASS)
                    ECP.multiaffine(8, W);

                // make exponent odd - add 2P if even, P if odd 
                t.copy(e);
                s = t.parity();
                t.inc(1);
                t.norm();
                ns = t.parity();
                mt.copy(t);
                mt.inc(1);
                mt.norm();
                t.cmove(mt, s);
                Q.cmove(this, ns);
                C.copy(Q);

                nb = 1 + Math.floor((t.nbits() + 3) / 4);

                // convert exponent to signed 4-bit window 
                for (i = 0; i < nb; i++) {
                    w[i] = (t.lastbits(5) - 16);
                    t.dec(w[i]);
                    t.norm();
                    t.fshr(4);
                }
                w[nb] = t.lastbits(5);

                P.copy(W[Math.floor((w[nb] - 1) / 2)]);
                for (i = nb - 1; i >= 0; i--) {
                    Q.select(W, w[i]);
                    P.dbl();
                    P.dbl();
                    P.dbl();
                    P.dbl();
                    P.add(Q);
                }
                P.sub(C);
            }
            P.affine();
            return P;
        },

        /* Return e.this+f.Q */

        mul2: function(e, Q, f) {
            var te = new ctx.BIG();
            var tf = new ctx.BIG();
            var mt = new ctx.BIG();
            var S = new ECP();
            var T = new ECP();
            var C = new ECP();
            var W = [];
            var w = [];
            var i, s, ns, nb;
            var a, b;

            this.affine();
            Q.affine();

            te.copy(e);
            tf.copy(f);

            // precompute table 
            W[1] = new ECP();
            W[1].copy(this);
            W[1].sub(Q);
            W[2] = new ECP();
            W[2].copy(this);
            W[2].add(Q);
            S.copy(Q);
            S.dbl();
            W[0] = new ECP();
            W[0].copy(W[1]);
            W[0].sub(S);
            W[3] = new ECP();
            W[3].copy(W[2]);
            W[3].add(S);
            T.copy(this);
            T.dbl();
            W[5] = new ECP();
            W[5].copy(W[1]);
            W[5].add(T);
            W[6] = new ECP();
            W[6].copy(W[2]);
            W[6].add(T);
            W[4] = new ECP();
            W[4].copy(W[5]);
            W[4].sub(S);
            W[7] = new ECP();
            W[7].copy(W[6]);
            W[7].add(S);

            // convert the table to affine 
            if (ECP.CURVETYPE == ECP.WEIERSTRASS)
                ECP.multiaffine(8, W);

            // if multiplier is odd, add 2, else add 1 to multiplier, and add 2P or P to correction 

            s = te.parity();
            te.inc(1);
            te.norm();
            ns = te.parity();
            mt.copy(te);
            mt.inc(1);
            mt.norm();
            te.cmove(mt, s);
            T.cmove(this, ns);
            C.copy(T);

            s = tf.parity();
            tf.inc(1);
            tf.norm();
            ns = tf.parity();
            mt.copy(tf);
            mt.inc(1);
            mt.norm();
            tf.cmove(mt, s);
            S.cmove(Q, ns);
            C.add(S);

            mt.copy(te);
            mt.add(tf);
            mt.norm();
            nb = 1 + Math.floor((mt.nbits() + 1) / 2);

            // convert exponent to signed 2-bit window 
            for (i = 0; i < nb; i++) {
                a = (te.lastbits(3) - 4);
                te.dec(a);
                te.norm();
                te.fshr(2);
                b = (tf.lastbits(3) - 4);
                tf.dec(b);
                tf.norm();
                tf.fshr(2);
                w[i] = (4 * a + b);
            }
            w[nb] = (4 * te.lastbits(3) + tf.lastbits(3));
            S.copy(W[Math.floor((w[nb] - 1) / 2)]);

            for (i = nb - 1; i >= 0; i--) {
                T.select(W, w[i]);
                S.dbl();
                S.dbl();
                S.add(T);
            }
            S.sub(C); /* apply correction */
            S.affine();
            return S;
        }

    };

    ECP.multiaffine = function(m, P) {
        var i;
        var t1 = new ctx.FP(0);
        var t2 = new ctx.FP(0);
        var work = [];

        for (i = 0; i < m; i++)
            work[i] = new ctx.FP(0);

        work[0].one();
        work[1].copy(P[0].z);

        for (i = 2; i < m; i++) {
            work[i].copy(work[i - 1]);
            work[i].mul(P[i - 1].z);
        }

        t1.copy(work[m - 1]);
        t1.mul(P[m - 1].z);
        t1.inverse();
        t2.copy(P[m - 1].z);
        work[m - 1].mul(t1);

        for (i = m - 2;; i--) {
            if (i == 0) {
                work[0].copy(t1);
                work[0].mul(t2);
                break;
            }
            work[i].mul(t2);
            work[i].mul(t1);
            t2.mul(P[i].z);
        }
        /* now work[] contains inverses of all Z coordinates */

        for (i = 0; i < m; i++) {
            P[i].z.one();
            t1.copy(work[i]);
            t1.sqr();
            P[i].x.mul(t1);
            t1.mul(work[i]);
            P[i].y.mul(t1);
        }
    };

    /* return 1 if b==c, no branching */
    ECP.teq = function(b, c) {
        var x = b ^ c;
        x -= 1; // if x=0, x now -1
        return ((x >> 31) & 1);
    };

    /* convert from byte array to ECP */
    ECP.fromBytes = function(b) {
        var i, t = [];
        var P = new ECP();
        var p = new ctx.BIG(0);
        p.rcopy(ctx.ROM_FIELD.Modulus);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) t[i] = b[i + 1];
        var px = ctx.BIG.fromBytes(t);
        if (ctx.BIG.comp(px, p) >= 0) return P;

        if (b[0] == 0x04) {
            for (i = 0; i < ctx.BIG.MODBYTES; i++) t[i] = b[i + ctx.BIG.MODBYTES + 1];
            var py = ctx.BIG.fromBytes(t);
            if (ctx.BIG.comp(py, p) >= 0) return P;
            P.setxy(px, py);
            return P;
        } else {
            P.setx(px);
            return P;
        }
    };

    /* Calculate RHS of curve equation */
    ECP.RHS = function(x) {
        x.norm();
        var r = new ctx.FP(0);
        r.copy(x);
        r.sqr();

        if (ECP.CURVETYPE == ECP.WEIERSTRASS) { // x^3+Ax+B
            var b = new ctx.FP(0);
            b.rcopy(ctx.ROM_CURVE.CURVE_B);
            r.mul(x);
            if (ctx.ROM_CURVE.CURVE_A == -3) {
                var cx = new ctx.FP(0);
                cx.copy(x);
                cx.imul(3);
                cx.neg();
                cx.norm();
                r.add(cx);
            }
            r.add(b);
        }
        if (ECP.CURVETYPE == ECP.EDWARDS) { // (Ax^2-1)/(Bx^2-1) 
            var b = new ctx.FP(0);
            b.rcopy(ctx.ROM_CURVE.CURVE_B);

            var one = new ctx.FP(1);
            b.mul(r);
            b.sub(one);
            if (ctx.ROM_CURVE.CURVE_A == -1) r.neg();
            r.sub(one);
            r.norm();
            b.inverse();

            r.mul(b);
        }
        if (ECP.CURVETYPE == ECP.MONTGOMERY) { // x^3+Ax^2+x
            var x3 = new ctx.FP(0);
            x3.copy(r);
            x3.mul(x);
            r.imul(ctx.ROM_CURVE.CURVE_A);
            r.add(x3);
            r.add(x);
        }
        r.reduce();
        return r;
    };
    ECP.ctx = ctx;
    return ECP;
};
},{}],7:[function(require,module,exports){
/*
	Licensed to the Apache Software Foundation (ASF) under one
	or more contributor license agreements.  See the NOTICE file
	distributed with this work for additional information
	regarding copyright ownership.  The ASF licenses this file
	to you under the Apache License, Version 2.0 (the
	"License"); you may not use this file except in compliance
	with the License.  You may obtain a copy of the License at
	
	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing,
	software distributed under the License is distributed on an
	"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
	KIND, either express or implied.  See the License for the
	specific language governing permissions and limitations
	under the License.
*/

/* AMCL Weierstrass elliptic curve functions over ctx.FP2 */

module.exports.ECP2 = function(ctx) {

    /* Constructor, set this=O */
    var ECP2 = function() {
        this.x = new ctx.FP2(0);
        this.y = new ctx.FP2(1);
        this.z = new ctx.FP2(1);
        this.INF = true;
    };

    ECP2.prototype = {
        /* Test this=O? */
        is_infinity: function() {
            return this.INF;
        },
        /* copy this=P */
        copy: function(P) {
            this.x.copy(P.x);
            this.y.copy(P.y);
            this.z.copy(P.z);
            this.INF = P.INF;
        },
        /* set this=O */
        inf: function() {
            this.INF = true;
            this.x.zero();
            this.y.zero();
            this.z.zero();
        },

        /* conditional move of Q to P dependant on d */
        cmove: function(Q, d) {
            this.x.cmove(Q.x, d);
            this.y.cmove(Q.y, d);
            this.z.cmove(Q.z, d);

            var bd = (d !== 0) ? true : false;
            this.INF ^= (this.INF ^ Q.INF) & bd;
        },

        /* Constant time select from pre-computed table */
        select: function(W, b) {
            var MP = new ECP2();
            var m = b >> 31;
            var babs = (b ^ m) - m;

            babs = (babs - 1) / 2;

            this.cmove(W[0], ECP2.teq(babs, 0)); // conditional move
            this.cmove(W[1], ECP2.teq(babs, 1));
            this.cmove(W[2], ECP2.teq(babs, 2));
            this.cmove(W[3], ECP2.teq(babs, 3));
            this.cmove(W[4], ECP2.teq(babs, 4));
            this.cmove(W[5], ECP2.teq(babs, 5));
            this.cmove(W[6], ECP2.teq(babs, 6));
            this.cmove(W[7], ECP2.teq(babs, 7));

            MP.copy(this);
            MP.neg();
            this.cmove(MP, (m & 1));
        },

        /* Test P == Q */

        equals: function(Q) {
            if (this.is_infinity() && Q.is_infinity()) return true;
            if (this.is_infinity() || Q.is_infinity()) return false;

            var zs2 = new ctx.FP2(this.z); /*zs2.copy(this.z);*/
            zs2.sqr();
            var zo2 = new ctx.FP2(Q.z); /*zo2.copy(Q.z);*/
            zo2.sqr();
            var zs3 = new ctx.FP2(zs2); /*zs3.copy(zs2);*/
            zs3.mul(this.z);
            var zo3 = new ctx.FP2(zo2); /*zo3.copy(zo2);*/
            zo3.mul(Q.z);
            zs2.mul(Q.x);
            zo2.mul(this.x);
            if (!zs2.equals(zo2)) return false;
            zs3.mul(Q.y);
            zo3.mul(this.y);
            if (!zs3.equals(zo3)) return false;

            return true;
        },
        /* set this=-this */
        neg: function() {
            if (this.is_infinity()) return;
            this.y.norm();
            this.y.neg();
            this.y.norm();
            return;
        },
        /* convert this to affine, from (x,y,z) to (x,y) */
        affine: function() {
            if (this.is_infinity()) return;
            var one = new ctx.FP2(1);
            if (this.z.equals(one)) return;
            this.z.inverse();

            var z2 = new ctx.FP2(this.z); //z2.copy(this.z);
            z2.sqr();
            this.x.mul(z2);
            this.x.reduce();
            this.y.mul(z2);
            this.y.mul(this.z);
            this.y.reduce();
            this.z = one;
        },
        /* extract affine x as ctx.FP2 */
        getX: function() {
            this.affine();
            return this.x;
        },
        /* extract affine y as ctx.FP2 */
        getY: function() {
            this.affine();
            return this.y;
        },
        /* extract projective x */
        getx: function() {
            return this.x;
        },
        /* extract projective y */
        gety: function() {
            return this.y;
        },
        /* extract projective z */
        getz: function() {
            return this.z;
        },
        /* convert this to byte array */
        toBytes: function(b) {
            var i, t = [];
            this.affine();
            this.x.getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++)
                b[i] = t[i];
            this.x.getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++)
                b[i + ctx.BIG.MODBYTES] = t[i];

            this.y.getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++)
                b[i + 2 * ctx.BIG.MODBYTES] = t[i];
            this.y.getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++)
                b[i + 3 * ctx.BIG.MODBYTES] = t[i];
        },
        /* convert this to hex string */
        toString: function() {
            if (this.is_infinity()) return "infinity";
            this.affine();
            return "(" + this.x.toString() + "," + this.y.toString() + ")";
        },
        /* set this=(x,y) */
        setxy: function(ix, iy) {
            this.x.copy(ix);
            this.y.copy(iy);
            this.z.one();

            var rhs = ECP2.RHS(this.x);

            var y2 = new ctx.FP2(this.y); //y2.copy(this.y);
            y2.sqr();
            if (y2.equals(rhs)) this.INF = false;
            else this.inf();
        },

        /* set this=(x,.) */
        setx: function(ix) {
            this.x.copy(ix);
            this.z.one();

            var rhs = ECP2.RHS(this.x);

            if (rhs.sqrt()) {
                this.y.copy(rhs);
                this.INF = false;
            } else this.inf();
        },

        /* set this*=q, where q is Modulus, using Frobenius */
        frob: function(X) {
            if (this.INF) return;
            var X2 = new ctx.FP2(X); //X2.copy(X);
            X2.sqr();
            this.x.conj();
            this.y.conj();
            this.z.conj();
            this.z.reduce();
            this.x.mul(X2);
            this.y.mul(X2);
            this.y.mul(X);
        },
        /* this+=this */
        dbl: function() {
            if (this.INF) return -1;
            if (this.y.iszilch()) {
                this.inf();
                return -1;
            }

            var w1 = new ctx.FP2(this.x); //w1.copy(this.x);
            var w2 = new ctx.FP2(0);
            var w3 = new ctx.FP2(this.x); //w3.copy(this.x);
            var w8 = new ctx.FP2(this.x); //w8.copy(this.x);

            w1.sqr();
            w8.copy(w1);
            w8.imul(3);

            w2.copy(this.y);
            w2.sqr();
            w3.copy(this.x);
            w3.imul(4);
            w3.mul(w2);

            w1.copy(w3);
            w1.neg();


            this.x.copy(w8);
            this.x.sqr();
            this.x.add(w1);
            this.x.add(w1);
            this.x.norm();

            this.z.add(this.z);
            this.z.norm();
            this.z.mul(this.y);


            w2.add(w2);
            w2.norm();
            w2.sqr();
            w2.add(w2);
            w3.sub(this.x);
            w2.norm(); // ??
            w3.norm();
            this.y.copy(w8);
            this.y.mul(w3);
            this.y.sub(w2);
            this.y.norm();
            this.z.norm();

            return 1;
        },
        /* this+=Q - return 0 for add, 1 for double, -1 for O */
        /* this+=Q */
        add: function(Q) {
            if (this.INF) {
                this.copy(Q);
                return -1;
            }
            if (Q.INF) return -1;

            var aff = false;

            if (Q.z.isunity()) aff = true;

            var A, C;
            var B = new ctx.FP2(this.z);
            var D = new ctx.FP2(this.z);
            if (!aff) {
                A = new ctx.FP2(Q.z);
                C = new ctx.FP2(Q.z);

                A.sqr();
                B.sqr();
                C.mul(A);
                D.mul(B);

                A.mul(this.x);
                C.mul(this.y);
            } else {
                A = new ctx.FP2(this.x);
                C = new ctx.FP2(this.y);

                B.sqr();
                D.mul(B);
            }

            B.mul(Q.x);
            B.sub(A);
            D.mul(Q.y);
            D.sub(C);

            if (B.iszilch()) {
                if (D.iszilch()) {
                    this.dbl();
                    return 1;
                } else {
                    this.INF = true;
                    return -1;
                }
            }

            if (!aff) this.z.mul(Q.z);
            this.z.mul(B);

            var e = new ctx.FP2(B);
            e.sqr();
            B.mul(e);
            A.mul(e);

            e.copy(A);
            e.add(A);
            e.add(B);
            e.norm();
            D.norm();
            this.x.copy(D);
            this.x.sqr();
            this.x.sub(e);
            this.x.norm(); // ??

            A.sub(this.x);
            A.norm();
            this.y.copy(A);
            this.y.mul(D);
            C.mul(B);
            this.y.sub(C);

            //this.x.norm();
            this.y.norm();
            this.z.norm();
            return 0;
        },
        /* this-=Q */
        sub: function(Q) {
            Q.neg();
            var D = this.add(Q);
            Q.neg();
            return D;
        },

        /* P*=e */
        mul: function(e) {
            /* fixed size windows */
            var i, b, nb, m, s, ns;
            var mt = new ctx.BIG();
            var t = new ctx.BIG();
            var C = new ECP2();
            var P = new ECP2();
            var Q = new ECP2();
            var W = [];
            var w = [];

            if (this.is_infinity()) return new ECP2();

            this.affine();

            // precompute table 
            Q.copy(this);
            Q.dbl();
            W[0] = new ECP2();
            W[0].copy(this);

            for (i = 1; i < 8; i++) {
                W[i] = new ECP2();
                W[i].copy(W[i - 1]);
                W[i].add(Q);
            }

            // convert the table to affine 

            ECP2.multiaffine(8, W);

            // make exponent odd - add 2P if even, P if odd 
            t.copy(e);
            s = t.parity();
            t.inc(1);
            t.norm();
            ns = t.parity();
            mt.copy(t);
            mt.inc(1);
            mt.norm();
            t.cmove(mt, s);
            Q.cmove(this, ns);
            C.copy(Q);

            nb = 1 + Math.floor((t.nbits() + 3) / 4);

            // convert exponent to signed 4-bit window 
            for (i = 0; i < nb; i++) {
                w[i] = (t.lastbits(5) - 16);
                t.dec(w[i]);
                t.norm();
                t.fshr(4);
            }
            w[nb] = t.lastbits(5);

            P.copy(W[Math.floor((w[nb] - 1) / 2)]);
            for (i = nb - 1; i >= 0; i--) {
                Q.select(W, w[i]);
                P.dbl();
                P.dbl();
                P.dbl();
                P.dbl();
                P.add(Q);
            }
            P.sub(C);
            P.affine();
            return P;
        }
    };

    /* convert from byte array to point */
    ECP2.fromBytes = function(b) {
        var i, t = [];
        var ra, rb;

        for (i = 0; i < ctx.BIG.MODBYTES; i++) t[i] = b[i];
        ra = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) t[i] = b[i + ctx.BIG.MODBYTES];
        rb = ctx.BIG.fromBytes(t);

        var rx = new ctx.FP2(ra, rb); //rx.bset(ra,rb);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) t[i] = b[i + 2 * ctx.BIG.MODBYTES];
        ra = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) t[i] = b[i + 3 * ctx.BIG.MODBYTES];
        rb = ctx.BIG.fromBytes(t);

        var ry = new ctx.FP2(ra, rb); //ry.bset(ra,rb);

        var P = new ECP2();
        P.setxy(rx, ry);
        return P;
    };

    /* Calculate RHS of curve equation x^3+B */
    ECP2.RHS = function(x) {
        x.norm();
        var r = new ctx.FP2(x); //r.copy(x);
        r.sqr();

        var c = new ctx.BIG(0);
        c.rcopy(ctx.ROM_CURVE.CURVE_B);
        var b = new ctx.FP2(c); //b.bseta(c);
        b.div_ip();
        r.mul(x);
        r.add(b);

        r.reduce();
        return r;
    };

    /* normalises m-array of ECP2 points. Requires work vector of m FP2s */

    ECP2.multiaffine = function(m, P) {
        var i;
        var t1 = new ctx.FP2(0);
        var t2 = new ctx.FP2(0);
        var work = [];

        work[0] = new ctx.FP2(1);
        work[1] = new ctx.FP2(P[0].z);
        for (i = 2; i < m; i++) {
            work[i] = new ctx.FP2(work[i - 1]);
            work[i].mul(P[i - 1].z);
        }

        t1.copy(work[m - 1]);
        t1.mul(P[m - 1].z);

        t1.inverse();

        t2.copy(P[m - 1].z);
        work[m - 1].mul(t1);

        for (i = m - 2;; i--) {
            if (i == 0) {
                work[0].copy(t1);
                work[0].mul(t2);
                break;
            }
            work[i].mul(t2);
            work[i].mul(t1);
            t2.mul(P[i].z);
        }
        /* now work[] contains inverses of all Z coordinates */

        for (i = 0; i < m; i++) {
            P[i].z.one();
            t1.copy(work[i]);
            t1.sqr();
            P[i].x.mul(t1);
            t1.mul(work[i]);
            P[i].y.mul(t1);
        }
    };

    /* P=u0.Q0+u1*Q1+u2*Q2+u3*Q3 */
    ECP2.mul4 = function(Q, u) {
        var i, j, nb;
        var a = [];
        var T = new ECP2();
        var C = new ECP2();
        var P = new ECP2();
        var W = [];
        var mt = new ctx.BIG();
        var t = [];
        var w = [];

        for (i = 0; i < 4; i++) {
            t[i] = new ctx.BIG(u[i]);
            Q[i].affine();
        }

        /* precompute table */

        W[0] = new ECP2();
        W[0].copy(Q[0]);
        W[0].sub(Q[1]);
        W[1] = new ECP2();
        W[1].copy(W[0]);
        W[2] = new ECP2();
        W[2].copy(W[0]);
        W[3] = new ECP2();
        W[3].copy(W[0]);
        W[4] = new ECP2();
        W[4].copy(Q[0]);
        W[4].add(Q[1]);
        W[5] = new ECP2();
        W[5].copy(W[4]);
        W[6] = new ECP2();
        W[6].copy(W[4]);
        W[7] = new ECP2();
        W[7].copy(W[4]);
        T.copy(Q[2]);
        T.sub(Q[3]);
        W[1].sub(T);
        W[2].add(T);
        W[5].sub(T);
        W[6].add(T);
        T.copy(Q[2]);
        T.add(Q[3]);
        W[0].sub(T);
        W[3].add(T);
        W[4].sub(T);
        W[7].add(T);

        ECP2.multiaffine(8, W);

        /* if multiplier is even add 1 to multiplier, and add P to correction */
        mt.zero();
        C.inf();
        for (i = 0; i < 4; i++) {
            if (t[i].parity() == 0) {
                t[i].inc(1);
                t[i].norm();
                C.add(Q[i]);
            }
            mt.add(t[i]);
            mt.norm();
        }

        nb = 1 + mt.nbits();

        /* convert exponent to signed 1-bit window */
        for (j = 0; j < nb; j++) {
            for (i = 0; i < 4; i++) {
                a[i] = (t[i].lastbits(2) - 2);
                t[i].dec(a[i]);
                t[i].norm();
                t[i].fshr(1);
            }
            w[j] = (8 * a[0] + 4 * a[1] + 2 * a[2] + a[3]);
        }
        w[nb] = (8 * t[0].lastbits(2) + 4 * t[1].lastbits(2) + 2 * t[2].lastbits(2) + t[3].lastbits(2));

        P.copy(W[Math.floor((w[nb] - 1) / 2)]);

        for (i = nb - 1; i >= 0; i--) {
            T.select(W, w[i]);
            P.dbl();
            P.add(T);
        }
        P.sub(C); /* apply correction */

        P.affine();
        return P;
    };

    /* return 1 if b==c, no branching */
    ECP2.teq = function(b, c) {
        var x = b ^ c;
        x -= 1; // if x=0, x now -1
        return ((x >> 31) & 1);
    };

    ECP2.ctx = ctx;
    return ECP2;
};
},{}],8:[function(require,module,exports){
/*
	Licensed to the Apache Software Foundation (ASF) under one
	or more contributor license agreements.  See the NOTICE file
	distributed with this work for additional information
	regarding copyright ownership.  The ASF licenses this file
	to you under the Apache License, Version 2.0 (the
	"License"); you may not use this file except in compliance
	with the License.  You may obtain a copy of the License at
	
	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing,
	software distributed under the License is distributed on an
	"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
	KIND, either express or implied.  See the License for the
	specific language governing permissions and limitations
	under the License.
*/

/* AMCL FF number class */

module.exports.FF = function(ctx) {

    /* General purpose Constructor */
    var FF = function(n) {
        this.v = new Array(n);
        this.length = n;
        for (var i = 0; i < n; i++)
            this.v[i] = new ctx.BIG(0);
    };

    FF.FFLEN = ctx.config["@ML"];
    FF.P_MBITS = ctx.BIG.MODBYTES * 8;
    FF.P_OMASK = ((-1) << (FF.P_MBITS % ctx.BIG.BASEBITS));
    FF.P_FEXCESS = (1 << (ctx.BIG.BASEBITS * ctx.BIG.NLEN - FF.P_MBITS - 1));
    FF.P_TBITS = (FF.P_MBITS % ctx.BIG.BASEBITS);
    FF.FF_BITS = (ctx.BIG.BIGBITS * FF.FFLEN);
    FF.HFLEN = (FF.FFLEN / 2); /* Useful for half-size RSA private key operations */

    FF.prototype = {
        /* set to zero */

        P_EXCESS: function() {
            return ((this.v[this.length - 1].get(ctx.BIG.NLEN - 1) & FF.P_OMASK) >> (FF.P_TBITS)) + 1;
        },

        zero: function() {
            for (var i = 0; i < this.length; i++) this.v[i].zero();
            return this;
        },

        getlen: function() {
            return this.length;
        },

        /* set to integer */
        set: function(m) {
            this.zero();
            this.v[0].set(0, (m & ctx.BIG.BMASK));
            this.v[0].set(1, (m >> ctx.BIG.BASEBITS));
        },
        /* copy from FF b */
        copy: function(b) {
            for (var i = 0; i < this.length; i++) {
                this.v[i].copy(b.v[i]);
            }
        },
        /* copy from FF b */
        rcopy: function(b) {
            for (var i = 0; i < this.length; i++) {
                this.v[i].rcopy(b[i]);
            }
        },
        /* x=y<<n */
        dsucopy: function(b) {
            for (var i = 0; i < b.length; i++) {
                this.v[b.length + i].copy(b.v[i]);
                this.v[i].zero();
            }
        },
        /* x=y */
        dscopy: function(b) {
            for (var i = 0; i < b.length; i++) {
                this.v[i].copy(b.v[i]);
                this.v[b.length + i].zero();
            }
        },

        /* x=y>>n */
        sducopy: function(b) {
            for (var i = 0; i < this.length; i++) {
                this.v[i].copy(b.v[this.length + i]);
            }
        },
        one: function() {
            this.v[0].one();
            for (var i = 1; i < this.length; i++) {
                this.v[i].zero();
            }
        },
        /* test equals 0 */
        iszilch: function() {
            for (var i = 0; i < this.length; i++) {
                if (!this.v[i].iszilch()) return false;
            }
            return true;
        },
        /* shift right by BIGBITS-bit words */
        shrw: function(n) {
            for (var i = 0; i < n; i++) {
                this.v[i].copy(this.v[i + n]);
                this.v[i + n].zero();
            }
        },

        /* shift left by BIGBITS-bit words */
        shlw: function(n) {
            for (var i = 0; i < n; i++) {
                this.v[n + i].copy(this.v[i]);
                this.v[i].zero();
            }
        },
        /* extract last bit */
        parity: function() {
            return this.v[0].parity();
        },

        lastbits: function(m) {
            return this.v[0].lastbits(m);
        },


        /* recursive add */
        radd: function(vp, x, xp, y, yp, n) {
            for (var i = 0; i < n; i++) {
                this.v[vp + i].copy(x.v[xp + i]);
                this.v[vp + i].add(y.v[yp + i]);
            }
        },

        /* recursive inc */
        rinc: function(vp, y, yp, n) {
            for (var i = 0; i < n; i++) {
                this.v[vp + i].add(y.v[yp + i]);
            }
        },

        /* recursive sub */
        rsub: function(vp, x, xp, y, yp, n) {
            for (var i = 0; i < n; i++) {
                this.v[vp + i].copy(x.v[xp + i]);
                this.v[vp + i].sub(y.v[yp + i]);
            }
        },

        /* recursive dec */
        rdec: function(vp, y, yp, n) {
            for (var i = 0; i < n; i++) {
                this.v[vp + i].sub(y.v[yp + i]);
            }
        },

        /* simple add */
        add: function(b) {
            for (var i = 0; i < this.length; i++)
                this.v[i].add(b.v[i]);
        },

        /* simple sub */
        sub: function(b) {
            for (var i = 0; i < this.length; i++)
                this.v[i].sub(b.v[i]);
        },

        /* reverse sub */
        revsub: function(b) {
            for (var i = 0; i < this.length; i++)
                this.v[i].rsub(b.v[i]);
        },

        /* increment/decrement by a small integer */
        inc: function(m) {
            this.v[0].inc(m);
            this.norm();
        },

        dec: function(m) {
            this.v[0].dec(m);
            this.norm();
        },

        /* normalise - but hold any overflow in top part unless n<0 */
        rnorm: function(vp, n) {
            var trunc = false;
            var i, carry;
            if (n < 0) { /* -v n signals to do truncation */
                n = -n;
                trunc = true;
            }
            for (i = 0; i < n - 1; i++) {
                carry = this.v[vp + i].norm();
                this.v[vp + i].xortop(carry << FF.P_TBITS);
                this.v[vp + i + 1].inc(carry);
            }
            carry = this.v[vp + n - 1].norm();
            if (trunc)
                this.v[vp + n - 1].xortop(carry << FF.P_TBITS);
            return this;
        },
        norm: function() {
            this.rnorm(0, this.length);
        },

        /* shift left by one bit */
        shl: function() {
            var i, carry, delay_carry = 0;
            for (i = 0; i < this.length - 1; i++) {
                carry = this.v[i].fshl(1);
                this.v[i].inc(delay_carry);
                this.v[i].xortop(carry << FF.P_TBITS);
                delay_carry = carry;
            }
            this.v[this.length - 1].fshl(1);
            this.v[this.length - 1].inc(delay_carry);
        },

        /* shift right by one bit */
        shr: function() {
            var i, carry;
            for (i = this.length - 1; i > 0; i--) {
                carry = this.v[i].fshr(1);
                this.v[i - 1].ortop(carry << FF.P_TBITS);
            }
            this.v[0].fshr(1);
        },

        /* Convert to Hex String */
        toString: function() {
            this.norm();
            var s = "";

            for (var i = this.length - 1; i >= 0; i--) {
                s += this.v[i].toString();
            }
            return s;
        },
        /* Convert FFs to/from byte arrays */
        toBytes: function(b) {
            for (var i = 0; i < this.length; i++) {
                this.v[i].tobytearray(b, (this.length - i - 1) * ctx.BIG.MODBYTES);
            }
        },

        /* z=x*y, t is workspace */
        karmul: function(vp, x, xp, y, yp, t, tp, n) {
            var nd2;
            if (n == 1) {
                x.v[xp].norm();
                y.v[yp].norm();
                var d = ctx.BIG.mul(x.v[xp], y.v[yp]);
                this.v[vp + 1] = d.split(8 * ctx.BIG.MODBYTES);
                this.v[vp].copy(d);
                return;
            }
            nd2 = n / 2;
            this.radd(vp, x, xp, x, xp + nd2, nd2);
            this.rnorm(vp, nd2); /* Important - required for 32-bit build */
            this.radd(vp + nd2, y, yp, y, yp + nd2, nd2);
            this.rnorm(vp + nd2, nd2); /* Important - required for 32-bit build */
            t.karmul(tp, this, vp, this, vp + nd2, t, tp + n, nd2);
            this.karmul(vp, x, xp, y, yp, t, tp + n, nd2);
            this.karmul(vp + n, x, xp + nd2, y, yp + nd2, t, tp + n, nd2);
            t.rdec(tp, this, vp, n);
            t.rdec(tp, this, vp + n, n);
            this.rinc(vp + nd2, t, tp, n);
            this.rnorm(vp, 2 * n);
        },

        karsqr: function(vp, x, xp, t, tp, n) {
            var nd2;
            if (n == 1) {
                x.v[xp].norm();
                var d = ctx.BIG.sqr(x.v[xp]);
                this.v[vp + 1].copy(d.split(8 * ctx.BIG.MODBYTES));
                this.v[vp].copy(d);
                return;
            }

            nd2 = n / 2;
            this.karsqr(vp, x, xp, t, tp + n, nd2);
            this.karsqr(vp + n, x, xp + nd2, t, tp + n, nd2);
            t.karmul(tp, x, xp, x, xp + nd2, t, tp + n, nd2);
            this.rinc(vp + nd2, t, tp, n);
            this.rinc(vp + nd2, t, tp, n);
            this.rnorm(vp + nd2, n);
        },

        karmul_lower: function(vp, x, xp, y, yp, t, tp, n) { /* Calculates Least Significant bottom half of x*y */
            var nd2;
            if (n == 1) { /* only calculate bottom half of product */
                this.v[vp].copy(ctx.BIG.smul(x.v[xp], y.v[yp]));
                return;
            }
            nd2 = n / 2;

            this.karmul(vp, x, xp, y, yp, t, tp + n, nd2);
            t.karmul_lower(tp, x, xp + nd2, y, yp, t, tp + n, nd2);
            this.rinc(vp + nd2, t, tp, nd2);
            t.karmul_lower(tp, x, xp, y, yp + nd2, t, tp + n, nd2);

            this.rinc(vp + nd2, t, tp, nd2);
            this.rnorm(vp + nd2, -nd2); /* truncate it */
        },

        karmul_upper: function(x, y, t, n) { /* Calculates Most Significant upper half of x*y, given lower part */
            var nd2;

            nd2 = n / 2;
            this.radd(n, x, 0, x, nd2, nd2);
            this.radd(n + nd2, y, 0, y, nd2, nd2);
            this.rnorm(n, nd2);
            this.rnorm(n + nd2, nd2);

            t.karmul(0, this, n + nd2, this, n, t, n, nd2); /* t = (a0+a1)(b0+b1) */
            this.karmul(n, x, nd2, y, nd2, t, n, nd2); /* z[n]= a1*b1 */
            /* z[0-nd2]=l(a0b0) z[nd2-n]= h(a0b0)+l(t)-l(a0b0)-l(a1b1) */
            t.rdec(0, this, n, n); /* t=t-a1b1  */
            this.rinc(nd2, this, 0, nd2); /* z[nd2-n]+=l(a0b0) = h(a0b0)+l(t)-l(a1b1)  */
            this.rdec(nd2, t, 0, nd2); /* z[nd2-n]=h(a0b0)+l(t)-l(a1b1)-l(t-a1b1)=h(a0b0) */
            this.rnorm(0, -n); /* a0b0 now in z - truncate it */
            t.rdec(0, this, 0, n); /* (a0+a1)(b0+b1) - a0b0 */
            this.rinc(nd2, t, 0, n);

            this.rnorm(nd2, n);
        },

        /* return low part of product this*y */
        lmul: function(y) {
            var n = this.length;
            var t = new FF(2 * n);
            var x = new FF(n);
            x.copy(this);
            this.karmul_lower(0, x, 0, y, 0, t, 0, n);
        },

        /* Set b=b mod c */
        mod: function(c) {
            var k = 0;

            this.norm();
            if (FF.comp(this, c) < 0)
                return;
            do {
                c.shl();
                k++;
            } while (FF.comp(this, c) >= 0);

            while (k > 0) {
                c.shr();
                if (FF.comp(this, c) >= 0) {
                    this.sub(c);
                    this.norm();
                }
                k--;
            }
        },

        /* return This mod modulus, N is modulus, ND is Montgomery Constant */
        reduce: function(N, ND) { /* fast karatsuba Montgomery reduction */
            var n = N.length;
            var t = new FF(2 * n);
            var r = new FF(n);
            var m = new FF(n);

            r.sducopy(this);
            m.karmul_lower(0, this, 0, ND, 0, t, 0, n);
            this.karmul_upper(N, m, t, n);
            m.sducopy(this);

            r.add(N);
            r.sub(m);
            r.norm();

            return r;

        },

        /* Set r=this mod b */
        /* this is of length - 2*n */
        /* r,b is of length - n */
        dmod: function(b) {
            var k, n = b.length;
            var m = new FF(2 * n);
            var x = new FF(2 * n);
            var r = new FF(n);

            x.copy(this);
            x.norm();
            m.dsucopy(b);
            k = ctx.BIG.BIGBITS * n;

            while (FF.comp(x, m) >= 0) {
                x.sub(m);
                x.norm();
            }

            while (k > 0) {
                m.shr();

                if (FF.comp(x, m) >= 0) {
                    x.sub(m);
                    x.norm();
                }
                k--;
            }

            r.copy(x);
            r.mod(b);
            return r;
        },

        /* Set return=1/this mod p. Binary method - a<p on entry */
        invmodp: function(p) {
            var n = p.length;

            var u = new FF(n);
            var v = new FF(n);
            var x1 = new FF(n);
            var x2 = new FF(n);
            var t = new FF(n);
            var one = new FF(n);

            one.one();
            u.copy(this);
            v.copy(p);
            x1.copy(one);
            x2.zero();

            // reduce n in here as well! 
            while (FF.comp(u, one) !== 0 && FF.comp(v, one) !== 0) {
                while (u.parity() === 0) {
                    u.shr();
                    if (x1.parity() !== 0) {
                        x1.add(p);
                        x1.norm();
                    }
                    x1.shr();
                }
                while (v.parity() === 0) {
                    v.shr();
                    if (x2.parity() !== 0) {
                        x2.add(p);
                        x2.norm();
                    }
                    x2.shr();
                }
                if (FF.comp(u, v) >= 0) {

                    u.sub(v);
                    u.norm();
                    if (FF.comp(x1, x2) >= 0) x1.sub(x2);
                    else {
                        t.copy(p);
                        t.sub(x2);
                        x1.add(t);
                    }
                    x1.norm();
                } else {
                    v.sub(u);
                    v.norm();
                    if (FF.comp(x2, x1) >= 0) x2.sub(x1);
                    else {
                        t.copy(p);
                        t.sub(x1);
                        x2.add(t);
                    }
                    x2.norm();
                }
            }
            if (FF.comp(u, one) === 0)
                this.copy(x1);
            else
                this.copy(x2);
        },

        /* nresidue mod m */
        nres: function(m) {
            var n = m.length;
            if (n == 1) {
                var d = new ctx.DBIG(0);
                d.hcopy(this.v[0]);
                d.shl(ctx.BIG.NLEN * ctx.BIG.BASEBITS);
                this.v[0].copy(d.mod(m.v[0]));
            } else {
                var d = new FF(2 * n);
                d.dsucopy(this);
                this.copy(d.dmod(m));
            }
        },

        redc: function(m, ND) {
            var n = m.length;
            if (n == 1) {
                var d = new ctx.DBIG(0);
                d.hcopy(this.v[0]);
                this.v[0].copy(ctx.BIG.monty(m.v[0], (1 << ctx.BIG.BASEBITS) - ND.v[0].w[0], d));
            } else {
                var d = new FF(2 * n);
                this.mod(m);
                d.dscopy(this);
                this.copy(d.reduce(m, ND));
                this.mod(m);
            }
        },

        mod2m: function(m) {
            for (var i = m; i < this.length; i++)
                this.v[i].zero();
        },

        /* U=1/a mod 2^m - Arazi & Qi */
        invmod2m: function() {
            var i, n = this.length;

            var b = new FF(n);
            var c = new FF(n);
            var U = new FF(n);

            var t;

            U.zero();
            U.v[0].copy(this.v[0]);
            U.v[0].invmod2m();

            for (i = 1; i < n; i <<= 1) {
                b.copy(this);
                b.mod2m(i);
                t = FF.mul(U, b);
                t.shrw(i);
                b.copy(t);
                c.copy(this);
                c.shrw(i);
                c.mod2m(i);
                c.lmul(U);
                c.mod2m(i);

                b.add(c);
                b.norm();
                b.lmul(U);
                b.mod2m(i);

                c.one();
                c.shlw(i);
                b.revsub(c);
                b.norm();
                b.shlw(i);
                U.add(b);
            }
            U.norm();
            return U;
        },

        random: function(rng) {
            var n = this.length;
            for (var i = 0; i < n; i++) {
                this.v[i].copy(ctx.BIG.random(rng));
            }
            /* make sure top bit is 1 */
            while (this.v[n - 1].nbits() < ctx.BIG.MODBYTES * 8) this.v[n - 1].copy(ctx.BIG.random(rng));

        },

        /* generate random x */
        randomnum: function(p, rng) {
            var n = this.length;
            var d = new FF(2 * n);

            for (var i = 0; i < 2 * n; i++) {
                d.v[i].copy(ctx.BIG.random(rng));
            }
            this.copy(d.dmod(p));
        },

        /* this*=y mod p */
        modmul: function(y, p, nd) {
            var ex = this.P_EXCESS();
            var ey = y.P_EXCESS();
            if ((ex + 1) >= Math.floor((FF.P_FEXCESS - 1) / (ey + 1))) this.mod(p);
            var n = p.length;
            if (n == 1) {
                var d = ctx.BIG.mul(this.v[0], y.v[0]);
                this.v[0].copy(ctx.BIG.monty(p.v[0], (1 << ctx.BIG.BASEBITS) - nd.v[0].w[0], d));
            } else {
                var d = FF.mul(this, y);
                this.copy(d.reduce(p, nd));
            }
        },

        /* this*=y mod p */
        modsqr: function(p, nd) {
            var ex = this.P_EXCESS();
            if ((ex + 1) >= Math.floor((FF.P_FEXCESS - 1) / (ex + 1))) this.mod(p);
            var n = p.length
            if (n == 1) {
                var d = ctx.BIG.sqr(this.v[0]);
                this.v[0].copy(ctx.BIG.monty(p.v[0], (1 << ctx.BIG.BASEBITS) - nd.v[0].w[0], d));
            } else {
                var d = FF.sqr(this);
                this.copy(d.reduce(p, nd));
            }
        },

        /* this=this^e mod p using side-channel resistant Montgomery Ladder, for large e */
        skpow: function(e, p) {
            var i, b, n = p.length;
            var R0 = new FF(n);
            var R1 = new FF(n);
            var ND = p.invmod2m();

            this.mod(p);
            R0.one();
            R1.copy(this);
            R0.nres(p);
            R1.nres(p);

            for (i = 8 * ctx.BIG.MODBYTES * n - 1; i >= 0; i--) {

                b = e.v[Math.floor(i / ctx.BIG.BIGBITS)].bit(i % ctx.BIG.BIGBITS);

                this.copy(R0);
                this.modmul(R1, p, ND);

                FF.cswap(R0, R1, b);
                R0.modsqr(p, ND);

                R1.copy(this);
                FF.cswap(R0, R1, b);

            }

            this.copy(R0);
            this.redc(p, ND);
        },

        /* this =this^e mod p using side-channel resistant Montgomery Ladder, for short e */
        skspow: function(e, p) {
            var i, b, n = p.length;
            var R0 = new FF(n);
            var R1 = new FF(n);
            var ND = p.invmod2m();

            this.mod(p);
            R0.one();
            R1.copy(this);
            R0.nres(p);
            R1.nres(p);

            for (i = 8 * ctx.BIG.MODBYTES - 1; i >= 0; i--) {
                b = e.bit(i);
                this.copy(R0);
                this.modmul(R1, p, ND);

                FF.cswap(R0, R1, b);
                R0.modsqr(p, ND);

                R1.copy(this);
                FF.cswap(R0, R1, b);
            }
            this.copy(R0);
            this.redc(p, ND);
        },

        /* raise to an integer power - right-to-left method */
        power: function(e, p) {
            var n = p.length;
            var f = true;
            var w = new FF(n);
            var ND = p.invmod2m();

            w.copy(this);
            w.nres(p);

            if (e == 2) {
                this.copy(w);
                this.modsqr(p, ND);
            } else
                for (;;) {
                    if (e % 2 == 1) {
                        if (f) this.copy(w);
                        else {
                            this.modmul(w, p, ND);
                        }
                        f = false;

                    }
                    e >>= 1;
                    if (e === 0) break;
                    w.modsqr(p, ND);
                }

            this.redc(p, ND);
        },

        /* this=this^e mod p, faster but not side channel resistant */
        pow: function(e, p) {
            var i, b, n = p.length;
            var w = new FF(n);
            var ND = p.invmod2m();

            w.copy(this);
            this.one();
            this.nres(p);
            w.nres(p);
            for (i = 8 * ctx.BIG.MODBYTES * n - 1; i >= 0; i--) {
                this.modsqr(p, ND);
                b = e.v[Math.floor(i / ctx.BIG.BIGBITS)].bit(i % ctx.BIG.BIGBITS);
                if (b == 1) this.modmul(w, p, ND);
            }
            this.redc(p, ND);
        },

        /* double exponentiation r=x^e.y^f mod p */
        pow2: function(e, y, f, p) {
            var i, eb, fb, n = p.length;
            var xn = new FF(n);
            var yn = new FF(n);
            var xy = new FF(n);
            var ND = p.invmod2m();

            xn.copy(this);
            yn.copy(y);
            xn.nres(p);
            yn.nres(p);
            xy.copy(xn);
            xy.modmul(yn, p, ND);
            this.one();
            this.nres(p);

            for (i = 8 * ctx.BIG.MODBYTES - 1; i >= 0; i--) {
                eb = e.bit(i);
                fb = f.bit(i);
                this.modsqr(p, ND);
                if (eb == 1) {
                    if (fb == 1) this.modmul(xy, p, ND);
                    else this.modmul(xn, p, ND);
                } else {
                    if (fb == 1) this.modmul(yn, p, ND);
                }
            }
            this.redc(p, ND);
        },

        /* quick and dirty check for common factor with n */
        cfactor: function(s) {
            var r, n = this.length;
            var g;

            var x = new FF(n);
            var y = new FF(n);
            y.set(s);

            x.copy(this);
            x.norm();

            do {
                x.sub(y);
                x.norm();
                while (!x.iszilch() && x.parity() === 0) x.shr();
            }
            while (FF.comp(x, y) > 0);

            g = x.v[0].get(0);
            r = FF.igcd(s, g);
            if (r > 1) return true;
            return false;
        }


    };

    /* compare x and y - must be normalised, and of same length */
    FF.comp = function(a, b) {
        var i, j;
        for (i = a.length - 1; i >= 0; i--) {
            j = ctx.BIG.comp(a.v[i], b.v[i]);
            if (j !== 0) return j;
        }
        return 0;
    };

    FF.fromBytes = function(x, b) {
        for (var i = 0; i < x.length; i++) {
            x.v[i] = ctx.BIG.frombytearray(b, (x.length - i - 1) * ctx.BIG.MODBYTES);
        }
    };

    /* in-place swapping using xor - side channel resistant - lengths must be the same */
    FF.cswap = function(a, b, d) {
        for (var i = 0; i < a.length; i++) {
            //	ctx.BIG.cswap(a.v[i],b.v[i],d);
            a.v[i].cswap(b.v[i], d);
        }
    };

    /* z=x*y. Assumes x and y are of same length. */
    FF.mul = function(x, y) {
        var n = x.length;
        var z = new FF(2 * n);
        var t = new FF(2 * n);
        z.karmul(0, x, 0, y, 0, t, 0, n);
        return z;
    };

    /* z=x^2 */
    FF.sqr = function(x) {
        var n = x.length;
        var z = new FF(2 * n);
        var t = new FF(2 * n);
        z.karsqr(0, x, 0, t, 0, n);
        return z;
    };

    FF.igcd = function(x, y) { /* integer GCD, returns GCD of x and y */
        var r;
        if (y === 0) return x;
        while ((r = x % y) !== 0) {
            x = y;
            y = r;
        }
        return y;
    };

    /* Miller-Rabin test for primality. Slow. */
    FF.prime = function(p, rng) {
        var i, j, s = 0,
            n = p.length;
        var loop;
        var d = new FF(n);
        var x = new FF(n);
        var unity = new FF(n);
        var nm1 = new FF(n);

        var sf = 4849845; /* 3*5*.. *19 */
        p.norm();

        if (p.cfactor(sf)) return false;
        unity.one();
        nm1.copy(p);
        nm1.sub(unity);
        nm1.norm();
        d.copy(nm1);

        while (d.parity() === 0) {
            d.shr();
            s++;
        }
        if (s === 0) return false;

        for (i = 0; i < 10; i++) {
            x.randomnum(p, rng);
            x.pow(d, p);
            if (FF.comp(x, unity) === 0 || FF.comp(x, nm1) === 0) continue;
            loop = false;
            for (j = 1; j < s; j++) {
                x.power(2, p);
                if (FF.comp(x, unity) === 0) return false;
                if (FF.comp(x, nm1) === 0) {
                    loop = true;
                    break;
                }
            }
            if (loop) continue;
            return false;
        }
        return true;
    };
    FF.ctx = ctx;
    return FF;
};
},{}],9:[function(require,module,exports){
/*
	Licensed to the Apache Software Foundation (ASF) under one
	or more contributor license agreements.  See the NOTICE file
	distributed with this work for additional information
	regarding copyright ownership.  The ASF licenses this file
	to you under the Apache License, Version 2.0 (the
	"License"); you may not use this file except in compliance
	with the License.  You may obtain a copy of the License at
	
	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing,
	software distributed under the License is distributed on an
	"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
	KIND, either express or implied.  See the License for the
	specific language governing permissions and limitations
	under the License.
*/

/* Finite Field arithmetic */
/* AMCL mod p functions */

module.exports.FP = function(ctx) {

    /* General purpose Constructor */
    var FP = function(x) {
        if (x instanceof FP) {
            this.f = new ctx.BIG(x.f);
        } else {
            this.f = new ctx.BIG(x);
            this.nres();
        }
    };

    FP.NOT_SPECIAL = 0;
    FP.PSEUDO_MERSENNE = 1;
    FP.GENERALISED_MERSENNE = 2;
    FP.MONTGOMERY_FRIENDLY = 3;

    FP.MODBITS = ctx.config["@NBT"];
    FP.MOD8 = ctx.config["@M8"];
    FP.MODTYPE = ctx.config["@MT"];

    FP.FEXCESS = (1 << (ctx.BIG.BASEBITS * ctx.BIG.NLEN - FP.MODBITS - 1)); // 2^(BASEBITS*NLEN-MODBITS)
    FP.OMASK = (-1) << FP.TBITS;
    FP.TBITS = FP.MODBITS % ctx.BIG.BASEBITS;
    FP.TMASK = (1 << FP.TBITS) - 1;

    FP.prototype = {
        /* set this=0 */
        zero: function() {
            return this.f.zero();
        },

        /* copy from a ctx.BIG in ROM */
        rcopy: function(y) {
            this.f.rcopy(y);
            this.nres();
        },

        /* copy from another ctx.BIG */
        bcopy: function(y) {
            this.f.copy(y);
            this.nres();
            //alert("4. f= "+this.f.toString());
        },

        /* copy from another FP */
        copy: function(y) {
            return this.f.copy(y.f);
        },

        /* conditional swap of a and b depending on d */
        cswap: function(b, d) {
            this.f.cswap(b.f, d);
        },

        /* conditional copy of b to a depending on d */
        cmove: function(b, d) {
            this.f.cmove(b.f, d);
        },

        /* convert to Montgomery n-residue form */
        nres: function() {
            if (FP.MODTYPE != FP.PSEUDO_MERSENNE && FP.MODTYPE != FP.GENERALISED_MERSENNE) {
                var p = new ctx.BIG();
                p.rcopy(ctx.ROM_FIELD.Modulus);
                var d = new ctx.DBIG(0);

                d.hcopy(this.f);
                d.norm();
                d.shl(ctx.BIG.NLEN * ctx.BIG.BASEBITS);
                this.f.copy(d.mod(p));
            }
            return this;
        },

        /* convert back to regular form */
        redc: function() {
            var r = new ctx.BIG(0);
            r.copy(this.f);
            if (FP.MODTYPE != FP.PSEUDO_MERSENNE && FP.MODTYPE != FP.GENERALISED_MERSENNE) {
                var d = new ctx.DBIG(0);
                d.hcopy(this.f);
                var w = FP.mod(d);
                r.copy(w);
            }

            return r;
        },

        /* convert this to string */
        toString: function() {
            var s = this.redc().toString();
            return s;
        },

        /* test this=0 */
        iszilch: function() {
            this.reduce();
            return this.f.iszilch();
        },

        /* reduce this mod Modulus */
        reduce: function() {
            var p = new ctx.BIG(0);
            p.rcopy(ctx.ROM_FIELD.Modulus);
            return this.f.mod(p);
        },

        /* set this=1 */
        one: function() {
            this.f.one();
            return this.nres();
        },

        /* normalise this */
        norm: function() {
            return this.f.norm();
        },

        /* this*=b mod Modulus */
        mul: function(b) {
            var ea = FP.EXCESS(this.f);
            var eb = FP.EXCESS(b.f);

            if ((ea + 1) * (eb + 1) > FP.FEXCESS) this.reduce();

            var d = ctx.BIG.mul(this.f, b.f);
            this.f.copy(FP.mod(d));
            return this;
        },

        /* this*=c mod Modulus where c is an int */
        imul: function(c) {
            var s = false;
            this.norm();
            if (c < 0) {
                c = -c;
                s = true;
            }

            var afx = (FP.EXCESS(this.f) + 1) * (c + 1) + 1;
            if (c <= ctx.BIG.NEXCESS && afx < FP.FEXCESS) {
                this.f.imul(c);
                this.norm();
            } else {
                if (afx < FP.FEXCESS) this.f.pmul(c);
                else {
                    var p = new ctx.BIG(0);
                    p.rcopy(ctx.ROM_FIELD.Modulus);
                    var d = this.f.pxmul(c);
                    this.f.copy(d.mod(p));
                }
            }
            if (s) {
                this.neg();
                this.norm();
            }
            return this;
        },

        /* this*=this mod Modulus */
        sqr: function() {
            var d;
            //		this.norm();
            var ea = FP.EXCESS(this.f);

            if ((ea + 1) * (ea + 1) > FP.FEXCESS) this.reduce();
            //if ((ea+1)>= Math.floor((FP.FEXCESS-1)/(ea+1))) this.reduce();

            d = ctx.BIG.sqr(this.f);
            var t = FP.mod(d);
            this.f.copy(t);
            return this;
        },

        /* this+=b */
        add: function(b) {
            this.f.add(b.f);
            if (FP.EXCESS(this.f) + 2 >= FP.FEXCESS) this.reduce();
            return this;
        },
        /* this=-this mod Modulus */
        neg: function() {
            var sb, ov;
            var m = new ctx.BIG(0);
            m.rcopy(ctx.ROM_FIELD.Modulus);

            //		this.norm();
            sb = FP.logb2(FP.EXCESS(this.f) + 1);

            //		ov=FP.EXCESS(this.f); 
            //		sb=1; while(ov!==0) {sb++;ov>>=1;} 

            m.fshl(sb);
            this.f.rsub(m);
            if (FP.EXCESS(this.f) >= FP.FEXCESS) this.reduce();
            return this;
        },

        /* this-=b */
        sub: function(b) {
            var n = new FP(0);
            n.copy(b);
            n.neg();
            this.add(n);
            return this;
        },

        /* this/=2 mod Modulus */
        div2: function() {
            //		this.norm();
            if (this.f.parity() === 0)
                this.f.fshr(1);
            else {
                var p = new ctx.BIG(0);
                p.rcopy(ctx.ROM_FIELD.Modulus);

                this.f.add(p);
                this.f.norm();
                this.f.fshr(1);
            }
            return this;
        },

        /* this=1/this mod Modulus */
        inverse: function() {
            var p = new ctx.BIG(0);
            p.rcopy(ctx.ROM_FIELD.Modulus);
            var r = this.redc();
            r.invmodp(p);
            this.f.copy(r);
            return this.nres();
        },

        /* return TRUE if this==a */
        equals: function(a) {
            a.reduce();
            this.reduce();
            if (ctx.BIG.comp(a.f, this.f) === 0) return true;
            return false;
        },

        /* return this^e mod Modulus */
        pow: function(e) {
            var bt;
            var r = new FP(1);
            e.norm();
            this.norm();
            var m = new FP(0);
            m.copy(this);
            while (true) {
                bt = e.parity();
                e.fshr(1);
                if (bt == 1) r.mul(m);
                if (e.iszilch()) break;
                m.sqr();
            }

            r.reduce();
            return r;
        },

        /* return jacobi symbol (this/Modulus) */
        jacobi: function() {
            var p = new ctx.BIG(0);
            p.rcopy(ctx.ROM_FIELD.Modulus);
            var w = this.redc();
            return w.jacobi(p);
        },

        /* return sqrt(this) mod Modulus */
        sqrt: function() {
            this.reduce();
            var b = new ctx.BIG(0);
            b.rcopy(ctx.ROM_FIELD.Modulus);
            if (FP.MOD8 == 5) {
                b.dec(5);
                b.norm();
                b.shr(3);
                var i = new FP(0);
                i.copy(this);
                i.f.shl(1);
                var v = i.pow(b);
                i.mul(v);
                i.mul(v);
                i.f.dec(1);
                var r = new FP(0);
                r.copy(this);
                r.mul(v);
                r.mul(i);
                r.reduce();
                return r;
            } else {
                b.inc(1);
                b.norm();
                b.shr(2);
                return this.pow(b);
            }
        }

    };

    FP.logb2 = function(v) {
        v |= v >>> 1;
        v |= v >>> 2;
        v |= v >>> 4;
        v |= v >>> 8;
        v |= v >>> 16;

        v = v - ((v >>> 1) & 0x55555555);
        v = (v & 0x33333333) + ((v >>> 2) & 0x33333333);
        var r = ((v + (v >>> 4) & 0xF0F0F0F) * 0x1010101) >>> 24;
        return r + 1;
    };

    /* calculate Field Excess */
    FP.EXCESS = function(a) {
        return ((a.w[ctx.BIG.NLEN - 1] & FP.OMASK) >> (FP.MODBITS % ctx.BIG.BASEBITS)) + 1;
    };


    /* reduce a ctx.DBIG to a ctx.BIG using a "special" modulus */
    FP.mod = function(d) {
        var i, j, b = new ctx.BIG(0);
        if (FP.MODTYPE == FP.PSEUDO_MERSENNE) {
            var v, tw;
            var t = d.split(FP.MODBITS);
            b.hcopy(d);

            if (ctx.ROM_FIELD.MConst != 1)
                v = t.pmul(ctx.ROM_FIELD.MConst);
            else v = 0;

            t.add(b);
            t.norm();

            tw = t.w[ctx.BIG.NLEN - 1];
            t.w[ctx.BIG.NLEN - 1] &= FP.TMASK;
            t.inc(ctx.ROM_FIELD.MConst * ((tw >> FP.TBITS) + (v << (ctx.BIG.BASEBITS - FP.TBITS))));
            //		b.add(t);
            t.norm();
            return t;
        }

        if (FP.MODTYPE == FP.MONTGOMERY_FRIENDLY) {
            for (i = 0; i < ctx.BIG.NLEN; i++)
                d.w[ctx.BIG.NLEN + i] += d.muladd(d.w[i], ctx.ROM_FIELD.MConst - 1, d.w[i], ctx.BIG.NLEN + i - 1);
            for (i = 0; i < ctx.BIG.NLEN; i++)
                b.w[i] = d.w[ctx.BIG.NLEN + i];
        }

        if (FP.MODTYPE == FP.GENERALISED_MERSENNE) { // GoldiLocks Only
            var t = d.split(FP.MODBITS);
            b.hcopy(d);
            b.add(t);
            var dd = new ctx.DBIG(0);
            dd.hcopy(t);
            dd.shl(FP.MODBITS / 2);

            var tt = dd.split(FP.MODBITS);
            var lo = new ctx.BIG();
            lo.hcopy(dd);

            b.add(tt);
            b.add(lo);
            //b.norm();
            tt.shl(FP.MODBITS / 2);
            b.add(tt);

            var carry = b.w[ctx.BIG.NLEN - 1] >> FP.TBITS;
            b.w[ctx.BIG.NLEN - 1] &= FP.TMASK;
            b.w[0] += carry;

            b.w[Math.floor(224 / ctx.BIG.BASEBITS)] += carry << (224 % ctx.BIG.BASEBITS);
        }

        if (FP.MODTYPE == FP.NOT_SPECIAL) {

            var m = new ctx.BIG(0);
            m.rcopy(ctx.ROM_FIELD.Modulus);

            b.copy(ctx.BIG.monty(m, ctx.ROM_FIELD.MConst, d));

        }
        b.norm();
        return b;
    };
    FP.ctx = ctx;
    return FP;
};
},{}],10:[function(require,module,exports){
/*
	Licensed to the Apache Software Foundation (ASF) under one
	or more contributor license agreements.  See the NOTICE file
	distributed with this work for additional information
	regarding copyright ownership.  The ASF licenses this file
	to you under the Apache License, Version 2.0 (the
	"License"); you may not use this file except in compliance
	with the License.  You may obtain a copy of the License at
	
	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing,
	software distributed under the License is distributed on an
	"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
	KIND, either express or implied.  See the License for the
	specific language governing permissions and limitations
	under the License.
*/

/* AMCL Fp^12 functions */

/* FP12 elements are of the form a+i.b+i^2.c */

module.exports.FP12 = function(ctx) {

    /* general purpose constructor */
    var FP12 = function(d, e, f) {
        if (d instanceof FP12) {
            this.a = new ctx.FP4(d.a);
            this.b = new ctx.FP4(d.b);
            this.c = new ctx.FP4(d.c);
        } else {
            this.a = new ctx.FP4(d);
            this.b = new ctx.FP4(e);
            this.c = new ctx.FP4(f);
        }
    };

    FP12.prototype = {
        /* reduce all components of this mod Modulus */
        reduce: function() {
            this.a.reduce();
            this.b.reduce();
            this.c.reduce();
        },
        /* normalize all components of this mod Modulus */
        norm: function() {
            this.a.norm();
            this.b.norm();
            this.c.norm();
        },
        /* test x==0 ? */
        iszilch: function() {
            this.reduce();
            return (this.a.iszilch() && this.b.iszilch() && this.c.iszilch());
        },
        /* test x==1 ? */
        isunity: function() {
            var one = new ctx.FP4(1);
            return (this.a.equals(one) && this.b.iszilch() && this.b.iszilch());
        },
        /* extract a from this */
        geta: function() {
            return this.a;
        },
        /* extract b */
        getb: function() {
            return this.b;
        },
        /* extract c */
        getc: function() {
            return this.c;
        },
        /* return 1 if x==y, else 0 */
        equals: function(x) {
            return (this.a.equals(x.a) && this.b.equals(x.b) && this.c.equals(x.c));
        },
        /* copy this=x */
        copy: function(x) {
            this.a.copy(x.a);
            this.b.copy(x.b);
            this.c.copy(x.c);
        },
        /* set this=1 */
        one: function() {
            this.a.one();
            this.b.zero();
            this.c.zero();
        },
        /* this=conj(this) */
        conj: function() {
            this.a.conj();
            this.b.nconj();
            this.c.conj();
        },

        /* set this from 3 FP4s */
        set: function(d, e, f) {
            this.a.copy(d);
            this.b.copy(e);
            this.c.copy(f);
        },
        /* set this from one ctx.FP4 */
        seta: function(d) {
            this.a.copy(d);
            this.b.zero();
            this.c.zero();
        },

        /* Granger-Scott Unitary Squaring */
        usqr: function() {
            var A = new ctx.FP4(this.a); //A.copy(this.a);
            var B = new ctx.FP4(this.c); //B.copy(this.c);
            var C = new ctx.FP4(this.b); //C.copy(this.b);
            var D = new ctx.FP4(0);

            this.a.sqr();
            D.copy(this.a);
            D.add(this.a);
            this.a.add(D);

            A.nconj();

            A.add(A);
            this.a.add(A);
            B.sqr();
            B.times_i();

            D.copy(B);
            D.add(B);
            B.add(D);

            C.sqr();
            D.copy(C);
            D.add(C);
            C.add(D);

            this.b.conj();
            this.b.add(this.b);
            this.c.nconj();

            this.c.add(this.c);
            this.b.add(B);
            this.c.add(C);
            this.reduce();
        },

        /* Chung-Hasan SQR2 method from http://cacr.uwaterloo.ca/techreports/2006/cacr2006-24.pdf */
        sqr: function() {
            var A = new ctx.FP4(this.a); //A.copy(this.a);
            var B = new ctx.FP4(this.b); //B.copy(this.b);
            var C = new ctx.FP4(this.c); //C.copy(this.c);
            var D = new ctx.FP4(this.a); //D.copy(this.a);

            A.sqr();
            B.mul(this.c);
            B.add(B); //B.norm();
            C.sqr();
            D.mul(this.b);
            D.add(D);

            this.c.add(this.a);
            this.c.add(this.b);
            this.c.norm();
            this.c.sqr();

            this.a.copy(A);

            A.add(B);
            A.add(C);
            A.add(D);
            A.neg();
            B.times_i();
            C.times_i();

            this.a.add(B);
            this.b.copy(C);
            this.b.add(D);
            this.c.add(A);

            this.norm();
        },

        /* FP12 full multiplication this=this*y */
        mul: function(y) {
            var z0 = new ctx.FP4(this.a); //z0.copy(this.a);
            var z1 = new ctx.FP4(0);
            var z2 = new ctx.FP4(this.b); //z2.copy(this.b);
            var z3 = new ctx.FP4(0);
            var t0 = new ctx.FP4(this.a); //t0.copy(this.a);
            var t1 = new ctx.FP4(y.a); //t1.copy(y.a);

            z0.mul(y.a);
            z2.mul(y.b);

            t0.add(this.b);
            t1.add(y.b);

            t0.norm();
            t1.norm();

            z1.copy(t0);
            z1.mul(t1);
            t0.copy(this.b);
            t0.add(this.c);

            t1.copy(y.b);
            t1.add(y.c);

            t0.norm();
            t1.norm();
            z3.copy(t0);
            z3.mul(t1);

            t0.copy(z0);
            t0.neg();
            t1.copy(z2);
            t1.neg();

            z1.add(t0);
            this.b.copy(z1);
            this.b.add(t1);

            z3.add(t1);
            z2.add(t0);

            t0.copy(this.a);
            t0.add(this.c);
            t1.copy(y.a);
            t1.add(y.c);

            t0.norm();
            t1.norm();

            t0.mul(t1);
            z2.add(t0);

            t0.copy(this.c);
            t0.mul(y.c);
            t1.copy(t0);
            t1.neg();

            this.c.copy(z2);
            this.c.add(t1);
            z3.add(t1);
            t0.times_i();
            this.b.add(t0);
            // z3.norm();
            z3.times_i();
            this.a.copy(z0);
            this.a.add(z3);

            this.norm();
        },

        /* Special case this*=y that arises from special form of ATE pairing line function */
        smul: function(y) {
            var z0 = new ctx.FP4(this.a); //z0.copy(this.a);
            var z2 = new ctx.FP4(this.b); //z2.copy(this.b);
            var z3 = new ctx.FP4(this.b); //z3.copy(this.b);
            var t0 = new ctx.FP4(0);
            var t1 = new ctx.FP4(y.a); //t1.copy(y.a);

            z0.mul(y.a);
            z2.pmul(y.b.real());
            this.b.add(this.a);
            t1.real().add(y.b.real());

            this.b.norm();
            t1.norm();

            this.b.mul(t1);
            z3.add(this.c);
            z3.norm();
            z3.pmul(y.b.real());

            t0.copy(z0);
            t0.neg();
            t1.copy(z2);
            t1.neg();

            this.b.add(t0);

            this.b.add(t1);
            z3.add(t1);
            z2.add(t0);

            t0.copy(this.a);
            t0.add(this.c);
            t0.norm();
            t0.mul(y.a);
            this.c.copy(z2);
            this.c.add(t0);
            //z3.norm();
            z3.times_i();
            this.a.copy(z0);
            this.a.add(z3);

            this.norm();
        },

        /* this=1/this */
        inverse: function() {
            var f0 = new ctx.FP4(this.a); //f0.copy(this.a);
            var f1 = new ctx.FP4(this.b); //f1.copy(this.b);
            var f2 = new ctx.FP4(this.a); //f2.copy(this.a);
            var f3 = new ctx.FP4(0);

            f0.sqr();
            f1.mul(this.c);
            f1.times_i();
            f0.sub(f1);
            f0.norm();

            f1.copy(this.c);
            f1.sqr();
            f1.times_i();
            f2.mul(this.b);
            f1.sub(f2);
            f1.norm();

            f2.copy(this.b);
            f2.sqr();
            f3.copy(this.a);
            f3.mul(this.c);
            f2.sub(f3);
            f2.norm();

            f3.copy(this.b);
            f3.mul(f2);
            f3.times_i();
            this.a.mul(f0);
            f3.add(this.a);
            this.c.mul(f1);
            this.c.times_i();

            f3.add(this.c);
            f3.norm();
            f3.inverse();
            this.a.copy(f0);
            this.a.mul(f3);
            this.b.copy(f1);
            this.b.mul(f3);
            this.c.copy(f2);
            this.c.mul(f3);
        },

        /* this=this^p, where p=Modulus, using Frobenius */
        frob: function(f) {
            var f2 = new ctx.FP2(f);
            var f3 = new ctx.FP2(f);

            f2.sqr();
            f3.mul(f2);

            this.a.frob(f3);
            this.b.frob(f3);
            this.c.frob(f3);

            this.b.pmul(f);
            this.c.pmul(f2);
        },

        /* trace function */
        trace: function() {
            var t = new ctx.FP4(0);
            t.copy(this.a);
            t.imul(3);
            t.reduce();
            return t;
        },
        /* convert this to hex string */
        toString: function() {
            return ("[" + this.a.toString() + "," + this.b.toString() + "," + this.c.toString() + "]");
        },
        /* convert this to byte array */
        toBytes: function(w) {
            var i;
            var t = [];
            this.a.geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) w[i] = t[i];
            this.a.geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) w[i + ctx.BIG.MODBYTES] = t[i];
            this.a.getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) w[i + 2 * ctx.BIG.MODBYTES] = t[i];
            this.a.getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) w[i + 3 * ctx.BIG.MODBYTES] = t[i];

            this.b.geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) w[i + 4 * ctx.BIG.MODBYTES] = t[i];
            this.b.geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) w[i + 5 * ctx.BIG.MODBYTES] = t[i];
            this.b.getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) w[i + 6 * ctx.BIG.MODBYTES] = t[i];
            this.b.getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) w[i + 7 * ctx.BIG.MODBYTES] = t[i];

            this.c.geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) w[i + 8 * ctx.BIG.MODBYTES] = t[i];
            this.c.geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) w[i + 9 * ctx.BIG.MODBYTES] = t[i];
            this.c.getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) w[i + 10 * ctx.BIG.MODBYTES] = t[i];
            this.c.getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) w[i + 11 * ctx.BIG.MODBYTES] = t[i];
        },

        /* set this=this^e */
        pow: function(e) {
            this.norm();
            e.norm();
            var w = new FP12(this); //w.copy(this);
            var z = new ctx.BIG(e); //z.copy(e);
            var r = new FP12(1);

            while (true) {
                var bt = z.parity();
                z.fshr(1);
                if (bt == 1) r.mul(w);
                if (z.iszilch()) break;
                w.usqr();
            }
            r.reduce();
            return r;
        },

        /* constant time powering by small integer of max length bts */
        pinpow: function(e, bts) {
            var i, b;
            var R = [];
            R[0] = new FP12(1);
            R[1] = new FP12(this);
            for (i = bts - 1; i >= 0; i--) {
                b = (e >> i) & 1;
                R[1 - b].mul(R[b]);
                R[b].usqr();
            }
            this.copy(R[0]);
        },

        /* Faster compressed powering for unitary elements */
        compow: function(e, r) {
            var fa = new ctx.BIG(0);
            fa.rcopy(ctx.ROM_FIELD.Fra);
            var fb = new ctx.BIG(0);
            fb.rcopy(ctx.ROM_FIELD.Frb);
            var f = new ctx.FP2(fa, fb);

            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_FIELD.Modulus);

            var m = new ctx.BIG(q);
            m.mod(r);

            var a = new ctx.BIG(e);
            a.mod(m);

            var b = new ctx.BIG(e);
            b.div(m);

            var g1 = new FP12(0);
            var g2 = new FP12(0);
            g1.copy(this);

            var c = g1.trace();
            g2.copy(g1);
            g2.frob(f);
            var cp = g2.trace();
            g1.conj();
            g2.mul(g1);
            var cpm1 = g2.trace();
            g2.mul(g1);
            var cpm2 = g2.trace();

            c = c.xtr_pow2(cp, cpm1, cpm2, a, b);
            return c;
        }
    };

    /* convert from byte array to FP12 */
    FP12.fromBytes = function(w) {
        var i, a, b, c, d, e, f, g;
        var t = [];

        for (i = 0; i < ctx.BIG.MODBYTES; i++) t[i] = w[i];
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) t[i] = w[i + ctx.BIG.MODBYTES];
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b); //c.bset(a,b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) t[i] = w[i + 2 * ctx.BIG.MODBYTES];
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) t[i] = w[i + 3 * ctx.BIG.MODBYTES];
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b); //d.bset(a,b);

        e = new ctx.FP4(c, d); //e.set(c,d);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) t[i] = w[i + 4 * ctx.BIG.MODBYTES];
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) t[i] = w[i + 5 * ctx.BIG.MODBYTES];
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b); //c.bset(a,b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) t[i] = w[i + 6 * ctx.BIG.MODBYTES];
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) t[i] = w[i + 7 * ctx.BIG.MODBYTES];
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b);

        f = new ctx.FP4(c, d); //f.set(c,d);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) t[i] = w[i + 8 * ctx.BIG.MODBYTES];
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) t[i] = w[i + 9 * ctx.BIG.MODBYTES];
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b); //c.bset(a,b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) t[i] = w[i + 10 * ctx.BIG.MODBYTES];
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) t[i] = w[i + 11 * ctx.BIG.MODBYTES];
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b); //d.bset(a,b);

        g = new ctx.FP4(c, d); //g.set(c,d);

        var r = new FP12(e, f, g); //r.set(e,f,g);

        return r;
    };

    /* p=q0^u0.q1^u1.q2^u2.q3^u3 */
    /* Timing attack secure, but not cache attack secure */

    FP12.pow4 = function(q, u) {
        var i, j, nb, m;
        var a = [];
        var g = [];
        var s = [];

        var c = new FP12(1);
        var p = new FP12(0);
        var t = [];

        var mt = new ctx.BIG(0);
        var w = [];

        for (i = 0; i < 4; i++)
            t[i] = new ctx.BIG(u[i]);

        s[0] = new FP12(0);
        s[1] = new FP12(0);

        g[0] = new FP12(q[0]);
        s[0].copy(q[1]);
        s[0].conj();
        g[0].mul(s[0]);
        g[1] = new FP12(g[0]);
        g[2] = new FP12(g[0]);
        g[3] = new FP12(g[0]);
        g[4] = new FP12(q[0]);
        g[4].mul(q[1]);
        g[5] = new FP12(g[4]);
        g[6] = new FP12(g[4]);
        g[7] = new FP12(g[4]);

        s[1].copy(q[2]);
        s[0].copy(q[3]);
        s[0].conj();
        s[1].mul(s[0]);
        s[0].copy(s[1]);
        s[0].conj();
        g[1].mul(s[0]);
        g[2].mul(s[1]);
        g[5].mul(s[0]);
        g[6].mul(s[1]);
        s[1].copy(q[2]);
        s[1].mul(q[3]);
        s[0].copy(s[1]);
        s[0].conj();
        g[0].mul(s[0]);
        g[3].mul(s[1]);
        g[4].mul(s[0]);
        g[7].mul(s[1]);

        /* if power is even add 1 to power, and add q to correction */

        for (i = 0; i < 4; i++) {
            if (t[i].parity() == 0) {
                t[i].inc(1);
                t[i].norm();
                c.mul(q[i]);
            }
            mt.add(t[i]);
            mt.norm();
        }
        c.conj();
        nb = 1 + mt.nbits();

        /* convert exponent to signed 1-bit window */
        for (j = 0; j < nb; j++) {
            for (i = 0; i < 4; i++) {
                a[i] = (t[i].lastbits(2) - 2);
                t[i].dec(a[i]);
                t[i].norm();
                t[i].fshr(1);
            }
            w[j] = (8 * a[0] + 4 * a[1] + 2 * a[2] + a[3]);
        }
        w[nb] = (8 * t[0].lastbits(2) + 4 * t[1].lastbits(2) + 2 * t[2].lastbits(2) + t[3].lastbits(2));
        p.copy(g[Math.floor((w[nb] - 1) / 2)]);

        for (i = nb - 1; i >= 0; i--) {
            m = w[i] >> 31;
            j = (w[i] ^ m) - m; /* j=abs(w[i]) */
            j = (j - 1) / 2;
            s[0].copy(g[j]);
            s[1].copy(g[j]);
            s[1].conj();
            p.usqr();
            p.mul(s[m & 1]);
        }
        p.mul(c); /* apply correction */
        p.reduce();
        return p;
    };

    FP12.ctx = ctx;
    return FP12;
};
},{}],11:[function(require,module,exports){
/*
	Licensed to the Apache Software Foundation (ASF) under one
	or more contributor license agreements.  See the NOTICE file
	distributed with this work for additional information
	regarding copyright ownership.  The ASF licenses this file
	to you under the Apache License, Version 2.0 (the
	"License"); you may not use this file except in compliance
	with the License.  You may obtain a copy of the License at
	
	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing,
	software distributed under the License is distributed on an
	"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
	KIND, either express or implied.  See the License for the
	specific language governing permissions and limitations
	under the License.
*/

/* Finite Field arithmetic  Fp^2 functions */

/* FP2 elements are of the form a+ib, where i is sqrt(-1) */

module.exports.FP2 = function(ctx) {

    /* general purpose constructor */
    var FP2 = function(c, d) {
        if (c instanceof FP2) {
            this.a = new ctx.FP(c.a);
            this.b = new ctx.FP(c.b);
        } else {
            this.a = new ctx.FP(c);
            this.b = new ctx.FP(d);
        }
    };

    FP2.prototype = {
        /* reduce components mod Modulus */
        reduce: function() {
            this.a.reduce();
            this.b.reduce();
        },
        /* normalise components of w */
        norm: function() {
            this.a.norm();
            this.b.norm();
        },
        /* test this=0 ? */
        iszilch: function() {
            this.reduce();
            return (this.a.iszilch() && this.b.iszilch());
        },
        /* test this=1 ? */
        isunity: function() {
            var one = new ctx.FP(1);
            return (this.a.equals(one) && this.b.iszilch());
        },
        /* conditional copy of g to this depending on d */
        cmove: function(g, d) {
            this.a.cmove(g.a, d);
            this.b.cmove(g.b, d);
        },

        /* test this=x */
        equals: function(x) {
            return (this.a.equals(x.a) && this.b.equals(x.b));
        },
        /* extract a */
        getA: function() {
            return this.a.redc();
        },
        /* extract b */
        getB: function() {
            return this.b.redc();
        },

        /* set from pair of FPs */
        set: function(c, d) {
            this.a.copy(c);
            this.b.copy(d);
        },
        /* set a */
        seta: function(c) {
            this.a.copy(c);
            this.b.zero();
        },

        /* set from two BIGs */
        bset: function(c, d) {
            this.a.bcopy(c);
            this.b.bcopy(d);
        },

        /* set from one ctx.BIG */
        bseta: function(c) {
            this.a.bcopy(c);
            this.b.zero();
        },
        /* copy this=x */
        copy: function(x) {
            this.a.copy(x.a);
            this.b.copy(x.b);
        },
        /* set this=0 */
        zero: function() {
            this.a.zero();
            this.b.zero();
        },
        /* set this=1 */
        one: function() {
            this.a.one();
            this.b.zero();
        },
        /* negate this */
        neg: function() {
            //		this.norm();
            var m = new ctx.FP(this.a);
            var t = new ctx.FP(0);

            m.add(this.b);
            m.neg();
            //		m.norm();
            t.copy(m);
            t.add(this.b);
            this.b.copy(m);
            this.b.add(this.a);
            this.a.copy(t);
            //this.norm();
        },
        /* conjugate this */
        conj: function() {
            this.b.neg();
            this.b.norm();
        },
        /* this+=a */
        add: function(x) {
            this.a.add(x.a);
            this.b.add(x.b);
        },
        /* this-=x */
        sub: function(x) {
            var m = new FP2(x); //var m=new FP2(0); m.copy(x);
            m.neg();
            this.add(m);
        },
        /* this*=s, where s is FP */
        pmul: function(s) {
            this.a.mul(s);
            this.b.mul(s);
        },
        /* this*=c, where s is int */
        imul: function(c) {
            this.a.imul(c);
            this.b.imul(c);
        },
        /* this*=this */
        sqr: function() {
            //		this.norm();

            var w1 = new ctx.FP(this.a);
            var w3 = new ctx.FP(this.a);
            var mb = new ctx.FP(this.b);

            //		w3.mul(this.b);
            w1.add(this.b);


            w3.add(this.a);
            w3.norm();
            this.b.mul(w3);

            mb.neg();
            this.a.add(mb);

            this.a.norm();
            w1.norm();

            this.a.mul(w1);
            //		this.b.copy(w3); this.b.add(w3);
            //		this.b.norm();
        },
        /* this*=y */
        /* Now using Lazy reduction - inputs must be normed */
        mul: function(y) {
            var p = new ctx.BIG(0);
            p.rcopy(ctx.ROM_FIELD.Modulus);
            var pR = new ctx.DBIG(0);
            pR.ucopy(p);

            var exa = ctx.FP.EXCESS(this.a.f);
            var exb = ctx.FP.EXCESS(this.b.f);
            var eya = ctx.FP.EXCESS(y.a.f);
            var eyb = ctx.FP.EXCESS(y.b.f);

            var eC = exa + exb + 1;
            var eD = eya + eyb + 1;

            if ((eC + 1) * (eD + 1) > ctx.FP.FEXCESS) {
                if (eC > 0) this.a.reduce();
                if (eD > 0) this.b.reduce();
                //	if (eD>1) y.reduce();
            }

            var A = ctx.BIG.mul(this.a.f, y.a.f);
            var B = ctx.BIG.mul(this.b.f, y.b.f);

            var C = new ctx.BIG(this.a.f);
            var D = new ctx.BIG(y.a.f);

            C.add(this.b.f);
            C.norm();
            D.add(y.b.f);
            D.norm();

            var E = ctx.BIG.mul(C, D);
            var F = new ctx.DBIG(0);
            F.copy(A);
            F.add(B);
            B.rsub(pR);

            A.add(B);
            A.norm();
            E.sub(F);
            E.norm();

            this.a.f.copy(ctx.FP.mod(A));
            this.b.f.copy(ctx.FP.mod(E));


            /*

            		var w1=new ctx.FP(this.a); 
            		var w2=new ctx.FP(this.b); 
            		var w5=new ctx.FP(this.a); 
            		var mw=new ctx.FP(0);

            		w1.mul(y.a);  // w1=a*y.a  - this norms w1 and y.a, NOT a
            		w2.mul(y.b);  // w2=b*y.b  - this norms w2 and y.b, NOT b
            		w5.add(this.b);    // w5=a+b
            		this.b.copy(y.a); this.b.add(y.b); // b=y.a+y.b

            		this.b.norm();
            		w5.norm();

            		this.b.mul(w5);
            		mw.copy(w1); mw.add(w2); mw.neg();

            		this.b.add(mw); mw.add(w1);
            		this.a.copy(w1); this.a.add(mw);

            		this.norm(); */
        },

        /* sqrt(a+ib) = sqrt(a+sqrt(a*a-n*b*b)/2)+ib/(2*sqrt(a+sqrt(a*a-n*b*b)/2)) */
        /* returns true if this is QR */
        sqrt: function() {
            if (this.iszilch()) return true;
            var w1 = new ctx.FP(this.b);
            var w2 = new ctx.FP(this.a);

            w1.sqr();
            w2.sqr();
            w1.add(w2);
            if (w1.jacobi() != 1) {
                this.zero();
                return false;
            }
            w1 = w1.sqrt();
            w2.copy(this.a);
            w2.add(w1);
            w2.norm();
            w2.div2();
            if (w2.jacobi() != 1) {
                w2.copy(this.a);
                w2.sub(w1);
                w2.norm();
                w2.div2();
                if (w2.jacobi() != 1) {
                    this.zero();
                    return false;
                }
            }
            w2 = w2.sqrt();
            this.a.copy(w2);
            w2.add(w2);
            w2.inverse();
            this.b.mul(w2);
            return true;
        },

        /* convert this to hex string */
        toString: function() {
            return ("[" + this.a.toString() + "," + this.b.toString() + "]");
        },
        /* this=1/this */
        inverse: function() {
            this.norm();
            var w1 = new ctx.FP(this.a);
            var w2 = new ctx.FP(this.b);
            w1.sqr();
            w2.sqr();
            w1.add(w2);
            w1.inverse();
            this.a.mul(w1);
            w1.neg();
            w1.norm();
            this.b.mul(w1);
        },
        /* this/=2 */
        div2: function() {
            this.a.div2();
            this.b.div2();
        },
        /* this*=sqrt(-1) */
        times_i: function() {
            var z = new ctx.FP(this.a); //z.copy(this.a);
            this.a.copy(this.b);
            this.a.neg();
            this.b.copy(z);
        },

        /* w*=(1+sqrt(-1)) */
        /* where X*2-(1+sqrt(-1)) is irreducible for FP4, assumes p=3 mod 8 */
        mul_ip: function() {
            //		this.norm();
            var t = new FP2(this); // t.copy(this);
            var z = new ctx.FP(this.a); //z.copy(this.a);
            this.a.copy(this.b);
            this.a.neg();
            this.b.copy(z);
            this.add(t);
            //		this.norm();
        },

        /* w/=(1+sqrt(-1)) */
        div_ip: function() {
            var t = new FP2(0);
            this.norm();
            t.a.copy(this.a);
            t.a.add(this.b);
            t.b.copy(this.b);
            t.b.sub(this.a);
            this.copy(t);
            this.norm();
            this.div2();
        },
        /* this=this^e */
        pow: function(e) {
            var bt;
            var r = new FP2(1);
            this.norm();
            var x = new FP2(this); //x.copy(this);
            e.norm();
            while (true) {
                bt = e.parity();
                e.fshr(1);
                if (bt == 1) r.mul(x);
                if (e.iszilch()) break;
                x.sqr();
            }

            r.reduce();
            return r;
        }

    };

    FP2.ctx = ctx;
    return FP2;
};
},{}],12:[function(require,module,exports){
/*
	Licensed to the Apache Software Foundation (ASF) under one
	or more contributor license agreements.  See the NOTICE file
	distributed with this work for additional information
	regarding copyright ownership.  The ASF licenses this file
	to you under the Apache License, Version 2.0 (the
	"License"); you may not use this file except in compliance
	with the License.  You may obtain a copy of the License at
	
	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing,
	software distributed under the License is distributed on an
	"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
	KIND, either express or implied.  See the License for the
	specific language governing permissions and limitations
	under the License.
*/

/* Finite Field arithmetic  Fp^4 functions */

/* FP4 elements are of the form a+ib, where i is sqrt(-1+sqrt(-1))  */

module.exports.FP4 = function(ctx) {

    /* general purpose constructor */
    var FP4 = function(c, d) {
        if (c instanceof FP4) {
            this.a = new ctx.FP2(c.a);
            this.b = new ctx.FP2(c.b);
        } else {
            this.a = new ctx.FP2(c);
            this.b = new ctx.FP2(d);
        }
    };

    FP4.prototype = {
        /* reduce all components of this mod Modulus */
        reduce: function() {
            this.a.reduce();
            this.b.reduce();
        },
        /* normalise all components of this mod Modulus */
        norm: function() {
            this.a.norm();
            this.b.norm();
        },
        /* test this==0 ? */
        iszilch: function() {
            this.reduce();
            return (this.a.iszilch() && this.b.iszilch());
        },
        /* test this==1 ? */
        isunity: function() {
            var one = new ctx.FP2(1);
            return (this.a.equals(one) && this.b.iszilch());
        },
        /* test is w real? That is in a+ib test b is zero */
        isreal: function() {
            return this.b.iszilch();
        },
        /* extract real part a */
        real: function() {
            return this.a;
        },

        geta: function() {
            return this.a;
        },
        /* extract imaginary part b */
        getb: function() {
            return this.b;
        },
        /* test this=x? */
        equals: function(x) {
            return (this.a.equals(x.a) && this.b.equals(x.b));
        },
        /* copy this=x */
        copy: function(x) {
            this.a.copy(x.a);
            this.b.copy(x.b);
        },
        /* this=0 */
        zero: function() {
            this.a.zero();
            this.b.zero();
        },
        /* this=1 */
        one: function() {
            this.a.one();
            this.b.zero();
        },

        /* set from two FP2s */
        set: function(c, d) {
            this.a.copy(c);
            this.b.copy(d);
        },
        /* set a */
        seta: function(c) {
            this.a.copy(c);
            this.b.zero();
        },
        /* this=-this */
        neg: function() {
            var m = new ctx.FP2(this.a); //m.copy(this.a);
            var t = new ctx.FP2(0);
            m.add(this.b);
            m.neg();
            //	m.norm();
            t.copy(m);
            t.add(this.b);
            this.b.copy(m);
            this.b.add(this.a);
            this.a.copy(t);
            this.norm();
        },
        /* this=conjugate(this) */
        conj: function() {
            this.b.neg();
            this.norm();
        },
        /* this=-conjugate(this) */
        nconj: function() {
            this.a.neg();
            this.norm();
        },
        /* this+=x */
        add: function(x) {
            this.a.add(x.a);
            this.b.add(x.b);
        },
        /* this-=x */
        sub: function(x) {
            var m = new FP4(x); // m.copy(x); 
            m.neg();
            this.add(m);
        },
        /* this*=s where s is FP2 */
        pmul: function(s) {
            this.a.mul(s);
            this.b.mul(s);
        },
        /* this*=c where s is int */
        imul: function(c) {
            this.a.imul(c);
            this.b.imul(c);
        },
        /* this*=this */
        sqr: function() {
            //		this.norm();

            var t1 = new ctx.FP2(this.a); //t1.copy(this.a);
            var t2 = new ctx.FP2(this.b); //t2.copy(this.b);
            var t3 = new ctx.FP2(this.a); //t3.copy(this.a);

            t3.mul(this.b);
            t1.add(this.b);
            t1.norm();
            t2.mul_ip();

            t2.add(this.a);
            t2.norm();
            this.a.copy(t1);

            this.a.mul(t2);

            t2.copy(t3);
            t2.mul_ip();
            t2.add(t3);
            //		t2.norm();  // ??

            t2.neg();

            this.a.add(t2);

            this.b.copy(t3);
            this.b.add(t3);

            this.norm();
        },
        /* this*=y */
        mul: function(y) {
            //		this.norm();

            var t1 = new ctx.FP2(this.a); //t1.copy(this.a);
            var t2 = new ctx.FP2(this.b); //t2.copy(this.b);
            var t3 = new ctx.FP2(0);
            var t4 = new ctx.FP2(this.b); //t4.copy(this.b);

            t1.mul(y.a);
            t2.mul(y.b);
            t3.copy(y.b);
            t3.add(y.a);
            t4.add(this.a);

            t3.norm();
            t4.norm();

            t4.mul(t3);

            t3.copy(t1);
            t3.neg();
            t4.add(t3);
            //		t4.norm(); // ??

            // t4.sub(t1);

            t3.copy(t2);
            t3.neg();
            this.b.copy(t4);
            this.b.add(t3);

            t2.mul_ip();
            this.a.copy(t2);
            this.a.add(t1);

            this.norm();
        },
        /* convert to hex string */
        toString: function() {
            return ("[" + this.a.toString() + "," + this.b.toString() + "]");
        },
        /* this=1/this */
        inverse: function() {
            this.norm();

            var t1 = new ctx.FP2(this.a); //t1.copy(this.a);
            var t2 = new ctx.FP2(this.b); // t2.copy(this.b);

            t1.sqr();
            t2.sqr();
            t2.mul_ip();
            t2.norm() // ??
            t1.sub(t2);
            t1.inverse();
            this.a.mul(t1);
            t1.neg();
            t1.norm();
            this.b.mul(t1);
        },

        /* this*=i where i = sqrt(-1+sqrt(-1)) */
        times_i: function() {
            var s = new ctx.FP2(this.b); //s.copy(this.b);
            var t = new ctx.FP2(this.b); //t.copy(this.b);
            s.times_i();
            t.add(s);
            this.b.copy(this.a);
            this.a.copy(t);
            this.norm();
        },

        /* this=this^q using Frobenius, where q is Modulus */
        frob: function(f) {
            this.a.conj();
            this.b.conj();
            this.b.mul(f);
        },

        /* this=this^e */
        pow: function(e) {
            this.norm();
            e.norm();
            var w = new FP4(this); //w.copy(this);
            var z = new ctx.BIG(e); //z.copy(e);
            var r = new FP4(1);
            while (true) {
                var bt = z.parity();
                z.fshr(1);
                if (bt == 1) r.mul(w);
                if (z.iszilch()) break;
                w.sqr();
            }
            r.reduce();
            return r;
        },

        /* XTR xtr_a function */
        xtr_A: function(w, y, z) {
            var r = new FP4(w); //r.copy(w);
            var t = new FP4(w); //t.copy(w);
            //y.norm(); // ??
            r.sub(y);
            r.norm();
            r.pmul(this.a);
            t.add(y);
            t.norm();
            t.pmul(this.b);
            t.times_i();

            this.copy(r);
            this.add(t);
            this.add(z);

            this.reduce();
        },
        /* XTR xtr_d function */
        xtr_D: function() {
            var w = new FP4(this); //w.copy(this);
            this.sqr();
            w.conj();
            w.add(w); //w.norm(); // ??
            this.sub(w);
            this.reduce();
        },
        /* r=x^n using XTR method on traces of FP12s */
        xtr_pow: function(n) {
            var a = new FP4(3);
            var b = new FP4(this);
            var c = new FP4(b);
            c.xtr_D();
            var t = new FP4(0);
            var r = new FP4(0);

            n.norm();
            var par = n.parity();
            var v = new ctx.BIG(n);
            v.fshr(1);
            if (par === 0) {
                v.dec(1);
                v.norm();
            }

            var nb = v.nbits();
            for (var i = nb - 1; i >= 0; i--) {
                if (v.bit(i) != 1) {
                    t.copy(b);
                    this.conj();
                    c.conj();
                    b.xtr_A(a, this, c);
                    this.conj();
                    c.copy(t);
                    c.xtr_D();
                    a.xtr_D();
                } else {
                    t.copy(a);
                    t.conj();
                    a.copy(b);
                    a.xtr_D();
                    b.xtr_A(c, this, t);
                    c.xtr_D();
                }
            }
            if (par === 0) r.copy(c);
            else r.copy(b);
            r.reduce();
            return r;
        },

        /* r=ck^a.cl^n using XTR double exponentiation method on traces of FP12s. See Stam thesis. */
        xtr_pow2: function(ck, ckml, ckm2l, a, b) {
            a.norm();
            b.norm();
            var e = new ctx.BIG(a); //e.copy(a);
            var d = new ctx.BIG(b); //d.copy(b);
            var w = new ctx.BIG(0);

            var cu = new FP4(ck); //cu.copy(ck); // can probably be passed in w/o copying
            var cv = new FP4(this); //cv.copy(this);
            var cumv = new FP4(ckml); //cumv.copy(ckml);
            var cum2v = new FP4(ckm2l); //cum2v.copy(ckm2l);
            var r = new FP4(0);
            var t = new FP4(0);

            var f2 = 0;
            while (d.parity() === 0 && e.parity() === 0) {
                d.fshr(1);
                e.fshr(1);
                f2++;
            }

            while (ctx.BIG.comp(d, e) !== 0) {
                if (ctx.BIG.comp(d, e) > 0) {
                    w.copy(e);
                    w.imul(4);
                    w.norm();
                    if (ctx.BIG.comp(d, w) <= 0) {
                        w.copy(d);
                        d.copy(e);
                        e.rsub(w);
                        e.norm();

                        t.copy(cv);
                        t.xtr_A(cu, cumv, cum2v);
                        cum2v.copy(cumv);
                        cum2v.conj();
                        cumv.copy(cv);
                        cv.copy(cu);
                        cu.copy(t);

                    } else if (d.parity() === 0) {
                        d.fshr(1);
                        r.copy(cum2v);
                        r.conj();
                        t.copy(cumv);
                        t.xtr_A(cu, cv, r);
                        cum2v.copy(cumv);
                        cum2v.xtr_D();
                        cumv.copy(t);
                        cu.xtr_D();
                    } else if (e.parity() == 1) {
                        d.sub(e);
                        d.norm();
                        d.fshr(1);
                        t.copy(cv);
                        t.xtr_A(cu, cumv, cum2v);
                        cu.xtr_D();
                        cum2v.copy(cv);
                        cum2v.xtr_D();
                        cum2v.conj();
                        cv.copy(t);
                    } else {
                        w.copy(d);
                        d.copy(e);
                        d.fshr(1);
                        e.copy(w);
                        t.copy(cumv);
                        t.xtr_D();
                        cumv.copy(cum2v);
                        cumv.conj();
                        cum2v.copy(t);
                        cum2v.conj();
                        t.copy(cv);
                        t.xtr_D();
                        cv.copy(cu);
                        cu.copy(t);
                    }
                }
                if (ctx.BIG.comp(d, e) < 0) {
                    w.copy(d);
                    w.imul(4);
                    w.norm();
                    if (ctx.BIG.comp(e, w) <= 0) {
                        e.sub(d);
                        e.norm();
                        t.copy(cv);
                        t.xtr_A(cu, cumv, cum2v);
                        cum2v.copy(cumv);
                        cumv.copy(cu);
                        cu.copy(t);
                    } else if (e.parity() === 0) {
                        w.copy(d);
                        d.copy(e);
                        d.fshr(1);
                        e.copy(w);
                        t.copy(cumv);
                        t.xtr_D();
                        cumv.copy(cum2v);
                        cumv.conj();
                        cum2v.copy(t);
                        cum2v.conj();
                        t.copy(cv);
                        t.xtr_D();
                        cv.copy(cu);
                        cu.copy(t);
                    } else if (d.parity() == 1) {
                        w.copy(e);
                        e.copy(d);
                        w.sub(d);
                        w.norm();
                        d.copy(w);
                        d.fshr(1);
                        t.copy(cv);
                        t.xtr_A(cu, cumv, cum2v);
                        cumv.conj();
                        cum2v.copy(cu);
                        cum2v.xtr_D();
                        cum2v.conj();
                        cu.copy(cv);
                        cu.xtr_D();
                        cv.copy(t);
                    } else {
                        d.fshr(1);
                        r.copy(cum2v);
                        r.conj();
                        t.copy(cumv);
                        t.xtr_A(cu, cv, r);
                        cum2v.copy(cumv);
                        cum2v.xtr_D();
                        cumv.copy(t);
                        cu.xtr_D();
                    }
                }
            }
            r.copy(cv);
            r.xtr_A(cu, cumv, cum2v);
            for (var i = 0; i < f2; i++)
                r.xtr_D();
            r = r.xtr_pow(d);
            return r;
        }

    };
    FP4.ctx = ctx;
    return FP4;
};
},{}],13:[function(require,module,exports){
/*
	Licensed to the Apache Software Foundation (ASF) under one
	or more contributor license agreements.  See the NOTICE file
	distributed with this work for additional information
	regarding copyright ownership.  The ASF licenses this file
	to you under the Apache License, Version 2.0 (the
	"License"); you may not use this file except in compliance
	with the License.  You may obtain a copy of the License at
	
	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing,
	software distributed under the License is distributed on an
	"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
	KIND, either express or implied.  See the License for the
	specific language governing permissions and limitations
	under the License.
*/

/*
 * Implementation of the AES-GCM Encryption/Authentication
 *
 * Some restrictions.. 
 * 1. Only for use with AES
 * 2. Returned tag is always 128-bits. Truncate at your own risk.
 * 3. The order of function calls must follow some rules
 *
 * Typical sequence of calls..
 * 1. call GCM_init
 * 2. call GCM_add_header any number of times, as long as length of header is multiple of 16 bytes (block size)
 * 3. call GCM_add_header one last time with any length of header
 * 4. call GCM_add_cipher any number of times, as long as length of cipher/plaintext is multiple of 16 bytes
 * 5. call GCM_add_cipher one last time with any length of cipher/plaintext
 * 6. call GCM_finish to extract the tag.
 *
 * See http://www.mindspring.com/~dmcgrew/gcm-nist-6.pdf
 */

module.exports.GCM = function(ctx) {

    var GCM = function() {
        this.table = new Array(128);
        for (var i = 0; i < 128; i++)
            this.table[i] = new Array(4); /* 2k bytes */
        this.stateX = [];
        this.Y_0 = [];
        this.counter = 0;
        this.lenA = [];
        this.lenC = [];
        this.status = 0;
        this.a = new ctx.AES();
    };

    // GCM constants

    GCM.ACCEPTING_HEADER = 0;
    GCM.ACCEPTING_CIPHER = 1;
    GCM.NOT_ACCEPTING_MORE = 2;
    GCM.FINISHED = 3;
    GCM.ENCRYPTING = 0;
    GCM.DECRYPTING = 1;

    GCM.prototype = {

        precompute: function(H) {
            var i, j, c;
            var b = [];

            for (i = j = 0; i < 4; i++, j += 4) {
                b[0] = H[j];
                b[1] = H[j + 1];
                b[2] = H[j + 2];
                b[3] = H[j + 3];
                this.table[0][i] = GCM.pack(b);
            }
            for (i = 1; i < 128; i++) {
                c = 0;
                for (j = 0; j < 4; j++) {
                    this.table[i][j] = c | (this.table[i - 1][j]) >>> 1;
                    c = this.table[i - 1][j] << 31;
                }
                if (c !== 0) this.table[i][0] ^= 0xE1000000; /* irreducible polynomial */
            }
        },

        gf2mul: function() { /* gf2m mul - Z=H*X mod 2^128 */
            var i, j, m, k;
            var P = [];
            var c;
            var b = [];

            P[0] = P[1] = P[2] = P[3] = 0;
            j = 8;
            m = 0;
            for (i = 0; i < 128; i++) {
                c = (this.stateX[m] >>> (--j)) & 1;
                c = ~c + 1;
                for (k = 0; k < 4; k++) P[k] ^= (this.table[i][k] & c);
                if (j === 0) {
                    j = 8;
                    m++;
                    if (m == 16) break;
                }
            }
            for (i = j = 0; i < 4; i++, j += 4) {
                b = GCM.unpack(P[i]);
                this.stateX[j] = b[0];
                this.stateX[j + 1] = b[1];
                this.stateX[j + 2] = b[2];
                this.stateX[j + 3] = b[3];
            }
        },

        wrap: function() { /* Finish off GHASH */
            var i, j;
            var F = [];
            var L = [];
            var b = [];

            /* convert lengths from bytes to bits */
            F[0] = (this.lenA[0] << 3) | (this.lenA[1] & 0xE0000000) >>> 29;
            F[1] = this.lenA[1] << 3;
            F[2] = (this.lenC[0] << 3) | (this.lenC[1] & 0xE0000000) >>> 29;
            F[3] = this.lenC[1] << 3;
            for (i = j = 0; i < 4; i++, j += 4) {
                b = GCM.unpack(F[i]);
                L[j] = b[0];
                L[j + 1] = b[1];
                L[j + 2] = b[2];
                L[j + 3] = b[3];
            }
            for (i = 0; i < 16; i++) this.stateX[i] ^= L[i];
            this.gf2mul();
        },

        /* Initialize GCM mode */
        init: function(nk, key, niv, iv) { /* iv size niv is usually 12 bytes (96 bits). ctx.AES key size nk can be 16,24 or 32 bytes */
            var i;
            var H = [];
            var b = [];

            for (i = 0; i < 16; i++) {
                H[i] = 0;
                this.stateX[i] = 0;
            }

            this.a.init(ctx.AES.ECB, nk, key, iv);
            this.a.ecb_encrypt(H); /* E(K,0) */
            this.precompute(H);

            this.lenA[0] = this.lenC[0] = this.lenA[1] = this.lenC[1] = 0;
            if (niv == 12) {
                for (i = 0; i < 12; i++) this.a.f[i] = iv[i];
                b = GCM.unpack(1);
                this.a.f[12] = b[0];
                this.a.f[13] = b[1];
                this.a.f[14] = b[2];
                this.a.f[15] = b[3]; /* initialise IV */
                for (i = 0; i < 16; i++) this.Y_0[i] = this.a.f[i];
            } else {
                this.status = GCM.ACCEPTING_CIPHER;
                this.ghash(iv, niv); /* GHASH(H,0,IV) */
                this.wrap();
                for (i = 0; i < 16; i++) {
                    this.a.f[i] = this.stateX[i];
                    this.Y_0[i] = this.a.f[i];
                    this.stateX[i] = 0;
                }
                this.lenA[0] = this.lenC[0] = this.lenA[1] = this.lenC[1] = 0;
            }
            this.status = GCM.ACCEPTING_HEADER;
        },

        /* Add Header data - included but not encrypted */
        add_header: function(header, len) { /* Add some header. Won't be encrypted, but will be authenticated. len is length of header */
            var i, j = 0;
            if (this.status != GCM.ACCEPTING_HEADER) return false;

            while (j < len) {
                for (i = 0; i < 16 && j < len; i++) {
                    this.stateX[i] ^= header[j++];
                    this.lenA[1]++;
                    this.lenA[1] |= 0;
                    if (this.lenA[1] === 0) this.lenA[0]++;
                }
                this.gf2mul();
            }
            if (len % 16 !== 0) this.status = GCM.ACCEPTING_CIPHER;
            return true;
        },

        ghash: function(plain, len) {
            var i, j = 0;

            if (this.status == GCM.ACCEPTING_HEADER) this.status = GCM.ACCEPTING_CIPHER;
            if (this.status != GCM.ACCEPTING_CIPHER) return false;

            while (j < len) {
                for (i = 0; i < 16 && j < len; i++) {
                    this.stateX[i] ^= plain[j++];
                    this.lenC[1]++;
                    this.lenC[1] |= 0;
                    if (this.lenC[1] === 0) this.lenC[0]++;
                }
                this.gf2mul();
            }
            if (len % 16 !== 0) this.status = GCM.NOT_ACCEPTING_MORE;
            return true;
        },

        /* Add Plaintext - included and encrypted */
        add_plain: function(plain, len) {
            var i, j = 0;
            var B = [];
            var b = [];
            var cipher = [];

            if (this.status == GCM.ACCEPTING_HEADER) this.status = GCM.ACCEPTING_CIPHER;
            if (this.status != GCM.ACCEPTING_CIPHER) return cipher;

            while (j < len) {

                b[0] = this.a.f[12];
                b[1] = this.a.f[13];
                b[2] = this.a.f[14];
                b[3] = this.a.f[15];
                this.counter = GCM.pack(b);
                this.counter++;
                b = GCM.unpack(this.counter);
                this.a.f[12] = b[0];
                this.a.f[13] = b[1];
                this.a.f[14] = b[2];
                this.a.f[15] = b[3]; /* increment counter */
                for (i = 0; i < 16; i++) B[i] = this.a.f[i];
                this.a.ecb_encrypt(B); /* encrypt it  */

                for (i = 0; i < 16 && j < len; i++) {
                    cipher[j] = (plain[j] ^ B[i]);
                    this.stateX[i] ^= cipher[j++];
                    this.lenC[1]++;
                    this.lenC[1] |= 0;
                    if (this.lenC[1] === 0) this.lenC[0]++;
                }
                this.gf2mul();
            }
            if (len % 16 !== 0) this.status = GCM.NOT_ACCEPTING_MORE;
            return cipher;
        },

        /* Add Ciphertext - decrypts to plaintext */
        add_cipher: function(cipher, len) {
            var i, j = 0;
            var B = [];
            var b = [];
            var plain = [];

            if (this.status == GCM.ACCEPTING_HEADER) this.status = GCM.ACCEPTING_CIPHER;
            if (this.status != GCM.ACCEPTING_CIPHER) return plain;

            while (j < len) {
                b[0] = this.a.f[12];
                b[1] = this.a.f[13];
                b[2] = this.a.f[14];
                b[3] = this.a.f[15];
                this.counter = GCM.pack(b);
                this.counter++;
                b = GCM.unpack(this.counter);
                this.a.f[12] = b[0];
                this.a.f[13] = b[1];
                this.a.f[14] = b[2];
                this.a.f[15] = b[3]; /* increment counter */
                for (i = 0; i < 16; i++) B[i] = this.a.f[i];
                this.a.ecb_encrypt(B); /* encrypt it  */
                for (i = 0; i < 16 && j < len; i++) {
                    var oc = cipher[j];
                    plain[j] = (cipher[j] ^ B[i]);
                    this.stateX[i] ^= oc;
                    j++;
                    this.lenC[1]++;
                    this.lenC[1] |= 0;
                    if (this.lenC[1] === 0) this.lenC[0]++;
                }
                this.gf2mul();
            }
            if (len % 16 !== 0) this.status = GCM.NOT_ACCEPTING_MORE;
            return plain;
        },

        /* Finish and extract Tag */
        finish: function(extract) { /* Finish off GHASH and extract tag (MAC) */
            var i;
            var tag = [];

            this.wrap();
            /* extract tag */
            if (extract) {
                this.a.ecb_encrypt(this.Y_0); /* E(K,Y0) */
                for (i = 0; i < 16; i++) this.Y_0[i] ^= this.stateX[i];
                for (i = 0; i < 16; i++) {
                    tag[i] = this.Y_0[i];
                    this.Y_0[i] = this.stateX[i] = 0;
                }
            }
            this.status = GCM.FINISHED;
            this.a.end();
            return tag;
        }

    };

    GCM.pack = function(b) { /* pack 4 bytes into a 32-bit Word */
        return (((b[0]) & 0xff) << 24) | ((b[1] & 0xff) << 16) | ((b[2] & 0xff) << 8) | (b[3] & 0xff);
    };

    GCM.unpack = function(a) { /* unpack bytes from a word */
        var b = [];
        b[3] = (a & 0xff);
        b[2] = ((a >>> 8) & 0xff);
        b[1] = ((a >>> 16) & 0xff);
        b[0] = ((a >>> 24) & 0xff);
        return b;
    };

    GCM.hex2bytes = function(s) {
        var len = s.length;
        var data = [];
        for (var i = 0; i < len; i += 2)
            data[i / 2] = parseInt(s.substr(i, 2), 16);

        return data;
    };
    GCM.ctx = ctx;
    return GCM;
};
},{}],14:[function(require,module,exports){
/*
	Licensed to the Apache Software Foundation (ASF) under one
	or more contributor license agreements.  See the NOTICE file
	distributed with this work for additional information
	regarding copyright ownership.  The ASF licenses this file
	to you under the Apache License, Version 2.0 (the
	"License"); you may not use this file except in compliance
	with the License.  You may obtain a copy of the License at
	
	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing,
	software distributed under the License is distributed on an
	"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
	KIND, either express or implied.  See the License for the
	specific language governing permissions and limitations
	under the License.
*/

module.exports.HASH256 = function(ctx) {


    var HASH256 = function() {
        this.length = [];
        this.h = [];
        this.w = [];
        this.init();
    };

    HASH256.prototype = {

        /* functions */

        transform: function() { /* basic transformation step */
            var a, b, c, d, e, f, g, hh, t1, t2;
            var j;
            for (j = 16; j < 64; j++)
                this.w[j] = (HASH256.theta1(this.w[j - 2]) + this.w[j - 7] + HASH256.theta0(this.w[j - 15]) + this.w[j - 16]) | 0;

            a = this.h[0];
            b = this.h[1];
            c = this.h[2];
            d = this.h[3];
            e = this.h[4];
            f = this.h[5];
            g = this.h[6];
            hh = this.h[7];

            for (j = 0; j < 64; j++) { /* 64 times - mush it up */
                t1 = (hh + HASH256.Sig1(e) + HASH256.Ch(e, f, g) + HASH256.HK[j] + this.w[j]) | 0;
                t2 = (HASH256.Sig0(a) + HASH256.Maj(a, b, c)) | 0;
                hh = g;
                g = f;
                f = e;
                e = (d + t1) | 0; // Need to knock these back down to prevent 52-bit overflow
                d = c;
                c = b;
                b = a;
                a = (t1 + t2) | 0;

            }
            this.h[0] += a;
            this.h[1] += b;
            this.h[2] += c;
            this.h[3] += d;
            this.h[4] += e;
            this.h[5] += f;
            this.h[6] += g;
            this.h[7] += hh;

        },

        /* Initialise Hash function */
        init: function() { /* initialise */
            var i;
            for (i = 0; i < 64; i++) this.w[i] = 0;
            this.length[0] = this.length[1] = 0;
            this.h[0] = HASH256.H[0];
            this.h[1] = HASH256.H[1];
            this.h[2] = HASH256.H[2];
            this.h[3] = HASH256.H[3];
            this.h[4] = HASH256.H[4];
            this.h[5] = HASH256.H[5];
            this.h[6] = HASH256.H[6];
            this.h[7] = HASH256.H[7];
        },

        /* process a single byte */
        process: function(byt) { /* process the next message byte */
            var cnt;

            cnt = (this.length[0] >>> 5) % 16;
            this.w[cnt] <<= 8;
            this.w[cnt] |= (byt & 0xFF);
            this.length[0] += 8;
            if ((this.length[0] & 0xffffffff) === 0) {
                this.length[1]++;
                this.length[0] = 0;
            }
            if ((this.length[0] % 512) === 0) this.transform();
        },

        /* process an array of bytes */
        process_array: function(b) {
            for (var i = 0; i < b.length; i++) this.process(b[i]);
        },

        /* process a 32-bit integer */
        process_num: function(n) {
            this.process((n >> 24) & 0xff);
            this.process((n >> 16) & 0xff);
            this.process((n >> 8) & 0xff);
            this.process(n & 0xff);
        },

        hash: function() { /* pad message and finish - supply digest */
            var i;
            var digest = [];
            var len0, len1;
            len0 = this.length[0];
            len1 = this.length[1];
            this.process(0x80);
            while ((this.length[0] % 512) != 448) this.process(0);

            this.w[14] = len1;
            this.w[15] = len0;
            this.transform();

            for (i = 0; i < HASH256.len; i++) { /* convert to bytes */
                digest[i] = ((this.h[i >>> 2] >> (8 * (3 - i % 4))) & 0xff);
            }
            this.init();
            return digest;
        }
    };

    /* static functions */

    HASH256.S = function(n, x) {
        return (((x) >>> n) | ((x) << (32 - n)));
    };

    HASH256.R = function(n, x) {
        return ((x) >>> n);
    };

    HASH256.Ch = function(x, y, z) {
        return ((x & y) ^ (~(x) & z));
    };

    HASH256.Maj = function(x, y, z) {
        return ((x & y) ^ (x & z) ^ (y & z));
    };

    HASH256.Sig0 = function(x) {
        return (HASH256.S(2, x) ^ HASH256.S(13, x) ^ HASH256.S(22, x));
    };

    HASH256.Sig1 = function(x) {
        return (HASH256.S(6, x) ^ HASH256.S(11, x) ^ HASH256.S(25, x));
    };

    HASH256.theta0 = function(x) {
        return (HASH256.S(7, x) ^ HASH256.S(18, x) ^ HASH256.R(3, x));
    };

    HASH256.theta1 = function(x) {
        return (HASH256.S(17, x) ^ HASH256.S(19, x) ^ HASH256.R(10, x));
    };

    /* constants */
    HASH256.len = 32;

    HASH256.H = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];

    HASH256.HK = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    HASH256.ctx = ctx;
    return HASH256;
};
},{}],15:[function(require,module,exports){
/*
	Licensed to the Apache Software Foundation (ASF) under one
	or more contributor license agreements.  See the NOTICE file
	distributed with this work for additional information
	regarding copyright ownership.  The ASF licenses this file
	to you under the Apache License, Version 2.0 (the
	"License"); you may not use this file except in compliance
	with the License.  You may obtain a copy of the License at
	
	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing,
	software distributed under the License is distributed on an
	"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
	KIND, either express or implied.  See the License for the
	specific language governing permissions and limitations
	under the License.
*/

module.exports.HASH384 = function(ctx) {

    var HASH384 = function() {
        this.length = [];
        this.h = [];
        this.w = [];
        this.init();
    };

    HASH384.prototype = {
        /* constants */


        transform: function() { /* basic transformation step */
            var a, b, c, d, e, ee, zz, f, g, hh, t1, t2;
            var j, r;
            for (j = 16; j < 80; j++)
                this.w[j] = HASH384.theta1(this.w[j - 2]).add(this.w[j - 7]).add(HASH384.theta0(this.w[j - 15])).add(this.w[j - 16]);

            a = this.h[0].copy();
            b = this.h[1].copy();
            c = this.h[2].copy();
            d = this.h[3].copy();
            e = this.h[4].copy();
            f = this.h[5].copy();
            g = this.h[6].copy();
            hh = this.h[7].copy();

            for (j = 0; j < 80; j++) { /* 80 times - mush it up */
                t1 = hh.copy();
                t1.add(HASH384.Sig1(e)).add(HASH384.Ch(e, f, g)).add(HASH384.HK[j]).add(this.w[j]);

                t2 = HASH384.Sig0(a);
                t2.add(HASH384.Maj(a, b, c));
                hh = g;
                g = f;
                f = e;
                e = d.copy();
                e.add(t1);

                d = c;
                c = b;
                b = a;
                a = t1.copy();
                a.add(t2);
            }

            this.h[0].add(a);
            this.h[1].add(b);
            this.h[2].add(c);
            this.h[3].add(d);
            this.h[4].add(e);
            this.h[5].add(f);
            this.h[6].add(g);
            this.h[7].add(hh);
        },

        /* Initialise Hash function */
        init: function() { /* initialise */
            var i;
            for (i = 0; i < 80; i++) this.w[i] = new ctx.UInt64(0, 0);
            this.length[0] = new ctx.UInt64(0, 0);
            this.length[1] = new ctx.UInt64(0, 0);
            this.h[0] = HASH384.H[0].copy();
            this.h[1] = HASH384.H[1].copy();
            this.h[2] = HASH384.H[2].copy();
            this.h[3] = HASH384.H[3].copy();
            this.h[4] = HASH384.H[4].copy();
            this.h[5] = HASH384.H[5].copy();
            this.h[6] = HASH384.H[6].copy();
            this.h[7] = HASH384.H[7].copy();
        },

        /* process a single byte */
        process: function(byt) { /* process the next message byte */
            var cnt;
            cnt = (this.length[0].bot >>> 6) % 16;
            this.w[cnt].shlb();
            this.w[cnt].bot |= (byt & 0xFF);

            var e = new ctx.UInt64(0, 8);
            this.length[0].add(e);
            if (this.length[0].top === 0 && this.length[0].bot == 0) {
                e = new ctx.UInt64(0, 1);
                this.length[1].add(e);
            }
            if ((this.length[0].bot % 1024) === 0) this.transform();
        },

        /* process an array of bytes */
        process_array: function(b) {
            for (var i = 0; i < b.length; i++) this.process(b[i]);
        },

        /* process a 32-bit integer */
        process_num: function(n) {
            this.process((n >> 24) & 0xff);
            this.process((n >> 16) & 0xff);
            this.process((n >> 8) & 0xff);
            this.process(n & 0xff);
        },

        hash: function() { /* pad message and finish - supply digest */
            var i;
            var digest = [];
            var len0, len1;
            len0 = this.length[0].copy();
            len1 = this.length[1].copy();
            this.process(0x80);
            while ((this.length[0].bot % 1024) != 896) this.process(0);

            this.w[14] = len1;
            this.w[15] = len0;
            this.transform();

            for (i = 0; i < HASH384.len; i++) { /* convert to bytes */
                digest[i] = HASH384.R(8 * (7 - i % 8), this.h[i >>> 3]).bot & 0xff;
            }

            this.init();
            return digest;
        }
    };


    /* static  functions */
    HASH384.S = function(n, x) {
        if (n == 0) return x;
        if (n < 32)
            return new ctx.UInt64((x.top >>> n) | (x.bot << (32 - n)), (x.bot >>> n) | (x.top << (32 - n)));
        else
            return new ctx.UInt64((x.bot >>> (n - 32)) | (x.top << (64 - n)), (x.top >>> (n - 32)) | (x.bot << (64 - n)));

    };

    HASH384.R = function(n, x) {
        if (n == 0) return x;
        if (n < 32)
            return new ctx.UInt64((x.top >>> n), (x.bot >>> n | (x.top << (32 - n))));
        else
            return new ctx.UInt64(0, x.top >>> (n - 32));
    };

    HASH384.Ch = function(x, y, z) {
        return new ctx.UInt64((x.top & y.top) ^ (~(x.top) & z.top), (x.bot & y.bot) ^ (~(x.bot) & z.bot));
    };

    HASH384.Maj = function(x, y, z) {
        return new ctx.UInt64((x.top & y.top) ^ (x.top & z.top) ^ (y.top & z.top), (x.bot & y.bot) ^ (x.bot & z.bot) ^ (y.bot & z.bot));
    };

    HASH384.Sig0 = function(x) {
        var r1 = HASH384.S(28, x);
        var r2 = HASH384.S(34, x);
        var r3 = HASH384.S(39, x);
        return new ctx.UInt64(r1.top ^ r2.top ^ r3.top, r1.bot ^ r2.bot ^ r3.bot);
    };

    HASH384.Sig1 = function(x) {
        var r1 = HASH384.S(14, x);
        var r2 = HASH384.S(18, x);
        var r3 = HASH384.S(41, x);
        return new ctx.UInt64(r1.top ^ r2.top ^ r3.top, r1.bot ^ r2.bot ^ r3.bot);
    };

    HASH384.theta0 = function(x) {
        var r1 = HASH384.S(1, x);
        var r2 = HASH384.S(8, x);
        var r3 = HASH384.R(7, x);
        return new ctx.UInt64(r1.top ^ r2.top ^ r3.top, r1.bot ^ r2.bot ^ r3.bot);
    };

    HASH384.theta1 = function(x) {
        var r1 = HASH384.S(19, x);
        var r2 = HASH384.S(61, x);
        var r3 = HASH384.R(6, x);
        return new ctx.UInt64(r1.top ^ r2.top ^ r3.top, r1.bot ^ r2.bot ^ r3.bot);
    };

    HASH384.len = 48;

    HASH384.H = [new ctx.UInt64(0xcbbb9d5d, 0xc1059ed8), new ctx.UInt64(0x629a292a, 0x367cd507),
        new ctx.UInt64(0x9159015a, 0x3070dd17), new ctx.UInt64(0x152fecd8, 0xf70e5939),
        new ctx.UInt64(0x67332667, 0xffc00b31), new ctx.UInt64(0x8eb44a87, 0x68581511),
        new ctx.UInt64(0xdb0c2e0d, 0x64f98fa7), new ctx.UInt64(0x47b5481d, 0xbefa4fa4)
    ];

    HASH384.HK = [new ctx.UInt64(0x428a2f98, 0xd728ae22), new ctx.UInt64(0x71374491, 0x23ef65cd),
        new ctx.UInt64(0xb5c0fbcf, 0xec4d3b2f), new ctx.UInt64(0xe9b5dba5, 0x8189dbbc),
        new ctx.UInt64(0x3956c25b, 0xf348b538), new ctx.UInt64(0x59f111f1, 0xb605d019),
        new ctx.UInt64(0x923f82a4, 0xaf194f9b), new ctx.UInt64(0xab1c5ed5, 0xda6d8118),
        new ctx.UInt64(0xd807aa98, 0xa3030242), new ctx.UInt64(0x12835b01, 0x45706fbe),
        new ctx.UInt64(0x243185be, 0x4ee4b28c), new ctx.UInt64(0x550c7dc3, 0xd5ffb4e2),
        new ctx.UInt64(0x72be5d74, 0xf27b896f), new ctx.UInt64(0x80deb1fe, 0x3b1696b1),
        new ctx.UInt64(0x9bdc06a7, 0x25c71235), new ctx.UInt64(0xc19bf174, 0xcf692694),
        new ctx.UInt64(0xe49b69c1, 0x9ef14ad2), new ctx.UInt64(0xefbe4786, 0x384f25e3),
        new ctx.UInt64(0x0fc19dc6, 0x8b8cd5b5), new ctx.UInt64(0x240ca1cc, 0x77ac9c65),
        new ctx.UInt64(0x2de92c6f, 0x592b0275), new ctx.UInt64(0x4a7484aa, 0x6ea6e483),
        new ctx.UInt64(0x5cb0a9dc, 0xbd41fbd4), new ctx.UInt64(0x76f988da, 0x831153b5),
        new ctx.UInt64(0x983e5152, 0xee66dfab), new ctx.UInt64(0xa831c66d, 0x2db43210),
        new ctx.UInt64(0xb00327c8, 0x98fb213f), new ctx.UInt64(0xbf597fc7, 0xbeef0ee4),
        new ctx.UInt64(0xc6e00bf3, 0x3da88fc2), new ctx.UInt64(0xd5a79147, 0x930aa725),
        new ctx.UInt64(0x06ca6351, 0xe003826f), new ctx.UInt64(0x14292967, 0x0a0e6e70),
        new ctx.UInt64(0x27b70a85, 0x46d22ffc), new ctx.UInt64(0x2e1b2138, 0x5c26c926),
        new ctx.UInt64(0x4d2c6dfc, 0x5ac42aed), new ctx.UInt64(0x53380d13, 0x9d95b3df),
        new ctx.UInt64(0x650a7354, 0x8baf63de), new ctx.UInt64(0x766a0abb, 0x3c77b2a8),
        new ctx.UInt64(0x81c2c92e, 0x47edaee6), new ctx.UInt64(0x92722c85, 0x1482353b),
        new ctx.UInt64(0xa2bfe8a1, 0x4cf10364), new ctx.UInt64(0xa81a664b, 0xbc423001),
        new ctx.UInt64(0xc24b8b70, 0xd0f89791), new ctx.UInt64(0xc76c51a3, 0x0654be30),
        new ctx.UInt64(0xd192e819, 0xd6ef5218), new ctx.UInt64(0xd6990624, 0x5565a910),
        new ctx.UInt64(0xf40e3585, 0x5771202a), new ctx.UInt64(0x106aa070, 0x32bbd1b8),
        new ctx.UInt64(0x19a4c116, 0xb8d2d0c8), new ctx.UInt64(0x1e376c08, 0x5141ab53),
        new ctx.UInt64(0x2748774c, 0xdf8eeb99), new ctx.UInt64(0x34b0bcb5, 0xe19b48a8),
        new ctx.UInt64(0x391c0cb3, 0xc5c95a63), new ctx.UInt64(0x4ed8aa4a, 0xe3418acb),
        new ctx.UInt64(0x5b9cca4f, 0x7763e373), new ctx.UInt64(0x682e6ff3, 0xd6b2b8a3),
        new ctx.UInt64(0x748f82ee, 0x5defb2fc), new ctx.UInt64(0x78a5636f, 0x43172f60),
        new ctx.UInt64(0x84c87814, 0xa1f0ab72), new ctx.UInt64(0x8cc70208, 0x1a6439ec),
        new ctx.UInt64(0x90befffa, 0x23631e28), new ctx.UInt64(0xa4506ceb, 0xde82bde9),
        new ctx.UInt64(0xbef9a3f7, 0xb2c67915), new ctx.UInt64(0xc67178f2, 0xe372532b),
        new ctx.UInt64(0xca273ece, 0xea26619c), new ctx.UInt64(0xd186b8c7, 0x21c0c207),
        new ctx.UInt64(0xeada7dd6, 0xcde0eb1e), new ctx.UInt64(0xf57d4f7f, 0xee6ed178),
        new ctx.UInt64(0x06f067aa, 0x72176fba), new ctx.UInt64(0x0a637dc5, 0xa2c898a6),
        new ctx.UInt64(0x113f9804, 0xbef90dae), new ctx.UInt64(0x1b710b35, 0x131c471b),
        new ctx.UInt64(0x28db77f5, 0x23047d84), new ctx.UInt64(0x32caab7b, 0x40c72493),
        new ctx.UInt64(0x3c9ebe0a, 0x15c9bebc), new ctx.UInt64(0x431d67c4, 0x9c100d4c),
        new ctx.UInt64(0x4cc5d4be, 0xcb3e42b6), new ctx.UInt64(0x597f299c, 0xfc657e2a),
        new ctx.UInt64(0x5fcb6fab, 0x3ad6faec), new ctx.UInt64(0x6c44198c, 0x4a475817)
    ];
    HASH384.ctx = ctx;
    return HASH384;
};
},{}],16:[function(require,module,exports){
    /*
    	Licensed to the Apache Software Foundation (ASF) under one
    	or more contributor license agreements.  See the NOTICE file
    	distributed with this work for additional information
    	regarding copyright ownership.  The ASF licenses this file
    	to you under the Apache License, Version 2.0 (the
    	"License"); you may not use this file except in compliance
    	with the License.  You may obtain a copy of the License at
    	
    	http://www.apache.org/licenses/LICENSE-2.0

    	Unless required by applicable law or agreed to in writing,
    	software distributed under the License is distributed on an
    	"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    	KIND, either express or implied.  See the License for the
    	specific language governing permissions and limitations
    	under the License.
    */

module.exports.HASH512 = function(ctx) {

    var HASH512 = function() {
        this.length = [];
        this.h = [];
        this.w = [];
        this.init();
    };

    HASH512.prototype = {

        transform: function() { /* basic transformation step */
            var a, b, c, d, e, ee, zz, f, g, hh, t1, t2;
            var j, r;
            for (j = 16; j < 80; j++)
                this.w[j] = HASH512.theta1(this.w[j - 2]).add(this.w[j - 7]).add(HASH512.theta0(this.w[j - 15])).add(this.w[j - 16]);

            a = this.h[0].copy();
            b = this.h[1].copy();
            c = this.h[2].copy();
            d = this.h[3].copy();
            e = this.h[4].copy();
            f = this.h[5].copy();
            g = this.h[6].copy();
            hh = this.h[7].copy();

            for (j = 0; j < 80; j++) { /* 80 times - mush it up */
                t1 = hh.copy();
                t1.add(HASH512.Sig1(e)).add(HASH512.Ch(e, f, g)).add(HASH512.HK[j]).add(this.w[j]);

                t2 = HASH512.Sig0(a);
                t2.add(HASH512.Maj(a, b, c));
                hh = g;
                g = f;
                f = e;
                e = d.copy();
                e.add(t1);

                d = c;
                c = b;
                b = a;
                a = t1.copy();
                a.add(t2);
            }

            this.h[0].add(a);
            this.h[1].add(b);
            this.h[2].add(c);
            this.h[3].add(d);
            this.h[4].add(e);
            this.h[5].add(f);
            this.h[6].add(g);
            this.h[7].add(hh);
        },

        /* Initialise Hash function */
        init: function() { /* initialise */
            var i;
            for (i = 0; i < 80; i++) this.w[i] = new ctx.UInt64(0, 0);
            this.length[0] = new ctx.UInt64(0, 0);
            this.length[1] = new ctx.UInt64(0, 0);
            this.h[0] = HASH512.H[0].copy();
            this.h[1] = HASH512.H[1].copy();
            this.h[2] = HASH512.H[2].copy();
            this.h[3] = HASH512.H[3].copy();
            this.h[4] = HASH512.H[4].copy();
            this.h[5] = HASH512.H[5].copy();
            this.h[6] = HASH512.H[6].copy();
            this.h[7] = HASH512.H[7].copy();
        },

        /* process a single byte */
        process: function(byt) { /* process the next message byte */
            var cnt;
            cnt = (this.length[0].bot >>> 6) % 16;
            this.w[cnt].shlb();
            this.w[cnt].bot |= (byt & 0xFF);

            var e = new ctx.UInt64(0, 8);
            this.length[0].add(e);
            if (this.length[0].top === 0 && this.length[0].bot == 0) {
                e = new ctx.UInt64(0, 1);
                this.length[1].add(e);
            }
            if ((this.length[0].bot % 1024) === 0) this.transform();
        },

        /* process an array of bytes */
        process_array: function(b) {
            for (var i = 0; i < b.length; i++) this.process(b[i]);
        },

        /* process a 32-bit integer */
        process_num: function(n) {
            this.process((n >> 24) & 0xff);
            this.process((n >> 16) & 0xff);
            this.process((n >> 8) & 0xff);
            this.process(n & 0xff);
        },

        hash: function() { /* pad message and finish - supply digest */
            var i;
            var digest = [];
            var len0, len1;
            len0 = this.length[0].copy();
            len1 = this.length[1].copy();
            this.process(0x80);
            while ((this.length[0].bot % 1024) != 896) this.process(0);

            this.w[14] = len1;
            this.w[15] = len0;
            this.transform();

            for (i = 0; i < HASH512.len; i++) { /* convert to bytes */
                digest[i] = HASH512.R(8 * (7 - i % 8), this.h[i >>> 3]).bot & 0xff;
            }

            this.init();
            return digest;
        }
    };

    /* static functions */
    HASH512.S = function(n, x) {
        if (n == 0) return x;
        if (n < 32)
            return new ctx.UInt64((x.top >>> n) | (x.bot << (32 - n)), (x.bot >>> n) | (x.top << (32 - n)));
        else
            return new ctx.UInt64((x.bot >>> (n - 32)) | (x.top << (64 - n)), (x.top >>> (n - 32)) | (x.bot << (64 - n)));

    };

    HASH512.R = function(n, x) {
        if (n == 0) return x;
        if (n < 32)
            return new ctx.UInt64((x.top >>> n), (x.bot >>> n | (x.top << (32 - n))));
        else
            return new ctx.UInt64(0, x.top >>> (n - 32));
    };

    HASH512.Ch = function(x, y, z) {
        return new ctx.UInt64((x.top & y.top) ^ (~(x.top) & z.top), (x.bot & y.bot) ^ (~(x.bot) & z.bot));
    };

    HASH512.Maj = function(x, y, z) {
        return new ctx.UInt64((x.top & y.top) ^ (x.top & z.top) ^ (y.top & z.top), (x.bot & y.bot) ^ (x.bot & z.bot) ^ (y.bot & z.bot));
    };

    HASH512.Sig0 = function(x) {
        var r1 = HASH512.S(28, x);
        var r2 = HASH512.S(34, x);
        var r3 = HASH512.S(39, x);
        return new ctx.UInt64(r1.top ^ r2.top ^ r3.top, r1.bot ^ r2.bot ^ r3.bot);
    };

    HASH512.Sig1 = function(x) {
        var r1 = HASH512.S(14, x);
        var r2 = HASH512.S(18, x);
        var r3 = HASH512.S(41, x);
        return new ctx.UInt64(r1.top ^ r2.top ^ r3.top, r1.bot ^ r2.bot ^ r3.bot);
    };

    HASH512.theta0 = function(x) {
        var r1 = HASH512.S(1, x);
        var r2 = HASH512.S(8, x);
        var r3 = HASH512.R(7, x);
        return new ctx.UInt64(r1.top ^ r2.top ^ r3.top, r1.bot ^ r2.bot ^ r3.bot);
    };

    HASH512.theta1 = function(x) {
        var r1 = HASH512.S(19, x);
        var r2 = HASH512.S(61, x);
        var r3 = HASH512.R(6, x);
        return new ctx.UInt64(r1.top ^ r2.top ^ r3.top, r1.bot ^ r2.bot ^ r3.bot);
    };

    /* constants */
    HASH512.len = 64;

    HASH512.H = [new ctx.UInt64(0x6a09e667, 0xf3bcc908), new ctx.UInt64(0xbb67ae85, 0x84caa73b),
        new ctx.UInt64(0x3c6ef372, 0xfe94f82b), new ctx.UInt64(0xa54ff53a, 0x5f1d36f1),
        new ctx.UInt64(0x510e527f, 0xade682d1), new ctx.UInt64(0x9b05688c, 0x2b3e6c1f),
        new ctx.UInt64(0x1f83d9ab, 0xfb41bd6b), new ctx.UInt64(0x5be0cd19, 0x137e2179)
    ];

    HASH512.HK = [new ctx.UInt64(0x428a2f98, 0xd728ae22), new ctx.UInt64(0x71374491, 0x23ef65cd),
        new ctx.UInt64(0xb5c0fbcf, 0xec4d3b2f), new ctx.UInt64(0xe9b5dba5, 0x8189dbbc),
        new ctx.UInt64(0x3956c25b, 0xf348b538), new ctx.UInt64(0x59f111f1, 0xb605d019),
        new ctx.UInt64(0x923f82a4, 0xaf194f9b), new ctx.UInt64(0xab1c5ed5, 0xda6d8118),
        new ctx.UInt64(0xd807aa98, 0xa3030242), new ctx.UInt64(0x12835b01, 0x45706fbe),
        new ctx.UInt64(0x243185be, 0x4ee4b28c), new ctx.UInt64(0x550c7dc3, 0xd5ffb4e2),
        new ctx.UInt64(0x72be5d74, 0xf27b896f), new ctx.UInt64(0x80deb1fe, 0x3b1696b1),
        new ctx.UInt64(0x9bdc06a7, 0x25c71235), new ctx.UInt64(0xc19bf174, 0xcf692694),
        new ctx.UInt64(0xe49b69c1, 0x9ef14ad2), new ctx.UInt64(0xefbe4786, 0x384f25e3),
        new ctx.UInt64(0x0fc19dc6, 0x8b8cd5b5), new ctx.UInt64(0x240ca1cc, 0x77ac9c65),
        new ctx.UInt64(0x2de92c6f, 0x592b0275), new ctx.UInt64(0x4a7484aa, 0x6ea6e483),
        new ctx.UInt64(0x5cb0a9dc, 0xbd41fbd4), new ctx.UInt64(0x76f988da, 0x831153b5),
        new ctx.UInt64(0x983e5152, 0xee66dfab), new ctx.UInt64(0xa831c66d, 0x2db43210),
        new ctx.UInt64(0xb00327c8, 0x98fb213f), new ctx.UInt64(0xbf597fc7, 0xbeef0ee4),
        new ctx.UInt64(0xc6e00bf3, 0x3da88fc2), new ctx.UInt64(0xd5a79147, 0x930aa725),
        new ctx.UInt64(0x06ca6351, 0xe003826f), new ctx.UInt64(0x14292967, 0x0a0e6e70),
        new ctx.UInt64(0x27b70a85, 0x46d22ffc), new ctx.UInt64(0x2e1b2138, 0x5c26c926),
        new ctx.UInt64(0x4d2c6dfc, 0x5ac42aed), new ctx.UInt64(0x53380d13, 0x9d95b3df),
        new ctx.UInt64(0x650a7354, 0x8baf63de), new ctx.UInt64(0x766a0abb, 0x3c77b2a8),
        new ctx.UInt64(0x81c2c92e, 0x47edaee6), new ctx.UInt64(0x92722c85, 0x1482353b),
        new ctx.UInt64(0xa2bfe8a1, 0x4cf10364), new ctx.UInt64(0xa81a664b, 0xbc423001),
        new ctx.UInt64(0xc24b8b70, 0xd0f89791), new ctx.UInt64(0xc76c51a3, 0x0654be30),
        new ctx.UInt64(0xd192e819, 0xd6ef5218), new ctx.UInt64(0xd6990624, 0x5565a910),
        new ctx.UInt64(0xf40e3585, 0x5771202a), new ctx.UInt64(0x106aa070, 0x32bbd1b8),
        new ctx.UInt64(0x19a4c116, 0xb8d2d0c8), new ctx.UInt64(0x1e376c08, 0x5141ab53),
        new ctx.UInt64(0x2748774c, 0xdf8eeb99), new ctx.UInt64(0x34b0bcb5, 0xe19b48a8),
        new ctx.UInt64(0x391c0cb3, 0xc5c95a63), new ctx.UInt64(0x4ed8aa4a, 0xe3418acb),
        new ctx.UInt64(0x5b9cca4f, 0x7763e373), new ctx.UInt64(0x682e6ff3, 0xd6b2b8a3),
        new ctx.UInt64(0x748f82ee, 0x5defb2fc), new ctx.UInt64(0x78a5636f, 0x43172f60),
        new ctx.UInt64(0x84c87814, 0xa1f0ab72), new ctx.UInt64(0x8cc70208, 0x1a6439ec),
        new ctx.UInt64(0x90befffa, 0x23631e28), new ctx.UInt64(0xa4506ceb, 0xde82bde9),
        new ctx.UInt64(0xbef9a3f7, 0xb2c67915), new ctx.UInt64(0xc67178f2, 0xe372532b),
        new ctx.UInt64(0xca273ece, 0xea26619c), new ctx.UInt64(0xd186b8c7, 0x21c0c207),
        new ctx.UInt64(0xeada7dd6, 0xcde0eb1e), new ctx.UInt64(0xf57d4f7f, 0xee6ed178),
        new ctx.UInt64(0x06f067aa, 0x72176fba), new ctx.UInt64(0x0a637dc5, 0xa2c898a6),
        new ctx.UInt64(0x113f9804, 0xbef90dae), new ctx.UInt64(0x1b710b35, 0x131c471b),
        new ctx.UInt64(0x28db77f5, 0x23047d84), new ctx.UInt64(0x32caab7b, 0x40c72493),
        new ctx.UInt64(0x3c9ebe0a, 0x15c9bebc), new ctx.UInt64(0x431d67c4, 0x9c100d4c),
        new ctx.UInt64(0x4cc5d4be, 0xcb3e42b6), new ctx.UInt64(0x597f299c, 0xfc657e2a),
        new ctx.UInt64(0x5fcb6fab, 0x3ad6faec), new ctx.UInt64(0x6c44198c, 0x4a475817)
    ];
    HASH512.ctx = ctx;
    return HASH512;
};
},{}],17:[function(require,module,exports){
/*
	Licensed to the Apache Software Foundation (ASF) under one
	or more contributor license agreements.  See the NOTICE file
	distributed with this work for additional information
	regarding copyright ownership.  The ASF licenses this file
	to you under the Apache License, Version 2.0 (the
	"License"); you may not use this file except in compliance
	with the License.  You may obtain a copy of the License at
	
	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing,
	software distributed under the License is distributed on an
	"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
	KIND, either express or implied.  See the License for the
	specific language governing permissions and limitations
	under the License.
*/

/* MPIN API Functions */

module.exports.MPIN = function(ctx) {

    var MPIN = {
        BAD_PARAMS: -11,
        INVALID_POINT: -14,
        WRONG_ORDER: -18,
        BAD_PIN: -19,
        /* configure PIN here */
        MAXPIN: 10000,
        /* max PIN */
        PBLEN: 14,
        /* MAXPIN length in bits */
        TS: 10,
        /* 10 for 4 digit PIN, 14 for 6-digit PIN - 2^TS/TS approx = sqrt(MAXPIN) */
        TRAP: 2000,
        /* 200 for 4 digit PIN, 2000 for 6-digit PIN  - approx 2*sqrt(MAXPIN) */
        EFS: ctx.BIG.MODBYTES,
        EGS: ctx.BIG.MODBYTES,
        PAS: 16,

        SHA256: 32,
        SHA384: 48,
        SHA512: 64,

        HASH_TYPE: 32,


        /* return time in slots since epoch */
        today: function() {
            var now = new Date();
            return Math.floor(now.getTime() / (60000 * 1440)); // for daily tokens
        },

        bytestostring: function(b) {
            var s = "";
            var len = b.length;
            var ch;

            for (var i = 0; i < len; i++) {
                ch = b[i];
                s += ((ch >>> 4) & 15).toString(16);
                s += (ch & 15).toString(16);

            }
            return s;
        },

        stringtobytes: function(s) {
            var b = [];
            for (var i = 0; i < s.length; i++)
                b.push(s.charCodeAt(i));
            return b;
        },

        comparebytes: function(a, b) {
            if (a.length != b.length) return false;
            for (var i = 0; i < a.length; i++) {
                if (a[i] != b[i]) return false;
            }
            return true;
        },

        mpin_hash: function(sha, c, U) {
            var t = [];
            var w = [];
            var h = [];

            c.geta().getA().toBytes(w);
            for (var i = 0; i < this.EFS; i++) t[i] = w[i];
            c.geta().getB().toBytes(w);
            for (var i = this.EFS; i < 2 * this.EFS; i++) t[i] = w[i - this.EFS];
            c.getb().getA().toBytes(w);
            for (var i = 2 * this.EFS; i < 3 * this.EFS; i++) t[i] = w[i - 2 * this.EFS];
            c.getb().getB().toBytes(w);
            for (var i = 3 * this.EFS; i < 4 * this.EFS; i++) t[i] = w[i - 3 * this.EFS];

            U.getX().toBytes(w);
            for (var i = 4 * this.EFS; i < 5 * this.EFS; i++) t[i] = w[i - 4 * this.EFS];
            U.getY().toBytes(w);
            for (var i = 5 * this.EFS; i < 6 * this.EFS; i++) t[i] = w[i - 5 * this.EFS];

            if (sha == this.SHA256) {
                var H = new ctx.HASH256();
                H.process_array(t);
                h = H.hash();
            }
            if (sha == this.SHA384) {
                var H = new ctx.HASH384();
                H.process_array(t);
                h = H.hash();
            }
            if (sha == this.SHA512) {
                var H = new ctx.HASH512();
                H.process_array(t);
                h = H.hash();
            }
            if (h.length == 0) return null;
            var R = [];
            for (var i = 0; i < this.PAS; i++) R[i] = h[i];
            return R;
        },
        /* Hash number (optional) and string to point on curve */

        hashit: function(sha, n, B) {
            var R = [];

            if (sha == this.SHA256) {
                var H = new ctx.HASH256();
                if (n > 0) H.process_num(n);
                H.process_array(B);
                R = H.hash();
            }
            if (sha == this.SHA384) {
                var H = new ctx.HASH384();
                if (n > 0) H.process_num(n);
                H.process_array(B);
                R = H.hash();
            }
            if (sha == this.SHA512) {
                var H = new ctx.HASH512();
                if (n > 0) H.process_num(n);
                H.process_array(B);
                R = H.hash();
            }
            if (R.length == 0) return null;
            var W = [];

            if (sha >= ctx.BIG.MODBYTES)
                for (var i = 0; i < ctx.BIG.MODBYTES; i++) W[i] = R[i];
            else {
                for (var i = 0; i < sha; i++) W[i] = R[i];
                for (var i = sha; i < ctx.BIG.MODBYTES; i++) W[i] = 0;
            }
            return W;
        },

        mapit: function(h) {
            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_FIELD.Modulus);
            var x = ctx.BIG.fromBytes(h);
            x.mod(q);
            var P = new ctx.ECP();
            while (true) {
                P.setxi(x, 0);
                if (!P.is_infinity()) break;
                x.inc(1);
                x.norm();
            }
            if (ctx.ECP.CURVE_PAIRING_TYPE != ctx.ECP.BN) {
                var c = new ctx.BIG(0);
                c.rcopy(ctx.ROM_CURVE.CURVE_Cof);
                P = P.mul(c);
            }
            return P;
        },

        /* needed for SOK */
        mapit2: function(h) {
            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_FIELD.Modulus);
            var x = ctx.BIG.fromBytes(h);
            var one = new ctx.BIG(1);
            x.mod(q);
            var Q, T, K, X;
            while (true) {
                X = new ctx.FP2(one, x);
                Q = new ctx.ECP2();
                Q.setx(X);
                if (!Q.is_infinity()) break;
                x.inc(1);
                x.norm();
            }
            /* Fast Hashing to G2 - Fuentes-Castaneda, Knapp and Rodriguez-Henriquez */

            var Fa = new ctx.BIG(0);
            Fa.rcopy(ctx.ROM_FIELD.Fra);
            var Fb = new ctx.BIG(0);
            Fb.rcopy(ctx.ROM_FIELD.Frb);
            X = new ctx.FP2(Fa, Fb);
            x = new ctx.BIG(0);
            x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);

            T = new ctx.ECP2();
            T.copy(Q);
            T.mul(x);
            T.neg();
            K = new ctx.ECP2();
            K.copy(T);
            K.dbl();
            K.add(T);
            K.affine();

            K.frob(X);
            Q.frob(X);
            Q.frob(X);
            Q.frob(X);
            Q.add(T);
            Q.add(K);
            T.frob(X);
            T.frob(X);
            Q.add(T);
            Q.affine();
            return Q;

        },

        /* these next two functions help to implement elligator squared - http://eprint.iacr.org/2014/043 */
        /* maps a random u to a point on the curve */
        map: function(u, cb) {
            var P = new ctx.ECP();
            var x = new ctx.BIG(u);
            var p = new ctx.BIG(0);
            p.rcopy(ctx.ROM_FIELD.Modulus);
            x.mod(p);
            while (true) {
                P.setxi(x, cb);
                if (!P.is_infinity()) break;
                x.inc(1);
                x.norm();
            }
            return P;
        },

        /* returns u derived from P. Random value in range 1 to return value should then be added to u */
        unmap: function(u, P) {
            var s = P.getS();
            var R = new ctx.ECP();
            var r = 0;
            var x = P.getX();
            u.copy(x);
            while (true) {
                u.dec(1);
                u.norm();
                r++;
                R.setxi(u, s); //=new ECP(u,s);
                if (!R.is_infinity()) break;
            }
            return r;
        },

        /* these next two functions implement elligator squared - http://eprint.iacr.org/2014/043 */
        /* Elliptic curve point E in format (0x04,x,y} is converted to form {0x0-,u,v} */
        /* Note that u and v are indistinguisible from random strings */
        ENCODING: function(rng, E) {
            var i, rn, m, su, sv;
            var T = [];

            for (i = 0; i < this.EFS; i++) T[i] = E[i + 1];
            var u = ctx.BIG.fromBytes(T);
            for (i = 0; i < this.EFS; i++) T[i] = E[i + this.EFS + 1];
            var v = ctx.BIG.fromBytes(T);

            var P = new ctx.ECP(0);
            P.setxy(u, v);
            if (P.is_infinity()) return this.INVALID_POINT;

            var p = new ctx.BIG(0);
            p.rcopy(ctx.ROM_FIELD.Modulus);
            u = ctx.BIG.randomnum(p, rng);

            su = rng.getByte();
            if (su < 0) su = -su;
            su %= 2;

            var W = this.map(u, su);
            P.sub(W);
            sv = P.getS();
            rn = this.unmap(v, P);
            m = rng.getByte();
            if (m < 0) m = -m;
            m %= rn;
            v.inc(m + 1);
            E[0] = (su + 2 * sv);
            u.toBytes(T);
            for (i = 0; i < this.EFS; i++) E[i + 1] = T[i];
            v.toBytes(T);
            for (i = 0; i < this.EFS; i++) E[i + this.EFS + 1] = T[i];

            return 0;
        },

        DECODING: function(D) {
            var i, su, sv;
            var T = [];

            if ((D[0] & 0x04) !== 0) return this.INVALID_POINT;

            for (i = 0; i < this.EFS; i++) T[i] = D[i + 1];
            var u = ctx.BIG.fromBytes(T);
            for (i = 0; i < this.EFS; i++) T[i] = D[i + this.EFS + 1];
            var v = ctx.BIG.fromBytes(T);

            su = D[0] & 1;
            sv = (D[0] >> 1) & 1;
            var W = this.map(u, su);
            var P = this.map(v, sv);
            P.add(W);
            u = P.getX();
            v = P.getY();
            D[0] = 0x04;
            u.toBytes(T);
            for (i = 0; i < this.EFS; i++) D[i + 1] = T[i];
            v.toBytes(T);
            for (i = 0; i < this.EFS; i++) D[i + this.EFS + 1] = T[i];

            return 0;
        },

        /* R=R1+R2 in group G1 */
        RECOMBINE_G1: function(R1, R2, R) {
            var P = ctx.ECP.fromBytes(R1);
            var Q = ctx.ECP.fromBytes(R2);

            if (P.is_infinity() || Q.is_infinity()) return this.INVALID_POINT;

            P.add(Q);

            P.toBytes(R);
            return 0;
        },

        /* W=W1+W2 in group G2 */
        RECOMBINE_G2: function(W1, W2, W) {
            var P = ctx.ECP2.fromBytes(W1);
            var Q = ctx.ECP2.fromBytes(W2);

            if (P.is_infinity() || Q.is_infinity()) return this.INVALID_POINT;

            P.add(Q);

            P.toBytes(W);
            return 0;
        },

        HASH_ID: function(sha, ID) {
            return this.hashit(sha, 0, ID);
        },

        /* create random secret S */
        RANDOM_GENERATE: function(rng, S) {
            var r = new ctx.BIG(0);
            r.rcopy(ctx.ROM_CURVE.CURVE_Order);
            var s = ctx.BIG.randomnum(r, rng);
            //if (ROM.AES_S>0)
            //{
            //	s.mod2m(2*ROM.AES_S);
            //}		
            s.toBytes(S);
            return 0;
        },

        /* Extract PIN from TOKEN for identity CID */
        EXTRACT_PIN: function(sha, CID, pin, TOKEN) {
            var P = ctx.ECP.fromBytes(TOKEN);
            if (P.is_infinity()) return this.INVALID_POINT;
            var h = this.hashit(sha, 0, CID);
            var R = this.mapit(h);

            pin %= this.MAXPIN;

            R = R.pinmul(pin, this.PBLEN);
            P.sub(R);

            P.toBytes(TOKEN);

            return 0;
        },

        /* Extract Server Secret SST=S*Q where Q is fixed generator in G2 and S is master secret */
        GET_SERVER_SECRET: function(S, SST) {

            var A = new ctx.BIG(0);
            var B = new ctx.BIG(0);
            A.rcopy(ctx.ROM_CURVE.CURVE_Pxa);
            B.rcopy(ctx.ROM_CURVE.CURVE_Pxb);
            var QX = new ctx.FP2(0);
            QX.bset(A, B);
            A.rcopy(ctx.ROM_CURVE.CURVE_Pya);
            B.rcopy(ctx.ROM_CURVE.CURVE_Pyb);
            var QY = new ctx.FP2(0);
            QY.bset(A, B);

            var Q = new ctx.ECP2();
            Q.setxy(QX, QY);

            var s = ctx.BIG.fromBytes(S);
            Q = ctx.PAIR.G2mul(Q, s);
            Q.toBytes(SST);
            return 0;
        },

        TEST_PAIR: function(PR) {
            var G = new ctx.ECP(0);
            var A = new ctx.BIG(0);
            var B = new ctx.BIG(0);
            A.rcopy(ctx.ROM_CURVE.CURVE_Pxa);
            B.rcopy(ctx.ROM_CURVE.CURVE_Pxb);
            var QX = new ctx.FP2(0);
            QX.bset(A, B);
            A.rcopy(ctx.ROM_CURVE.CURVE_Pya);
            B.rcopy(ctx.ROM_CURVE.CURVE_Pyb);
            var QY = new ctx.FP2(0);
            QY.bset(A, B);

            var Q = new ctx.ECP2();
            Q.setxy(QX, QY);

            var gx = new ctx.BIG(0);
            gx.rcopy(ctx.ROM_CURVE.CURVE_Gx);
            var gy = new ctx.BIG(0);
            gy.rcopy(ctx.ROM_CURVE.CURVE_Gy);
            G.setxy(gx, gy);

            var g = ctx.PAIR.ate(Q, G);
            g = ctx.PAIR.fexp(g);
            g.toBytes(PR);
        },

        /*
         W=x*H(G);
         if RNG == NULL then X is passed in 
         if RNG != NULL the X is passed out 
         if type=0 W=x*G where G is point on the curve, else W=x*M(G), where M(G) is mapping of octet G to point on the curve
        */
        GET_G1_MULTIPLE: function(rng, type, X, G, W) {
            var x;
            var r = new ctx.BIG(0);
            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            if (rng != null) {
                x = ctx.BIG.randomnum(r, rng);
                //if (ROM.AES_S>0)
                //{
                //	x.mod2m(2*ROM.AES_S);
                //}
                x.toBytes(X);
            } else {
                x = ctx.BIG.fromBytes(X);
            }
            var P;
            if (type == 0) {
                P = ctx.ECP.fromBytes(G);
                if (P.is_infinity()) return INVALID_POINT;
            } else
                P = this.mapit(G);

            ctx.PAIR.G1mul(P, x).toBytes(W);
            return 0;
        },


        /* Client secret CST=S*H(CID) where CID is client ID and S is master secret */
        GET_CLIENT_SECRET: function(S, CID, CST) {
            return this.GET_G1_MULTIPLE(null, 1, S, CID, CST);
        },

        /* Time Permit CTT=S*(date|H(CID)) where S is master secret */
        GET_CLIENT_PERMIT: function(sha, date, S, CID, CTT) {
            var h = this.hashit(sha, date, CID);
            var P = this.mapit(h);

            var s = ctx.BIG.fromBytes(S);
            P = ctx.PAIR.G1mul(P, s);
            P.toBytes(CTT);
            return 0;
        },

        /* Implement step 1 on client side of MPin protocol */
        CLIENT_1: function(sha, date, CLIENT_ID, rng, X, pin, TOKEN, SEC, xID, xCID, PERMIT) {
            var r = new ctx.BIG(0);
            r.rcopy(ctx.ROM_CURVE.CURVE_Order);
            //	var q=new ctx.BIG(0); q.rcopy(ctx.ROM_FIELD.Modulus);
            var x;
            if (rng !== null) {
                x = ctx.BIG.randomnum(r, rng);
                //if (ROM.AES_S>0)
                //{
                //	x.mod2m(2*ROM.AES_S);
                //}
                x.toBytes(X);
            } else {
                x = ctx.BIG.fromBytes(X);
            }
            var P, T, W;

            var h = this.hashit(sha, 0, CLIENT_ID);
            P = this.mapit(h);
            T = ctx.ECP.fromBytes(TOKEN);
            if (T.is_infinity()) return this.INVALID_POINT;

            pin %= this.MAXPIN;
            W = P.pinmul(pin, this.PBLEN);
            T.add(W);

            if (date != 0) {
                W = ctx.ECP.fromBytes(PERMIT);
                if (W.is_infinity()) return this.INVALID_POINT;
                T.add(W);
                h = this.hashit(sha, date, h);
                W = this.mapit(h);
                if (xID != null) {
                    P = ctx.PAIR.G1mul(P, x);
                    P.toBytes(xID);
                    W = ctx.PAIR.G1mul(W, x);
                    P.add(W);
                } else {
                    P.add(W);
                    P = ctx.PAIR.G1mul(P, x);
                }
                if (xCID != null) P.toBytes(xCID);
            } else {
                if (xID != null) {
                    P = ctx.PAIR.G1mul(P, x);
                    P.toBytes(xID);
                }
            }

            T.toBytes(SEC);
            return 0;
        },

        /* Implement step 2 on client side of MPin protocol */
        CLIENT_2: function(X, Y, SEC) {
            var r = new ctx.BIG(0);
            r.rcopy(ctx.ROM_CURVE.CURVE_Order);
            var P = ctx.ECP.fromBytes(SEC);
            if (P.is_infinity()) return this.INVALID_POINT;

            var px = ctx.BIG.fromBytes(X);
            var py = ctx.BIG.fromBytes(Y);
            px.add(py);
            px.mod(r);
            //	px.rsub(r);

            P = ctx.PAIR.G1mul(P, px);
            P.neg();
            P.toBytes(SEC);
            //ctx.PAIR.G1mul(P,px).toBytes(SEC);
            return 0;
        },

        /* Outputs H(CID) and H(T|H(CID)) for time permits. If no time permits set HID=HTID */
        SERVER_1: function(sha, date, CID, HID, HTID) {
            var h = this.hashit(sha, 0, CID);
            var R, P = this.mapit(h);

            P.toBytes(HID);
            if (date !== 0) {
                //if (HID!=null) P.toBytes(HID);
                h = this.hashit(sha, date, h);
                R = this.mapit(h);
                P.add(R);
                P.toBytes(HTID);
            }
            //else P.toBytes(HID);
        },

        /* Implement step 1 of MPin protocol on server side. Pa is the client public key in case of DVS, otherwise must be set to null */
        SERVER_2: function(date, HID, HTID, Y, SST, xID, xCID, mSEC, E, F, Pa) {

            if ((Pa === undefined) || (Pa == null)) {
                var A = new ctx.BIG(0);
                var B = new ctx.BIG(0);
                A.rcopy(ctx.ROM_CURVE.CURVE_Pxa);
                B.rcopy(ctx.ROM_CURVE.CURVE_Pxb);
                var QX = new ctx.FP2(0);
                QX.bset(A, B);
                A.rcopy(ctx.ROM_CURVE.CURVE_Pya);
                B.rcopy(ctx.ROM_CURVE.CURVE_Pyb);
                var QY = new ctx.FP2(0);
                QY.bset(A, B);

                var Q = new ctx.ECP2();
                Q.setxy(QX, QY);
            } else {
                var Q = ctx.ECP2.fromBytes(Pa);
                if (Q.is_infinity()) return this.INVALID_POINT;
            }

            var sQ = ctx.ECP2.fromBytes(SST);
            if (sQ.is_infinity()) return this.INVALID_POINT;

            var R;
            if (date !== 0)
                R = ctx.ECP.fromBytes(xCID);
            else {
                if (xID == null) return this.BAD_PARAMS;
                R = ctx.ECP.fromBytes(xID);
            }
            if (R.is_infinity()) return this.INVALID_POINT;

            var y = ctx.BIG.fromBytes(Y);
            var P;

            if (date != 0) P = ctx.ECP.fromBytes(HTID);
            else {
                if (HID == null) return this.BAD_PARAMS;
                P = ctx.ECP.fromBytes(HID);
            }
            if (P.is_infinity()) return this.INVALID_POINT;

            P = ctx.PAIR.G1mul(P, y);
            P.add(R);
            P.affine();
            R = ctx.ECP.fromBytes(mSEC);
            if (R.is_infinity()) return this.INVALID_POINT;

            var g = ctx.PAIR.ate2(Q, R, sQ, P);
            g = ctx.PAIR.fexp(g);

            if (!g.isunity()) {
                if (HID != null && xID != null && E != null && F != null) {
                    g.toBytes(E);
                    if (date !== 0) {
                        P = ctx.ECP.fromBytes(HID);
                        if (P.is_infinity()) return this.INVALID_POINT;
                        R = ctx.ECP.fromBytes(xID);
                        if (R.is_infinity()) return this.INVALID_POINT;

                        P = ctx.PAIR.G1mul(P, y);
                        P.add(R);
                        P.affine();
                    }
                    g = ctx.PAIR.ate(Q, P);
                    g = ctx.PAIR.fexp(g);

                    g.toBytes(F);
                }
                return this.BAD_PIN;
            }
            return 0;
        },

        /* Pollards kangaroos used to return PIN error */
        KANGAROO: function(E, F) {
            var ge = ctx.FP12.fromBytes(E);
            var gf = ctx.FP12.fromBytes(F);
            var distance = [];
            var t = new ctx.FP12(gf);
            var table = [];
            var i, j, m, s, dn, dm, res, steps;

            s = 1;
            for (m = 0; m < this.TS; m++) {
                distance[m] = s;
                table[m] = new ctx.FP12(t);
                s *= 2;
                t.usqr();
            }
            t.one();
            dn = 0;
            for (j = 0; j < this.TRAP; j++) {
                i = t.geta().geta().getA().lastbits(20) % this.TS;
                t.mul(table[i]);
                dn += distance[i];
            }
            gf.copy(t);
            gf.conj();
            steps = 0;
            dm = 0;
            res = 0;
            while (dm - dn < this.MAXPIN) {
                steps++;
                if (steps > 4 * this.TRAP) break;
                i = ge.geta().geta().getA().lastbits(20) % this.TS;
                ge.mul(table[i]);
                dm += distance[i];
                if (ge.equals(t)) {
                    res = dm - dn;
                    break;
                }
                if (ge.equals(gf)) {
                    res = dn - dm;
                    break;
                }

            }
            if (steps > 4 * this.TRAP || dm - dn >= this.MAXPIN) {
                res = 0;
            } // Trap Failed  - probable invalid token
            return res;
        },

        /* return time  since epoch */
        GET_TIME: function() {
            var now = new Date();
            return Math.floor(now.getTime() / (1000));
        },

        /* y = H(time,xCID) */
        GET_Y: function(sha, TimeValue, xCID, Y) {
            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);
            var h = this.hashit(sha, TimeValue, xCID);
            var y = ctx.BIG.fromBytes(h);
            y.mod(q);
            //if (ROM.AES_S>0)
            //{
            //	y.mod2m(2*ROM.AES_S);
            //}
            y.toBytes(Y);
            return 0;
        },

        /* One pass MPIN Client - DVS signature. Message must be null in case of One pass MPIN. */
        CLIENT: function(sha, date, CLIENT_ID, rng, X, pin, TOKEN, SEC, xID, xCID, PERMIT, TimeValue, Y, Message) {

            var rtn = 0;
            var pID;
            var M = [];
            if (date == 0) {
                pID = xID;
            } else {
                pID = xCID;
                xID = null;
            }

            rtn = this.CLIENT_1(sha, date, CLIENT_ID, rng, X, pin, TOKEN, SEC, xID, xCID, PERMIT);
            if (rtn != 0)
                return rtn;

            M = pID.slice();

            if ((Message != undefined) || (Message != null)) {
                for (var i = 0; i < Message.length; i++)
                    M.push(Message[i]);
            }

            this.GET_Y(sha, TimeValue, M, Y);

            rtn = this.CLIENT_2(X, Y, SEC);
            if (rtn != 0)
                return rtn;

            return 0;
        },

        /* One pass MPIN Server */
        SERVER: function(sha, date, HID, HTID, Y, SST, xID, xCID, mSEC, E, F, CID, TimeValue, Message, Pa) {
            var rtn = 0;
            var pID;
            var M = [];
            if (date == 0) {
                pID = xID;
            } else {
                pID = xCID;
            }

            this.SERVER_1(sha, date, CID, HID, HTID);

            M = pID.slice();

            if ((Message != undefined) || (Message != null)) {
                for (var i = 0; i < Message.length; i++)
                    M.push(Message[i]);
            }

            this.GET_Y(sha, TimeValue, M, Y);

            rtn = this.SERVER_2(date, HID, HTID, Y, SST, xID, xCID, mSEC, E, F, Pa);
            if (rtn != 0)
                return rtn;

            return 0;
        },

        /* Functions to support M-Pin Full */

        PRECOMPUTE: function(TOKEN, CID, G1, G2) {
            var P, T;
            var g;

            T = ctx.ECP.fromBytes(TOKEN);
            if (T.is_infinity()) return INVALID_POINT;

            P = this.mapit(CID);

            var A = new ctx.BIG(0);
            var B = new ctx.BIG(0);
            A.rcopy(ctx.ROM_CURVE.CURVE_Pxa);
            B.rcopy(ctx.ROM_CURVE.CURVE_Pxb);
            var QX = new ctx.FP2(0);
            QX.bset(A, B);
            A.rcopy(ctx.ROM_CURVE.CURVE_Pya);
            B.rcopy(ctx.ROM_CURVE.CURVE_Pyb);
            var QY = new ctx.FP2(0);
            QY.bset(A, B);

            var Q = new ctx.ECP2();
            Q.setxy(QX, QY);

            g = ctx.PAIR.ate(Q, T);
            g = ctx.PAIR.fexp(g);
            g.toBytes(G1);

            g = ctx.PAIR.ate(Q, P);
            g = ctx.PAIR.fexp(g);
            g.toBytes(G2);

            return 0;
        },

        /* Hash the M-Pin transcript - new */

        HASH_ALL: function(sha, HID, xID, xCID, SEC, Y, R, W) {
            var tlen = 0;
            var T = [];


            for (var i = 0; i < HID.length; i++) T[i] = HID[i];
            tlen += HID.length;
            if (xCID != null) {
                for (var i = 0; i < xCID.length; i++) T[i + tlen] = xCID[i];
                tlen += xCID.length;
            } else {
                for (i = 0; i < xID.length; i++) T[i + tlen] = xID[i];
                tlen += xID.length;
            }
            for (var i = 0; i < SEC.length; i++) T[i + tlen] = SEC[i];
            tlen += SEC.length;
            for (var i = 0; i < Y.length; i++) T[i + tlen] = Y[i];
            tlen += Y.length;
            for (var i = 0; i < R.length; i++) T[i + tlen] = R[i];
            tlen += R.length;
            for (var i = 0; i < W.length; i++) T[i + tlen] = W[i];
            tlen += W.length;

            return this.hashit(sha, 0, T);
        },

        /* calculate common key on client side */
        /* wCID = w.(A+AT) */
        CLIENT_KEY: function(sha, G1, G2, pin, R, X, H, wCID, CK) {
            var t = [];

            var g1 = ctx.FP12.fromBytes(G1);
            var g2 = ctx.FP12.fromBytes(G2);
            var z = ctx.BIG.fromBytes(R);
            var x = ctx.BIG.fromBytes(X);
            var h = ctx.BIG.fromBytes(H);

            var W = ctx.ECP.fromBytes(wCID);
            if (W.is_infinity()) return this.INVALID_POINT;

            W = ctx.PAIR.G1mul(W, x);

            //	var fa=new ctx.BIG(0); fa.rcopy(ctx.ROM_FIELD.Fra);
            //	var fb=new ctx.BIG(0); fb.rcopy(ctx.ROM_FIELD.Frb);
            //	var f=new ctx.FP2(fa,fb); //f.bset(fa,fb);

            var r = new ctx.BIG(0);
            r.rcopy(ctx.ROM_CURVE.CURVE_Order);
            //	var q=new ctx.BIG(0); q.rcopy(ctx.ROM_FIELD.Modulus);

            z.add(h);
            z.mod(r);

            g2.pinpow(pin, this.PBLEN);
            g1.mul(g2);

            c = g1.compow(z, r);
            /*
            		var m=new ctx.BIG(q);
            		m.mod(r);

            		var a=new ctx.BIG(z);
            		a.mod(m);

            		var b=new ctx.BIG(z);
            		b.div(m);


            		var c=g1.trace();
            		g2.copy(g1);
            		g2.frob(f);
            		var cp=g2.trace();
            		g1.conj();
            		g2.mul(g1);
            		var cpm1=g2.trace();
            		g2.mul(g1);
            		var cpm2=g2.trace();

            		c=c.xtr_pow2(cp,cpm1,cpm2,a,b);
            */
            t = this.mpin_hash(sha, c, W);

            for (var i = 0; i < this.PAS; i++) CK[i] = t[i];

            return 0;
        },

        /* calculate common key on server side */
        /* Z=r.A - no time permits involved */

        SERVER_KEY: function(sha, Z, SST, W, H, HID, xID, xCID, SK) {
            var t = [];

            var sQ = ctx.ECP2.fromBytes(SST);
            if (sQ.is_infinity()) return this.INVALID_POINT;
            var R = ctx.ECP.fromBytes(Z);
            if (R.is_infinity()) return this.INVALID_POINT;
            var A = ctx.ECP.fromBytes(HID);
            if (A.is_infinity()) return this.INVALID_POINT;

            var U;
            if (xCID != null)
                U = ctx.ECP.fromBytes(xCID);
            else
                U = ctx.ECP.fromBytes(xID);
            if (U.is_infinity()) return this.INVALID_POINT;

            var w = ctx.BIG.fromBytes(W);
            var h = ctx.BIG.fromBytes(H);
            A = ctx.PAIR.G1mul(A, h);
            R.add(A);
            R.affine()

            U = ctx.PAIR.G1mul(U, w);
            var g = ctx.PAIR.ate(sQ, R);
            g = ctx.PAIR.fexp(g);

            var c = g.trace();

            t = this.mpin_hash(sha, c, U);

            for (var i = 0; i < this.PAS; i++) SK[i] = t[i];

            return 0;
        },

        /* Generate a public key and the corresponding z for the key-escrow less scheme */
        /*
            if R==NULL then Z is passed in
            if R!=NULL then Z is passed out
            Pa=(z^-1).Q
        */
        GET_DVS_KEYPAIR: function(rng, Z, Pa) {

            Q = new ctx.ECP2();
            var r = new ctx.BIG(0);
            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            if (rng != null)
                this.RANDOM_GENERATE(rng, Z);

            var z = ctx.BIG.fromBytes(Z);
            z.invmodp(r);

            var pa = new ctx.BIG(0);
            pa.rcopy(ctx.ROM_CURVE.CURVE_Pxa);
            var pb = new ctx.BIG(0);
            pb.rcopy(ctx.ROM_CURVE.CURVE_Pxb);
            var QX = new ctx.FP2(0);
            QX.bset(pa, pb);
            var pa = new ctx.BIG(0);
            pa.rcopy(ctx.ROM_CURVE.CURVE_Pya);
            var pb = new ctx.BIG(0);
            pb.rcopy(ctx.ROM_CURVE.CURVE_Pyb);
            var QY = new ctx.FP2(0);
            QY.bset(pa, pb);

            Q.setxy(QX, QY);
            if (Q.INF)
                return MPIN.INVALID_POINT;

            Q = ctx.PAIR.G2mul(Q, z);
            Q.toBytes(Pa);
            return 0;
        }
    };
    MPIN.ctx = ctx;
    return MPIN;
};
},{}],18:[function(require,module,exports){
/*
	Licensed to the Apache Software Foundation (ASF) under one
	or more contributor license agreements.  See the NOTICE file
	distributed with this work for additional information
	regarding copyright ownership.  The ASF licenses this file
	to you under the Apache License, Version 2.0 (the
	"License"); you may not use this file except in compliance
	with the License.  You may obtain a copy of the License at
	
	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing,
	software distributed under the License is distributed on an
	"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
	KIND, either express or implied.  See the License for the
	specific language governing permissions and limitations
	under the License.
*/

module.exports.PAIR = function(ctx) {

    var PAIR = {
        /* Line function */
        line: function(A, B, Qx, Qy) {
            var P = new ctx.ECP2();
            var a, b, c;
            var r = new ctx.FP12(1);
            P.copy(A);

            var ZZ = new ctx.FP2(P.getz()); //ZZ.copy(P.getz());
            ZZ.sqr();
            var D;
            if (A == B) D = A.dbl();
            else D = A.add(B);
            if (D < 0) return r;
            var Z3 = new ctx.FP2(A.getz()); //Z3.copy(A.getz());
            c = new ctx.FP4(0);
            var X, Y, T;
            if (D === 0) { /* Addition */
                X = new ctx.FP2(B.getx()); //X.copy(B.getx());
                Y = new ctx.FP2(B.gety()); //Y.copy(B.gety());
                T = new ctx.FP2(P.getz()); //T.copy(P.getz());

                T.mul(Y);
                ZZ.mul(T);

                var NY = new ctx.FP2(P.gety()); /*NY.copy(P.gety());*/
                NY.neg();
                NY.norm();
                ZZ.add(NY); // ZZ.norm();
                Z3.pmul(Qy);
                T.mul(P.getx());
                X.mul(NY);
                T.add(X);
                T.norm();
                a = new ctx.FP4(Z3, T); //a.set(Z3,T);
                ZZ.neg();
                ZZ.norm();
                ZZ.pmul(Qx);
                b = new ctx.FP4(ZZ); //b.seta(ZZ);
            } else { /* Doubling */
                X = new ctx.FP2(P.getx()); //X.copy(P.getx());
                Y = new ctx.FP2(P.gety()); //Y.copy(P.gety());
                T = new ctx.FP2(P.getx()); //T.copy(P.getx());
                T.sqr();
                T.imul(3);

                Y.sqr();
                Y.add(Y);
                Z3.mul(ZZ);
                Z3.pmul(Qy);

                X.mul(T);
                X.sub(Y);
                X.norm();
                a = new ctx.FP4(Z3, X); //a.set(Z3,X);
                T.neg();
                T.norm();
                ZZ.mul(T);

                ZZ.pmul(Qx);

                b = new ctx.FP4(ZZ); //b.seta(ZZ);
            }
            r.set(a, b, c);
            return r;
        },

        /* Optimal R-ate pairing */
        ate: function(P, Q) {
            var fa = new ctx.BIG(0);
            fa.rcopy(ctx.ROM_FIELD.Fra);
            var fb = new ctx.BIG(0);
            fb.rcopy(ctx.ROM_FIELD.Frb);
            var f = new ctx.FP2(fa, fb); //f.bset(fa,fb);

            var x = new ctx.BIG(0);
            x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);
            var n = new ctx.BIG(x); //n.copy(x);
            var K = new ctx.ECP2();
            var lv;

            if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BN) {
                n.pmul(6);
                n.dec(2);
            } else
                n.copy(x);
            n.norm();

            //	P.affine();
            //	Q.affine();
            var Qx = new ctx.FP(Q.getx()); //Qx.copy(Q.getx());
            var Qy = new ctx.FP(Q.gety()); //Qy.copy(Q.gety());

            var A = new ctx.ECP2();
            var r = new ctx.FP12(1);

            A.copy(P);
            var nb = n.nbits();

            for (var i = nb - 2; i >= 1; i--) {
                lv = PAIR.line(A, A, Qx, Qy);

                r.smul(lv);

                if (n.bit(i) == 1) {
                    lv = PAIR.line(A, P, Qx, Qy);
                    r.smul(lv);
                }
                r.sqr();
            }
            lv = PAIR.line(A, A, Qx, Qy);
            r.smul(lv);
            if (n.parity() == 1) {
                lv = line(A, P, Qx, Qy);
                r.smul(lv);
            }

            /* R-ate fixup */
            if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BN) {
                r.conj();
                K.copy(P);
                K.frob(f);
                A.neg();
                lv = PAIR.line(A, K, Qx, Qy);
                r.smul(lv);
                K.frob(f);
                K.neg();
                lv = PAIR.line(A, K, Qx, Qy);
                r.smul(lv);
            }
            return r;
        },

        /* Optimal R-ate double pairing e(P,Q).e(R,S) */
        ate2: function(P, Q, R, S) {
            var fa = new ctx.BIG(0);
            fa.rcopy(ctx.ROM_FIELD.Fra);
            var fb = new ctx.BIG(0);
            fb.rcopy(ctx.ROM_FIELD.Frb);
            var f = new ctx.FP2(fa, fb); //f.bset(fa,fb);
            var x = new ctx.BIG(0);
            x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);

            var n = new ctx.BIG(x); //n.copy(x);
            var K = new ctx.ECP2();
            var lv;

            if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BN) {
                n.pmul(6);
                n.dec(2);
            } else
                n.copy(x);
            n.norm();

            //	P.affine();
            //	Q.affine();
            //	R.affine();
            //	S.affine();

            var Qx = new ctx.FP(Q.getx()); //Qx.copy(Q.getx());
            var Qy = new ctx.FP(Q.gety()); //Qy.copy(Q.gety());

            var Sx = new ctx.FP(S.getx()); //Sx.copy(S.getx());
            var Sy = new ctx.FP(S.gety()); //Sy.copy(S.gety());

            var A = new ctx.ECP2();
            var B = new ctx.ECP2();
            var r = new ctx.FP12(1);

            A.copy(P);
            B.copy(R);
            var nb = n.nbits();

            for (var i = nb - 2; i >= 1; i--) {
                lv = PAIR.line(A, A, Qx, Qy);
                r.smul(lv);
                lv = PAIR.line(B, B, Sx, Sy);
                r.smul(lv);
                if (n.bit(i) == 1) {
                    lv = PAIR.line(A, P, Qx, Qy);
                    r.smul(lv);
                    lv = PAIR.line(B, R, Sx, Sy);
                    r.smul(lv);
                }
                r.sqr();
            }

            lv = PAIR.line(A, A, Qx, Qy);
            r.smul(lv);
            lv = PAIR.line(B, B, Sx, Sy);
            r.smul(lv);
            if (n.parity() == 1) {
                lv = line(A, P, Qx, Qy);
                r.smul(lv);
                lv = line(B, R, Sx, Sy);
                r.smul(lv);
            }

            /* R-ate fixup required for BN curves */
            if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BN) {
                r.conj();

                K.copy(P);
                K.frob(f);
                A.neg();
                lv = PAIR.line(A, K, Qx, Qy);
                r.smul(lv);
                K.frob(f);
                K.neg();
                lv = PAIR.line(A, K, Qx, Qy);
                r.smul(lv);

                K.copy(R);
                K.frob(f);
                B.neg();
                lv = PAIR.line(B, K, Sx, Sy);
                r.smul(lv);
                K.frob(f);
                K.neg();
                lv = PAIR.line(B, K, Sx, Sy);
                r.smul(lv);
            }
            return r;
        },

        /* final exponentiation - keep separate for multi-pairings and to avoid thrashing stack */
        fexp: function(m) {
            var fa = new ctx.BIG(0);
            fa.rcopy(ctx.ROM_FIELD.Fra);
            var fb = new ctx.BIG(0);
            fb.rcopy(ctx.ROM_FIELD.Frb);
            var f = new ctx.FP2(fa, fb);
            var x = new ctx.BIG(0);
            x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);

            var r = new ctx.FP12(m); //r.copy(m);

            /* Easy part of final exp */
            var lv = new ctx.FP12(r); //lv.copy(r);
            lv.inverse();
            r.conj();
            r.mul(lv);
            lv.copy(r);
            r.frob(f);
            r.frob(f);
            r.mul(lv);

            /* Hard part of final exp */
            if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BN) {
                var x0, x1, x2, x3, x4, x5;
                lv.copy(r);
                lv.frob(f);
                x0 = new ctx.FP12(lv); //x0.copy(lv);
                x0.frob(f);
                lv.mul(r);
                x0.mul(lv);
                x0.frob(f);
                x1 = new ctx.FP12(r); //x1.copy(r);
                x1.conj();

                x4 = r.pow(x);

                x3 = new ctx.FP12(x4); //x3.copy(x4);
                x3.frob(f);
                x2 = x4.pow(x);

                x5 = new ctx.FP12(x2); /*x5.copy(x2);*/
                x5.conj();
                lv = x2.pow(x);

                x2.frob(f);
                r.copy(x2);
                r.conj();

                x4.mul(r);
                x2.frob(f);

                r.copy(lv);
                r.frob(f);
                lv.mul(r);

                lv.usqr();
                lv.mul(x4);
                lv.mul(x5);
                r.copy(x3);
                r.mul(x5);
                r.mul(lv);
                lv.mul(x2);
                r.usqr();
                r.mul(lv);
                r.usqr();
                lv.copy(r);
                lv.mul(x1);
                r.mul(x0);
                lv.usqr();
                r.mul(lv);
                r.reduce();
            } else {
                var y0, y1, y2, y3;
                // Ghamman & Fouotsa Method
                y0 = new ctx.FP12(r);
                y0.usqr();
                y1 = y0.pow(x);
                x.fshr(1);
                y2 = y1.pow(x);
                x.fshl(1);
                y3 = new ctx.FP12(r);
                y3.conj();
                y1.mul(y3);

                y1.conj();
                y1.mul(y2);

                y2 = y1.pow(x);

                y3 = y2.pow(x);
                y1.conj();
                y3.mul(y1);

                y1.conj();
                y1.frob(f);
                y1.frob(f);
                y1.frob(f);
                y2.frob(f);
                y2.frob(f);
                y1.mul(y2);

                y2 = y3.pow(x);
                y2.mul(y0);
                y2.mul(r);

                y1.mul(y2);
                y2.copy(y3);
                y2.frob(f);
                y1.mul(y2);
                r.copy(y1);
                r.reduce();


                /*
                			x0=new ctx.FP12(r);
                			x1=new ctx.FP12(r);
                			lv.copy(r); lv.frob(f);
                			x3=new ctx.FP12(lv); x3.conj(); x1.mul(x3);
                			lv.frob(f); lv.frob(f);
                			x1.mul(lv);

                			r.copy(r.pow(x));  //r=r.pow(x);
                			x3.copy(r); x3.conj(); x1.mul(x3);
                			lv.copy(r); lv.frob(f);
                			x0.mul(lv);
                			lv.frob(f);
                			x1.mul(lv);
                			lv.frob(f);
                			x3.copy(lv); x3.conj(); x0.mul(x3);

                			r.copy(r.pow(x));
                			x0.mul(r);
                			lv.copy(r); lv.frob(f); lv.frob(f);
                			x3.copy(lv); x3.conj(); x0.mul(x3);
                			lv.frob(f);
                			x1.mul(lv);

                			r.copy(r.pow(x));
                			lv.copy(r); lv.frob(f);
                			x3.copy(lv); x3.conj(); x0.mul(x3);
                			lv.frob(f);
                			x1.mul(lv);

                			r.copy(r.pow(x));
                			x3.copy(r); x3.conj(); x0.mul(x3);
                			lv.copy(r); lv.frob(f);
                			x1.mul(lv);

                			r.copy(r.pow(x));
                			x1.mul(r);

                			x0.usqr();
                			x0.mul(x1);
                			r.copy(x0);
                			r.reduce(); */
            }
            return r;
        }
    };

    /* GLV method */
    PAIR.glv = function(e) {
        var u = [];
        if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BN) {
            var i, j;
            var t = new ctx.BIG(0);
            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);
            var v = [];

            for (i = 0; i < 2; i++) {
                t.rcopy(ctx.ROM_CURVE.CURVE_W[i]);
                var d = ctx.BIG.mul(t, e);
                v[i] = new ctx.BIG(d.div(q));
                u[i] = new ctx.BIG(0);
            }
            u[0].copy(e);
            for (i = 0; i < 2; i++)
                for (j = 0; j < 2; j++) {
                    t.rcopy(ctx.ROM_CURVE.CURVE_SB[j][i]);
                    t.copy(ctx.BIG.modmul(v[j], t, q));
                    u[i].add(q);
                    u[i].sub(t);
                    u[i].mod(q);
                }
        } else { // -(x^2).P = (Beta.x,y)
            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);
            var x = new ctx.BIG(0);
            x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);
            var x2 = ctx.BIG.smul(x, x);
            u[0] = new ctx.BIG(e);
            u[0].mod(x2);
            u[1] = new ctx.BIG(e);
            u[1].div(x2);
            u[1].rsub(q);
        }
        return u;
    };

    /* Galbraith & Scott Method */
    PAIR.gs = function(e) {
        var u = [];
        if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BN) {
            var i, j;
            var t = new ctx.BIG(0);
            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            var v = [];

            for (i = 0; i < 4; i++) {
                t.rcopy(ctx.ROM_CURVE.CURVE_WB[i]);
                var d = ctx.BIG.mul(t, e);
                v[i] = new ctx.BIG(d.div(q));
                u[i] = new ctx.BIG(0);
            }

            u[0].copy(e);
            for (i = 0; i < 4; i++)
                for (j = 0; j < 4; j++) {
                    t.rcopy(ctx.ROM_CURVE.CURVE_BB[j][i]);
                    t.copy(ctx.BIG.modmul(v[j], t, q));
                    u[i].add(q);
                    u[i].sub(t);
                    u[i].mod(q);
                }
        } else {
            var x = new ctx.BIG(0);
            x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);
            var w = new ctx.BIG(e);
            for (var i = 0; i < 4; i++) {
                u[i] = new ctx.BIG(w);
                u[i].mod(x);
                w.div(x);
            }
        }
        return u;
    };

    /* Multiply P by e in group G1 */
    PAIR.G1mul = function(P, e) {
        var R;
        if (ctx.ROM_CURVE.USE_GLV) {
            P.affine();
            R = new ctx.ECP();
            R.copy(P);
            var np, nn;
            var Q = new ctx.ECP();
            Q.copy(P);
            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);
            var bcru = new ctx.BIG(0);
            bcru.rcopy(ctx.ROM_CURVE.CURVE_Cru);
            var cru = new ctx.FP(bcru);
            var t = new ctx.BIG(0);
            var u = PAIR.glv(e);

            Q.getx().mul(cru);

            np = u[0].nbits();
            t.copy(ctx.BIG.modneg(u[0], q));
            nn = t.nbits();
            if (nn < np) {
                u[0].copy(t);
                R.neg();
            }

            np = u[1].nbits();
            t.copy(ctx.BIG.modneg(u[1], q));
            nn = t.nbits();
            if (nn < np) {
                u[1].copy(t);
                Q.neg();
            }

            R = R.mul2(u[0], Q, u[1]);

        } else {
            R = P.mul(e);
        }
        return R;
    };

    /* Multiply P by e in group G2 */
    PAIR.G2mul = function(P, e) {
        var R;
        if (ctx.ROM_CURVE.USE_GS_G2) {
            var Q = [];
            var fa = new ctx.BIG(0);
            fa.rcopy(ctx.ROM_FIELD.Fra);
            var fb = new ctx.BIG(0);
            fb.rcopy(ctx.ROM_FIELD.Frb);
            var f = new ctx.FP2(fa, fb); //f.bset(fa,fb);
            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            var u = PAIR.gs(e);
            var t = new ctx.BIG(0);
            var i, np, nn;
            P.affine();
            Q[0] = new ctx.ECP2();
            Q[0].copy(P);
            for (i = 1; i < 4; i++) {
                Q[i] = new ctx.ECP2();
                Q[i].copy(Q[i - 1]);
                Q[i].frob(f);
            }

            for (i = 0; i < 4; i++) {
                np = u[i].nbits();
                t.copy(ctx.BIG.modneg(u[i], q));
                nn = t.nbits();
                if (nn < np) {
                    u[i].copy(t);
                    Q[i].neg();
                }
            }

            R = ctx.ECP2.mul4(Q, u);
        } else {
            R = P.mul(e);
        }
        return R;
    };

    /* Note that this method requires a lot of RAM! Better to use compressed XTR method, see ctx.FP4.js */
    PAIR.GTpow = function(d, e) {
        var r;
        if (ctx.ROM_CURVE.USE_GS_GT) {
            var g = [];
            var fa = new ctx.BIG(0);
            fa.rcopy(ctx.ROM_FIELD.Fra);
            var fb = new ctx.BIG(0);
            fb.rcopy(ctx.ROM_FIELD.Frb);
            var f = new ctx.FP2(fa, fb);
            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);
            var t = new ctx.BIG(0);
            var i, np, nn;
            var u = PAIR.gs(e);

            g[0] = new ctx.FP12(d);
            for (i = 1; i < 4; i++) {
                g[i] = new ctx.FP12(0);
                g[i].copy(g[i - 1]);
                g[i].frob(f);
            }
            for (i = 0; i < 4; i++) {
                np = u[i].nbits();
                t.copy(ctx.BIG.modneg(u[i], q));
                nn = t.nbits();
                if (nn < np) {
                    u[i].copy(t);
                    g[i].conj();
                }
            }
            r = ctx.FP12.pow4(g, u);
        } else {
            r = d.pow(e);
        }
        return r;
    };

    /* test group membership - no longer needed */
    /* with GT-Strong curve, now only check that m!=1, conj(m)*m==1, and m.m^{p^4}=m^{p^2} */
    /*
    PAIR.GTmember= function(m)
    {
    	if (m.isunity()) return false;
    	var r=new ctx.FP12(m);
    	r.conj();
    	r.mul(m);
    	if (!r.isunity()) return false;

    	var fa=new ctx.BIG(0); fa.rcopy(ctx.ROM_FIELD.Fra);
    	var fb=new ctx.BIG(0); fb.rcopy(ctx.ROM_FIELD.Frb);
    	var f=new ctx.FP2(fa,fb); //f.bset(fa,fb);

    	r.copy(m); r.frob(f); r.frob(f);
    	var w=new ctx.FP12(r); w.frob(f); w.frob(f);
    	w.mul(m);
    	if (!ctx.ROM_CURVE.GT_STRONG)
    	{
    		if (!w.equals(r)) return false;
    		var x=new ctx.BIG(0); x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);
    		r.copy(m); w=r.pow(x); w=w.pow(x);
    		r.copy(w); r.sqr(); r.mul(w); r.sqr();
    		w.copy(m); w.frob(f);
    	}
    	return w.equals(r);
    };
    */
    PAIR.ctx = ctx;
    return PAIR;
};
},{}],19:[function(require,module,exports){
/*
	Licensed to the Apache Software Foundation (ASF) under one
	or more contributor license agreements.  See the NOTICE file
	distributed with this work for additional information
	regarding copyright ownership.  The ASF licenses this file
	to you under the Apache License, Version 2.0 (the
	"License"); you may not use this file except in compliance
	with the License.  You may obtain a copy of the License at
	
	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing,
	software distributed under the License is distributed on an
	"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
	KIND, either express or implied.  See the License for the
	specific language governing permissions and limitations
	under the License.
*/

/*
 *   Cryptographic strong random number generator 
 *
 *   Unguessable seed -> SHA -> PRNG internal state -> SHA -> random numbers
 *   Slow - but secure
 *
 *   See ftp://ftp.rsasecurity.com/pub/pdfs/bull-1.pdf for a justification
 */

/* Marsaglia & Zaman Random number generator constants */

module.exports.RAND = function(ctx) {

    var RAND = function() {
        /* Cryptographically strong pseudo-random number generator */
        this.ira = []; /* random number...   */
        this.rndptr = 0; /* ...array & pointer */
        this.borrow = 0;
        this.pool_ptr = 0;
        this.pool = []; /* random pool */
        this.clean();
    };

    RAND.prototype = {
        NK: 21,
        NJ: 6,
        NV: 8,

        /* Terminate and clean up */
        clean: function() {
            var i;
            for (i = 0; i < 32; i++) this.pool[i] = 0;
            for (i = 0; i < this.NK; i++) this.ira[i] = 0;
            this.rndptr = 0;
            this.borrow = 0;
            this.pool_ptr = 0;
        },

        sbrand: function() { /* Marsaglia & Zaman random number generator */
            var i, k;
            var pdiff, t; /* unsigned 32-bit */

            this.rndptr++;
            if (this.rndptr < this.NK) return this.ira[this.rndptr];
            this.rndptr = 0;
            for (i = 0, k = this.NK - this.NJ; i < this.NK; i++, k++) { /* calculate next NK values */
                if (k == this.NK) k = 0;
                t = this.ira[k] >>> 0;
                pdiff = (t - this.ira[i] - this.borrow) | 0;
                pdiff >>>= 0; /* This is seriously wierd shit. I got to do this to get a proper unsigned comparison... */
                if (pdiff < t) this.borrow = 0;
                if (pdiff > t) this.borrow = 1;
                this.ira[i] = (pdiff | 0);
            }
            return this.ira[0];
        },

        sirand: function(seed) {
            var i, inn;
            var t, m = 1;
            this.borrow = 0;
            this.rndptr = 0;
            seed >>>= 0;
            this.ira[0] ^= seed;

            for (i = 1; i < this.NK; i++) { /* fill initialisation vector */
                inn = (this.NV * i) % this.NK;
                this.ira[inn] ^= m; /* note XOR */
                t = m;
                m = (seed - m) | 0;
                seed = t;
            }

            for (i = 0; i < 10000; i++) this.sbrand(); /* "warm-up" & stir the generator */
        },

        fill_pool: function() {
            var sh = new ctx.HASH256();
            for (var i = 0; i < 128; i++) sh.process(this.sbrand());
            this.pool = sh.hash();
            this.pool_ptr = 0;
        },

        /* Initialize RNG with some real entropy from some external source */
        seed: function(rawlen, raw) { /* initialise from at least 128 byte string of raw random entropy */
            var i;
            var digest = [];
            var b = [];
            var sh = new ctx.HASH256();
            this.pool_ptr = 0;
            for (i = 0; i < this.NK; i++) this.ira[i] = 0;
            if (rawlen > 0) {
                for (i = 0; i < rawlen; i++)
                    sh.process(raw[i]);
                digest = sh.hash();

                /* initialise PRNG from distilled randomness */
                for (i = 0; i < 8; i++) {
                    b[0] = digest[4 * i];
                    b[1] = digest[4 * i + 1];
                    b[2] = digest[4 * i + 2];
                    b[3] = digest[4 * i + 3];
                    this.sirand(RAND.pack(b));
                }
            }
            this.fill_pool();
        },

        /* get random byte */
        getByte: function() {
            var r = this.pool[this.pool_ptr++];
            if (this.pool_ptr >= 32) this.fill_pool();
            return (r & 0xff);
        }
    };

    RAND.pack = function(b) { /* pack 4 bytes into a 32-bit Word */
        return (((b[3]) & 0xff) << 24) | ((b[2] & 0xff) << 16) | ((b[1] & 0xff) << 8) | (b[0] & 0xff);
    };

    RAND.ctx = ctx;
    return RAND;
};
},{}],20:[function(require,module,exports){
/*
	Licensed to the Apache Software Foundation (ASF) under one
	or more contributor license agreements.  See the NOTICE file
	distributed with this work for additional information
	regarding copyright ownership.  The ASF licenses this file
	to you under the Apache License, Version 2.0 (the
	"License"); you may not use this file except in compliance
	with the License.  You may obtain a copy of the License at
	
	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing,
	software distributed under the License is distributed on an
	"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
	KIND, either express or implied.  See the License for the
	specific language governing permissions and limitations
	under the License.
*/

module.exports.ROM_CURVE_ANSSI = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_ANSSI = {

        // ANSSI curve

        CURVE_A: -3,
        CURVE_B: [0x7BB73F, 0xED967B, 0x803075, 0xE4B1A1, 0xEC0C9A, 0xC00FDF, 0x754A44, 0xD4ABA, 0x28A930, 0x3FCA54, 0xEE35],
        CURVE_Order: [0xD655E1, 0xD459C6, 0x941FFD, 0x40D2BF, 0xDC67E1, 0x435B53, 0xE8CE42, 0x10126D, 0x3AD58F, 0x178C0B, 0xF1FD],
        CURVE_Gx: [0x8F5CFF, 0x7A2DD9, 0x164C9, 0xAF98B7, 0x27D2DC, 0x23958C, 0x4749D4, 0x31183D, 0xC139EB, 0xD4C356, 0xB6B3],
        CURVE_Gy: [0x62CFB, 0x5A1554, 0xE18311, 0xE8E4C9, 0x1C307, 0xEF8C27, 0xF0F3EC, 0x1F9271, 0xB20491, 0xE0F7C8, 0x6142],

    };
    ROM_CURVE_ANSSI.ctx = ctx;
    return ROM_CURVE_ANSSI;
};

module.exports.ROM_CURVE_BLS383 = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_BLS383 = {

        // BLS383 Curve 

        CURVE_A: 0,

        CURVE_Order: [0x7FF001, 0x700001, 0x6003FF, 0x387F3, 0x4BFDE0, 0xBDBE3, 0x127, 0x3D18, 0x7F910, 0x198800, 0x190401, 0xA, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_B: [0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Cof: [0x52B, 0x54000, 0x328000, 0x555559, 0x55560A, 0xC0A, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gx: [0x10786B, 0x36691A, 0x2B4356, 0x71FAA, 0x33477C, 0xAF173, 0x496DCD, 0x37B2DF, 0x4007BB, 0x389ED5, 0x3FD5FA, 0x7EAC18, 0x6EC02E, 0x3F11F6, 0x262B6E, 0x67725E, 0xB08],
        CURVE_Gy: [0x145DDB, 0x34047A, 0x5F3017, 0x462FF7, 0x713F51, 0x5654CD, 0x3B0D18, 0x492FAB, 0x19C7A, 0x7D2DE6, 0x660488, 0x30823, 0x5BE599, 0x215B1E, 0x1C4120, 0x499BB, 0x1F39],

        CURVE_Bnx: [0x40, 0x2000, 0x44000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Cru: [0x2155A9, 0x5589DB, 0x78F68E, 0x43B0F2, 0x5DF2FE, 0x4C64C4, 0x37EAB7, 0x1AD35E, 0x128D30, 0x6A246, 0x6FAB5A, 0x5F9D15, 0x24190D, 0x756408, 0x7DD717, 0x104054, 0x7AC5],
        CURVE_Pxa: [0x2C9472, 0x3310B7, 0xDB581, 0xEF16E, 0x77C4D3, 0x119114, 0x72430C, 0x447E5E, 0x1971C6, 0x4E53E0, 0x710FC5, 0x349A9C, 0x6B8BF3, 0x4B4AC3, 0x2FF607, 0x3915AB, 0x4D50],
        CURVE_Pxb: [0x72AB23, 0x17AF44, 0x73A26D, 0x6A7A26, 0x47AF19, 0x640D46, 0x5BDEE4, 0xCFD9F, 0x53E2A8, 0x5CAE3B, 0x58D75F, 0x515D1D, 0x1A1263, 0x18F018, 0x16EB0A, 0x30BE1F, 0xEE3],
        CURVE_Pya: [0x7BD4FD, 0x24612E, 0x7F1A07, 0x3906FE, 0x40B660, 0x191341, 0x7F2564, 0x143D20, 0x3CF878, 0x4A5C3F, 0x53BB9, 0x8E118, 0x3325E0, 0x7102D7, 0x170A21, 0x42CD0, 0x8F4],
        CURVE_Pyb: [0x2C4CE6, 0x44144A, 0x32297, 0x3A57FA, 0x35907A, 0x4891DE, 0x5D8290, 0x50CCA0, 0x2B0FD, 0x13FFDF, 0x6353A9, 0x794D0, 0x4997BA, 0x6F70DC, 0x4AB1F, 0x5DD446, 0x1DCA],

        // not used 
        CURVE_W: [
            [],
            []
        ],
        CURVE_SB: [
            [
                [],
                []
            ],
            [
                [],
                []
            ]
        ],
        CURVE_WB: [
            [],
            [],
            [],
            []
        ],
        CURVE_BB: [
            [
                [],
                [],
                [],
                []
            ],
            [
                [],
                [],
                [],
                []
            ],
            [
                [],
                [],
                [],
                []
            ],
            [
                [],
                [],
                [],
                []
            ]
        ],

        USE_GLV: true,
        USE_GS_G2: true,
        USE_GS_GT: true,
        GT_STRONG: false,

        //debug: false,

    };

    ROM_CURVE_BLS383.ctx = ctx;
    return ROM_CURVE_BLS383;
};

module.exports.ROM_CURVE_BN254 = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_BN254 = {

        // BN254 Curve 

        CURVE_A: 0,
        CURVE_B: [0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Cof: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0xD, 0x0, 0x10A100, 0x0, 0x9F8000, 0x7FF, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
        CURVE_Bnx: [0x1, 0x0, 0x4080],
        CURVE_Cru: [0x7, 0x0, 0x6CD80, 0x0, 0x90000, 0x249, 0x400000, 0x49B362],
        CURVE_Pxa: [0x3FB2B, 0x4224C8, 0xD91EE, 0x4898BF, 0x648BBB, 0xEDB6A4, 0x7E8C61, 0xEB8D8C, 0x9EB62F, 0x10BB51, 0x61A],
        CURVE_Pxb: [0xD54CF3, 0x34C1E7, 0xB70D8C, 0xAE3784, 0x4D746B, 0xAA5B1F, 0x8C5982, 0x310AA7, 0x737833, 0xAAF9BA, 0x516],
        CURVE_Pya: [0xCD2B9A, 0xE07891, 0xBD19F0, 0xBDBE09, 0xBD0AE6, 0x822329, 0x96698C, 0x9A90E0, 0xAF9343, 0x97A06B, 0x218],
        CURVE_Pyb: [0x3ACE9B, 0x1AEC6B, 0x578A2D, 0xD739C9, 0x9006FF, 0x8D37B0, 0x56F5F3, 0x8F6D44, 0x8B1526, 0x2B0E7C, 0xEBB],
        CURVE_Gx: [0x12, 0x0, 0x13A700, 0x0, 0x210000, 0x861, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
        CURVE_Gy: [0x1],
        CURVE_W: [
            [0x3, 0x0, 0x20400, 0x0, 0x818000, 0x61, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x1, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        CURVE_SB: [
            [
                [0x4, 0x0, 0x28500, 0x0, 0x818000, 0x61, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x1, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ],
            [
                [0x1, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0xA, 0x0, 0xE9D00, 0x0, 0x1E0000, 0x79E, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523]
            ]
        ],
        CURVE_WB: [
            [0x0, 0x0, 0x4080, 0x0, 0x808000, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x5, 0x0, 0x54A80, 0x0, 0x70000, 0x1C7, 0x800000, 0x312241, 0x0, 0x0, 0x0],
            [0x3, 0x0, 0x2C580, 0x0, 0x838000, 0xE3, 0xC00000, 0x189120, 0x0, 0x0, 0x0],
            [0x1, 0x0, 0xC180, 0x0, 0x808000, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        CURVE_BB: [
            [
                [0xD, 0x0, 0x106080, 0x0, 0x9F8000, 0x7FF, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
                [0xC, 0x0, 0x106080, 0x0, 0x9F8000, 0x7FF, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
                [0xC, 0x0, 0x106080, 0x0, 0x9F8000, 0x7FF, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
                [0x2, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ],
            [
                [0x1, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0xC, 0x0, 0x106080, 0x0, 0x9F8000, 0x7FF, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
                [0xD, 0x0, 0x106080, 0x0, 0x9F8000, 0x7FF, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
                [0xC, 0x0, 0x106080, 0x0, 0x9F8000, 0x7FF, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523]
            ],
            [
                [0x2, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x1, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x1, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x1, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ],
            [
                [0x2, 0x0, 0x4080, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x2, 0x0, 0x10200, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0xA, 0x0, 0x102000, 0x0, 0x9F8000, 0x7FF, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
                [0x2, 0x0, 0x4080, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ]
        ],

        USE_GLV: true,
        USE_GS_G2: true,
        USE_GS_GT: true,
        GT_STRONG: false,

        //debug: false,

    };

    ROM_CURVE_BN254.ctx = ctx;
    return ROM_CURVE_BN254;
};

module.exports.ROM_CURVE_BN254CX = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_BN254CX = {

        // BN254CX Curve 

        CURVE_A: 0,
        CURVE_B: [0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Cof: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0xEB1F6D, 0xC0A636, 0xCEBE11, 0xCC906, 0x3FD6EE, 0x66D2C4, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
        CURVE_Bnx: [0xC012B1, 0x3, 0x4000],
        CURVE_Cru: [0x235C97, 0x931794, 0x5631E0, 0x71EF87, 0xBDDF64, 0x3F1440, 0xCA8, 0x480000],
        CURVE_Pxa: [0xD2EC74, 0x1CEEE4, 0x26C085, 0xA03E27, 0x7C85BF, 0x4BBB90, 0xF5C3, 0x358B25, 0x53B256, 0x2D2C70, 0x1968],
        CURVE_Pxb: [0x29CFE1, 0x8E8B2E, 0xF47A5, 0xC209C3, 0x1B97B0, 0x9743F8, 0x37A8E9, 0xA011C9, 0x19F64A, 0xB9EC3E, 0x1466],
        CURVE_Pya: [0xBE09F, 0xFCEBCF, 0xB30CFB, 0x847EC1, 0x61B33D, 0xE20963, 0x157DAE, 0xD81E22, 0x332B8D, 0xEDD972, 0xA79],
        CURVE_Pyb: [0x98EE9D, 0x4B2288, 0xEBED90, 0x69D2ED, 0x864EA5, 0x3461C2, 0x512D8D, 0x35C6E4, 0xC4C090, 0xC39EC, 0x616],
        CURVE_Gx: [0x1B55B2, 0x23EF5C, 0xE1BE66, 0x18093E, 0x3FD6EE, 0x66D324, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
        CURVE_Gy: [0x1],

        // Arrays must be padded!

        CURVE_W: [
            [0x2FEB83, 0x634916, 0x120054, 0xB4038, 0x0, 0x60, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x802561, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        CURVE_SB: [
            [
                [0xB010E4, 0x63491D, 0x128054, 0xB4038, 0x0, 0x60, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x802561, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ],
            [
                [0x802561, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0xBB33EA, 0x5D5D20, 0xBCBDBD, 0x188CE, 0x3FD6EE, 0x66D264, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400]
            ]
        ],
        CURVE_WB: [
            [0x7A84B0, 0x211856, 0xB0401C, 0x3C012, 0x0, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x220475, 0xF995BE, 0x9A36CD, 0xA8CA7F, 0x7E94ED, 0x2A0DC0, 0x870, 0x300000, 0x0, 0x0, 0x0],
            [0xF10B93, 0xFCCAE0, 0xCD3B66, 0xD4653F, 0x3F4A76, 0x1506E0, 0x438, 0x180000, 0x0, 0x0, 0x0],
            [0xFAAA11, 0x21185D, 0xB0C01C, 0x3C012, 0x0, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        CURVE_BB: [
            [
                [0x2B0CBD, 0xC0A633, 0xCE7E11, 0xCC906, 0x3FD6EE, 0x66D2C4, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
                [0x2B0CBC, 0xC0A633, 0xCE7E11, 0xCC906, 0x3FD6EE, 0x66D2C4, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
                [0x2B0CBC, 0xC0A633, 0xCE7E11, 0xCC906, 0x3FD6EE, 0x66D2C4, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
                [0x802562, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ],
            [
                [0x802561, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x2B0CBC, 0xC0A633, 0xCE7E11, 0xCC906, 0x3FD6EE, 0x66D2C4, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
                [0x2B0CBD, 0xC0A633, 0xCE7E11, 0xCC906, 0x3FD6EE, 0x66D2C4, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
                [0x2B0CBC, 0xC0A633, 0xCE7E11, 0xCC906, 0x3FD6EE, 0x66D2C4, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400]
            ],
            [
                [0x802562, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x802561, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x802561, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x802561, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ],
            [
                [0xC012B2, 0x3, 0x4000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x4AC2, 0xF, 0x10000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x6AFA0A, 0xC0A62F, 0xCE3E11, 0xCC906, 0x3FD6EE, 0x66D2C4, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
                [0xC012B2, 0x3, 0x4000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ]
        ],
        USE_GLV: true,
        USE_GS_G2: true,
        USE_GS_GT: true,
        GT_STRONG: false,

        //debug: false,

    };

    ROM_CURVE_BN254CX.ctx = ctx;
    return ROM_CURVE_BN254CX;
};

module.exports.ROM_CURVE_BRAINPOOL = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_BRAINPOOL = {

        // Brainpool curve

        CURVE_A: -3,
        CURVE_B: [0xE92B04, 0x8101FE, 0x256AE5, 0xAF2F49, 0x93EBC4, 0x76B7BF, 0x733D0B, 0xFE66A7, 0xD84EA4, 0x61C430, 0x662C],
        CURVE_Order: [0x4856A7, 0xE8297, 0xF7901E, 0xB561A6, 0x397AA3, 0x8D718C, 0x909D83, 0x3E660A, 0xEEA9BC, 0x57DBA1, 0xA9FB],
        CURVE_Gx: [0x1305F4, 0x91562E, 0x2B79A1, 0x7AAFBC, 0xA142C4, 0x6149AF, 0xB23A65, 0x732213, 0xCFE7B7, 0xEB3CC1, 0xA3E8],
        CURVE_Gy: [0x25C9BE, 0xE8F35B, 0x1DAB, 0x39D027, 0xBCB6DE, 0x417E69, 0xE14644, 0x7F7B22, 0x39C56D, 0x6C8234, 0x2D99],

    };
    ROM_CURVE_BRAINPOOL.ctx = ctx;
    return ROM_CURVE_BRAINPOOL;
};

module.exports.ROM_CURVE_C25519 = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_C25519 = {

        // C25519 Curve 

        CURVE_A: 486662,
        CURVE_B: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0xF5D3ED, 0x631A5C, 0xD65812, 0xA2F79C, 0xDEF9DE, 0x14, 0x0, 0x0, 0x0, 0x0, 0x1000],
        CURVE_Gx: [0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],

    };
    ROM_CURVE_C25519.ctx = ctx;
    return ROM_CURVE_C25519;
};

module.exports.ROM_CURVE_C41417 = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_C41417 = {

        // C41417 curve

        CURVE_A: 1,
        CURVE_B: [0xE21, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x6af79, 0x634bc2, 0x606c39, 0x6b1e78, 0x40338a, 0x566de3, 0x5c1808, 0x120a67, 0x6b3cc9, 0x7fffff, 0x7fffff, 0x7fffff, 0x7fffff, 0x7fffff, 0x7fffff, 0x7fffff, 0x7fffff, 0xfffff],
        CURVE_Gx: [0x4bc595, 0x7025e7, 0x1313f4, 0x429be3, 0x273faa, 0x222603, 0x5b5ae8, 0x5255a6, 0x735498, 0xfeaff, 0x1300fb, 0x31b4fa, 0x65fcd4, 0x63864d, 0x63018, 0x219801, 0x51414, 0x346692],
        CURVE_Gy: [0x22, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],

    };

    ROM_CURVE_C41417.ctx = ctx;
    return ROM_CURVE_C41417;
};

module.exports.ROM_CURVE_ED25519 = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_ED25519 = {

        // ED25519 Curve 

        CURVE_A: -1,
        CURVE_B: [0x5978A3, 0x4DCA13, 0xAB75EB, 0x4141D8, 0x700A4D, 0xE89800, 0x797779, 0x8CC740, 0x6FFE73, 0x6CEE2B, 0x5203],
        CURVE_Order: [0xF5D3ED, 0x631A5C, 0xD65812, 0xA2F79C, 0xDEF9DE, 0x14, 0x0, 0x0, 0x0, 0x0, 0x1000],
        CURVE_Gx: [0x25D51A, 0x2D608F, 0xB2C956, 0x9525A7, 0x2CC760, 0xDC5C69, 0x31FDD6, 0xC0A4E2, 0x6E53FE, 0x36D3CD, 0x2169],
        CURVE_Gy: [0x666658, 0x666666, 0x666666, 0x666666, 0x666666, 0x666666, 0x666666, 0x666666, 0x666666, 0x666666, 0x6666],

    };
    ROM_CURVE_ED25519.ctx = ctx;
    return ROM_CURVE_ED25519;
};

module.exports.ROM_CURVE_GOLDILOCKS = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_GOLDILOCKS = {

        // GOLDILOCKS curve

        CURVE_A: 1,
        CURVE_B: [0x7F6756, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7DFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FF],
        CURVE_Order: [0x5844F3, 0x52556, 0x548DE3, 0x6E2C7A, 0x4C2728, 0x52042D, 0x6BB58D, 0x276DA4, 0x23E9C4, 0x7EF994, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x1FF],
        CURVE_Gx: [0x555555, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x52AAAA, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555],
        CURVE_Gy: [0x1386ED, 0x779BD5, 0x2F6BAB, 0xE6D03, 0x4B2BED, 0x131777, 0x4E8A8C, 0x32B2C1, 0x44B80D, 0x6515B1, 0x5F8DB5, 0x426EBD, 0x7A0358, 0x6DDA, 0x21B0AC, 0x6B1028, 0xDB359, 0x15AE09, 0x17A58D, 0x570],

    };
    ROM_CURVE_GOLDILOCKS.ctx = ctx;
    return ROM_CURVE_GOLDILOCKS;
};

module.exports.ROM_CURVE_HIFIVE = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_HIFIVE = {

        // HIFIVE curve

        CURVE_A: 1,
        CURVE_B: [0x2B67, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x1FA805, 0x2B2E7D, 0x29ECBE, 0x3FC9DD, 0xBD6B8, 0x530A18, 0x45057E, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x800],
        CURVE_Gx: [0xC, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0x7E8632, 0xD0A0B, 0x6C4AFB, 0x501B2E, 0x55650C, 0x36DB6B, 0x1FBD0D, 0x61C08E, 0x314B46, 0x70A7A3, 0x587401, 0xC70E0, 0x56502E, 0x38C2D6, 0x303],

    };
    ROM_CURVE_HIFIVE.ctx = ctx;
    return ROM_CURVE_HIFIVE;
};

module.exports.ROM_CURVE_MF254E = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_MF254E = {

        // MF254 Edwards curve

        CURVE_A: -1,
        CURVE_B: [0x367B, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x6E98C7, 0xD3FEC4, 0xB0EAF3, 0x8BD62F, 0x95306C, 0xFFFFEB, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x3FFFFF, 0xFE0],
        CURVE_Gx: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0x2701E5, 0xD0FDAF, 0x187C52, 0xE3212, 0x329A84, 0x3F4E36, 0xD50236, 0x951D00, 0xA4C335, 0xE690D6, 0x19F0],

    };
    ROM_CURVE_MF254E.ctx = ctx;
    return ROM_CURVE_MF254E;
};

module.exports.ROM_CURVE_MF254M = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_MF254M = {

        // MF254 Montgomery curve

        CURVE_A: -55790,
        CURVE_B: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x6E98C7, 0xD3FEC4, 0xB0EAF3, 0x8BD62F, 0x95306C, 0xFFFFEB, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x3FFFFF, 0xFE0],
        CURVE_Gx: [0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    };
    ROM_CURVE_MF254M.ctx = ctx;
    return ROM_CURVE_MF254M;
};

module.exports.ROM_CURVE_MF254W = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_MF254W = {

        // MF254 Weierstrass curve

        CURVE_A: -3,
        CURVE_B: [0xFFD08D, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x3F80],
        CURVE_Order: [0x8DF83F, 0x19C4AF, 0xC06FA4, 0xDA375, 0x818BEA, 0xFFFFEB, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x3F80],
        CURVE_Gx: [0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0xD4EBC, 0xDF37F9, 0x31AD65, 0xF85119, 0xB738E3, 0x8AEBDF, 0x75BD77, 0x4AE15A, 0x2E5601, 0x3FD33B, 0x140E],

    };
    ROM_CURVE_MF254W.ctx = ctx;
    return ROM_CURVE_MF254W;
};

module.exports.ROM_CURVE_MF256E = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_MF256E = {

        // MF256 EDWARDS curve

        CURVE_A: -1,
        CURVE_B: [0x350A, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0xEC7BAB, 0x2EDED8, 0xC966D9, 0xB86733, 0x54BBAF, 0xFFFFB1, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x3FE9],
        CURVE_Gx: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0xF3C908, 0xA722F2, 0x8D7DEA, 0x8DFEA6, 0xC05E64, 0x1AACA0, 0xF3DB2C, 0xEAEBEE, 0xCC4D5A, 0xD4F8F8, 0xDAD8],
    };
    ROM_CURVE_MF256E.ctx = ctx;
    return ROM_CURVE_MF256E;
};

module.exports.ROM_CURVE_MF256M = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_MF256M = {

        // MF256 Montgomery curve

        CURVE_A: -54314,
        CURVE_B: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0xEC7BAB, 0x2EDED8, 0xC966D9, 0xB86733, 0x54BBAF, 0xFFFFB1, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x3FE9],
        CURVE_Gx: [0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    };
    ROM_CURVE_MF256M.ctx = ctx;
    return ROM_CURVE_MF256M;
};

module.exports.ROM_CURVE_MF256W = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_MF256W = {

        // MF256 WEIERSTRASS curve

        CURVE_A: -3,
        CURVE_B: [0x14E6A, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x9857EB, 0xC5E1A7, 0x4B9D10, 0xE6E507, 0x517513, 0xFFFFFC, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFA7],
        CURVE_Gx: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0x724D2A, 0x954C2B, 0x661007, 0x8D94DC, 0x6947EB, 0xAE2895, 0x26123D, 0x7BABBA, 0x1808CE, 0x7C87BE, 0x2088],
    };
    ROM_CURVE_MF256W.ctx = ctx;
    return ROM_CURVE_MF256W;
};

module.exports.ROM_CURVE_MS255E = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_MS255E = {

        // MS255 Edwards curve

        CURVE_A: -1,
        CURVE_B: [0xEA97, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x36EB75, 0xD1ED04, 0x2EAC49, 0xEDA683, 0xF1A785, 0xFFFFDC, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x1FFF],
        CURVE_Gx: [0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0x8736A0, 0x255BD0, 0x45BA2A, 0xED445A, 0x914B8A, 0x47E552, 0xDD8E0C, 0xEC254C, 0x7BB545, 0x78534A, 0x26CB],
    };
    ROM_CURVE_MS255E.ctx = ctx;
    return ROM_CURVE_MS255E;
};

module.exports.ROM_CURVE_MS255M = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_MS255M = {

        // MS255 Montgomery curve

        CURVE_A: -240222,
        CURVE_B: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x36EB75, 0xD1ED04, 0x2EAC49, 0xEDA683, 0xF1A785, 0xFFFFDC, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x1FFF],
        CURVE_Gx: [0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    };
    ROM_CURVE_MS255M.ctx = ctx;
    return ROM_CURVE_MS255M;
};

module.exports.ROM_CURVE_MS255W = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_MS255W = {

        // MS255 WEIERSTRASS curve

        CURVE_A: -3,
        CURVE_B: [0xFFAB46, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x7FFF],
        CURVE_Order: [0x594AEB, 0xAC983C, 0xDFAB8F, 0x3AD2B3, 0x4A3828, 0xFFFF86, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x7FFF],
        CURVE_Gx: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0xCB44BA, 0xFF6769, 0xD1733, 0xDDFDA6, 0xB6C78C, 0x7D177D, 0xF9B2FF, 0x921EBF, 0xBA7833, 0x6AC0ED, 0x6F7A],
    };
    ROM_CURVE_MS255W.ctx = ctx;
    return ROM_CURVE_MS255W;
};

module.exports.ROM_CURVE_MS256E = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_MS256E = {

        // MS256 Edwards curve

        CURVE_A: -1,
        CURVE_B: [0x3BEE, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x22B4AD, 0x4E6F11, 0x64E5B8, 0xD0A6BC, 0x6AA55A, 0xFFFFBE, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x3FFF],
        CURVE_Gx: [0xD, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0x1CADBA, 0x6FB533, 0x3F707F, 0x824D30, 0x2A6D63, 0x46BFBE, 0xB39FA0, 0xA3D330, 0x1276DB, 0xB41E2A, 0x7D0A],
    };
    ROM_CURVE_MS256E.ctx = ctx;
    return ROM_CURVE_MS256E;
};

module.exports.ROM_CURVE_MS256M = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_MS256M = {

        // MS256 Montgomery curve

        CURVE_A: -61370,
        CURVE_B: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x22B4AD, 0x4E6F11, 0x64E5B8, 0xD0A6BC, 0x6AA55A, 0xFFFFBE, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x3FFF],
        CURVE_Gx: [0xb, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    };
    ROM_CURVE_MS256M.ctx = ctx;
    return ROM_CURVE_MS256M;
};

module.exports.ROM_CURVE_MS256W = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_MS256W = {

        // MS256 Weierstrass curve

        CURVE_A: -3,
        CURVE_B: [0x25581, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x51A825, 0x202947, 0x6020AB, 0xEA265C, 0x3C8275, 0xFFFFE4, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFF],
        CURVE_Gx: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0xB56C77, 0x6306C2, 0xC10BF4, 0x75894E, 0x2C2F93, 0xDD6BD0, 0x6CCEEE, 0xFC82C9, 0xE466D7, 0x1853C1, 0x696F],

    };
    ROM_CURVE_MS256W.ctx = ctx;
    return ROM_CURVE_MS256W;
};

module.exports.ROM_CURVE_NIST256 = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_NIST256 = {

        // NIST256 Curve 

        CURVE_A: -3,
        CURVE_B: [0xD2604B, 0x3C3E27, 0xF63BCE, 0xCC53B0, 0x1D06B0, 0x86BC65, 0x557698, 0xB3EBBD, 0x3A93E7, 0x35D8AA, 0x5AC6],
        CURVE_Order: [0x632551, 0xCAC2FC, 0x84F3B9, 0xA7179E, 0xE6FAAD, 0xFFFFBC, 0xFFFFFF, 0xFFFFFF, 0x0, 0xFFFF00, 0xFFFF],
        CURVE_Gx: [0x98C296, 0x3945D8, 0xA0F4A1, 0x2DEB33, 0x37D81, 0x40F277, 0xE563A4, 0xF8BCE6, 0x2C4247, 0xD1F2E1, 0x6B17],
        CURVE_Gy: [0xBF51F5, 0x406837, 0xCECBB6, 0x6B315E, 0xCE3357, 0x9E162B, 0x4A7C0F, 0x8EE7EB, 0x1A7F9B, 0x42E2FE, 0x4FE3],

    };
    ROM_CURVE_NIST256.ctx = ctx;
    return ROM_CURVE_NIST256;
};

module.exports.ROM_CURVE_NIST384 = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_NIST384 = {

        // NIST384 curve

        CURVE_A: -3,
        CURVE_B: [0x6C2AEF, 0x11DBA7, 0x74AA17, 0x51768C, 0x6398D8, 0x6B58CA, 0x5404E1, 0xA0447, 0x411203, 0x5DFD02, 0x607671, 0x4168C8, 0x56BE3F, 0x1311C0, 0xFB9F9, 0x17D3F1, 0xB331],
        CURVE_Order: [0x452973, 0x32D599, 0x6BB3B0, 0x45853B, 0x20DB24, 0x3BEB03, 0x7D0DCB, 0x31A6C0, 0x7FFFC7, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0xFFFF],
        CURVE_Gx: [0x760AB7, 0x3C70E4, 0x30E951, 0x7AA94B, 0x2F25DB, 0x470AA0, 0x20950A, 0x7BA0F0, 0x1B9859, 0x45174F, 0x3874ED, 0x56BA3, 0x71EF32, 0x71D638, 0x22C14D, 0x65115F, 0xAA87],
        CURVE_Gy: [0x6A0E5F, 0x3AF921, 0x75E90C, 0x6BF40C, 0xB1CE1, 0x18014C, 0x6D7C2E, 0x6D1889, 0x147CE9, 0x7A5134, 0x63D076, 0x16E14F, 0xBF929, 0x6BB3D3, 0x98B1B, 0x6F254B, 0x3617],

    };
    ROM_CURVE_NIST384.ctx = ctx;
    return ROM_CURVE_NIST384;
};

module.exports.ROM_CURVE_NIST521 = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_NIST521 = {

        // NIST521 curve

        CURVE_A: -3,
        CURVE_B: [0x503F00, 0x3FA8D6, 0x47BD14, 0x6961A7, 0x3DF883, 0x60E6AE, 0x4EEC6F, 0x29605E, 0x137B16, 0x23D8FD, 0x5864E5, 0x84F0A, 0x1918EF, 0x771691, 0x6CC57C, 0x392DCC, 0x6EA2DA, 0x6D0A81, 0x688682, 0x50FC94, 0x18E1C9, 0x27D72C, 0x1465],
        CURVE_Order: [0x386409, 0x6E3D22, 0x3AEDBE, 0x4CE23D, 0x5C9B88, 0x3A0776, 0x3DC269, 0x6600A4, 0x166B7F, 0x77E5F, 0x461A1E, 0x7FFFD2, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFF],
        CURVE_Gx: [0x65BD66, 0x7C6385, 0x6FE5F9, 0x2B5214, 0xB3C18, 0x1BC669, 0x68BFEA, 0xEE093, 0x5928FE, 0x6FDFCE, 0x52D79, 0x69EDD5, 0x7606B4, 0x3F0515, 0x4FED48, 0x409C82, 0x429C64, 0x472B68, 0x7B2D98, 0x4E6CF1, 0x70404E, 0x31C0D6, 0x31A1],
        CURVE_Gy: [0x516650, 0x28ED3F, 0x222FA, 0x139612, 0x47086A, 0x6C26A7, 0x4FEB41, 0x285C80, 0x2640C5, 0x32BDE8, 0x5FB9CA, 0x733164, 0x517273, 0x2F5F7, 0x66D11A, 0x2224AB, 0x5998F5, 0x58FA37, 0x297ED0, 0x22E4, 0x9A3BC, 0x252D4F, 0x460E],

    };
    ROM_CURVE_NIST521.ctx = ctx;
    return ROM_CURVE_NIST521;
};
},{}],21:[function(require,module,exports){
/*
	Licensed to the Apache Software Foundation (ASF) under one
	or more contributor license agreements.  See the NOTICE file
	distributed with this work for additional information
	regarding copyright ownership.  The ASF licenses this file
	to you under the Apache License, Version 2.0 (the
	"License"); you may not use this file except in compliance
	with the License.  You may obtain a copy of the License at
	
	http://www.apache.org/licenses/LICENSE-2.0
	Unless required by applicable law or agreed to in writing,
	software distributed under the License is distributed on an
	"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
	KIND, either express or implied.  See the License for the
	specific language governing permissions and limitations
	under the License.
*/

module.exports.ROM_FIELD_254MF = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_254MF = {
        // MF254 modulus
        Modulus: [0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x3F80],
        MConst: 0x3F81,

    };
    ROM_FIELD_254MF.ctx = ctx;
    return ROM_FIELD_254MF;
};
module.exports.ROM_FIELD_25519 = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_25519 = {
        // 25519 Curve Modulus
        Modulus: [0xFFFFED, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x7FFF],
        MConst: 19,
    };
    ROM_FIELD_25519.ctx = ctx;
    return ROM_FIELD_25519;
};
module.exports.ROM_FIELD_255MS = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_255MS = {
        // MS255 modulus
        Modulus: [0xFFFD03, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x7FFF],
        MConst: 0x2FD,
    };
    ROM_FIELD_255MS.ctx = ctx;
    return ROM_FIELD_255MS;
};
module.exports.ROM_FIELD_256MF = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_256MF = {
        // MF256 modulus
        Modulus: [0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFA7],
        MConst: 0xFFA8,
    };
    ROM_FIELD_256MF.ctx = ctx;
    return ROM_FIELD_256MF;
};
module.exports.ROM_FIELD_256MS = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_256MS = {
        // MS256 modulus
        Modulus: [0xFFFF43, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFF],
        MConst: 0xBD,
    };
    ROM_FIELD_256MS.ctx = ctx;
    return ROM_FIELD_256MS;
};
module.exports.ROM_FIELD_ANSSI = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_ANSSI = {
        // ANSSI modulus
        Modulus: [0x6E9C03, 0xF353D8, 0x6DE8FC, 0xABC8CA, 0x61ADBC, 0x435B39, 0xE8CE42, 0x10126D, 0x3AD58F, 0x178C0B, 0xF1FD],
        MConst: 0x4E1155,

    };
    ROM_FIELD_ANSSI.ctx = ctx;
    return ROM_FIELD_ANSSI;
};
module.exports.ROM_FIELD_BLS383 = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_BLS383 = {
        // BLS383 Modulus 
        Modulus: [0x2D556B, 0x556A55, 0x75EAB2, 0x23AFBA, 0x1BB01, 0x2BAEA4, 0x5CC20F, 0x758B67, 0x20F99, 0x640A63, 0x69A3A8, 0x6009AA, 0x2A7852, 0x20B8AA, 0x7DD718, 0x104054, 0x7AC5],
        MConst: 0x23D0BD,
        Fra: [0x34508B, 0x4B3525, 0x4D0CAE, 0x503777, 0x463DB7, 0x3BF78E, 0xD072C, 0x2AE9A0, 0x69D32D, 0x282C73, 0x1730DB, 0xCD9F8, 0x6AB98B, 0x7DC9B0, 0x1CBCC8, 0x7D8CC3, 0x5A5],
        Frb: [0x7904E0, 0xA352F, 0x28DE04, 0x537843, 0x3B7D49, 0x6FB715, 0x4FBAE2, 0x4AA1C7, 0x183C6C, 0x3BDDEF, 0x5272CD, 0x532FB2, 0x3FBEC7, 0x22EEF9, 0x611A4F, 0x12B391, 0x751F],
    };
    ROM_FIELD_BLS383.ctx = ctx;
    return ROM_FIELD_BLS383;
};
module.exports.ROM_FIELD_BN254 = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_BN254 = {
        // BN254 Modulus 
        Modulus: [0x13, 0x0, 0x13A700, 0x0, 0x210000, 0x861, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
        MConst: 0x9435E5,
        Fra: [0x2A6DE9, 0xE6C06F, 0xC2E17D, 0x4D3F77, 0x97492, 0x953F85, 0x50A846, 0xB6499B, 0x2E7C8C, 0x761921, 0x1B37],
        Frb: [0xD5922A, 0x193F90, 0x50C582, 0xB2C088, 0x178B6D, 0x6AC8DC, 0x2F57B9, 0x3EAB2, 0xD18375, 0xEE691E, 0x9EB],
    };
    ROM_FIELD_BN254.ctx = ctx;
    return ROM_FIELD_BN254;
};
module.exports.ROM_FIELD_BN254CX = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_BN254CX = {
        // BN254CX Modulus 
        Modulus: [0x1B55B3, 0x23EF5C, 0xE1BE66, 0x18093E, 0x3FD6EE, 0x66D324, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
        MConst: 0x789E85,
        Fra: [0xC80EA3, 0x83355, 0x215BD9, 0xF173F8, 0x677326, 0x189868, 0x8AACA7, 0xAFE18B, 0x3A0164, 0x82FA6, 0x1359],
        Frb: [0x534710, 0x1BBC06, 0xC0628D, 0x269546, 0xD863C7, 0x4E3ABB, 0xD9CDBC, 0xDC53, 0x3628A9, 0xF7D062, 0x10A6],
    };
    ROM_FIELD_BN254CX.ctx = ctx;
    return ROM_FIELD_BN254CX;
};
module.exports.ROM_FIELD_BRAINPOOL = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_BRAINPOOL = {
        // Brainpool modulus
        Modulus: [0x6E5377, 0x481D1F, 0x282013, 0xD52620, 0x3BF623, 0x8D726E, 0x909D83, 0x3E660A, 0xEEA9BC, 0x57DBA1, 0xA9FB],
        MConst: 0xFD89B9,
    };
    ROM_FIELD_BRAINPOOL.ctx = ctx;
    return ROM_FIELD_BRAINPOOL;
};
module.exports.ROM_FIELD_C41417 = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_FIELD_C41417 = {
        // C41417 modulus
        Modulus: [0x7FFFEF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF],
        MConst: 0x11,
    };
    ROM_FIELD_C41417.ctx = ctx;
    return ROM_FIELD_C41417;
};
module.exports.ROM_FIELD_GOLDILOCKS = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_GOLDILOCKS = {
        // GOLDILOCKS modulus
        Modulus: [0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7DFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FF],
        MConst: 0x1,

    };
    ROM_FIELD_GOLDILOCKS.ctx = ctx;
    return ROM_FIELD_GOLDILOCKS;
};
module.exports.ROM_FIELD_HIFIVE = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_HIFIVE = {
        // HIFIVE modulus
        Modulus: [0x7FFFFD, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3FFF],
        MConst: 0x3,

    };
    ROM_FIELD_HIFIVE.ctx = ctx;
    return ROM_FIELD_HIFIVE;
};
module.exports.ROM_FIELD_NIST256 = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_NIST256 = {
        // NIST256 Modulus 
        Modulus: [0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x0, 0x0, 0x0, 0x0, 0x1, 0xFFFF00, 0xFFFF],
        MConst: 0x1,

    };
    ROM_FIELD_NIST256.ctx = ctx;
    return ROM_FIELD_NIST256;
};
module.exports.ROM_FIELD_NIST384 = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_NIST384 = {
        // NIST384 modulus
        Modulus: [0x7FFFFF, 0x1FF, 0x0, 0x0, 0x7FFFF0, 0x7FDFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0xFFFF],
        MConst: 0x1,
    };
    ROM_FIELD_NIST384.ctx = ctx;
    return ROM_FIELD_NIST384;
};
module.exports.ROM_FIELD_NIST521 = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_NIST521 = {
        // NIST521 modulus
        Modulus: [0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFF],
        MConst: 0x1,
    };
    ROM_FIELD_NIST521.ctx = ctx;
    return ROM_FIELD_NIST521;
};
},{}],22:[function(require,module,exports){
/*
	Licensed to the Apache Software Foundation (ASF) under one
	or more contributor license agreements.  See the NOTICE file
	distributed with this work for additional information
	regarding copyright ownership.  The ASF licenses this file
	to you under the Apache License, Version 2.0 (the
	"License"); you may not use this file except in compliance
	with the License.  You may obtain a copy of the License at
	
	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing,
	software distributed under the License is distributed on an
	"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
	KIND, either express or implied.  See the License for the
	specific language governing permissions and limitations
	under the License.
*/

/* RSA API Functions */

module.exports.RSA = function(ctx) {

    var RSA = {
        RFS: ctx.BIG.MODBYTES * ctx.FF.FFLEN,
        SHA256: 32,
        SHA384: 48,
        SHA512: 64,

        HASH_TYPE: 32,

        /* SHAXXX identifier strings */
        SHA256ID: [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20],
        SHA384ID: [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30],
        SHA512ID: [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40],

        bytestohex: function(b) {
            var s = "";
            var len = b.length;
            var ch;

            for (var i = 0; i < len; i++) {
                ch = b[i];
                s += ((ch >>> 4) & 15).toString(16);
                s += (ch & 15).toString(16);

            }
            return s;
        },

        bytestostring: function(b) {
            var s = "";
            for (var i = 0; i < b.length; i++) {
                s += String.fromCharCode(b[i]);
            }
            return s;
        },

        stringtobytes: function(s) {
            var b = [];
            for (var i = 0; i < s.length; i++)
                b.push(s.charCodeAt(i));
            return b;
        },

        hashit: function(sha, A, n) {
            var R = [];
            if (sha == this.SHA256) {
                var H = new ctx.HASH256();
                if (A != null) H.process_array(A);
                if (n >= 0) H.process_num(n);
                R = H.hash();
            }
            if (sha == this.SHA384) {
                H = new ctx.HASH384();
                if (A != null) H.process_array(A);
                if (n >= 0) H.process_num(n);
                R = H.hash();
            }
            if (sha == this.SHA512) {
                H = new ctx.HASH512();
                if (A != null) H.process_array(A);
                if (n >= 0) H.process_num(n);
                R = H.hash();
            }
            return R;
        },

        KEY_PAIR: function(rng, e, PRIV, PUB) { /* IEEE1363 A16.11/A16.12 more or less */

            //	var m,r,bytes,hbytes,words,err,res=0;
            var n = PUB.n.length >> 1;
            var t = new ctx.FF(n);
            var p1 = new ctx.FF(n);
            var q1 = new ctx.FF(n);

            for (;;) {

                PRIV.p.random(rng);
                while (PRIV.p.lastbits(2) != 3) PRIV.p.inc(1);
                while (!ctx.FF.prime(PRIV.p, rng)) PRIV.p.inc(4);

                p1.copy(PRIV.p);
                p1.dec(1);

                if (p1.cfactor(e)) continue;
                break;
            }

            for (;;) {
                PRIV.q.random(rng);
                while (PRIV.q.lastbits(2) != 3) PRIV.q.inc(1);
                while (!ctx.FF.prime(PRIV.q, rng)) PRIV.q.inc(4);

                q1.copy(PRIV.q);
                q1.dec(1);

                if (q1.cfactor(e)) continue;
                break;
            }

            PUB.n = ctx.FF.mul(PRIV.p, PRIV.q);
            PUB.e = e;

            t.copy(p1);
            t.shr();
            PRIV.dp.set(e);
            PRIV.dp.invmodp(t);
            if (PRIV.dp.parity() === 0) PRIV.dp.add(t);
            PRIV.dp.norm();

            t.copy(q1);
            t.shr();
            PRIV.dq.set(e);
            PRIV.dq.invmodp(t);
            if (PRIV.dq.parity() === 0) PRIV.dq.add(t);
            PRIV.dq.norm();

            PRIV.c.copy(PRIV.p);
            PRIV.c.invmodp(PRIV.q);

            return;
        },

        /* Mask Generation Function */
        MGF1: function(sha, Z, olen, K) {
            var i, hlen = sha;
            var B = [];

            var counter, cthreshold, k = 0;
            for (i = 0; i < K.length; i++) K[i] = 0;

            cthreshold = Math.floor(olen / hlen);
            if (olen % hlen !== 0) cthreshold++;
            for (counter = 0; counter < cthreshold; counter++) {
                B = this.hashit(sha, Z, counter);
                if (k + hlen > olen)
                    for (i = 0; i < olen % hlen; i++) K[k++] = B[i];
                else
                    for (i = 0; i < hlen; i++) K[k++] = B[i];
            }
        },

        PKCS15: function(sha, m, w) {
            var olen = ctx.FF.FF_BITS / 8;
            var i, hlen = sha;
            var idlen = 19;

            if (olen < idlen + hlen + 10) return false;
            var H = this.hashit(sha, m, -1);

            for (i = 0; i < w.length; i++) w[i] = 0;
            i = 0;
            w[i++] = 0;
            w[i++] = 1;
            for (var j = 0; j < olen - idlen - hlen - 3; j++)
                w[i++] = 0xFF;
            w[i++] = 0;


            if (hlen == this.SHA256)
                for (var j = 0; j < idlen; j++) w[i++] = this.SHA256ID[j];
            if (hlen == this.SHA384)
                for (var j = 0; j < idlen; j++) w[i++] = this.SHA384ID[j];
            if (hlen == this.SHA512)
                for (var j = 0; j < idlen; j++) w[i++] = this.SHA512ID[j];

            for (var j = 0; j < hlen; j++)
                w[i++] = H[j];

            return true;
        },

        /* OAEP Message Encoding for Encryption */
        OAEP_ENCODE: function(sha, m, rng, p) {
            var i, slen, olen = RSA.RFS - 1;
            var mlen = m.length;
            var hlen, seedlen;
            var f = [];

            hlen = sha;
            var SEED = [];
            seedlen = hlen;

            if (mlen > olen - hlen - seedlen - 1) return null;

            var DBMASK = [];

            var h = this.hashit(sha, p, -1);
            for (i = 0; i < hlen; i++) f[i] = h[i];

            slen = olen - mlen - hlen - seedlen - 1;

            for (i = 0; i < slen; i++) f[hlen + i] = 0;
            f[hlen + slen] = 1;
            for (i = 0; i < mlen; i++) f[hlen + slen + 1 + i] = m[i];

            for (i = 0; i < seedlen; i++) SEED[i] = rng.getByte();
            this.MGF1(sha, SEED, olen - seedlen, DBMASK);

            for (i = 0; i < olen - seedlen; i++) DBMASK[i] ^= f[i];
            this.MGF1(sha, DBMASK, seedlen, f);

            for (i = 0; i < seedlen; i++) f[i] ^= SEED[i];

            for (i = 0; i < olen - seedlen; i++) f[i + seedlen] = DBMASK[i];

            /* pad to length RFS */
            var d = 1;
            for (i = RSA.RFS - 1; i >= d; i--)
                f[i] = f[i - d];
            for (i = d - 1; i >= 0; i--)
                f[i] = 0;

            return f;
        },

        /* OAEP Message Decoding for Decryption */
        OAEP_DECODE: function(sha, p, f) {
            var x, t;
            var comp;
            var i, k, olen = RSA.RFS - 1;
            var hlen, seedlen;

            hlen = sha;
            var SEED = [];
            seedlen = hlen;
            var CHASH = [];
            seedlen = hlen = sha;

            if (olen < seedlen + hlen + 1) return null;

            var DBMASK = [];
            for (i = 0; i < olen - seedlen; i++) DBMASK[i] = 0;

            if (f.length < RSA.RFS) {
                var d = RSA.RFS - f.length;
                for (i = RFS - 1; i >= d; i--)
                    f[i] = f[i - d];
                for (i = d - 1; i >= 0; i--)
                    f[i] = 0;

            }

            var h = this.hashit(sha, p, -1);
            for (i = 0; i < hlen; i++) CHASH[i] = h[i];

            x = f[0];

            for (i = seedlen; i < olen; i++)
                DBMASK[i - seedlen] = f[i + 1];

            this.MGF1(sha, DBMASK, seedlen, SEED);
            for (i = 0; i < seedlen; i++) SEED[i] ^= f[i + 1];
            this.MGF1(sha, SEED, olen - seedlen, f);
            for (i = 0; i < olen - seedlen; i++) DBMASK[i] ^= f[i];

            comp = true;
            for (i = 0; i < hlen; i++) {
                if (CHASH[i] != DBMASK[i]) comp = false;
            }

            for (i = 0; i < olen - seedlen - hlen; i++)
                DBMASK[i] = DBMASK[i + hlen];

            for (i = 0; i < hlen; i++)
                SEED[i] = CHASH[i] = 0;

            for (k = 0;; k++) {
                if (k >= olen - seedlen - hlen) return null;
                if (DBMASK[k] !== 0) break;
            }

            t = DBMASK[k];

            if (!comp || x !== 0 || t != 0x01) {
                for (i = 0; i < olen - seedlen; i++) DBMASK[i] = 0;
                return null;
            }

            var r = [];

            for (i = 0; i < olen - seedlen - hlen - k - 1; i++)
                r[i] = DBMASK[i + k + 1];

            for (i = 0; i < olen - seedlen; i++) DBMASK[i] = 0;

            return r;
        },

        /* destroy the Private Key structure */
        PRIVATE_KEY_KILL: function(PRIV) {
            PRIV.p.zero();
            PRIV.q.zero();
            PRIV.dp.zero();
            PRIV.dq.zero();
            PRIV.c.zero();
        },

        /* RSA encryption with the public key */
        ENCRYPT: function(PUB, F, G) {
            var n = PUB.n.getlen();
            var f = new ctx.FF(n);

            ctx.FF.fromBytes(f, F);

            f.power(PUB.e, PUB.n);

            f.toBytes(G);
        },

        /* RSA decryption with the private key */
        DECRYPT: function(PRIV, G, F) {
            var n = PRIV.p.getlen();
            var g = new ctx.FF(2 * n);

            ctx.FF.fromBytes(g, G);
            var jp = g.dmod(PRIV.p);
            var jq = g.dmod(PRIV.q);

            jp.skpow(PRIV.dp, PRIV.p);
            jq.skpow(PRIV.dq, PRIV.q);

            g.zero();
            g.dscopy(jp);
            jp.mod(PRIV.q);
            if (ctx.FF.comp(jp, jq) > 0) jq.add(PRIV.q);
            jq.sub(jp);
            jq.norm();

            var t = ctx.FF.mul(PRIV.c, jq);
            jq = t.dmod(PRIV.q);

            t = ctx.FF.mul(jq, PRIV.p);
            g.add(t);
            g.norm();

            g.toBytes(F);
        }
    };


    RSA.ctx = ctx;
    return RSA;
};

module.exports.rsa_private_key = function(ctx) {

    var rsa_private_key = function(n) {
        this.p = new ctx.FF(n);
        this.q = new ctx.FF(n);
        this.dp = new ctx.FF(n);
        this.dq = new ctx.FF(n);
        this.c = new ctx.FF(n);
    };

    rsa_private_key.ctx = ctx;
    return rsa_private_key;
};

module.exports.rsa_public_key = function(ctx) {

    var rsa_public_key = function(m) {
        this.e = 0;
        this.n = new ctx.FF(m);
    };

    rsa_public_key.ctx = ctx;
    return rsa_public_key;
};
},{}],23:[function(require,module,exports){
/*
	Licensed to the Apache Software Foundation (ASF) under one
	or more contributor license agreements.  See the NOTICE file
	distributed with this work for additional information
	regarding copyright ownership.  The ASF licenses this file
	to you under the Apache License, Version 2.0 (the
	"License"); you may not use this file except in compliance
	with the License.  You may obtain a copy of the License at
	
	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing,
	software distributed under the License is distributed on an
	"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
	KIND, either express or implied.  See the License for the
	specific language governing permissions and limitations
	under the License.
*/

/* rudimentary unsigned 64-bit type for SHA384 and SHA512 */

module.exports.UInt64 = function(ctx) {

    var UInt64 = function(top, bot) {
        this.top = top;
        this.bot = bot;
    };

    UInt64.prototype = {
        add: function(y) {
            var t = (this.bot >>> 0) + (y.bot >>> 0);
            var low = t >>> 0;
            var high = (this.top >>> 0) + (y.top >>> 0);

            this.bot = low;
            if (low != t)
                this.top = (high + 1) >>> 0;
            else
                this.top = high;

            return this;
        },
        copy: function() {
            var r = new UInt64(this.top, this.bot);
            return r;
        },
        shlb: function() {
            var t = this.bot >>> 24;
            this.top = t + (this.top << 8);
            this.bot <<= 8;
            return this;
        }
    };
    UInt64.ctx = ctx;
    return UInt64;
};
},{}],24:[function(require,module,exports){
module.exports=[
{"PrivP" : "f6f575715c4bdf42801110aa872083fdfe161ec5b1cdb24f118f43f9e6f5e4eb09396c27c54595a555f9f45c04ba30a6caf275a15a4961043d8ff6abd31b9bcd499236587e0e0799bd357c91f4f67fb3650fce7e98aecb6ac849e7965e806c185edd5a81d21f1f9173271d6595117dffb12fa604a4caf5e298694f56e65f543b", "PrivQ" : "b217ecd0264bed14172aaa5dfd53d90c7dcbf9eb2545c003c4e4899cdda0000b489bc762fbe7e6e18534c81acaed3a46c7888467e2ba9f39cdad6995b65e80a7a97eff9f9642016f79a37ad307b6e5f70f17614ab0b31db309f012b5a82aa72feb8c18a89c3b10717cca61c452b982a00e4e5a5ba3193f5714c37ea414beea0b", "PrivDP" : "a42e97bf9faec964faa35dc32146dab9979cb924918ac10a940ffd0f3d1f28eba11c4ded3ad7821f834343d39148ff6343f56182bdf59ecc24e97b02ccbcc41dfcd579cfe72e089b8b10ee1a531335dedc475fef062edf09c4d26d66a8b91424379d4db8952b1fdfa100d6285cac5e6a0930365d4bf9aaf2d484debc5537f755", "PrivDQ" : "300b6447830d5897e2e80fadeb7983446b6b6bb0940d8d0f773e70217168889a82ac03ce20471f72178d75ae44b05ad85d5be6dc5fbe18d66f362915ca6d14282701abd451a4dcde45e2647029d49d9558ece5c2508901aa1b3438d7e8d618e4449736cfc5d5e949b470a48f6201c9cb84107f2fd980262647e3b5766e6252a1", "PrivC" : "6c2fefc7c97b1c5cd2db12b77a5b1bbd42fef79b68b0ce5b7120344bcd165e8c849da00661bf7f502066f1655e56067ba493b8d550f3fa70a4ad10c2c4c799b786aa41ae1e5ba6be8751a5c99792f34fd5663fbf8f7de44ae64683f0019c0e2ca641d187cc14b94cc04c074813e43118b684d0bcb8ee082bd29af674699431e8",  "PubN" : "abcdc0297401a74b16a5b60eb50bed0ff7fc20e5d1611a0d22edb9188078271b729a412aee73077a77730232e31c24dc3573e5758a3415c112f8b375ad5dd3902eba2c93e5ed14db2bfbb9c18e3f8f14518b94cc39695626bca9a1463ae32e756e847c0b58898dad7db92581501f20517d02d5ab44987db9e3a2ccb0512d952f2d2b82c8577749445f3099df6c103ee646ce1091a4c61dd5d775d5c5eb3df4249f61d7aa0fb418b425fc4af0362a95940963b38bd90aa35cf4cdb3384b3abdba5fc1a10a032e7407ccbcb8b80f23316c11974370982888dc1e6baf9b8dbcf5a291ba85a0e63b06994ff81922323c68e54ba123680826b3b5c102447028e08c89", "PubE" : 65537},
{"PrivP" : "fff866a5cb444b5e30772752049de1960e6d212de8bec02e95685a795a520db0f345604c0641609411ad7be56357644003ddc37db1f0df2543787786bf0394d4683ecac5d125959340fa670f311291b154eb195363f8593a78c9430f90ad29f4326018a7a7132421ce82064e85f56d4684b4af9268162f74664d91fd4068241b", "PrivQ" : "c66776f3fa65ddbc9fdb964604888ab1ac21db98291f9eed117f2b87c6123fa1b008eb8f942d7f10c5e2a1945dc84c64e57a3e57db42e9a69b0355a73415a589daad2ebacbedbf4e4324636aa8f272d5b8d6d7d1b8377d8b8eb166924cef0978366fba2cd1e096ef76be3f11bab34edda42d67d723051730277ebc485cc7effb", "PrivDP" : "92de10ef8200ae89dd9f107593e68ec00d88fa27a04a8a74700f8f11e00c02850c203b4f83ab5161c3fed97ed590181a4edd98446fabb82d665821a4b3c6b7476484dacdc3e21fbf7ce1efee1c86fe0754a50c43f7b150692752bb629bed6f8c08b7708e096407304a8ffa5465b25b3fc1f6f66237ccbaefbb9f386ba9dfd70f", "PrivDQ" : "1ee10b8a7d764d44863cceeea6d5f9801da247632f4354a0e11041de27ddbf39930450655052a46c1fe05df591831320c0f67dad7edab332d2fd79df4423fa57b24931f4b0b89805be3d739bae1fcdefa58d0a9a0169e1884ef51d59b7cf9c51b167423aa78fa4ee3034fbebee7ae9d365320bef57ebfae7ebbdb5e02d5090f1", "PrivC" : "0cbaa1c587add6b8f77ee7aae03d62b6c9c6bc95f26a1d4e8861e13eaf2f5467345a646c038535864c458ecf16a18a0086b0b1e1c300fa3e92f735d81671c34f23feaf330da2cc6cc10f57be4ece06e3929a616f7154238d4a57b48b6909e913642e774737085a5cdf41201d8ca5e280b06c3b7ebe27ec9c270db3bd79a85934",  "PubN" : "c6619345fa63e4cb0bbbda62792f2a504aa6992fdbffe1053d360eaf33885df96423e5395a9b51bebc31678e97e24cc8e812d942a9290171b73d107879c8072a6efca8a100e40f8c2fedd761e9fb68294fe7a91cefc39bc081382199b3eeeae10cb4ef2109b2d44f82352a3312747f0339f9de41b257bd6b061277066751331fe4fc75666ea559afbd89413e6a745bdbb61e212f9ea050ec561a37952fce4a8f32b23d9a584ef095503ac4f7347d9afe865c225177ff45d62ecd546ad846a7035560b666e642f298a4ff6bbe2b3ad09710e6824eb53cff71e63075c3efc89163f00ef4f76b78aac66b619ff810f57830d06584397d1666beb2740bf524cd9b79", "PubE" : 65537},
{"PrivP" : "d985f38e25fc4de6045dc7a998893633080c01514c0f4771f711951918dfe2e9c59565e787f5a33941e8433e27c81924c1017bee446106859294b08ea214b6cf4d0767b94e48923098a94190a7dba3522382e6f415e37d3527106da45002e2b382d091e2806293313a2405bc4adbd14905f744a05c47e2ea5ed23aa2e8d1ab47", "PrivQ" : "9b96312e23a3834e0b696c2340b03170fdcff4684a316889b5813036a4269ea87c74c0b657abaafc8d0254367173015a5000fcebadacda737919b2b5eeb3ec51f2143fa91c1063ca623ea07f068e0354bb1d9694fa9c12ce3df841095b74b6201c76df4aa724c1a294275797e232ef3417b3c3fb2e5c86da1fd6498d6537106f", "PrivDP" : "1f51a60ba5747a52cff620b54e7d130cadefec90a3fedf2e8d803e936a7d71d26edc5fdbc23b9fd0b2a89a65ec9c66e25fd7b2dc4f8418c84a9e95fd3361002140d9fc19362844c43276cc35e3b54002a7924566877045aacd811408406ce9ef26ba99069fad91bbd8bf2f04395305031a94cb90bb38ae774847c4a1881c0829", "PrivDQ" : "84fd0218a019d9d851e4d0abe955314d9585b53197895803ad833984db16afb2f07e9362c8d9519401aba5f3cb51342cd009a826831326be611ad828ae5a587b4ae287efb2af47bcebf1001ad3ad7ba76731494f1a4f61bbac3890cec0bfa815167f7d29406928a220e4e7f8493ea43bf0ae95ac13dabee19f28f941c4ec263d", "PrivC" : "5ae76b451c8b6fcc1ca8a093b03cf2c5a121771e2f6f6483b0a7fc99337f5ac7f9d4f36c352492ed29f6a48ec23541defc1cfaeb4b257cc44ab848b5fcab52b251db17822b390af182a9272099aa58be353fa5030e6120fc189fbb51e14464fed01f6d42b804c519a07b686d41d3b79e04870aa055544a3516f43f4fde01b77d",  "PubN" : "8433b8bd9e423df8668253579b8cb87e0f628975ef000fb00d412fe6d075d5f07e014744a491adfac1a409f06cf2c4a7a0bd015ca61b097ef11b5df5f29edd0b8eb1856114290b6c7e08c173e77987202f5a16ace5d5c3d15d54206e56ff19206882490dfdf30d6daf5ee6cf21c4c0874db78b9daa11ecbb28c3e7fa511b660dc410b43efc74a867fc7a036dd6eeff1faaa250d8fd59f74cae8e0352afc189c8f9e22df8cd7a35ca3584966964fc48fc4f4991f3dd132131ba85c64b998be286ae661ed255c9942204238aca7547a0ea0c8596ea1ffc840043b6c5189d9b3790e8576c26dea6a4dd2665784955a6913ab2d81090f5b7216feb58ede9dcdeb3c9", "PubE" : 65537},
{"PrivP" : "ae9a8aa7ff27fa61e4156eccbcf06181bda4e0b1f390a24153c918419b310bca385a95692f7fb19882c0dcdcc4997d2ce3a4a32f9116c8123bf251fa9892a8f625701864cd9a6834b6830eecd11fc017ada90b3e80a2c9e5cf8dd66b1316ea1842b27bf06a03fcea6ae31949ffa5bf64d7b6118e85f44d5a6b4b5b124a515ea3", "PrivQ" : "80097eaffa0a7c9ebd99f81298d249711eb6d846239beea514e1df456802922201555cee206379fd96969d0da13ccc1d6d27b9ebbccef5a6b5339a4eea140197c882e50c3ba4d77d3c1bcc5f4d97ff1d8fb09a887ae7e90a2a3299747e19ba3fed9395f276d78520f41a8bac9a7e5f98df71a272c8afc4d74d8f396cd6d8bedf", "PrivDP" : "0257824a948a85ba3063f5337bc941958ae49e3ae4c868d4b579fa004f438e23ed3391d37256a51c258ccea98b5d7fa74d7a54d1fb8131b7c4e410236b4e7443b0e6dafce7210e0abef3ed0c5215b9eed75e700f2b8c8366b8acef564a50415d87ef7ae81393f01d78c788fc4c187e03ad3cfce94b74a660f31574a83f24ee3f", "PrivDQ" : "49ea3152d21c7fb8fc68088863e4f234f5b044c6a903fa0f1f310e3df93f92b142e7ced041ae6bdc73b4db51e5053e28b6bd3a5dd70ffb4c944b08080aa6260d43da1cf4a4f212dcdf7884d177f0097d3d588cbdc186644853f80612f44151fe59dedbafafdfd7a1208aba9b984ce04f569f3952de7c6a3c892fe7cce773152d", "PrivC" : "4277307a4c613bf7011c22bd1bb0bd5d1d762de7186fc6f082e272faead2d9b6794f101cc6d607c422c31dedd30eefe45246857e46d42aa27cd2488f739e00d93babddef411d40c22f9f411b54df7ff25f47ae48086d15f730c482f481acd982b516f9d27fdca3cb895b8fbedb5e9d86199648b1e191dfd97bdadbb8b19b1e87",  "PubN" : "5753bf2af5e9807672a5249c3e91d3057b60d91d6e898486254c2be8e2ece9710597e1fae4626204f27518058783a5899267be41b8feb4fc02114e62ec839779355a2f0f1734dd7fa6545499bbff2600367c6010fbb2ebfdfc6486eb391558978ba7040370bb610fb9fe385882649da2d254e401323e2acbbfafe807a791e1761eea9db73570c8867fef546e69d0fc251317b54767a47fe5269f51ff9866fd20e70fe0fba6ae7397c393070cfcc145f7af133c2a265344f6bf21f2e4ec20bd07d513d143fb60af7b70593f1b09c72d21a560e6682347bd0c0833e8792f71abec59a73957a0c913e97fe419fa54271efaff93d64a060fc52ee23dd99f3ca669fd", "PubE" : 65537},
{"PrivP" : "9cd32fee83c1f359fd16527bbedf1ef57b07a14c9767ca2ba0914992cbc7991bdcea5ab3637363c61737249a456ff64a1954ca664856f522b209ca67675b0cc6e55520ff7c929a8031f0469bc45edc552b9bf8a321b40ad5098a4f40c667ba6fac69242ab50d7aceace53f14e9c5a4e8ad74ced2e557b16b270bbbbc052ad547", "PrivQ" : "93f9b234e2f0adb896f4f6012dfe2c53ec4d2d927ecdb84b2379b58d8e3e9b083c69d773105b0302a30d3f5aab1fa8dadd288f6384c5039ec490603a33634104629f215cd016c2533565d29207b7d2f9b848b14a8d7d980cc413cddbd1a6d56b7a958cd326c02daa5a6796598e18f8c08a45487bf6c7bbfec2121f99515f3217", "PrivDP" : "67e906b96353ff8a80c7699fd4b8c22aa57a48c6170c0e4919fb2a64b9e166f1af4f190a03bb5140cfe119bf9e82b10e27faa6a15f0d3f1fde17dea4e536cf207a940d693b81681dc8f90bcfea2d70907e74ba2a5d0a8ea2d9cf6af3e0829a65a437865f45d7c8a768a7fd443e21574354ab30df4c56ee97b127751cffcf81c1", "PrivDQ" : "72696dd05667a0ea484dbea7cad7eb8e37f6b475c0756f392984c14b61e0261e88178dedf987651c74d5995691593945801a0c43f6341e4873d2ed9412877b8dd8731168a1bbf7243ef52b8a9d4d1462e089d40ac0bb8b04d3d63c24ea45045ec5b93bd946ecf061f6e480eb5d6311724d76a444b4da5a10f01cf331a828e2a1", "PrivC" : "7aa72f1e80c613afb6d28ed4434950ec30ef3c59eb298287025069009f9165c3cb2a36aceb5b08ec68a31e46dbe173b938cf25414704824cb0354f04fffe58a3fcfef09c9b634f692c549023641f9be297c74f8418393b0c60e221cad7252c6a13e8294bff95caf581b3f6b1fcea4cdf8e20fcdf1b1075817ca65ae16673e752",  "PubN" : "5aa63b1ad1e5fb2b490a2b89ab17b4364c81e5dbeb8c0d7eff57cebfa4cb421e3a12c08d88879d6c9c8225ffecdcae9985238b6ef7cd4a91d0effd255f9b4450ec5189c04dee2732729f291f16fd7b803190e00943ceb06d1463dec8254c209213afc564839d09f5d300e958492bb64c0305282505ed88e02736cfc9d0f711e35d55681ee0c9efa9df22a0aa045bb6a6e7af83192fa4438eea876afca7af50dad2370835c5c56dec8274825f0e4d30b7c32314ec72654b1733f0d00f5d6f94db0db9ae31d9f8669a1dff8e49b6a06faac67251f7d0adc106249bcfa74b1363121e30af8288d3b3706863765ad9648cea735580f659035616088c1fb670da0761", "PubE" : 65537}
]
},{}],25:[function(require,module,exports){
module.exports=[
{"PrivP" : "87f06e9818cc284b03f96c9f3eb124df4fe9ec05671a63a5dd89e416071f221778325ceb92ae12dbbecd9c0b26125127f897c2545f912a3d050aa5df9491fa70251e24dfbabfe22b817c4fbce8ffedcb9eaa1a265d3930d40ed468cf04c3619ba208f1bd5fae9b41076222d55811b305ffaaee42dfa038513b504278ca878d1d46162d856533262cc40f881d75051ab7cecef5be60707001a9492a3be05860097a60dee06c3e921bd61285f09cc4339219128439e2edd613b59887bedb643267", "PrivQ" : "ba6574252e6070cdb40c7496be4658f78c75f735f512dcf1e66a3859db28acd48601e54adf349ac3820cc4c05f6725564b7ae1e384e1280a49b5f207605db25f0143664d6abc62a950444778b8993574d2dc4c986bf28eb34c373a0a63d88ca1593c50b080737bc68bda961887c7126b29d882a59c8989accb60d6e0b083b0b0a19bd7d1fd2f681479fed87cba719025a8c3282255556b9f33ae4d7b6e172a2ee94797edbe476c9c09cf5b430974b0c8c98c7df66c13a57432266ed418766d93", "PrivDP" : "4c7e60dd3966f86d6de916d46d24a548fbe0f7acfa9d80e13ece6f086e2d78b398314ed4488fa790fbc71b3db2c8afde3c26b9755ce984c91d63267faf4c8d8e3974c2ef1a590b5dcbd935cd69974a2a40381bcae6be5dd99616b47b7984b0123195b2e20b4b6795aa1ff0d5f85ecd4c5cd7c486e0eb79854c49177e7d08d5c15944f58c90abbd998721ee4815273027aa3a0f5277560dd1017f6842953565a52fb5fef46e34af66f68929d181856e3791e03783934c9e202d198d993a3f2195", "PrivDQ" : "7135ffa63995cfcdd0a6a4058ec9f16d617da0c9bff1560b0294cf671c2a875689920b2f3f8496df5a54e107aaaa5e4e1c88253ce84f4cdf7ac7ac99f858d066cdc09f193453f964b6e0d1bc2bfaba321b843c6d735b1e7b1e3688e518a1c540968f80bec335e11ec580dd1b47148d465363326ede35d74e0134ef2e0767e4e05337f18c9447bfe277fa6688d340f8793718597f08ef59ef97172dee62fe64db9b4aa5a77ba3abfed622805ea6169eed452534b8800a2abaf95ec87fbfdfe64b", "PrivC" : "31468c7d28ea7d6cc182793ab6a17ea2254a8dc62125acd823e2486d5f6a585d89c388121d20516f48415d9518a62c9c33e21e272acf878d1afa7cbc167dc18bf8f7f84f3ee6fe24ab3eef4a693e21dcdfb04410d8339041328979bb8d4975fb9c14ca93b85ee7e0307f361c87a0ddd2bd5ebfe052e42464222b491c9a7fb8e1fa91d44afb4380186c2033f2ac79dcce52343674fef24f36da34becc6e6799b0fdc6d709b63501e39d8612d1fcd13a7105d4b87e9b9a1114162b67d8d00e1694",  "PubN" : "62fa8fe2d4836ef9b7445c5b0932ec49ad7b94b9cec88c90ac7e67b4096c4440bc9d46455ffcb59c1b0dbff104cfbba6977de976371ec9a200eff119d2945d6c94599f88c610a5290d062102b754dffbdfd1f6962ec66e160b9b17a5c4e83a763a3fe6f497263c2e69a6a5c279a5809721b3fc933460f5d4766068e12fbe54ce3d1f16dc4887641c8039ac7e23adc6e56b92a086e6735be3e8d067dfa3bee29098005accb82428d142d3f66fb36ab161849bf8498a6e3c9fe6f2f182b1fa6c900227f1d6d0e132f3a1c0238bf5ce00c4a803ba64230e1e42b1677d8479b1aa4d88e487d027de2e589c35f442daf54ba2612f7135e0519d2c190e94d3d92abccab2c2821598b6e331a3ab232431a50e160bbf19eef8f10e7f1dfd46b3167ece9a21a1526c115654ffe04349329ac44c95cf427c136db1df87b453829fc68ad9c05d67a4145740d3a2735201f9377144380aaf8790051e58e412f8470c0e0e264fecf35b2ad26b55c410aea6a6d049a0fcc5c6c5a0a22f1b6204d8ba368778cc25", "PubE" : 65537},
{"PrivP" : "f2c39f07a69a108bd47390dd5cd1b2408253e0bf92f82d2cf755dba5ffa47da06320b2be26068cdba310cf7fb41d80c5ac69242ab50d7aceace53f14e9c5a4e8ad74ced2e557b16b270bbbbc052ad128e5d6744eb4ecd5486a2e5be802d725fd1954ca664856f522b209ca67675b0cc6e55520ff7c929a8031f0469bc45edc552b9bf8a321b40ad5098a4f40c667ba6f9cd32fee83c1f359fd16527bbedf1ef57b07a14c9767ca2ba0914992cbc7991bdcea5ab3637363c61737249a456ff95f", "PrivQ" : "8d617f64574f6d1e15bfe4f8545c2df81e83620d50b6c1332bd5049bcfa405cfe243b6e9acafa04bdfdae29420d7656fa48a4d2c18b8afccb52420c6f2257da85286d2b3e52c2a47840360642a06318240e43a37eabf8767119dd4208a6bc430b9ba898670b1cbb782ab1950b4ca0840fe5a244134f2a225232946cb19b4bf41e8c2c686ed8d296fd0810d6e6baeaf3ef7bbca93e41d914a145c6bc137237838b3ef44ba11975538b6ebafc23db9ac6a3700a9add4679c0a686145df1d6240c3", "PrivDP" : "7b7ece58bb04e6e3eb38bafa112ccfac07609a157ab36b6fd386c6cd24464e6e17df5b6e65b3b1564e16d027dbbda2736ca8b3f051d840a000ce420fe67857d2d1e279104a01194d3438c0d0fe23f0f10832d749eeba0829e5721de8e20106df4152a3fff24ee2373b30c5d96277ac01464acf15890e9f3015b77083ef1a7ea58920b8146ca1c55ce894868aa223c470e0eb8217a8c9327d95c51442c52f85f54517f5931bf67d9f41f886dff9705950164ad5c72a115a313c401e0ba8c534ab", "PrivDQ" : "06771ff141c0e3178e1d11667dcd1d590c642bb6ba2b31589ab78a1769fe7139997a494214608faf0894a4e9eb3a8e6bf595518423b94668d11bced7ea38e6af2cdef781bc883182c5b9b5cdbed23baf5e3251ab3ef3f5483459085b58992706a767ad645580fbf4ef67cda7902cf105afdc056e69f27291ca32d806efad01560d43e2fa46a0bef55b0e9bc3a1ef021a9a0f9f6af5f29833500d0dec6f0e13305ca2237d72d27dd6331f42115aeb43c433b1b710b8f6e7feddd91cede0151f2b", "PrivC" : "2ca5c175cf8e76e640b05d4b5a9b94f00a5beacd928082ff439409d7cd28cf95067f567eb29ffe012b5d2cb56acbd9cea9f499828e3ec60913012fcab696186748b0ee212da17617b5444d39c6946a8ebe802f8ddfd880395399fa4a0f918aade4bd2ff7425d9ca6f706ac5dbc50313a32985ec892a84f6bf93ed3bc30a0a3b939aa83b251340765398712b661c5b56b196f61b85afd7df783e9df060323de17eb5d551a40d441bfacb84b5482dd98b37d53912a76a5436796e3a2ebfba71245",  "PubN" : "86123384abc3b3044aa0aab8dff9cc0f28333f2b5c1fdbf564e5c126a7eaf49880c85418773390fb14460dcf00d9fa05b2dcf843fa4834004a6fe1972ae8f66e7758c1ed45a54cff87d5905f45b106fb56f311499cf66d896d91ec0f1fe39fedeb7c37b6c780c7c0c0fdce0d4686fa84241f98578263b42875dd1c743cd10b3b7e2b81469d7014c97289eb59655963af1c89649f5ad26a9673190047c8e552bdb714b02c5704cd089c0ead1298d851d01c226dbcc70cb2685f010a95ef272bf0c0a1d791b84147e970888a9b4dca1274f7121991241169aa8b76169327789d44654ece944b8c14d4a13558c9c1e29cbb0a6c1866b262377a30bdb50759ecf602e5dfa7d259e76f9f7c07918b6a4c07243728eae62104cb0b36f67e48c331418942b736e4a6ae5f91e60598d625dae0bf789a834e394816f96db8d8bfea21930703517207fc7eccd9c0bbb7c5ddc4ab26fb83684bdafebc95a9507b1ede538869356f4e884dc62bcdfc8f368e311cf6272a58eba8d06b8d7eb4d38bbd1c00b35d", "PubE" : 65537},
{"PrivP" : "95eb23fcbe3d7cf80f8848ca6e34d8ba8b6395eca5b1a3d1cfa1f28fd34043b15310877c19f2e0b528d4d38c97b06a9d42b27bf06a03fcea6ae31949ffa5bf64d7b6118e85f44d5a6b4b5b124a515bf82c889be3eaf68cbfa060db23ef871adce3a4a32f9116c8123bf251fa9892a8f625701864cd9a6834b6830eecd11fc017ada90b3e80a2c9e5cf8dd66b1316ea18ae9a8aa7ff27fa61e4156eccbcf06181bda4e0b1f390a24153c918419b310bca385a95692f7fb19882c0dcdcc499981f", "PrivQ" : "f8c7f431a642f2ce7d764c177901546ee4db875150d60d0e40e2d8ec9cac85ef400807747aa437835c4bf669cf03bce10b01af50057afa711ef9261d4c801d66f54edd638cd194bf0e6ec6ed2208ae05c5d6bd3d0dc883302af5d386889bb6799a6e3a05214d21275b08c78143278746bee2fa37cd506faac4118670c3be485ba8e99aab3c335cba728bb2685f7b89ed64b537fc41659902cb6d28327fd5808fa2104b107ed0f91231660649f2ce4000558333defae7d439dd4194e8067c667b", "PrivDP" : "55a1264001856b70e0a64e3559b753a75160834cd4e35f17c309d45b34257bc4b81633dcbd918da9cbf5ac139cbcc658a6b4fdb7b74629dad74c79b05b9617790900d48c5c94caedff64de52d7221b6ee838eb19c6a62684799d78edd0ad91b96349317044e60746eaf8a0bc8b1311f0ee3755a7960c40c303105ea1035da8419e0e74feb148ca1b3a6ee06eee4b6350cfc233ba7b322180725f8f96dfc049616aa9d731ad560a6757ecffaed16eb5363ef3f66d4b151ba269e4b1026444faaf", "PrivDQ" : "a82d0b8fd0b42b4d9994b1c5a0605cc286653ce9a47abee2a6cc731628a79bf6eb53422ee485449dc173fc84f493b3487257563b03296a49b4457b158d54820bcac2e0785e86834650ac643f83a55876c091f4e563feeb68517252e6fc4c3f239f58ea51f37c1f706a62d9f3310174ba476a4afa140a4f22a25eb2826260acab81d9415c865ab651b80365bc96e77d8b046c590766f21668c439eb5590033560638f1e1f6d8b3904aa6e2ccc2a9e70b7891723a695f8c807c1e18696ff637327", "PrivC" : "a607f6e5800f6a7d137a7bf79355be5b2e899b952e960173025dda7f5786e5745e253548d931709678f1aa909f84c061b81fa39cccd96ba3122ce87874001cebae53c45abd098db3dc481a92a805b8d92556dc9a8fbd90eb8036fe13dbb35f6d09a0e6e58510eef20589d7bc33442ccc5317b3e03e339894aadc09048d01b4add81d56f59c35bde810069783773dd8d5e2dc2ea885479073c613b0dd1c67445f8b3bb9f541e215ab475ec8798ccc1822623a29ad2b34bfb48cfc85a56b856599",  "PubN" : "91b0e3a7036fe9b5d7fb575c6349115fc82d7b7c47623622c5f768b2c160abd6dfba0df30dcd18e12b95c045476d7d118d7606d9b4aaa933ff6e7effa15cfb820ffea9cb5b1212d676f6ae6736cf8bb8bd9f6fb5466a27e70740099346927d401956ca1722f3063a812f968331866c790a2858bee3fc3fc819aca71c060a417172c58f91fcbf93c14df9a0b12b810c37c5f71aa33f8a6b33958c21cf4a012b565635eac7cf61cb03149bc80695719ea2cdc0eded7acc7e39ca80acdc22dea8c94e0ba099df19eced38f61512dd8cdc40430708779567b95a3c0b1a71ae638384b6a889c5c0ea466b456cea1ecbce152a71b389e7f1d5c82736d95bf6e46215f755d14f83e4af6874e528ec9cdd0e8ad485019e0cc4e4e40615cb85aab5241ca4acf7b39e1f7f0569a7caea3dfeae8bf4658170511de42ae34b2f0c86ff20ab7005343fb296d58bac55e10dcf5246d5176097c89b0bf0ee4ff27b7c723af2e3e18805a5077c2ff59a52282e577dff322f9084feea7670caec2c37b076116c70e5", "PubE" : 65537},
{"PrivP" : "a5ca7ac0129fa3588cd01a2b57d6ae4ef0370232967f6f654e7f7ee77391140842afab3326d883bcb8a719ec1c321c8fd3f179ebcd5aff595d32db9e7f8c9af52ed7ac924291f76531c76315e64ea73abd4d0a519540f534561d24801abb1ec83c9c23daab1561b48300c9ee73000ec927bdcc2826015c2ac46e916775b9294c5f9458176463b047181a3e5c5c844c249ece92cc5b3489b1de3f47c1dd134d54693c78b8ed13f2d2820390ce6424e513d6d14b37cebc891469a22025429325b3", "PrivQ" : "f19cd1a8115c6905dc1ce2a6780447de485c0aec7d3d4e4fbc9b55fb0082aa85777af3e2561099fd6aa39a1b2e257c30e01cfd310e88e5049b220ae0176600f589694e79aeb0557809280e9dd305b505ba138d362c4a08fd7b9871a2257ea6f0e4320cb66ea25aff694e27d35533ca4965d68e1489b15d5ba88245272bc62e8597bc661690fd4e37111690db4f8b55f8dfa443b7f161e7a0835c65e9b7cba11e3ebe015be62a2489fbb26eebfbc1c64d353fa322a9de0b9389f9a83bc34376a3", "PrivDP" : "8c6a4b40760582c132b1e61823930d9a89d4ed258f556b3170248784dbda5a0f0cfbdf91b92ad3987903fdee7d8aeba9dd25bdcf3ae40134dcbc80496359e0bc1bea4a9cad8916f13c11d517ed315c6d617ae86c646ed9be73d8c6db40c88eafa4b5d1a0181a49e02abbf64ae057822e585c6596f3695f78515a1c08762a5691fab9974a689a0de888bf6165b46dd0578bb1059fd2f7524fb51dff56703932db752de4492b7223ccaa94fe85ef4758454f417fe54a5160004bdf263ea87e1c05", "PrivDQ" : "85eec145a24210b1bfdf7f407a5d1d1dba0cd3bd5e7b6272cf0168bb180056d85f7017cb8a9bef50cc115eb6dc70c9142ad7c6feafa8f113098fe8696a6f0fef0c3a04d76d1fb07136da2ea80c3728aec1045f8dfd251930b297c1bdf97ce8bbb6338c5a809f9d43e23301dea3676f261abec1c9debe241b5020ce86b53c49c3a2663c4d1c185e8825ffd552cd185712fb9e0a2fe82db68182eff04a8ba8e46a68ab59038166311510224c5ca2153b80c718bcacd56f1209ba3d5ba5ad4b3373", "PrivC" : "bf08586f9a28b057ae5626558b84c93265ae23225cd6e4cb039ed58e6048c954a763d19bdece12e491144dc64dfa7cafe509e7c31a0c0735ed37f4b19dacd2e7e2b08d2c78202be7b59de90e41eac9255a2c45a8204cb614558bbe9a370bb33cf79e6a612977b19a0047c5b065627ab56df4bf0dc1ca786625dbacf2531f78b51bad4b9b20d48adb25fd6344894f328c296d800259820afb2da574eeb6c7882905d38159a9d49888a986994d8b92b35b1eda85d747565b27c1fc484fc32c3465",  "PubN" : "9c792cb8c4e94a3d29c1638b86b93126dd47d73dfba24bddc5f340408359dec19b6418bcba2c1c9fe69a3bf865d45bb529915a74d0f8a68523c1b691a6b25268bc415cd983feaba8f06c22c0fbec1fbf10ac35debf8bfab4fd18ec37a91eecc0ab1d1164e2919ad541aea61c4d328288931d60a646f70028f390699e744a6e69019019f60a4090819f35b08e5b0a6e30bab37e95442b7d7d84a99414c15be772a90b1acadc1a043e46290aa42e32434924471ddb9ca4b316789f542a60827020acdd1a7fcdc986d1f7f1efe8d008dc93081a55726a9fb81abd10172ceb81bc881b8553b6055c6ac8cc52139fd0c670c956c0e943575dfdcd5d9cd2ed1c97d275866f3169a6b1da3ff9596d7013f0215633886f4de5638c069479dbc5d08f26ff04cbeebfafbd477beb1324cc444e0a19dabee7274005e0488cad6a235e3237214cd79dacd989bfe464936aa5bd23e5a717fab560f7f4ef0c67b4d324263692b57e097a138c24ad0620a2fa7286536f430a24be0751b487f727444ee46dea82f9", "PubE" : 65537},
{"PrivP" : "e4fe39b2db06e2493b61e07befb4d2ae855f3aa5235dc19313528d11ac8979d0bbf5956dccdd3c4b579b07276f6e81ea88239b5c9667df533d99b7dad5bb3888a3d76c6c451cb496ffca238d0f4cf596f103a7cf8434927c34794b707002dd2386f5cc4610ea55610e8e399f9e004145e7c4f2147e3fddd0d7de52dcf271354980b8c915b81884f8e680ff085a359a66f0436eab59aec561ea8b80cd569180d6ad71f1170a0e3b13f59fd7abf6e517074ea4cb17a34e4ec3fd4f463250c14597", "PrivQ" : "b4a5f02254370b0e2bc349eb9624a2f46195419ba64abc09a71a935ecf0696f3f29903eb8d5dfd56faaa039533378ee46f8263935dae4462cdbeff9725d8137213c7f9c4cfdad14656d2ed7d4db3bc76c99fc6d9696c620e241463ba26ee5c1ecb6903308c611afccddc863ff4f3a782b5079ca24614ce1eb3aea16a171dc4bc73e10506dfdad4e411ed2d7df61a9aaca11a417d7c7ca88e7587b8caea23941e2e2732e2dab2a433dd97ea81e1a38a4c65e8dd05096545ffaad63fdd39ba9123", "PrivDP" : "527265fbcb785308e2e47e9aa0d78df35ff9c577a7a01e0e022afab79e53711482580d9116eda0c3cfaaf58c71466c6830d4011ff8d73545172cbd51811a83644ef94504466deb676279390b94b2b4c9bfc4fd2a6e032faaa089fb6b6428e3cde2cda4daa54479b1143888eebb488437d316c9c22f22778eb5ea4a135b06ff94934ff4b6692e0ad242cbb7071ed3a5dfe229a532f47b447dd8a099a354c3d68b74af4d8a6a086da4e60ec2ec1b5ca849ed3ad01496ab9f18599fad3a7870ddc9", "PrivDQ" : "4f1c0c193c800e5b5a56df5c48182b34923766cfdef70379c6b020b178400e832e4e4c252f7765a65d876ea23c17ac7fe545588e048c786e3c63d45240c46b5f9dc209636313146a954331b599fd881f0d14e763f682fc3ded16f0c5689f21c06a9bc645d07405f987bd771d330c30e3509bd0c04fa874cb852c888b892c0427f3272ba86307d60b3abe7f199658f83b7921a2646dcbb995096b3245ca5b625605282d64a319704736577cdefc0d3e574e99b790a918ac9ad6199546302dbfb9", "PrivC" : "10e79214689331923daf4b42258ee9c85ea45f70656f1bb297171a4d8ca5d2f1a4119030e9596573d466ae79424c14337c214e29939f4551b2d1771cbffa2db164e297d993fd08bc08fd3861aef6809d7fe2e96aa2131c7f746487c37a6960a682e5a5f9dd5100d0d4ab514dc47ed4b8a72660ad592026e54f0ad6921cdaadfdd5215f861dc746e938feb97afc5df7d7fb0b5be49ff359552f2dbba9fdbfd2a35370aa098fe6d68b4778daea53b5d35be8da33f89dbb99587d9417554c76de1a",  "PubN" : "a1972f39fd78011390d558b49d59bb534945137384ec7946de0293274b8f98c5d43661b62146d04e631779237f607caf8184f0531f82a60f81a0b9105f361fb05add458252877f6f5f00929bd3ab08800fe47be12de379e949a04ed10a2af364580dd1e2317ac2d0d805cd6a7a5d2dd554995cadcd70b98e13f23e0b53d4962c1ab5742d1754d89443d606fe58ec1457a941ed17e9551d76bd13f36af665c4bad68a55837a4e36ee0fdf33f8d2589384eb5746403958bb0efd16b452513d276337c0169ad287b21fabaa7bbee37500e1c7e6abf7f47b81033c6c9b8ead9aabcea4ed21cd90d2e7ca6f10dcd82cd6da65cc4d3f7113cb9a8d74cb4015f5f4995b8bebb76c4596aac7cdee0f7b6f38fc8baf80b1dd4308d8771127872552853e5624d04e8d8a1a3f770f560cfb8d4f7a6867c7306aa270628e00bee9fd8207f603265146fa2aea39df5e1509c00f6199ddb5f3941f77f0f83c7293f1be7d7f86e3110ff5e4c986e35d8b2fe5438fbc163b5f66b81c1f5d52fe765609e4b18d0aa5", "PubE" : 65537}
]

},{}],26:[function(require,module,exports){
'use strict'

exports.byteLength = byteLength
exports.toByteArray = toByteArray
exports.fromByteArray = fromByteArray

var lookup = []
var revLookup = []
var Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array

var code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
for (var i = 0, len = code.length; i < len; ++i) {
  lookup[i] = code[i]
  revLookup[code.charCodeAt(i)] = i
}

revLookup['-'.charCodeAt(0)] = 62
revLookup['_'.charCodeAt(0)] = 63

function placeHoldersCount (b64) {
  var len = b64.length
  if (len % 4 > 0) {
    throw new Error('Invalid string. Length must be a multiple of 4')
  }

  // the number of equal signs (place holders)
  // if there are two placeholders, than the two characters before it
  // represent one byte
  // if there is only one, then the three characters before it represent 2 bytes
  // this is just a cheap hack to not do indexOf twice
  return b64[len - 2] === '=' ? 2 : b64[len - 1] === '=' ? 1 : 0
}

function byteLength (b64) {
  // base64 is 4/3 + up to two characters of the original data
  return (b64.length * 3 / 4) - placeHoldersCount(b64)
}

function toByteArray (b64) {
  var i, l, tmp, placeHolders, arr
  var len = b64.length
  placeHolders = placeHoldersCount(b64)

  arr = new Arr((len * 3 / 4) - placeHolders)

  // if there are placeholders, only get up to the last complete 4 chars
  l = placeHolders > 0 ? len - 4 : len

  var L = 0

  for (i = 0; i < l; i += 4) {
    tmp = (revLookup[b64.charCodeAt(i)] << 18) | (revLookup[b64.charCodeAt(i + 1)] << 12) | (revLookup[b64.charCodeAt(i + 2)] << 6) | revLookup[b64.charCodeAt(i + 3)]
    arr[L++] = (tmp >> 16) & 0xFF
    arr[L++] = (tmp >> 8) & 0xFF
    arr[L++] = tmp & 0xFF
  }

  if (placeHolders === 2) {
    tmp = (revLookup[b64.charCodeAt(i)] << 2) | (revLookup[b64.charCodeAt(i + 1)] >> 4)
    arr[L++] = tmp & 0xFF
  } else if (placeHolders === 1) {
    tmp = (revLookup[b64.charCodeAt(i)] << 10) | (revLookup[b64.charCodeAt(i + 1)] << 4) | (revLookup[b64.charCodeAt(i + 2)] >> 2)
    arr[L++] = (tmp >> 8) & 0xFF
    arr[L++] = tmp & 0xFF
  }

  return arr
}

function tripletToBase64 (num) {
  return lookup[num >> 18 & 0x3F] + lookup[num >> 12 & 0x3F] + lookup[num >> 6 & 0x3F] + lookup[num & 0x3F]
}

function encodeChunk (uint8, start, end) {
  var tmp
  var output = []
  for (var i = start; i < end; i += 3) {
    tmp = (uint8[i] << 16) + (uint8[i + 1] << 8) + (uint8[i + 2])
    output.push(tripletToBase64(tmp))
  }
  return output.join('')
}

function fromByteArray (uint8) {
  var tmp
  var len = uint8.length
  var extraBytes = len % 3 // if we have 1 byte left, pad 2 bytes
  var output = ''
  var parts = []
  var maxChunkLength = 16383 // must be multiple of 3

  // go through the array every three bytes, we'll deal with trailing stuff later
  for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
    parts.push(encodeChunk(uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)))
  }

  // pad the end with zeros, but make sure to not forget the extra bytes
  if (extraBytes === 1) {
    tmp = uint8[len - 1]
    output += lookup[tmp >> 2]
    output += lookup[(tmp << 4) & 0x3F]
    output += '=='
  } else if (extraBytes === 2) {
    tmp = (uint8[len - 2] << 8) + (uint8[len - 1])
    output += lookup[tmp >> 10]
    output += lookup[(tmp >> 4) & 0x3F]
    output += lookup[(tmp << 2) & 0x3F]
    output += '='
  }

  parts.push(output)

  return parts.join('')
}

},{}],27:[function(require,module,exports){
/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <feross@feross.org> <http://feross.org>
 * @license  MIT
 */
/* eslint-disable no-proto */

'use strict'

var base64 = require('base64-js')
var ieee754 = require('ieee754')

exports.Buffer = Buffer
exports.SlowBuffer = SlowBuffer
exports.INSPECT_MAX_BYTES = 50

var K_MAX_LENGTH = 0x7fffffff
exports.kMaxLength = K_MAX_LENGTH

/**
 * If `Buffer.TYPED_ARRAY_SUPPORT`:
 *   === true    Use Uint8Array implementation (fastest)
 *   === false   Print warning and recommend using `buffer` v4.x which has an Object
 *               implementation (most compatible, even IE6)
 *
 * Browsers that support typed arrays are IE 10+, Firefox 4+, Chrome 7+, Safari 5.1+,
 * Opera 11.6+, iOS 4.2+.
 *
 * We report that the browser does not support typed arrays if the are not subclassable
 * using __proto__. Firefox 4-29 lacks support for adding new properties to `Uint8Array`
 * (See: https://bugzilla.mozilla.org/show_bug.cgi?id=695438). IE 10 lacks support
 * for __proto__ and has a buggy typed array implementation.
 */
Buffer.TYPED_ARRAY_SUPPORT = typedArraySupport()

if (!Buffer.TYPED_ARRAY_SUPPORT && typeof console !== 'undefined' &&
    typeof console.error === 'function') {
  console.error(
    'This browser lacks typed array (Uint8Array) support which is required by ' +
    '`buffer` v5.x. Use `buffer` v4.x if you require old browser support.'
  )
}

function typedArraySupport () {
  // Can typed array instances can be augmented?
  try {
    var arr = new Uint8Array(1)
    arr.__proto__ = {__proto__: Uint8Array.prototype, foo: function () { return 42 }}
    return arr.foo() === 42
  } catch (e) {
    return false
  }
}

function createBuffer (length) {
  if (length > K_MAX_LENGTH) {
    throw new RangeError('Invalid typed array length')
  }
  // Return an augmented `Uint8Array` instance
  var buf = new Uint8Array(length)
  buf.__proto__ = Buffer.prototype
  return buf
}

/**
 * The Buffer constructor returns instances of `Uint8Array` that have their
 * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
 * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
 * and the `Uint8Array` methods. Square bracket notation works as expected -- it
 * returns a single octet.
 *
 * The `Uint8Array` prototype remains unmodified.
 */

function Buffer (arg, encodingOrOffset, length) {
  // Common case.
  if (typeof arg === 'number') {
    if (typeof encodingOrOffset === 'string') {
      throw new Error(
        'If encoding is specified then the first argument must be a string'
      )
    }
    return allocUnsafe(arg)
  }
  return from(arg, encodingOrOffset, length)
}

// Fix subarray() in ES2016. See: https://github.com/feross/buffer/pull/97
if (typeof Symbol !== 'undefined' && Symbol.species &&
    Buffer[Symbol.species] === Buffer) {
  Object.defineProperty(Buffer, Symbol.species, {
    value: null,
    configurable: true,
    enumerable: false,
    writable: false
  })
}

Buffer.poolSize = 8192 // not used by this implementation

function from (value, encodingOrOffset, length) {
  if (typeof value === 'number') {
    throw new TypeError('"value" argument must not be a number')
  }

  if (value instanceof ArrayBuffer) {
    return fromArrayBuffer(value, encodingOrOffset, length)
  }

  if (typeof value === 'string') {
    return fromString(value, encodingOrOffset)
  }

  return fromObject(value)
}

/**
 * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
 * if value is a number.
 * Buffer.from(str[, encoding])
 * Buffer.from(array)
 * Buffer.from(buffer)
 * Buffer.from(arrayBuffer[, byteOffset[, length]])
 **/
Buffer.from = function (value, encodingOrOffset, length) {
  return from(value, encodingOrOffset, length)
}

// Note: Change prototype *after* Buffer.from is defined to workaround Chrome bug:
// https://github.com/feross/buffer/pull/148
Buffer.prototype.__proto__ = Uint8Array.prototype
Buffer.__proto__ = Uint8Array

function assertSize (size) {
  if (typeof size !== 'number') {
    throw new TypeError('"size" argument must be a number')
  } else if (size < 0) {
    throw new RangeError('"size" argument must not be negative')
  }
}

function alloc (size, fill, encoding) {
  assertSize(size)
  if (size <= 0) {
    return createBuffer(size)
  }
  if (fill !== undefined) {
    // Only pay attention to encoding if it's a string. This
    // prevents accidentally sending in a number that would
    // be interpretted as a start offset.
    return typeof encoding === 'string'
      ? createBuffer(size).fill(fill, encoding)
      : createBuffer(size).fill(fill)
  }
  return createBuffer(size)
}

/**
 * Creates a new filled Buffer instance.
 * alloc(size[, fill[, encoding]])
 **/
Buffer.alloc = function (size, fill, encoding) {
  return alloc(size, fill, encoding)
}

function allocUnsafe (size) {
  assertSize(size)
  return createBuffer(size < 0 ? 0 : checked(size) | 0)
}

/**
 * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
 * */
Buffer.allocUnsafe = function (size) {
  return allocUnsafe(size)
}
/**
 * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
 */
Buffer.allocUnsafeSlow = function (size) {
  return allocUnsafe(size)
}

function fromString (string, encoding) {
  if (typeof encoding !== 'string' || encoding === '') {
    encoding = 'utf8'
  }

  if (!Buffer.isEncoding(encoding)) {
    throw new TypeError('"encoding" must be a valid string encoding')
  }

  var length = byteLength(string, encoding) | 0
  var buf = createBuffer(length)

  var actual = buf.write(string, encoding)

  if (actual !== length) {
    // Writing a hex string, for example, that contains invalid characters will
    // cause everything after the first invalid character to be ignored. (e.g.
    // 'abxxcd' will be treated as 'ab')
    buf = buf.slice(0, actual)
  }

  return buf
}

function fromArrayLike (array) {
  var length = array.length < 0 ? 0 : checked(array.length) | 0
  var buf = createBuffer(length)
  for (var i = 0; i < length; i += 1) {
    buf[i] = array[i] & 255
  }
  return buf
}

function fromArrayBuffer (array, byteOffset, length) {
  if (byteOffset < 0 || array.byteLength < byteOffset) {
    throw new RangeError('\'offset\' is out of bounds')
  }

  if (array.byteLength < byteOffset + (length || 0)) {
    throw new RangeError('\'length\' is out of bounds')
  }

  var buf
  if (byteOffset === undefined && length === undefined) {
    buf = new Uint8Array(array)
  } else if (length === undefined) {
    buf = new Uint8Array(array, byteOffset)
  } else {
    buf = new Uint8Array(array, byteOffset, length)
  }

  // Return an augmented `Uint8Array` instance
  buf.__proto__ = Buffer.prototype
  return buf
}

function fromObject (obj) {
  if (Buffer.isBuffer(obj)) {
    var len = checked(obj.length) | 0
    var buf = createBuffer(len)

    if (buf.length === 0) {
      return buf
    }

    obj.copy(buf, 0, 0, len)
    return buf
  }

  if (obj) {
    if (isArrayBufferView(obj) || 'length' in obj) {
      if (typeof obj.length !== 'number' || numberIsNaN(obj.length)) {
        return createBuffer(0)
      }
      return fromArrayLike(obj)
    }

    if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
      return fromArrayLike(obj.data)
    }
  }

  throw new TypeError('First argument must be a string, Buffer, ArrayBuffer, Array, or array-like object.')
}

function checked (length) {
  // Note: cannot use `length < K_MAX_LENGTH` here because that fails when
  // length is NaN (which is otherwise coerced to zero.)
  if (length >= K_MAX_LENGTH) {
    throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
                         'size: 0x' + K_MAX_LENGTH.toString(16) + ' bytes')
  }
  return length | 0
}

function SlowBuffer (length) {
  if (+length != length) { // eslint-disable-line eqeqeq
    length = 0
  }
  return Buffer.alloc(+length)
}

Buffer.isBuffer = function isBuffer (b) {
  return b != null && b._isBuffer === true
}

Buffer.compare = function compare (a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError('Arguments must be Buffers')
  }

  if (a === b) return 0

  var x = a.length
  var y = b.length

  for (var i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i]
      y = b[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

Buffer.isEncoding = function isEncoding (encoding) {
  switch (String(encoding).toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'latin1':
    case 'binary':
    case 'base64':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return true
    default:
      return false
  }
}

Buffer.concat = function concat (list, length) {
  if (!Array.isArray(list)) {
    throw new TypeError('"list" argument must be an Array of Buffers')
  }

  if (list.length === 0) {
    return Buffer.alloc(0)
  }

  var i
  if (length === undefined) {
    length = 0
    for (i = 0; i < list.length; ++i) {
      length += list[i].length
    }
  }

  var buffer = Buffer.allocUnsafe(length)
  var pos = 0
  for (i = 0; i < list.length; ++i) {
    var buf = list[i]
    if (!Buffer.isBuffer(buf)) {
      throw new TypeError('"list" argument must be an Array of Buffers')
    }
    buf.copy(buffer, pos)
    pos += buf.length
  }
  return buffer
}

function byteLength (string, encoding) {
  if (Buffer.isBuffer(string)) {
    return string.length
  }
  if (isArrayBufferView(string) || string instanceof ArrayBuffer) {
    return string.byteLength
  }
  if (typeof string !== 'string') {
    string = '' + string
  }

  var len = string.length
  if (len === 0) return 0

  // Use a for loop to avoid recursion
  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'ascii':
      case 'latin1':
      case 'binary':
        return len
      case 'utf8':
      case 'utf-8':
      case undefined:
        return utf8ToBytes(string).length
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return len * 2
      case 'hex':
        return len >>> 1
      case 'base64':
        return base64ToBytes(string).length
      default:
        if (loweredCase) return utf8ToBytes(string).length // assume utf8
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}
Buffer.byteLength = byteLength

function slowToString (encoding, start, end) {
  var loweredCase = false

  // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
  // property of a typed array.

  // This behaves neither like String nor Uint8Array in that we set start/end
  // to their upper/lower bounds if the value passed is out of range.
  // undefined is handled specially as per ECMA-262 6th Edition,
  // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.
  if (start === undefined || start < 0) {
    start = 0
  }
  // Return early if start > this.length. Done here to prevent potential uint32
  // coercion fail below.
  if (start > this.length) {
    return ''
  }

  if (end === undefined || end > this.length) {
    end = this.length
  }

  if (end <= 0) {
    return ''
  }

  // Force coersion to uint32. This will also coerce falsey/NaN values to 0.
  end >>>= 0
  start >>>= 0

  if (end <= start) {
    return ''
  }

  if (!encoding) encoding = 'utf8'

  while (true) {
    switch (encoding) {
      case 'hex':
        return hexSlice(this, start, end)

      case 'utf8':
      case 'utf-8':
        return utf8Slice(this, start, end)

      case 'ascii':
        return asciiSlice(this, start, end)

      case 'latin1':
      case 'binary':
        return latin1Slice(this, start, end)

      case 'base64':
        return base64Slice(this, start, end)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return utf16leSlice(this, start, end)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = (encoding + '').toLowerCase()
        loweredCase = true
    }
  }
}

// This property is used by `Buffer.isBuffer` (and the `is-buffer` npm package)
// to detect a Buffer instance. It's not possible to use `instanceof Buffer`
// reliably in a browserify context because there could be multiple different
// copies of the 'buffer' package in use. This method works even for Buffer
// instances that were created from another copy of the `buffer` package.
// See: https://github.com/feross/buffer/issues/154
Buffer.prototype._isBuffer = true

function swap (b, n, m) {
  var i = b[n]
  b[n] = b[m]
  b[m] = i
}

Buffer.prototype.swap16 = function swap16 () {
  var len = this.length
  if (len % 2 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 16-bits')
  }
  for (var i = 0; i < len; i += 2) {
    swap(this, i, i + 1)
  }
  return this
}

Buffer.prototype.swap32 = function swap32 () {
  var len = this.length
  if (len % 4 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 32-bits')
  }
  for (var i = 0; i < len; i += 4) {
    swap(this, i, i + 3)
    swap(this, i + 1, i + 2)
  }
  return this
}

Buffer.prototype.swap64 = function swap64 () {
  var len = this.length
  if (len % 8 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 64-bits')
  }
  for (var i = 0; i < len; i += 8) {
    swap(this, i, i + 7)
    swap(this, i + 1, i + 6)
    swap(this, i + 2, i + 5)
    swap(this, i + 3, i + 4)
  }
  return this
}

Buffer.prototype.toString = function toString () {
  var length = this.length
  if (length === 0) return ''
  if (arguments.length === 0) return utf8Slice(this, 0, length)
  return slowToString.apply(this, arguments)
}

Buffer.prototype.equals = function equals (b) {
  if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
  if (this === b) return true
  return Buffer.compare(this, b) === 0
}

Buffer.prototype.inspect = function inspect () {
  var str = ''
  var max = exports.INSPECT_MAX_BYTES
  if (this.length > 0) {
    str = this.toString('hex', 0, max).match(/.{2}/g).join(' ')
    if (this.length > max) str += ' ... '
  }
  return '<Buffer ' + str + '>'
}

Buffer.prototype.compare = function compare (target, start, end, thisStart, thisEnd) {
  if (!Buffer.isBuffer(target)) {
    throw new TypeError('Argument must be a Buffer')
  }

  if (start === undefined) {
    start = 0
  }
  if (end === undefined) {
    end = target ? target.length : 0
  }
  if (thisStart === undefined) {
    thisStart = 0
  }
  if (thisEnd === undefined) {
    thisEnd = this.length
  }

  if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
    throw new RangeError('out of range index')
  }

  if (thisStart >= thisEnd && start >= end) {
    return 0
  }
  if (thisStart >= thisEnd) {
    return -1
  }
  if (start >= end) {
    return 1
  }

  start >>>= 0
  end >>>= 0
  thisStart >>>= 0
  thisEnd >>>= 0

  if (this === target) return 0

  var x = thisEnd - thisStart
  var y = end - start
  var len = Math.min(x, y)

  var thisCopy = this.slice(thisStart, thisEnd)
  var targetCopy = target.slice(start, end)

  for (var i = 0; i < len; ++i) {
    if (thisCopy[i] !== targetCopy[i]) {
      x = thisCopy[i]
      y = targetCopy[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

// Finds either the first index of `val` in `buffer` at offset >= `byteOffset`,
// OR the last index of `val` in `buffer` at offset <= `byteOffset`.
//
// Arguments:
// - buffer - a Buffer to search
// - val - a string, Buffer, or number
// - byteOffset - an index into `buffer`; will be clamped to an int32
// - encoding - an optional encoding, relevant is val is a string
// - dir - true for indexOf, false for lastIndexOf
function bidirectionalIndexOf (buffer, val, byteOffset, encoding, dir) {
  // Empty buffer means no match
  if (buffer.length === 0) return -1

  // Normalize byteOffset
  if (typeof byteOffset === 'string') {
    encoding = byteOffset
    byteOffset = 0
  } else if (byteOffset > 0x7fffffff) {
    byteOffset = 0x7fffffff
  } else if (byteOffset < -0x80000000) {
    byteOffset = -0x80000000
  }
  byteOffset = +byteOffset  // Coerce to Number.
  if (numberIsNaN(byteOffset)) {
    // byteOffset: it it's undefined, null, NaN, "foo", etc, search whole buffer
    byteOffset = dir ? 0 : (buffer.length - 1)
  }

  // Normalize byteOffset: negative offsets start from the end of the buffer
  if (byteOffset < 0) byteOffset = buffer.length + byteOffset
  if (byteOffset >= buffer.length) {
    if (dir) return -1
    else byteOffset = buffer.length - 1
  } else if (byteOffset < 0) {
    if (dir) byteOffset = 0
    else return -1
  }

  // Normalize val
  if (typeof val === 'string') {
    val = Buffer.from(val, encoding)
  }

  // Finally, search either indexOf (if dir is true) or lastIndexOf
  if (Buffer.isBuffer(val)) {
    // Special case: looking for empty string/buffer always fails
    if (val.length === 0) {
      return -1
    }
    return arrayIndexOf(buffer, val, byteOffset, encoding, dir)
  } else if (typeof val === 'number') {
    val = val & 0xFF // Search for a byte value [0-255]
    if (typeof Uint8Array.prototype.indexOf === 'function') {
      if (dir) {
        return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset)
      } else {
        return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset)
      }
    }
    return arrayIndexOf(buffer, [ val ], byteOffset, encoding, dir)
  }

  throw new TypeError('val must be string, number or Buffer')
}

function arrayIndexOf (arr, val, byteOffset, encoding, dir) {
  var indexSize = 1
  var arrLength = arr.length
  var valLength = val.length

  if (encoding !== undefined) {
    encoding = String(encoding).toLowerCase()
    if (encoding === 'ucs2' || encoding === 'ucs-2' ||
        encoding === 'utf16le' || encoding === 'utf-16le') {
      if (arr.length < 2 || val.length < 2) {
        return -1
      }
      indexSize = 2
      arrLength /= 2
      valLength /= 2
      byteOffset /= 2
    }
  }

  function read (buf, i) {
    if (indexSize === 1) {
      return buf[i]
    } else {
      return buf.readUInt16BE(i * indexSize)
    }
  }

  var i
  if (dir) {
    var foundIndex = -1
    for (i = byteOffset; i < arrLength; i++) {
      if (read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
        if (foundIndex === -1) foundIndex = i
        if (i - foundIndex + 1 === valLength) return foundIndex * indexSize
      } else {
        if (foundIndex !== -1) i -= i - foundIndex
        foundIndex = -1
      }
    }
  } else {
    if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength
    for (i = byteOffset; i >= 0; i--) {
      var found = true
      for (var j = 0; j < valLength; j++) {
        if (read(arr, i + j) !== read(val, j)) {
          found = false
          break
        }
      }
      if (found) return i
    }
  }

  return -1
}

Buffer.prototype.includes = function includes (val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1
}

Buffer.prototype.indexOf = function indexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, true)
}

Buffer.prototype.lastIndexOf = function lastIndexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, false)
}

function hexWrite (buf, string, offset, length) {
  offset = Number(offset) || 0
  var remaining = buf.length - offset
  if (!length) {
    length = remaining
  } else {
    length = Number(length)
    if (length > remaining) {
      length = remaining
    }
  }

  // must be an even number of digits
  var strLen = string.length
  if (strLen % 2 !== 0) throw new TypeError('Invalid hex string')

  if (length > strLen / 2) {
    length = strLen / 2
  }
  for (var i = 0; i < length; ++i) {
    var parsed = parseInt(string.substr(i * 2, 2), 16)
    if (numberIsNaN(parsed)) return i
    buf[offset + i] = parsed
  }
  return i
}

function utf8Write (buf, string, offset, length) {
  return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
}

function asciiWrite (buf, string, offset, length) {
  return blitBuffer(asciiToBytes(string), buf, offset, length)
}

function latin1Write (buf, string, offset, length) {
  return asciiWrite(buf, string, offset, length)
}

function base64Write (buf, string, offset, length) {
  return blitBuffer(base64ToBytes(string), buf, offset, length)
}

function ucs2Write (buf, string, offset, length) {
  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length)
}

Buffer.prototype.write = function write (string, offset, length, encoding) {
  // Buffer#write(string)
  if (offset === undefined) {
    encoding = 'utf8'
    length = this.length
    offset = 0
  // Buffer#write(string, encoding)
  } else if (length === undefined && typeof offset === 'string') {
    encoding = offset
    length = this.length
    offset = 0
  // Buffer#write(string, offset[, length][, encoding])
  } else if (isFinite(offset)) {
    offset = offset >>> 0
    if (isFinite(length)) {
      length = length >>> 0
      if (encoding === undefined) encoding = 'utf8'
    } else {
      encoding = length
      length = undefined
    }
  } else {
    throw new Error(
      'Buffer.write(string, encoding, offset[, length]) is no longer supported'
    )
  }

  var remaining = this.length - offset
  if (length === undefined || length > remaining) length = remaining

  if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
    throw new RangeError('Attempt to write outside buffer bounds')
  }

  if (!encoding) encoding = 'utf8'

  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'hex':
        return hexWrite(this, string, offset, length)

      case 'utf8':
      case 'utf-8':
        return utf8Write(this, string, offset, length)

      case 'ascii':
        return asciiWrite(this, string, offset, length)

      case 'latin1':
      case 'binary':
        return latin1Write(this, string, offset, length)

      case 'base64':
        // Warning: maxLength not taken into account in base64Write
        return base64Write(this, string, offset, length)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return ucs2Write(this, string, offset, length)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}

Buffer.prototype.toJSON = function toJSON () {
  return {
    type: 'Buffer',
    data: Array.prototype.slice.call(this._arr || this, 0)
  }
}

function base64Slice (buf, start, end) {
  if (start === 0 && end === buf.length) {
    return base64.fromByteArray(buf)
  } else {
    return base64.fromByteArray(buf.slice(start, end))
  }
}

function utf8Slice (buf, start, end) {
  end = Math.min(buf.length, end)
  var res = []

  var i = start
  while (i < end) {
    var firstByte = buf[i]
    var codePoint = null
    var bytesPerSequence = (firstByte > 0xEF) ? 4
      : (firstByte > 0xDF) ? 3
      : (firstByte > 0xBF) ? 2
      : 1

    if (i + bytesPerSequence <= end) {
      var secondByte, thirdByte, fourthByte, tempCodePoint

      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 0x80) {
            codePoint = firstByte
          }
          break
        case 2:
          secondByte = buf[i + 1]
          if ((secondByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F)
            if (tempCodePoint > 0x7F) {
              codePoint = tempCodePoint
            }
          }
          break
        case 3:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F)
            if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
              codePoint = tempCodePoint
            }
          }
          break
        case 4:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          fourthByte = buf[i + 3]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F)
            if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
              codePoint = tempCodePoint
            }
          }
      }
    }

    if (codePoint === null) {
      // we did not generate a valid codePoint so insert a
      // replacement char (U+FFFD) and advance only 1 byte
      codePoint = 0xFFFD
      bytesPerSequence = 1
    } else if (codePoint > 0xFFFF) {
      // encode to utf16 (surrogate pair dance)
      codePoint -= 0x10000
      res.push(codePoint >>> 10 & 0x3FF | 0xD800)
      codePoint = 0xDC00 | codePoint & 0x3FF
    }

    res.push(codePoint)
    i += bytesPerSequence
  }

  return decodeCodePointsArray(res)
}

// Based on http://stackoverflow.com/a/22747272/680742, the browser with
// the lowest limit is Chrome, with 0x10000 args.
// We go 1 magnitude less, for safety
var MAX_ARGUMENTS_LENGTH = 0x1000

function decodeCodePointsArray (codePoints) {
  var len = codePoints.length
  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints) // avoid extra slice()
  }

  // Decode in chunks to avoid "call stack size exceeded".
  var res = ''
  var i = 0
  while (i < len) {
    res += String.fromCharCode.apply(
      String,
      codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
    )
  }
  return res
}

function asciiSlice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i] & 0x7F)
  }
  return ret
}

function latin1Slice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i])
  }
  return ret
}

function hexSlice (buf, start, end) {
  var len = buf.length

  if (!start || start < 0) start = 0
  if (!end || end < 0 || end > len) end = len

  var out = ''
  for (var i = start; i < end; ++i) {
    out += toHex(buf[i])
  }
  return out
}

function utf16leSlice (buf, start, end) {
  var bytes = buf.slice(start, end)
  var res = ''
  for (var i = 0; i < bytes.length; i += 2) {
    res += String.fromCharCode(bytes[i] + (bytes[i + 1] * 256))
  }
  return res
}

Buffer.prototype.slice = function slice (start, end) {
  var len = this.length
  start = ~~start
  end = end === undefined ? len : ~~end

  if (start < 0) {
    start += len
    if (start < 0) start = 0
  } else if (start > len) {
    start = len
  }

  if (end < 0) {
    end += len
    if (end < 0) end = 0
  } else if (end > len) {
    end = len
  }

  if (end < start) end = start

  var newBuf = this.subarray(start, end)
  // Return an augmented `Uint8Array` instance
  newBuf.__proto__ = Buffer.prototype
  return newBuf
}

/*
 * Need to make sure that buffer isn't trying to write out of bounds.
 */
function checkOffset (offset, ext, length) {
  if ((offset % 1) !== 0 || offset < 0) throw new RangeError('offset is not uint')
  if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length')
}

Buffer.prototype.readUIntLE = function readUIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }

  return val
}

Buffer.prototype.readUIntBE = function readUIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    checkOffset(offset, byteLength, this.length)
  }

  var val = this[offset + --byteLength]
  var mul = 1
  while (byteLength > 0 && (mul *= 0x100)) {
    val += this[offset + --byteLength] * mul
  }

  return val
}

Buffer.prototype.readUInt8 = function readUInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  return this[offset]
}

Buffer.prototype.readUInt16LE = function readUInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return this[offset] | (this[offset + 1] << 8)
}

Buffer.prototype.readUInt16BE = function readUInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return (this[offset] << 8) | this[offset + 1]
}

Buffer.prototype.readUInt32LE = function readUInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return ((this[offset]) |
      (this[offset + 1] << 8) |
      (this[offset + 2] << 16)) +
      (this[offset + 3] * 0x1000000)
}

Buffer.prototype.readUInt32BE = function readUInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] * 0x1000000) +
    ((this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    this[offset + 3])
}

Buffer.prototype.readIntLE = function readIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readIntBE = function readIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var i = byteLength
  var mul = 1
  var val = this[offset + --i]
  while (i > 0 && (mul *= 0x100)) {
    val += this[offset + --i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readInt8 = function readInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  if (!(this[offset] & 0x80)) return (this[offset])
  return ((0xff - this[offset] + 1) * -1)
}

Buffer.prototype.readInt16LE = function readInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset] | (this[offset + 1] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt16BE = function readInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset + 1] | (this[offset] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt32LE = function readInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset]) |
    (this[offset + 1] << 8) |
    (this[offset + 2] << 16) |
    (this[offset + 3] << 24)
}

Buffer.prototype.readInt32BE = function readInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] << 24) |
    (this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    (this[offset + 3])
}

Buffer.prototype.readFloatLE = function readFloatLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, true, 23, 4)
}

Buffer.prototype.readFloatBE = function readFloatBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, false, 23, 4)
}

Buffer.prototype.readDoubleLE = function readDoubleLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, true, 52, 8)
}

Buffer.prototype.readDoubleBE = function readDoubleBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, false, 52, 8)
}

function checkInt (buf, value, offset, ext, max, min) {
  if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance')
  if (value > max || value < min) throw new RangeError('"value" argument is out of bounds')
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
}

Buffer.prototype.writeUIntLE = function writeUIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var mul = 1
  var i = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUIntBE = function writeUIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var i = byteLength - 1
  var mul = 1
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUInt8 = function writeUInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0)
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeUInt16LE = function writeUInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeUInt16BE = function writeUInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeUInt32LE = function writeUInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset + 3] = (value >>> 24)
  this[offset + 2] = (value >>> 16)
  this[offset + 1] = (value >>> 8)
  this[offset] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeUInt32BE = function writeUInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeIntLE = function writeIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = 0
  var mul = 1
  var sub = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeIntBE = function writeIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = byteLength - 1
  var mul = 1
  var sub = 0
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeInt8 = function writeInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80)
  if (value < 0) value = 0xff + value + 1
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeInt16LE = function writeInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeInt16BE = function writeInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeInt32LE = function writeInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  this[offset + 2] = (value >>> 16)
  this[offset + 3] = (value >>> 24)
  return offset + 4
}

Buffer.prototype.writeInt32BE = function writeInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (value < 0) value = 0xffffffff + value + 1
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

function checkIEEE754 (buf, value, offset, ext, max, min) {
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
  if (offset < 0) throw new RangeError('Index out of range')
}

function writeFloat (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 4, 3.4028234663852886e+38, -3.4028234663852886e+38)
  }
  ieee754.write(buf, value, offset, littleEndian, 23, 4)
  return offset + 4
}

Buffer.prototype.writeFloatLE = function writeFloatLE (value, offset, noAssert) {
  return writeFloat(this, value, offset, true, noAssert)
}

Buffer.prototype.writeFloatBE = function writeFloatBE (value, offset, noAssert) {
  return writeFloat(this, value, offset, false, noAssert)
}

function writeDouble (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 8, 1.7976931348623157E+308, -1.7976931348623157E+308)
  }
  ieee754.write(buf, value, offset, littleEndian, 52, 8)
  return offset + 8
}

Buffer.prototype.writeDoubleLE = function writeDoubleLE (value, offset, noAssert) {
  return writeDouble(this, value, offset, true, noAssert)
}

Buffer.prototype.writeDoubleBE = function writeDoubleBE (value, offset, noAssert) {
  return writeDouble(this, value, offset, false, noAssert)
}

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function copy (target, targetStart, start, end) {
  if (!start) start = 0
  if (!end && end !== 0) end = this.length
  if (targetStart >= target.length) targetStart = target.length
  if (!targetStart) targetStart = 0
  if (end > 0 && end < start) end = start

  // Copy 0 bytes; we're done
  if (end === start) return 0
  if (target.length === 0 || this.length === 0) return 0

  // Fatal error conditions
  if (targetStart < 0) {
    throw new RangeError('targetStart out of bounds')
  }
  if (start < 0 || start >= this.length) throw new RangeError('sourceStart out of bounds')
  if (end < 0) throw new RangeError('sourceEnd out of bounds')

  // Are we oob?
  if (end > this.length) end = this.length
  if (target.length - targetStart < end - start) {
    end = target.length - targetStart + start
  }

  var len = end - start
  var i

  if (this === target && start < targetStart && targetStart < end) {
    // descending copy from end
    for (i = len - 1; i >= 0; --i) {
      target[i + targetStart] = this[i + start]
    }
  } else if (len < 1000) {
    // ascending copy from start
    for (i = 0; i < len; ++i) {
      target[i + targetStart] = this[i + start]
    }
  } else {
    Uint8Array.prototype.set.call(
      target,
      this.subarray(start, start + len),
      targetStart
    )
  }

  return len
}

// Usage:
//    buffer.fill(number[, offset[, end]])
//    buffer.fill(buffer[, offset[, end]])
//    buffer.fill(string[, offset[, end]][, encoding])
Buffer.prototype.fill = function fill (val, start, end, encoding) {
  // Handle string cases:
  if (typeof val === 'string') {
    if (typeof start === 'string') {
      encoding = start
      start = 0
      end = this.length
    } else if (typeof end === 'string') {
      encoding = end
      end = this.length
    }
    if (val.length === 1) {
      var code = val.charCodeAt(0)
      if (code < 256) {
        val = code
      }
    }
    if (encoding !== undefined && typeof encoding !== 'string') {
      throw new TypeError('encoding must be a string')
    }
    if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
      throw new TypeError('Unknown encoding: ' + encoding)
    }
  } else if (typeof val === 'number') {
    val = val & 255
  }

  // Invalid ranges are not set to a default, so can range check early.
  if (start < 0 || this.length < start || this.length < end) {
    throw new RangeError('Out of range index')
  }

  if (end <= start) {
    return this
  }

  start = start >>> 0
  end = end === undefined ? this.length : end >>> 0

  if (!val) val = 0

  var i
  if (typeof val === 'number') {
    for (i = start; i < end; ++i) {
      this[i] = val
    }
  } else {
    var bytes = Buffer.isBuffer(val)
      ? val
      : new Buffer(val, encoding)
    var len = bytes.length
    for (i = 0; i < end - start; ++i) {
      this[i + start] = bytes[i % len]
    }
  }

  return this
}

// HELPER FUNCTIONS
// ================

var INVALID_BASE64_RE = /[^+/0-9A-Za-z-_]/g

function base64clean (str) {
  // Node strips out invalid characters like \n and \t from the string, base64-js does not
  str = str.trim().replace(INVALID_BASE64_RE, '')
  // Node converts strings with length < 2 to ''
  if (str.length < 2) return ''
  // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
  while (str.length % 4 !== 0) {
    str = str + '='
  }
  return str
}

function toHex (n) {
  if (n < 16) return '0' + n.toString(16)
  return n.toString(16)
}

function utf8ToBytes (string, units) {
  units = units || Infinity
  var codePoint
  var length = string.length
  var leadSurrogate = null
  var bytes = []

  for (var i = 0; i < length; ++i) {
    codePoint = string.charCodeAt(i)

    // is surrogate component
    if (codePoint > 0xD7FF && codePoint < 0xE000) {
      // last char was a lead
      if (!leadSurrogate) {
        // no lead yet
        if (codePoint > 0xDBFF) {
          // unexpected trail
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        } else if (i + 1 === length) {
          // unpaired lead
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        }

        // valid lead
        leadSurrogate = codePoint

        continue
      }

      // 2 leads in a row
      if (codePoint < 0xDC00) {
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
        leadSurrogate = codePoint
        continue
      }

      // valid surrogate pair
      codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000
    } else if (leadSurrogate) {
      // valid bmp char, but last char was a lead
      if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
    }

    leadSurrogate = null

    // encode utf8
    if (codePoint < 0x80) {
      if ((units -= 1) < 0) break
      bytes.push(codePoint)
    } else if (codePoint < 0x800) {
      if ((units -= 2) < 0) break
      bytes.push(
        codePoint >> 0x6 | 0xC0,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x10000) {
      if ((units -= 3) < 0) break
      bytes.push(
        codePoint >> 0xC | 0xE0,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x110000) {
      if ((units -= 4) < 0) break
      bytes.push(
        codePoint >> 0x12 | 0xF0,
        codePoint >> 0xC & 0x3F | 0x80,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else {
      throw new Error('Invalid code point')
    }
  }

  return bytes
}

function asciiToBytes (str) {
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push(str.charCodeAt(i) & 0xFF)
  }
  return byteArray
}

function utf16leToBytes (str, units) {
  var c, hi, lo
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    if ((units -= 2) < 0) break

    c = str.charCodeAt(i)
    hi = c >> 8
    lo = c % 256
    byteArray.push(lo)
    byteArray.push(hi)
  }

  return byteArray
}

function base64ToBytes (str) {
  return base64.toByteArray(base64clean(str))
}

function blitBuffer (src, dst, offset, length) {
  for (var i = 0; i < length; ++i) {
    if ((i + offset >= dst.length) || (i >= src.length)) break
    dst[i + offset] = src[i]
  }
  return i
}

// Node 0.10 supports `ArrayBuffer` but lacks `ArrayBuffer.isView`
function isArrayBufferView (obj) {
  return (typeof ArrayBuffer.isView === 'function') && ArrayBuffer.isView(obj)
}

function numberIsNaN (obj) {
  return obj !== obj // eslint-disable-line no-self-compare
}

},{"base64-js":26,"ieee754":28}],28:[function(require,module,exports){
exports.read = function (buffer, offset, isLE, mLen, nBytes) {
  var e, m
  var eLen = nBytes * 8 - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var nBits = -7
  var i = isLE ? (nBytes - 1) : 0
  var d = isLE ? -1 : 1
  var s = buffer[offset + i]

  i += d

  e = s & ((1 << (-nBits)) - 1)
  s >>= (-nBits)
  nBits += eLen
  for (; nBits > 0; e = e * 256 + buffer[offset + i], i += d, nBits -= 8) {}

  m = e & ((1 << (-nBits)) - 1)
  e >>= (-nBits)
  nBits += mLen
  for (; nBits > 0; m = m * 256 + buffer[offset + i], i += d, nBits -= 8) {}

  if (e === 0) {
    e = 1 - eBias
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity)
  } else {
    m = m + Math.pow(2, mLen)
    e = e - eBias
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen)
}

exports.write = function (buffer, value, offset, isLE, mLen, nBytes) {
  var e, m, c
  var eLen = nBytes * 8 - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0)
  var i = isLE ? 0 : (nBytes - 1)
  var d = isLE ? 1 : -1
  var s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0

  value = Math.abs(value)

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0
    e = eMax
  } else {
    e = Math.floor(Math.log(value) / Math.LN2)
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--
      c *= 2
    }
    if (e + eBias >= 1) {
      value += rt / c
    } else {
      value += rt * Math.pow(2, 1 - eBias)
    }
    if (value * c >= 2) {
      e++
      c /= 2
    }

    if (e + eBias >= eMax) {
      m = 0
      e = eMax
    } else if (e + eBias >= 1) {
      m = (value * c - 1) * Math.pow(2, mLen)
      e = e + eBias
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen)
      e = 0
    }
  }

  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8) {}

  e = (e << mLen) | m
  eLen += mLen
  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8) {}

  buffer[offset + i - d] |= s * 128
}

},{}],29:[function(require,module,exports){
// shim for using process in browser
var process = module.exports = {};

// cached from whatever global is present so that test runners that stub it
// don't break things.  But we need to wrap it in a try catch in case it is
// wrapped in strict mode code which doesn't define any globals.  It's inside a
// function because try/catches deoptimize in certain engines.

var cachedSetTimeout;
var cachedClearTimeout;

function defaultSetTimout() {
    throw new Error('setTimeout has not been defined');
}
function defaultClearTimeout () {
    throw new Error('clearTimeout has not been defined');
}
(function () {
    try {
        if (typeof setTimeout === 'function') {
            cachedSetTimeout = setTimeout;
        } else {
            cachedSetTimeout = defaultSetTimout;
        }
    } catch (e) {
        cachedSetTimeout = defaultSetTimout;
    }
    try {
        if (typeof clearTimeout === 'function') {
            cachedClearTimeout = clearTimeout;
        } else {
            cachedClearTimeout = defaultClearTimeout;
        }
    } catch (e) {
        cachedClearTimeout = defaultClearTimeout;
    }
} ())
function runTimeout(fun) {
    if (cachedSetTimeout === setTimeout) {
        //normal enviroments in sane situations
        return setTimeout(fun, 0);
    }
    // if setTimeout wasn't available but was latter defined
    if ((cachedSetTimeout === defaultSetTimout || !cachedSetTimeout) && setTimeout) {
        cachedSetTimeout = setTimeout;
        return setTimeout(fun, 0);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedSetTimeout(fun, 0);
    } catch(e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't trust the global object when called normally
            return cachedSetTimeout.call(null, fun, 0);
        } catch(e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error
            return cachedSetTimeout.call(this, fun, 0);
        }
    }


}
function runClearTimeout(marker) {
    if (cachedClearTimeout === clearTimeout) {
        //normal enviroments in sane situations
        return clearTimeout(marker);
    }
    // if clearTimeout wasn't available but was latter defined
    if ((cachedClearTimeout === defaultClearTimeout || !cachedClearTimeout) && clearTimeout) {
        cachedClearTimeout = clearTimeout;
        return clearTimeout(marker);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedClearTimeout(marker);
    } catch (e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't  trust the global object when called normally
            return cachedClearTimeout.call(null, marker);
        } catch (e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error.
            // Some versions of I.E. have different rules for clearTimeout vs setTimeout
            return cachedClearTimeout.call(this, marker);
        }
    }



}
var queue = [];
var draining = false;
var currentQueue;
var queueIndex = -1;

function cleanUpNextTick() {
    if (!draining || !currentQueue) {
        return;
    }
    draining = false;
    if (currentQueue.length) {
        queue = currentQueue.concat(queue);
    } else {
        queueIndex = -1;
    }
    if (queue.length) {
        drainQueue();
    }
}

function drainQueue() {
    if (draining) {
        return;
    }
    var timeout = runTimeout(cleanUpNextTick);
    draining = true;

    var len = queue.length;
    while(len) {
        currentQueue = queue;
        queue = [];
        while (++queueIndex < len) {
            if (currentQueue) {
                currentQueue[queueIndex].run();
            }
        }
        queueIndex = -1;
        len = queue.length;
    }
    currentQueue = null;
    draining = false;
    runClearTimeout(timeout);
}

process.nextTick = function (fun) {
    var args = new Array(arguments.length - 1);
    if (arguments.length > 1) {
        for (var i = 1; i < arguments.length; i++) {
            args[i - 1] = arguments[i];
        }
    }
    queue.push(new Item(fun, args));
    if (queue.length === 1 && !draining) {
        runTimeout(drainQueue);
    }
};

// v8 likes predictible objects
function Item(fun, array) {
    this.fun = fun;
    this.array = array;
}
Item.prototype.run = function () {
    this.fun.apply(null, this.array);
};
process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];
process.version = ''; // empty string to avoid regexp issues
process.versions = {};

function noop() {}

process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;
process.prependListener = noop;
process.prependOnceListener = noop;

process.listeners = function (name) { return [] }

process.binding = function (name) {
    throw new Error('process.binding is not supported');
};

process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};
process.umask = function() { return 0; };

},{}]},{},[1]);
