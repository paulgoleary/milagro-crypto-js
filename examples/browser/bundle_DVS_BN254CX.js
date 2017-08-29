(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
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

/* Test DVS - test driver and function exerciser for Designator Verifier Signature API Functions */

var CTX = require("../src/ctx");

var ctx = new CTX("BN254CX");

var RAW = [];
var rng = new ctx.RAND();
rng.clean();
for (i = 0; i < 100; i++) RAW[i] = i;

rng.seed(100, RAW);


var res;

var S = [];
var SST = [];
var TOKEN = [];
var SEC = [];
var xID = [];
var X = [];
var Y1 = [];
var Y2 = [];
var Z = [];
var Pa = [];
var U = [];

var sha = ctx.MPIN.HASH_TYPE;

/* Trusted Authority set-up */
ctx.MPIN.RANDOM_GENERATE(rng, S);
console.log("M-Pin Master Secret s: 0x" + ctx.MPIN.bytestostring(S));

/* Create Client Identity */
var IDstr = "testuser@miracl.com";
var CLIENT_ID = ctx.MPIN.stringtobytes(IDstr);

console.log("Client ID= " + ctx.MPIN.bytestostring(CLIENT_ID));

/* Generate random public key and z */
res = ctx.MPIN.GET_DVS_KEYPAIR(rng, Z, Pa);
if (res != 0) {
    console.log("Can't generate DVS keypair, error ", res);
    return 1;
}

console.log("Z: 0x" + ctx.MPIN.bytestostring(Z));
console.log("Pa: 0x" + ctx.MPIN.bytestostring(Pa));

/* Append Pa to ID */
for (var i = 0; i < Pa.length; i++) {
    CLIENT_ID.push(Pa[i]);
}
console.log("ID|Pa: 0x" + ctx.MPIN.bytestostring(CLIENT_ID));
/* Hash Client ID */
HCID = ctx.MPIN.HASH_ID(sha, CLIENT_ID);

/* Client and Server are issued secrets by DTA */
ctx.MPIN.GET_SERVER_SECRET(S, SST);
console.log("Server Secret SS: 0x" + ctx.MPIN.bytestostring(SST));

ctx.MPIN.GET_CLIENT_SECRET(S, HCID, TOKEN);
console.log("Client Secret CS: 0x" + ctx.MPIN.bytestostring(TOKEN));

/* Compute client secret for key escrow less scheme z.CS */
res = ctx.MPIN.GET_G1_MULTIPLE(null, 0, Z, TOKEN, TOKEN);
if (res != 0) {
    console.log("Failed to compute z.CS, error ", res);
    return 1;
}
console.log("z.CS: 0x" + ctx.MPIN.bytestostring(TOKEN));

/* Client extracts PIN from secret to create Token */
var pin = 1234;
console.log("Client extracts PIN= " + pin);
res = ctx.MPIN.EXTRACT_PIN(sha, CLIENT_ID, pin, TOKEN);
if (res != 0)
    console.log("Failed to extract PIN, Error: ", res);

console.log("Client Token TK: 0x" + ctx.MPIN.bytestostring(TOKEN));

var date = 0;
var timeValue = ctx.MPIN.GET_TIME();

var message = "Message to sign";

res = ctx.MPIN.CLIENT(sha, 0, CLIENT_ID, rng, X, pin, TOKEN, SEC, U, null, null, timeValue, Y1, message);
if (res != 0) {
    console.log("Failed to extract PIN, error ", res);
    return 1;
}

console.log("U: 0x" + ctx.MPIN.bytestostring(U));

console.log("Y1: 0x" + ctx.MPIN.bytestostring(Y1));
console.log("V: 0x" + ctx.MPIN.bytestostring(SEC));

/* Server  */
res = ctx.MPIN.SERVER(sha, 0, xID, null, Y2, SST, U, null, SEC, null, null, CLIENT_ID, timeValue, message, Pa);
console.log("Y2: 0x" + ctx.MPIN.bytestostring(Y2));

if (res != 0) {
    console.log("FAILURE Signature Verification, error", res);
    return -1
} else {
    console.log("SUCCESS Error Code ", res);
}
return 0;
},{"../src/ctx":4}],2:[function(require,module,exports){
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

module.exports.AES = function() {

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
            for (var i = 0; i < 3; i++) {
                u[i] = new ctx.BIG(w);
                u[i].mod(x);
                w.div(x);
            }
            u[3]=new ctx.BIG(w);
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

module.exports.ROM_CURVE_ANSSI = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_ANSSI = {

        // ANSSI curve

        CURVE_A: -3,
        CURVE_B: [0x7BB73F, 0xED967B, 0x803075, 0xE4B1A1, 0xEC0C9A, 0xC00FDF, 0x754A44, 0xD4ABA, 0x28A930, 0x3FCA54, 0xEE35],
        CURVE_Order: [0xD655E1, 0xD459C6, 0x941FFD, 0x40D2BF, 0xDC67E1, 0x435B53, 0xE8CE42, 0x10126D, 0x3AD58F, 0x178C0B, 0xF1FD],
        CURVE_Gx: [0x8F5CFF, 0x7A2DD9, 0x164C9, 0xAF98B7, 0x27D2DC, 0x23958C, 0x4749D4, 0x31183D, 0xC139EB, 0xD4C356, 0xB6B3],
        CURVE_Gy: [0x62CFB, 0x5A1554, 0xE18311, 0xE8E4C9, 0x1C307, 0xEF8C27, 0xF0F3EC, 0x1F9271, 0xB20491, 0xE0F7C8, 0x6142],

    };
    return ROM_CURVE_ANSSI;
};

module.exports.ROM_CURVE_BLS383 = function() {

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

    return ROM_CURVE_BLS383;
};

module.exports.ROM_CURVE_BN254 = function() {

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

    return ROM_CURVE_BN254;
};

module.exports.ROM_CURVE_BN254CX = function() {

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

    return ROM_CURVE_BN254CX;
};

module.exports.ROM_CURVE_BRAINPOOL = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_BRAINPOOL = {

        // Brainpool curve

        CURVE_A: -3,
        CURVE_B: [0xE92B04, 0x8101FE, 0x256AE5, 0xAF2F49, 0x93EBC4, 0x76B7BF, 0x733D0B, 0xFE66A7, 0xD84EA4, 0x61C430, 0x662C],
        CURVE_Order: [0x4856A7, 0xE8297, 0xF7901E, 0xB561A6, 0x397AA3, 0x8D718C, 0x909D83, 0x3E660A, 0xEEA9BC, 0x57DBA1, 0xA9FB],
        CURVE_Gx: [0x1305F4, 0x91562E, 0x2B79A1, 0x7AAFBC, 0xA142C4, 0x6149AF, 0xB23A65, 0x732213, 0xCFE7B7, 0xEB3CC1, 0xA3E8],
        CURVE_Gy: [0x25C9BE, 0xE8F35B, 0x1DAB, 0x39D027, 0xBCB6DE, 0x417E69, 0xE14644, 0x7F7B22, 0x39C56D, 0x6C8234, 0x2D99],

    };
    return ROM_CURVE_BRAINPOOL;
};

module.exports.ROM_CURVE_C25519 = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_C25519 = {

        // C25519 Curve 

        CURVE_A: 486662,
        CURVE_B: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0xF5D3ED, 0x631A5C, 0xD65812, 0xA2F79C, 0xDEF9DE, 0x14, 0x0, 0x0, 0x0, 0x0, 0x1000],
        CURVE_Gx: [0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],

    };
    return ROM_CURVE_C25519;
};

module.exports.ROM_CURVE_C41417 = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_C41417 = {

        // C41417 curve

        CURVE_A: 1,
        CURVE_B: [0xE21, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x6af79, 0x634bc2, 0x606c39, 0x6b1e78, 0x40338a, 0x566de3, 0x5c1808, 0x120a67, 0x6b3cc9, 0x7fffff, 0x7fffff, 0x7fffff, 0x7fffff, 0x7fffff, 0x7fffff, 0x7fffff, 0x7fffff, 0xfffff],
        CURVE_Gx: [0x4bc595, 0x7025e7, 0x1313f4, 0x429be3, 0x273faa, 0x222603, 0x5b5ae8, 0x5255a6, 0x735498, 0xfeaff, 0x1300fb, 0x31b4fa, 0x65fcd4, 0x63864d, 0x63018, 0x219801, 0x51414, 0x346692],
        CURVE_Gy: [0x22, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],

    };

    return ROM_CURVE_C41417;
};

module.exports.ROM_CURVE_ED25519 = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_ED25519 = {

        // ED25519 Curve 

        CURVE_A: -1,
        CURVE_B: [0x5978A3, 0x4DCA13, 0xAB75EB, 0x4141D8, 0x700A4D, 0xE89800, 0x797779, 0x8CC740, 0x6FFE73, 0x6CEE2B, 0x5203],
        CURVE_Order: [0xF5D3ED, 0x631A5C, 0xD65812, 0xA2F79C, 0xDEF9DE, 0x14, 0x0, 0x0, 0x0, 0x0, 0x1000],
        CURVE_Gx: [0x25D51A, 0x2D608F, 0xB2C956, 0x9525A7, 0x2CC760, 0xDC5C69, 0x31FDD6, 0xC0A4E2, 0x6E53FE, 0x36D3CD, 0x2169],
        CURVE_Gy: [0x666658, 0x666666, 0x666666, 0x666666, 0x666666, 0x666666, 0x666666, 0x666666, 0x666666, 0x666666, 0x6666],

    };
    return ROM_CURVE_ED25519;
};

module.exports.ROM_CURVE_GOLDILOCKS = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_GOLDILOCKS = {

        // GOLDILOCKS curve

        CURVE_A: 1,
        CURVE_B: [0x7F6756, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7DFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FF],
        CURVE_Order: [0x5844F3, 0x52556, 0x548DE3, 0x6E2C7A, 0x4C2728, 0x52042D, 0x6BB58D, 0x276DA4, 0x23E9C4, 0x7EF994, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x1FF],
        CURVE_Gx: [0x555555, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x52AAAA, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555],
        CURVE_Gy: [0x1386ED, 0x779BD5, 0x2F6BAB, 0xE6D03, 0x4B2BED, 0x131777, 0x4E8A8C, 0x32B2C1, 0x44B80D, 0x6515B1, 0x5F8DB5, 0x426EBD, 0x7A0358, 0x6DDA, 0x21B0AC, 0x6B1028, 0xDB359, 0x15AE09, 0x17A58D, 0x570],

    };
    return ROM_CURVE_GOLDILOCKS;
};

module.exports.ROM_CURVE_HIFIVE = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_HIFIVE = {

        // HIFIVE curve

        CURVE_A: 1,
        CURVE_B: [0x2B67, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x1FA805, 0x2B2E7D, 0x29ECBE, 0x3FC9DD, 0xBD6B8, 0x530A18, 0x45057E, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x800],
        CURVE_Gx: [0xC, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0x7E8632, 0xD0A0B, 0x6C4AFB, 0x501B2E, 0x55650C, 0x36DB6B, 0x1FBD0D, 0x61C08E, 0x314B46, 0x70A7A3, 0x587401, 0xC70E0, 0x56502E, 0x38C2D6, 0x303],

    };
    return ROM_CURVE_HIFIVE;
};

module.exports.ROM_CURVE_MF254E = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_MF254E = {

        // MF254 Edwards curve

        CURVE_A: -1,
        CURVE_B: [0x367B, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x6E98C7, 0xD3FEC4, 0xB0EAF3, 0x8BD62F, 0x95306C, 0xFFFFEB, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x3FFFFF, 0xFE0],
        CURVE_Gx: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0x2701E5, 0xD0FDAF, 0x187C52, 0xE3212, 0x329A84, 0x3F4E36, 0xD50236, 0x951D00, 0xA4C335, 0xE690D6, 0x19F0],

    };
    return ROM_CURVE_MF254E;
};

module.exports.ROM_CURVE_MF254M = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_MF254M = {

        // MF254 Montgomery curve

        CURVE_A: -55790,
        CURVE_B: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x6E98C7, 0xD3FEC4, 0xB0EAF3, 0x8BD62F, 0x95306C, 0xFFFFEB, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x3FFFFF, 0xFE0],
        CURVE_Gx: [0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    };
    return ROM_CURVE_MF254M;
};

module.exports.ROM_CURVE_MF254W = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_MF254W = {

        // MF254 Weierstrass curve

        CURVE_A: -3,
        CURVE_B: [0xFFD08D, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x3F80],
        CURVE_Order: [0x8DF83F, 0x19C4AF, 0xC06FA4, 0xDA375, 0x818BEA, 0xFFFFEB, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x3F80],
        CURVE_Gx: [0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0xD4EBC, 0xDF37F9, 0x31AD65, 0xF85119, 0xB738E3, 0x8AEBDF, 0x75BD77, 0x4AE15A, 0x2E5601, 0x3FD33B, 0x140E],

    };
    return ROM_CURVE_MF254W;
};

module.exports.ROM_CURVE_MF256E = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_MF256E = {

        // MF256 EDWARDS curve

        CURVE_A: -1,
        CURVE_B: [0x350A, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0xEC7BAB, 0x2EDED8, 0xC966D9, 0xB86733, 0x54BBAF, 0xFFFFB1, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x3FE9],
        CURVE_Gx: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0xF3C908, 0xA722F2, 0x8D7DEA, 0x8DFEA6, 0xC05E64, 0x1AACA0, 0xF3DB2C, 0xEAEBEE, 0xCC4D5A, 0xD4F8F8, 0xDAD8],
    };
    return ROM_CURVE_MF256E;
};

module.exports.ROM_CURVE_MF256M = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_MF256M = {

        // MF256 Montgomery curve

        CURVE_A: -54314,
        CURVE_B: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0xEC7BAB, 0x2EDED8, 0xC966D9, 0xB86733, 0x54BBAF, 0xFFFFB1, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x3FE9],
        CURVE_Gx: [0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    };
    return ROM_CURVE_MF256M;
};

module.exports.ROM_CURVE_MF256W = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_MF256W = {

        // MF256 WEIERSTRASS curve

        CURVE_A: -3,
        CURVE_B: [0x14E6A, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x9857EB, 0xC5E1A7, 0x4B9D10, 0xE6E507, 0x517513, 0xFFFFFC, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFA7],
        CURVE_Gx: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0x724D2A, 0x954C2B, 0x661007, 0x8D94DC, 0x6947EB, 0xAE2895, 0x26123D, 0x7BABBA, 0x1808CE, 0x7C87BE, 0x2088],
    };
    return ROM_CURVE_MF256W;
};

module.exports.ROM_CURVE_MS255E = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_MS255E = {

        // MS255 Edwards curve

        CURVE_A: -1,
        CURVE_B: [0xEA97, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x36EB75, 0xD1ED04, 0x2EAC49, 0xEDA683, 0xF1A785, 0xFFFFDC, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x1FFF],
        CURVE_Gx: [0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0x8736A0, 0x255BD0, 0x45BA2A, 0xED445A, 0x914B8A, 0x47E552, 0xDD8E0C, 0xEC254C, 0x7BB545, 0x78534A, 0x26CB],
    };
    return ROM_CURVE_MS255E;
};

module.exports.ROM_CURVE_MS255M = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_MS255M = {

        // MS255 Montgomery curve

        CURVE_A: -240222,
        CURVE_B: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x36EB75, 0xD1ED04, 0x2EAC49, 0xEDA683, 0xF1A785, 0xFFFFDC, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x1FFF],
        CURVE_Gx: [0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    };
    return ROM_CURVE_MS255M;
};

module.exports.ROM_CURVE_MS255W = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_MS255W = {

        // MS255 WEIERSTRASS curve

        CURVE_A: -3,
        CURVE_B: [0xFFAB46, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x7FFF],
        CURVE_Order: [0x594AEB, 0xAC983C, 0xDFAB8F, 0x3AD2B3, 0x4A3828, 0xFFFF86, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x7FFF],
        CURVE_Gx: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0xCB44BA, 0xFF6769, 0xD1733, 0xDDFDA6, 0xB6C78C, 0x7D177D, 0xF9B2FF, 0x921EBF, 0xBA7833, 0x6AC0ED, 0x6F7A],
    };
    return ROM_CURVE_MS255W;
};

module.exports.ROM_CURVE_MS256E = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_MS256E = {

        // MS256 Edwards curve

        CURVE_A: -1,
        CURVE_B: [0x3BEE, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x22B4AD, 0x4E6F11, 0x64E5B8, 0xD0A6BC, 0x6AA55A, 0xFFFFBE, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x3FFF],
        CURVE_Gx: [0xD, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0x1CADBA, 0x6FB533, 0x3F707F, 0x824D30, 0x2A6D63, 0x46BFBE, 0xB39FA0, 0xA3D330, 0x1276DB, 0xB41E2A, 0x7D0A],
    };
    return ROM_CURVE_MS256E;
};

module.exports.ROM_CURVE_MS256M = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_MS256M = {

        // MS256 Montgomery curve

        CURVE_A: -61370,
        CURVE_B: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x22B4AD, 0x4E6F11, 0x64E5B8, 0xD0A6BC, 0x6AA55A, 0xFFFFBE, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x3FFF],
        CURVE_Gx: [0xb, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    };
    return ROM_CURVE_MS256M;
};

module.exports.ROM_CURVE_MS256W = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_MS256W = {

        // MS256 Weierstrass curve

        CURVE_A: -3,
        CURVE_B: [0x25581, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x51A825, 0x202947, 0x6020AB, 0xEA265C, 0x3C8275, 0xFFFFE4, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFF],
        CURVE_Gx: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0xB56C77, 0x6306C2, 0xC10BF4, 0x75894E, 0x2C2F93, 0xDD6BD0, 0x6CCEEE, 0xFC82C9, 0xE466D7, 0x1853C1, 0x696F],

    };
    return ROM_CURVE_MS256W;
};

module.exports.ROM_CURVE_NIST256 = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_NIST256 = {

        // NIST256 Curve 

        CURVE_A: -3,
        CURVE_B: [0xD2604B, 0x3C3E27, 0xF63BCE, 0xCC53B0, 0x1D06B0, 0x86BC65, 0x557698, 0xB3EBBD, 0x3A93E7, 0x35D8AA, 0x5AC6],
        CURVE_Order: [0x632551, 0xCAC2FC, 0x84F3B9, 0xA7179E, 0xE6FAAD, 0xFFFFBC, 0xFFFFFF, 0xFFFFFF, 0x0, 0xFFFF00, 0xFFFF],
        CURVE_Gx: [0x98C296, 0x3945D8, 0xA0F4A1, 0x2DEB33, 0x37D81, 0x40F277, 0xE563A4, 0xF8BCE6, 0x2C4247, 0xD1F2E1, 0x6B17],
        CURVE_Gy: [0xBF51F5, 0x406837, 0xCECBB6, 0x6B315E, 0xCE3357, 0x9E162B, 0x4A7C0F, 0x8EE7EB, 0x1A7F9B, 0x42E2FE, 0x4FE3],

    };
    return ROM_CURVE_NIST256;
};

module.exports.ROM_CURVE_NIST384 = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_NIST384 = {

        // NIST384 curve

        CURVE_A: -3,
        CURVE_B: [0x6C2AEF, 0x11DBA7, 0x74AA17, 0x51768C, 0x6398D8, 0x6B58CA, 0x5404E1, 0xA0447, 0x411203, 0x5DFD02, 0x607671, 0x4168C8, 0x56BE3F, 0x1311C0, 0xFB9F9, 0x17D3F1, 0xB331],
        CURVE_Order: [0x452973, 0x32D599, 0x6BB3B0, 0x45853B, 0x20DB24, 0x3BEB03, 0x7D0DCB, 0x31A6C0, 0x7FFFC7, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0xFFFF],
        CURVE_Gx: [0x760AB7, 0x3C70E4, 0x30E951, 0x7AA94B, 0x2F25DB, 0x470AA0, 0x20950A, 0x7BA0F0, 0x1B9859, 0x45174F, 0x3874ED, 0x56BA3, 0x71EF32, 0x71D638, 0x22C14D, 0x65115F, 0xAA87],
        CURVE_Gy: [0x6A0E5F, 0x3AF921, 0x75E90C, 0x6BF40C, 0xB1CE1, 0x18014C, 0x6D7C2E, 0x6D1889, 0x147CE9, 0x7A5134, 0x63D076, 0x16E14F, 0xBF929, 0x6BB3D3, 0x98B1B, 0x6F254B, 0x3617],

    };
    return ROM_CURVE_NIST384;
};

module.exports.ROM_CURVE_NIST521 = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_NIST521 = {

        // NIST521 curve

        CURVE_A: -3,
        CURVE_B: [0x503F00, 0x3FA8D6, 0x47BD14, 0x6961A7, 0x3DF883, 0x60E6AE, 0x4EEC6F, 0x29605E, 0x137B16, 0x23D8FD, 0x5864E5, 0x84F0A, 0x1918EF, 0x771691, 0x6CC57C, 0x392DCC, 0x6EA2DA, 0x6D0A81, 0x688682, 0x50FC94, 0x18E1C9, 0x27D72C, 0x1465],
        CURVE_Order: [0x386409, 0x6E3D22, 0x3AEDBE, 0x4CE23D, 0x5C9B88, 0x3A0776, 0x3DC269, 0x6600A4, 0x166B7F, 0x77E5F, 0x461A1E, 0x7FFFD2, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFF],
        CURVE_Gx: [0x65BD66, 0x7C6385, 0x6FE5F9, 0x2B5214, 0xB3C18, 0x1BC669, 0x68BFEA, 0xEE093, 0x5928FE, 0x6FDFCE, 0x52D79, 0x69EDD5, 0x7606B4, 0x3F0515, 0x4FED48, 0x409C82, 0x429C64, 0x472B68, 0x7B2D98, 0x4E6CF1, 0x70404E, 0x31C0D6, 0x31A1],
        CURVE_Gy: [0x516650, 0x28ED3F, 0x222FA, 0x139612, 0x47086A, 0x6C26A7, 0x4FEB41, 0x285C80, 0x2640C5, 0x32BDE8, 0x5FB9CA, 0x733164, 0x517273, 0x2F5F7, 0x66D11A, 0x2224AB, 0x5998F5, 0x58FA37, 0x297ED0, 0x22E4, 0x9A3BC, 0x252D4F, 0x460E],

    };
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

module.exports.ROM_FIELD_254MF = function() {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_254MF = {
        // MF254 modulus
        Modulus: [0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x3F80],
        MConst: 0x3F81,

    };
    return ROM_FIELD_254MF;
};
module.exports.ROM_FIELD_25519 = function() {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_25519 = {
        // 25519 Curve Modulus
        Modulus: [0xFFFFED, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x7FFF],
        MConst: 19,
    };
    return ROM_FIELD_25519;
};
module.exports.ROM_FIELD_255MS = function() {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_255MS = {
        // MS255 modulus
        Modulus: [0xFFFD03, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x7FFF],
        MConst: 0x2FD,
    };
    return ROM_FIELD_255MS;
};
module.exports.ROM_FIELD_256MF = function() {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_256MF = {
        // MF256 modulus
        Modulus: [0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFA7],
        MConst: 0xFFA8,
    };
    return ROM_FIELD_256MF;
};
module.exports.ROM_FIELD_256MS = function() {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_256MS = {
        // MS256 modulus
        Modulus: [0xFFFF43, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFF],
        MConst: 0xBD,
    };
    return ROM_FIELD_256MS;
};
module.exports.ROM_FIELD_ANSSI = function() {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_ANSSI = {
        // ANSSI modulus
        Modulus: [0x6E9C03, 0xF353D8, 0x6DE8FC, 0xABC8CA, 0x61ADBC, 0x435B39, 0xE8CE42, 0x10126D, 0x3AD58F, 0x178C0B, 0xF1FD],
        MConst: 0x4E1155,

    };
    return ROM_FIELD_ANSSI;
};
module.exports.ROM_FIELD_BLS383 = function() {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_BLS383 = {
        // BLS383 Modulus 
        Modulus: [0x2D556B, 0x556A55, 0x75EAB2, 0x23AFBA, 0x1BB01, 0x2BAEA4, 0x5CC20F, 0x758B67, 0x20F99, 0x640A63, 0x69A3A8, 0x6009AA, 0x2A7852, 0x20B8AA, 0x7DD718, 0x104054, 0x7AC5],
        MConst: 0x23D0BD,
        Fra: [0x34508B, 0x4B3525, 0x4D0CAE, 0x503777, 0x463DB7, 0x3BF78E, 0xD072C, 0x2AE9A0, 0x69D32D, 0x282C73, 0x1730DB, 0xCD9F8, 0x6AB98B, 0x7DC9B0, 0x1CBCC8, 0x7D8CC3, 0x5A5],
        Frb: [0x7904E0, 0xA352F, 0x28DE04, 0x537843, 0x3B7D49, 0x6FB715, 0x4FBAE2, 0x4AA1C7, 0x183C6C, 0x3BDDEF, 0x5272CD, 0x532FB2, 0x3FBEC7, 0x22EEF9, 0x611A4F, 0x12B391, 0x751F],
    };
    return ROM_FIELD_BLS383;
};
module.exports.ROM_FIELD_BN254 = function() {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_BN254 = {
        // BN254 Modulus 
        Modulus: [0x13, 0x0, 0x13A700, 0x0, 0x210000, 0x861, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
        MConst: 0x9435E5,
        Fra: [0x2A6DE9, 0xE6C06F, 0xC2E17D, 0x4D3F77, 0x97492, 0x953F85, 0x50A846, 0xB6499B, 0x2E7C8C, 0x761921, 0x1B37],
        Frb: [0xD5922A, 0x193F90, 0x50C582, 0xB2C088, 0x178B6D, 0x6AC8DC, 0x2F57B9, 0x3EAB2, 0xD18375, 0xEE691E, 0x9EB],
    };
    return ROM_FIELD_BN254;
};
module.exports.ROM_FIELD_BN254CX = function() {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_BN254CX = {
        // BN254CX Modulus 
        Modulus: [0x1B55B3, 0x23EF5C, 0xE1BE66, 0x18093E, 0x3FD6EE, 0x66D324, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
        MConst: 0x789E85,
        Fra: [0xC80EA3, 0x83355, 0x215BD9, 0xF173F8, 0x677326, 0x189868, 0x8AACA7, 0xAFE18B, 0x3A0164, 0x82FA6, 0x1359],
        Frb: [0x534710, 0x1BBC06, 0xC0628D, 0x269546, 0xD863C7, 0x4E3ABB, 0xD9CDBC, 0xDC53, 0x3628A9, 0xF7D062, 0x10A6],
    };
    return ROM_FIELD_BN254CX;
};
module.exports.ROM_FIELD_BRAINPOOL = function() {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_BRAINPOOL = {
        // Brainpool modulus
        Modulus: [0x6E5377, 0x481D1F, 0x282013, 0xD52620, 0x3BF623, 0x8D726E, 0x909D83, 0x3E660A, 0xEEA9BC, 0x57DBA1, 0xA9FB],
        MConst: 0xFD89B9,
    };
    return ROM_FIELD_BRAINPOOL;
};
module.exports.ROM_FIELD_C41417 = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_FIELD_C41417 = {
        // C41417 modulus
        Modulus: [0x7FFFEF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF],
        MConst: 0x11,
    };
    return ROM_FIELD_C41417;
};
module.exports.ROM_FIELD_GOLDILOCKS = function() {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_GOLDILOCKS = {
        // GOLDILOCKS modulus
        Modulus: [0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7DFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FF],
        MConst: 0x1,

    };
    return ROM_FIELD_GOLDILOCKS;
};
module.exports.ROM_FIELD_HIFIVE = function() {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_HIFIVE = {
        // HIFIVE modulus
        Modulus: [0x7FFFFD, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3FFF],
        MConst: 0x3,

    };
    return ROM_FIELD_HIFIVE;
};
module.exports.ROM_FIELD_NIST256 = function() {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_NIST256 = {
        // NIST256 Modulus 
        Modulus: [0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x0, 0x0, 0x0, 0x0, 0x1, 0xFFFF00, 0xFFFF],
        MConst: 0x1,

    };
    return ROM_FIELD_NIST256;
};
module.exports.ROM_FIELD_NIST384 = function() {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_NIST384 = {
        // NIST384 modulus
        Modulus: [0x7FFFFF, 0x1FF, 0x0, 0x0, 0x7FFFF0, 0x7FDFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0xFFFF],
        MConst: 0x1,
    };
    return ROM_FIELD_NIST384;
};
module.exports.ROM_FIELD_NIST521 = function() {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_NIST521 = {
        // NIST521 modulus
        Modulus: [0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFF],
        MConst: 0x1,
    };
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

    return rsa_private_key;
};

module.exports.rsa_public_key = function(ctx) {

    var rsa_public_key = function(m) {
        this.e = 0;
        this.n = new ctx.FF(m);
    };

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

module.exports.UInt64 = function() {

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
    return UInt64;
};
},{}]},{},[1]);
