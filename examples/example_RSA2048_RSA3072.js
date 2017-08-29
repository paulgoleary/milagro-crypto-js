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

/* Test RSA - test driver and function exerciser for RSA_2048 and RSA_3072 */

var CTX = require("../src/ctx");

var ctx = new CTX('RSA2048');

console.log('Start test RSA2048');

// Load test vectors
var vectors = require('../testVectors/rsa/RSA2048.json');

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

ctx.FF.fromBytes(priv.p, new Buffer(vectors[0].PrivP, "hex"));
ctx.FF.fromBytes(priv.q, new Buffer(vectors[0].PrivQ, "hex"));
ctx.FF.fromBytes(priv.dp, new Buffer(vectors[0].PrivDP, "hex"));
ctx.FF.fromBytes(priv.dq, new Buffer(vectors[0].PrivDQ, "hex"));
ctx.FF.fromBytes(priv.c, new Buffer(vectors[0].PrivC, "hex"));
ctx.FF.fromBytes(pub.n, new Buffer(vectors[0].PubN, "hex"));
pub.e = vectors[0].PubE;

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
var vectors = require('../testVectors/rsa/RSA3072.json');

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

ctx1.FF.fromBytes(priv.p, new Buffer(vectors[0].PrivP, "hex"));
ctx1.FF.fromBytes(priv.q, new Buffer(vectors[0].PrivQ, "hex"));
ctx1.FF.fromBytes(priv.dp, new Buffer(vectors[0].PrivDP, "hex"));
ctx1.FF.fromBytes(priv.dq, new Buffer(vectors[0].PrivDQ, "hex"));
ctx1.FF.fromBytes(priv.c, new Buffer(vectors[0].PrivC, "hex"));
ctx1.FF.fromBytes(pub.n, new Buffer(vectors[0].PubN, "hex"));
pub.e = vectors[0].PubE;

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