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

var fs = require('fs');

eval(fs.readFileSync('@SWD/BIG_XXX.js')+'');
eval(fs.readFileSync('@SWD/DBIG_XXX.js')+'');
eval(fs.readFileSync('@SWD/UInt64.js')+'');
eval(fs.readFileSync('@SWD/RAND.js')+'');
eval(fs.readFileSync('@SWD/FF_WWW.js')+'');
eval(fs.readFileSync('@SWD/RSA_WWW.js')+'');
eval(fs.readFileSync('@SWD/HASH256.js')+'');
eval(fs.readFileSync('@SWD/HASH384.js')+'');
eval(fs.readFileSync('@SWD/HASH512.js')+'');

console.log('Start test RSA');

var i,j=0,res;
var result;

var RAW=[];
var rng=new RAND();
rng.clean();
for (i=0;i<100;i++) RAW[i]=i;

rng.seed(100,RAW);

var sha=RSA_WWW.HASH_TYPE;
var message='Hello World\n';
var pub=new rsa_public_key(FF_WWW.FFLEN);
var priv=new rsa_private_key(FF_WWW.HFLEN);

var ML=[];
var C=[];
var S=[];

var start,end,time;
start=new Date().getTime();
console.log('Generating RSA public/private key pair (slow!)');
RSA_WWW.KEY_PAIR(rng,65537,priv,pub);
end=new Date().getTime();
time=end-start;
console.log('Time in ms= '+time);

var M=RSA_WWW.stringtobytes(message);  
console.log('Encrypting test string');

var E=RSA_WWW.OAEP_ENCODE(sha,M,rng,null); /* OAEP encode message m to e  */
console.log('Encoding= 0x' + RSA_WWW.bytestohex(E));  

console.log('Public key= 0x'+pub.n.toString()); 

start=new Date().getTime();	
RSA_WWW.ENCRYPT(pub,E,C);     /* encrypt encoded message */
end=new Date().getTime();	
time=end-start;
console.log('Time in ms= '+time);

console.log('Ciphertext= 0x' + RSA_WWW.bytestohex(C));  

console.log('Decrypting test string');
start=new Date().getTime();	
RSA_WWW.DECRYPT(priv,C,ML); 
end=new Date().getTime();
time=end-start;
console.log('Time in ms= '+time);

var cmp=true;
if (E.length!=ML.length) cmp=false;
else
{
	for (var j=0;j<E.length;j++)
		if (E[j]!=ML[j]) cmp=false;
}
if (cmp) console.log('Decryption is OK');
else{ 
	console.error('Decryption Failed');
	process.exit(-1);
}

var MS=RSA_WWW.OAEP_DECODE(sha,null,ML); /* OAEP decode message  */
console.log('Decoding= 0x' + RSA_WWW.bytestohex(MS));  

console.log('message= '+RSA_WWW.bytestostring(MS));  

console.log('Start test RSA signature');

RSA_WWW.PKCS15(sha,M,C);

RSA_WWW.DECRYPT(priv,C,S); /* create signature in S */ 

console.log('Signature= 0x' + RSA_WWW.bytestohex(S));  

RSA_WWW.ENCRYPT(pub,S,ML); 

cmp=true;
if (C.length!=ML.length) cmp=false;
else
{
	for (var j=0;j<C.length;j++)
		if (C[j]!=ML[j]) cmp=false;
}
if (cmp) console.log('Signature is valid');
else {
	console.error('Signature is INVALID');
	process.exit(-1);
}
RSA_WWW.PRIVATE_KEY_KILL(priv);

console.log('SUCCESS')