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


/* Test ECC - test driver and function exerciser for ECDH_ZZZ/ECIES/ECDSA API Functions */

var fs = require('fs');

eval(fs.readFileSync('@SWD/BIG_XXX.js')+'');
eval(fs.readFileSync('@SWD/DBIG_XXX.js')+'');
eval(fs.readFileSync('@SWD/ROM_CURVE_ZZZ.js')+'');
eval(fs.readFileSync('@SWD/ROM_FIELD_YYY.js')+'');
eval(fs.readFileSync('@SWD/UInt64.js')+'');
eval(fs.readFileSync('@SWD/RAND.js')+'');
eval(fs.readFileSync('@SWD/FP_YYY.js')+'');
eval(fs.readFileSync('@SWD/HASH256.js')+'');
eval(fs.readFileSync('@SWD/HASH512.js')+'');
eval(fs.readFileSync('@SWD/ECP_ZZZ.js')+'');
eval(fs.readFileSync('@SWD/ECDH_ZZZ.js')+'');
eval(fs.readFileSync('@SWD/AES.js')+'');

console.log('Start testing ECDH');

var i,j=0,res;
var result;
var pp="M0ng00se";

var EGS=ECDH_ZZZ.EGS;
var EFS=ECDH_ZZZ.EFS;
var EAS=16;
var sha=ECDH_ZZZ.HASH_TYPE;

var S1=[];
var W0=[];
var W1=[];
var Z0=[];
var Z1=[];
var RAW=[];
var SALT=[];
var P1=[];
var P2=[];
var V=[];
var M=[];
var T=new Array(12);  // must specify required length
var CS=[];
var DS=[];

var rng=new RAND();

rng.clean();
for (i=0;i<100;i++) RAW[i]=i;

rng.seed(100,RAW);


for (i=0;i<8;i++) SALT[i]=(i+1);  // set Salt

console.log("Alice's Passphrase= " + pp );

var PW=ECDH_ZZZ.stringtobytes(pp);
// private key S0 of size EGS bytes derived from Password and Salt 
var S0=ECDH_ZZZ.PBKDF2(sha,PW,SALT,1000,EGS);

console.log("Alice's private key= 0x"+ECDH_ZZZ.bytestostring(S0));
// Generate Key pair S/W 
ECDH_ZZZ.KEY_PAIR_GENERATE(null,S0,W0); 

console.log("Alice's public key= 0x"+ECDH_ZZZ.bytestostring(W0));

res=ECDH_ZZZ.PUBLIC_KEY_VALIDATE(W0);
if (res!=0)
	exit("ECP_ZZZ Public Key is invalid!");
// Random private key for other party 
ECDH_ZZZ.KEY_PAIR_GENERATE(rng,S1,W1);

console.log("Servers private key= 0x"+ECDH_ZZZ.bytestostring(S1));
console.log("Servers public key= 0x"+ECDH_ZZZ.bytestostring(W1));

res=ECDH_ZZZ.PUBLIC_KEY_VALIDATE(W1);
if (res!=0)
	exit("ECP_ZZZ Public Key is invalid!");
		

// Calculate common key using DH - IEEE 1363 method 

ECDH_ZZZ.ECPSVDP_DH(S0,W1,Z0);
ECDH_ZZZ.ECPSVDP_DH(S1,W0,Z1);

var same=true;
for (i=0;i<ECDH_ZZZ.EFS;i++)
	if (Z0[i]!=Z1[i]) same=false;

if (!same)
	exit("ECP_ZZZSVDP-DH Failed");

var KEY=ECDH_ZZZ.KDF2(sha,Z0,null,ECDH_ZZZ.EAS);

console.log("Alice's ECDH Key= 0x"+ECDH_ZZZ.bytestostring(KEY));
console.log("Servers ECDH Key= 0x"+ECDH_ZZZ.bytestostring(KEY));

if (ECP_ZZZ.CURVETYPE!=ECP_ZZZ.MONTGOMERY)
{
	console.log("Testing ECIES");

	P1[0]=0x0; P1[1]=0x1; P1[2]=0x2; 
	P2[0]=0x0; P2[1]=0x1; P2[2]=0x2; P2[3]=0x3; 

	for (i=0;i<=16;i++) M[i]=i; 

	var C=ECDH_ZZZ.ECIES_ENCRYPT(sha,P1,P2,rng,W1,M,V,T);

	console.log("Ciphertext= ");
	console.log("V= 0x"+ECDH_ZZZ.bytestostring(V));
	console.log("C= 0x"+ECDH_ZZZ.bytestostring(C));
	console.log("T= 0x"+ECDH_ZZZ.bytestostring(T));


	M=ECDH_ZZZ.ECIES_DECRYPT(sha,P1,P2,V,C,T,S1);
	if (M.length==0)
		exit("ECIES Decryption Failed");
	else console.log("Decryption succeeded");

	console.log("Message is 0x"+ECDH_ZZZ.bytestostring(M));

	console.log("Testing ECDSA");

	if (ECDH_ZZZ.ECPSP_DSA(sha,rng,S0,M,CS,DS)!=0)
		exit("ECDSA Signature Failed");
	
	console.log("Signature= ");
	console.log("C= 0x"+ECDH_ZZZ.bytestostring(CS));
	console.log("D= 0x"+ECDH_ZZZ.bytestostring(DS));

	if (ECDH_ZZZ.ECPVP_DSA(sha,W0,M,CS,DS)!=0)
		exit("ECDSA Verification Failed");
	else console.log("ECDSA Signature/Verification succeeded");
}

return('PASSED');