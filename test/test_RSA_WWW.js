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
var chai = require('chai');

eval(fs.readFileSync('@SWD/UInt64.js')+'');
eval(fs.readFileSync('@SWD/HASH256.js')+'');
eval(fs.readFileSync('@SWD/HASH384.js')+'');
eval(fs.readFileSync('@SWD/HASH512.js')+'');
eval(fs.readFileSync('@SWD/BIG_XXX.js')+'');
eval(fs.readFileSync('@SWD/DBIG_XXX.js')+'');
eval(fs.readFileSync('@SWD/RAND.js')+'');
eval(fs.readFileSync('@SWD/FF_WWW.js')+'');
eval(fs.readFileSync('@SWD/RSA_WWW.js')+'');

var expect = chai.expect;

describe('TEST RSA WWW', function() {

	var vectors;
	var i,j=0,res;
	var result;
	var RAW=[];
	var rng=new RAND();
	var sha;
	var message;
	var pub;
	var priv;

	var ML=[];
	var C=[];
	var S=[];
	var M;
	var E;

	before(function(done){

		rng.clean();
		for (i=0;i<100;i++) RAW[i]=i;	
		rng.seed(100,RAW);
		sha=RSA_WWW.HASH_TYPE;
		done();
	});

	it('test RSA Enctyption/Decryption', function(done) {
	this.timeout(0);

		message='Hello World\n';

		pub=new rsa_public_key(FF_WWW.FFLEN);
		priv=new rsa_private_key(FF_WWW.HFLEN);

		// Load test vectors
		vectors = require('@TVD/RSA_WWW.json');
		FF_WWW.fromBytes(priv.p, new Buffer(vectors['priv.p'], "hex"));
		FF_WWW.fromBytes(priv.q, new Buffer(vectors['priv.q'], "hex"));
		FF_WWW.fromBytes(priv.dp, new Buffer(vectors['priv.dp'], "hex"));
		FF_WWW.fromBytes(priv.dq, new Buffer(vectors['priv.dq'], "hex"));
		FF_WWW.fromBytes(priv.c, new Buffer(vectors['priv.c'], "hex"));
		FF_WWW.fromBytes(pub.n, new Buffer(vectors['pub.n'], "hex"));
		pub.e=vectors['pub.e'];
		M=RSA_WWW.stringtobytes(message);
		E=RSA_WWW.OAEP_ENCODE(sha,M,rng,null); /* OAEP encode message m to e  */
		RSA_WWW.ENCRYPT(pub,E,C);     /* encrypt encoded message */
		RSA_WWW.DECRYPT(priv,C,ML); 
		var cmp=true;
		if (E.length!=ML.length) cmp=false;
		else
		{
			for (var j=0;j<E.length;j++)
				if (E[j]!=ML[j]) cmp=false;
		}
		expect(cmp).to.be.equal(true);
		// var MS=RSA_WWW.OAEP_DECODE(sha,null,ML); /* OAEP decode message  */
		done();
	});

	it('test RSA Signature', function(done) {
	this.timeout(0);
	
		RSA_WWW.PKCS15(sha,M,C);

		RSA_WWW.DECRYPT(priv,C,S); /* create signature in S */ 

		RSA_WWW.ENCRYPT(pub,S,ML); 
		var cmp=true;
		if (C.length!=ML.length) cmp=false;
		else
		{
			for (var j=0;j<C.length;j++)
				if (C[j]!=ML[j]) cmp=false;
		}
		expect(cmp).to.be.equal(true);
		RSA_WWW.PRIVATE_KEY_KILL(priv);
		done();
	});
});
