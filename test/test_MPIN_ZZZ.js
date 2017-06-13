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

/* Test MPIN - test driver and function exerciser for MPIN API Functions */

var fs = require('fs');
var chai = require('chai');

eval(fs.readFileSync('@SWD/BIG_XXX.js')+'');
eval(fs.readFileSync('@SWD/DBIG_XXX.js')+'');
eval(fs.readFileSync('@SWD/ROM_CURVE_ZZZ.js')+'');
eval(fs.readFileSync('@SWD/ROM_FIELD_YYY.js')+'');
eval(fs.readFileSync('@SWD/UInt64.js')+'');
eval(fs.readFileSync('@SWD/RAND.js')+'');
eval(fs.readFileSync('@SWD/FP_YYY.js')+'');
eval(fs.readFileSync('@SWD/FP2_YYY.js')+'');
eval(fs.readFileSync('@SWD/FP4_YYY.js')+'');
eval(fs.readFileSync('@SWD/FP12_YYY.js')+'');
eval(fs.readFileSync('@SWD/HASH256.js')+'');
eval(fs.readFileSync('@SWD/HASH512.js')+'');
eval(fs.readFileSync('@SWD/ECP_ZZZ.js')+'');
eval(fs.readFileSync('@SWD/ECP2_ZZZ.js')+'');
eval(fs.readFileSync('@SWD/MPIN_ZZZ.js')+'');
eval(fs.readFileSync('@SWD/PAIR_ZZZ.js')+'');

var expect = chai.expect;

describe('TEST MPIN ZZZ', function() {

	var rng = new RAND();

	before(function(done){
		var RAW = [];
		rng.clean();
		for (i = 0; i < 100; i++) RAW[i] = i;
		rng.seed(100, RAW);
		done();
	});

	it('test MPin', function(done) {
		this.timeout(0);
		
		var i,res;
		var result;

		var EGS=MPIN_ZZZ.EGS;
		var EFS=MPIN_ZZZ.EFS;
		var EAS=16;

		var sha=MPIN_ZZZ.HASH_TYPE;

		var G1S=2*EFS+1; /* Group 1 Size */
		var G2S=4*EFS; /* Group 2 Size */

		var S=[];
		var SST=[];
		var TOKEN = [];
		var PERMIT = [];
		var SEC = [];
		var xID = [];
		var X= [];
		var Y= [];
		var HCID=[];
		var HID=[];

		var G1=[];
		var G2=[];
		var R=[];
		var Z=[];
		var W=[];
		var T=[];
		var CK=[];
		var SK=[];

		var HSID=[];

		/* Set configuration */
		var PINERROR=true;

		/* Trusted Authority set-up */
		MPIN_ZZZ.RANDOM_GENERATE(rng,S);

		/* Create Client Identity */
		var IDstr = "testUser@miracl.com";
		var CLIENT_ID = MPIN_ZZZ.stringtobytes(IDstr);  
		HCID=MPIN_ZZZ.HASH_ID(sha,CLIENT_ID);  /* Either Client or TA calculates Hash(ID) - you decide! */

		/* Client and Server are issued secrets by DTA */
		MPIN_ZZZ.GET_SERVER_SECRET(S,SST);

		MPIN_ZZZ.GET_CLIENT_SECRET(S,HCID,TOKEN);

		/* Client extracts PIN from secret to create Token */
		var pin=1234;
		var rtn=MPIN_ZZZ.EXTRACT_PIN(sha,CLIENT_ID,pin,TOKEN);
		expect(rtn).to.be.equal(0);  

		var date=0;
		pin=1234;

		var pxID=xID;
		var pHID=HID;

		var prHID;
		prHID=pHID;

		rtn=MPIN_ZZZ.CLIENT_1(sha,date,CLIENT_ID,rng,X,pin,TOKEN,SEC,pxID,null,null);
		expect(rtn).to.be.equal(0);

		/* Server calculates H(ID) and H(T|H(ID)) (if time permits enabled), and maps them to points on the curve HID and HTID resp. */
		MPIN_ZZZ.SERVER_1(sha,date,CLIENT_ID,pHID,null);

		/* Server generates Random number Y and sends it to Client */
		MPIN_ZZZ.RANDOM_GENERATE(rng,Y);

		/* Client Second Pass: Inputs Client secret SEC, x and y. Outputs -(x+y)*SEC */
		rtn=MPIN_ZZZ.CLIENT_2(X,Y,SEC);
		expect(rtn).to.be.equal(0);

		/* Server Second pass. Inputs hashed client id, random Y, -(x+y)*SEC, xID and xCID and Server secret SST. E and F help kangaroos to find error. */
		/* If PIN error not required, set E and F = NULL */
		rtn=MPIN_ZZZ.SERVER_2(date,pHID,null,Y,SST,pxID,null,SEC,null,null);

		expect(rtn).to.be.equal(0);
		done();
	});

	it('test MPin Time Permits', function(done) {
		this.timeout(0);
		var i,res;
		var result;

		var EGS=MPIN_ZZZ.EGS;
		var EFS=MPIN_ZZZ.EFS;
		var EAS=16;

		var sha=MPIN_ZZZ.HASH_TYPE;

		var G1S=2*EFS+1; /* Group 1 Size */
		var G2S=4*EFS; /* Group 2 Size */

		var S=[];
		var SST=[];
		var TOKEN = [];
		var PERMIT = [];
		var SEC = [];
		var xID = [];
		var xCID = [];
		var X= [];
		var Y= [];
		var HCID=[];
		var HID=[];
		var HTID=[];

		var HSID=[];

		/* Trusted Authority set-up */
		MPIN_ZZZ.RANDOM_GENERATE(rng,S);
		
		/* Create Client Identity */
		var IDstr = "testUser@miracl.com";
		var CLIENT_ID = MPIN_ZZZ.stringtobytes(IDstr);  
		HCID=MPIN_ZZZ.HASH_ID(sha,CLIENT_ID);  /* Either Client or TA calculates Hash(ID) - you decide! */
			
		/* Client and Server are issued secrets by DTA */
		MPIN_ZZZ.GET_SERVER_SECRET(S,SST);
		MPIN_ZZZ.GET_CLIENT_SECRET(S,HCID,TOKEN);
		
		/* Client extracts PIN from secret to create Token */
		var pin=1234;
		var rtn=MPIN_ZZZ.EXTRACT_PIN(sha,CLIENT_ID,pin,TOKEN);
		expect(rtn).to.be.equal(0); 

		var date = MPIN_ZZZ.today();
		/* Client gets "Time Token" permit from DTA */ 	
		MPIN_ZZZ.GET_CLIENT_PERMIT(sha,date,S,HCID,PERMIT);

		/* This encoding makes Time permit look random - Elligator squared */
		MPIN_ZZZ.ENCODING(rng,PERMIT);
		MPIN_ZZZ.DECODING(PERMIT);

		pin=1234;

		var pxCID=xCID;
		var pHID=HID;
		var pHTID=HTID;
		var pPERMIT=PERMIT;
		var prHID;

		prHID=pHTID;

		pxID=null;

		rtn=MPIN_ZZZ.CLIENT_1(sha,date,CLIENT_ID,rng,X,pin,TOKEN,SEC,pxID,pxCID,pPERMIT);
		expect(rtn).to.be.equal(0);

		/* Server calculates H(ID) and H(T|H(ID)) (if time permits enabled), and maps them to points on the curve HID and HTID resp. */
		MPIN_ZZZ.SERVER_1(sha,date,CLIENT_ID,pHID,pHTID);

		/* Server generates Random number Y and sends it to Client */
		MPIN_ZZZ.RANDOM_GENERATE(rng,Y);

		/* Client Second Pass: Inputs Client secret SEC, x and y. Outputs -(x+y)*SEC */
		rtn=MPIN_ZZZ.CLIENT_2(X,Y,SEC);
		expect(rtn).to.be.equal(0);

		/* Server Second pass. Inputs hashed client id, random Y, -(x+y)*SEC, xID and xCID and Server secret SST. E and F help kangaroos to find error. */
		/* If PIN error not required, set E and F = NULL */
		rtn=MPIN_ZZZ.SERVER_2(date,pHID,pHTID,Y,SST,pxID,pxCID,SEC,null,null);
		expect(rtn).to.be.equal(0);

		done();

	});

	it('test MPin Full One Pass', function(done) {
		this.timeout(0);
		var i,res, result;

		var EGS=MPIN_ZZZ.EGS;
		var EFS=MPIN_ZZZ.EFS;
		var EAS=16;

		var sha=MPIN_ZZZ.HASH_TYPE;

		var G1S=2*EFS+1; /* Group 1 Size */
		var G2S=4*EFS; /* Group 2 Size */

		var S=[];
		var SST=[];
		var TOKEN = [];
		var PERMIT = [];
		var SEC = [];
		var xID = [];
		var xCID = [];
		var X= [];
		var Y= [];
		var E=[];
		var F=[];
		var HCID=[];
		var HID=[];
		var HTID=[];

		var G1=[];
		var G2=[];
		var R=[];
		var Z=[];
		var W=[];
		var T=[];
		var CK=[];
		var SK=[];

		var HSID=[];

		/* Trusted Authority set-up */
		MPIN_ZZZ.RANDOM_GENERATE(rng,S);

		/* Create Client Identity */
		var IDstr = "testUser@miracl.com";
		var CLIENT_ID = MPIN_ZZZ.stringtobytes(IDstr);  
		HCID=MPIN_ZZZ.HASH_ID(sha,CLIENT_ID);  /* Either Client or TA calculates Hash(ID) - you decide! */
			
		/* Client and Server are issued secrets by DTA */
		MPIN_ZZZ.GET_SERVER_SECRET(S,SST);

		MPIN_ZZZ.GET_CLIENT_SECRET(S,HCID,TOKEN);    

		/* Client extracts PIN from secret to create Token */
		var pin=1234;
		var rtn=MPIN_ZZZ.EXTRACT_PIN(sha,CLIENT_ID,pin,TOKEN);
		expect(rtn).to.be.equal(0);

		MPIN_ZZZ.PRECOMPUTE(TOKEN,HCID,G1,G2);

		var date=0;

		pin=1234;

		var pxID=xID;
		var pxCID=xCID;
		var pHID=HID;
		var pHTID=HTID;
		var pE=E;
		var pF=F;
		var pPERMIT=PERMIT;
		var prHID;

		prHID=pHID;
		pPERMIT=null;
		pxCID=null;
		pHTID=null;

		pE=null;
		pF=null;

		timeValue = MPIN_ZZZ.GET_TIME();  

		rtn=MPIN_ZZZ.CLIENT(sha,date,CLIENT_ID,rng,X,pin,TOKEN,SEC,pxID,pxCID,pPERMIT,timeValue,Y);
		expect(rtn).to.be.equal(0);

		HCID=MPIN_ZZZ.HASH_ID(sha,CLIENT_ID);
		MPIN_ZZZ.GET_G1_MULTIPLE(rng,1,R,HCID,Z);  /* Also Send Z=r.ID to Server, remember random r */

		rtn=MPIN_ZZZ.SERVER(sha,date,pHID,pHTID,Y,SST,pxID,pxCID,SEC,pE,pF,CLIENT_ID,timeValue);
		expect(rtn).to.be.equal(0);

		HSID=MPIN_ZZZ.HASH_ID(sha,CLIENT_ID);
		MPIN_ZZZ.GET_G1_MULTIPLE(rng,0,W,prHID,T);  /* Also send T=w.ID to client, remember random w  */

		H=MPIN_ZZZ.HASH_ALL(sha,HCID,pxID,pxCID,SEC,Y,Z,T);
		MPIN_ZZZ.CLIENT_KEY(sha,G1,G2,pin,R,X,H,T,CK);
		
		H=MPIN_ZZZ.HASH_ALL(sha,HSID,pxID,pxCID,SEC,Y,Z,T);
		MPIN_ZZZ.SERVER_KEY(sha,Z,SST,W,H,pHID,pxID,pxCID,SK);
		expect(CK).to.be.equal(CK);

		done();
	});

	it('test MPin FUll Two Pass', function(done) {
		this.timeout(0);
		var i,res;
		var result;

		var EGS=MPIN_ZZZ.EGS;
		var EFS=MPIN_ZZZ.EFS;
		var EAS=16;

		var sha=MPIN_ZZZ.HASH_TYPE;

		var G1S=2*EFS+1; /* Group 1 Size */
		var G2S=4*EFS; /* Group 2 Size */

		var S=[];
		var SST=[];
		var TOKEN = [];
		var PERMIT = [];
		var SEC = [];
		var xID = [];
		var xCID = [];
		var X= [];
		var Y= [];
		var E=[];
		var F=[];
		var HCID=[];
		var HID=[];
		var HTID=[];

		var G1=[];
		var G2=[];
		var R=[];
		var Z=[];
		var W=[];
		var T=[];
		var CK=[];
		var SK=[];

		var HSID=[];

		/* Set configuration */
		var PERMITS=true;

		/* Trusted Authority set-up */
		MPIN_ZZZ.RANDOM_GENERATE(rng,S);
		
		/* Create Client Identity */
			var IDstr = "testUser@miracl.com";
		var CLIENT_ID = MPIN_ZZZ.stringtobytes(IDstr);  
		HCID=MPIN_ZZZ.HASH_ID(sha,CLIENT_ID);  /* Either Client or TA calculates Hash(ID) - you decide! */
		
		/* Client and Server are issued secrets by DTA */
		MPIN_ZZZ.GET_SERVER_SECRET(S,SST);
		MPIN_ZZZ.GET_CLIENT_SECRET(S,HCID,TOKEN);
		
		/* Client extracts PIN from secret to create Token */
		var pin=1234;
		var rtn=MPIN_ZZZ.EXTRACT_PIN(sha,CLIENT_ID,pin,TOKEN);
		expect(rtn).to.be.equal(0);

		MPIN_ZZZ.PRECOMPUTE(TOKEN,HCID,G1,G2);

		var date;
		if (PERMITS)
		{
			date=MPIN_ZZZ.today();
		/* Client gets "Time Token" permit from DTA */ 	
			MPIN_ZZZ.GET_CLIENT_PERMIT(sha,date,S,HCID,PERMIT);
			
		/* This encoding makes Time permit look random - Elligator squared */
			MPIN_ZZZ.ENCODING(rng,PERMIT);
			MPIN_ZZZ.DECODING(PERMIT);
		}
		else date=0;

		pin=1234;
		
		var pxID=xID;
		var pxCID=xCID;
		var pHID=HID;
		var pHTID=HTID;
		var pE=E;
		var pF=F;
		var pPERMIT=PERMIT;
		var prHID;

		if (date!=0)
		{
			prHID=pHTID;
			pxID=null;
		}
		else
		{
			prHID=pHID;
			pPERMIT=null;
			pxCID=null;
			pHTID=null;
		}
		pE=null;
		pF=null;

		rtn=MPIN_ZZZ.CLIENT_1(sha,date,CLIENT_ID,rng,X,pin,TOKEN,SEC,pxID,pxCID,pPERMIT);
		expect(rtn).to.be.equal(0);

		HCID=MPIN_ZZZ.HASH_ID(sha,CLIENT_ID);
		MPIN_ZZZ.GET_G1_MULTIPLE(rng,1,R,HCID,Z);  /* Also Send Z=r.ID to Server, remember random r */

	/* Server calculates H(ID) and H(T|H(ID)) (if time permits enabled), and maps them to points on the curve HID and HTID resp. */
		MPIN_ZZZ.SERVER_1(sha,date,CLIENT_ID,pHID,pHTID);

	/* Server generates Random number Y and sends it to Client */
		MPIN_ZZZ.RANDOM_GENERATE(rng,Y);

		HSID=MPIN_ZZZ.HASH_ID(sha,CLIENT_ID);
		MPIN_ZZZ.GET_G1_MULTIPLE(rng,0,W,prHID,T);  /* Also send T=w.ID to client, remember random w  */

	/* Client Second Pass: Inputs Client secret SEC, x and y. Outputs -(x+y)*SEC */
		rtn=MPIN_ZZZ.CLIENT_2(X,Y,SEC);
		expect(rtn).to.be.equal(0);

	/* Server Second pass. Inputs hashed client id, random Y, -(x+y)*SEC, xID and xCID and Server secret SST. E and F help kangaroos to find error. */
	/* If PIN error not required, set E and F = NULL */
		rtn=MPIN_ZZZ.SERVER_2(date,pHID,pHTID,Y,SST,pxID,pxCID,SEC,pE,pF);
		expect(rtn).to.be.equal(0);

		H=MPIN_ZZZ.HASH_ALL(sha,HCID,pxID,pxCID,SEC,Y,Z,T);
		MPIN_ZZZ.CLIENT_KEY(sha,G1,G2,pin,R,X,H,T,CK);
			
		H=MPIN_ZZZ.HASH_ALL(sha,HSID,pxID,pxCID,SEC,Y,Z,T);
		MPIN_ZZZ.SERVER_KEY(sha,Z,SST,W,H,pHID,pxID,pxCID,SK);

		expect(CK).to.be.equal(CK);

		done();
	});
});

