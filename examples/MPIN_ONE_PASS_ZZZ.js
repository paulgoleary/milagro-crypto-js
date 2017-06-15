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

eval(fs.readFileSync('@SWD/BIG_XXX.js') + '');
eval(fs.readFileSync('@SWD/DBIG_XXX.js') + '');
eval(fs.readFileSync('@SWD/ROM_CURVE_ZZZ.js') + '');
eval(fs.readFileSync('@SWD/ROM_FIELD_YYY.js') + '');
eval(fs.readFileSync('@SWD/UInt64.js') + '');
eval(fs.readFileSync('@SWD/RAND.js') + '');
eval(fs.readFileSync('@SWD/FP_YYY.js') + '');
eval(fs.readFileSync('@SWD/FP2_YYY.js') + '');
eval(fs.readFileSync('@SWD/FP4_YYY.js') + '');
eval(fs.readFileSync('@SWD/FP12_YYY.js') + '');
eval(fs.readFileSync('@SWD/HASH256.js') + '');
eval(fs.readFileSync('@SWD/HASH512.js') + '');
eval(fs.readFileSync('@SWD/ECP_ZZZ.js') + '');
eval(fs.readFileSync('@SWD/ECP2_ZZZ.js') + '');
eval(fs.readFileSync('@SWD/MPIN_ZZZ.js') + '');
eval(fs.readFileSync('@SWD/PAIR_ZZZ.js') + '');

/* Test M-Pin */

var RAW = [];
var rng = new RAND();
rng.clean();
for (i = 0; i < 100; i++) RAW[i] = i;

rng.seed(100, RAW);


var i, res;
var result;

var EGS = MPIN_ZZZ.EGS;
var EFS = MPIN_ZZZ.EFS;
var EAS = 16;

var sha = MPIN_ZZZ.HASH_TYPE;

var G1S = 2 * EFS + 1; /* Group 1 Size */
var G2S = 4 * EFS; /* Group 2 Size */

var S = [];
var SST = [];
var TOKEN = [];
var PERMIT = [];
var SEC = [];
var xID = [];
var xCID = [];
var X = [];
var Y = [];
var E = [];
var F = [];
var HCID = [];
var HID = [];
var HTID = [];

var G1 = [];
var G2 = [];
var R = [];
var Z = [];
var W = [];
var T = [];
var CK = [];
var SK = [];

var HSID = [];

/* Set configuration */
var PINERROR = true;
var FULL = true;

/* Trusted Authority set-up */
MPIN_ZZZ.RANDOM_GENERATE(rng, S);
console.log("M-Pin Master Secret s: 0x" + MPIN_ZZZ.bytestostring(S));

/* Create Client Identity */
var IDstr = "testUser@miracl.com";
var CLIENT_ID = MPIN_ZZZ.stringtobytes(IDstr);
HCID = MPIN_ZZZ.HASH_ID(sha, CLIENT_ID); /* Either Client or TA calculates Hash(ID) - you decide! */

console.log("Client ID= " + MPIN_ZZZ.bytestostring(CLIENT_ID));

/* Client and Server are issued secrets by DTA */
MPIN_ZZZ.GET_SERVER_SECRET(S, SST);
console.log("Server Secret SS: 0x" + MPIN_ZZZ.bytestostring(SST));

MPIN_ZZZ.GET_CLIENT_SECRET(S, HCID, TOKEN);
console.log("Client Secret CS: 0x" + MPIN_ZZZ.bytestostring(TOKEN));

/* Client extracts PIN from secret to create Token */
var pin = 1234;
console.log("Client extracts PIN= " + pin);
var rtn = MPIN_ZZZ.EXTRACT_PIN(sha, CLIENT_ID, pin, TOKEN);
if (rtn != 0)
    console.log("Failed to extract PIN ");

console.log("Client Token TK: 0x" + MPIN_ZZZ.bytestostring(TOKEN));

if (FULL) {
    MPIN_ZZZ.PRECOMPUTE(TOKEN, HCID, G1, G2);
}

var date = 0;

pin = 1234;

/* Set date=0 and PERMIT=null if time permits not in use

Client First pass: Inputs CLIENT_ID, optional RNG, pin, TOKEN and PERMIT. Output xID = x.H(CLIENT_ID) and re-combined secret SEC
If PERMITS are is use, then date!=0 and PERMIT is added to secret and xCID = x.(H(CLIENT_ID)+H_T(date|H(CLIENT_ID)))
Random value x is supplied externally if RNG=null, otherwise generated and passed out by RNG

If Time Permits OFF set xCID = null, HTID=null and use xID and HID only
If Time permits are ON, AND pin error detection is required then all of xID, xCID, HID and HTID are required
If Time permits are ON, AND pin error detection is NOT required, set xID=null, HID=null and use xCID and HTID only.


*/
var pxID = xID;
var pxCID = xCID;
var pHID = HID;
var pHTID = HTID;
var pE = E;
var pF = F;
var pPERMIT = PERMIT;
var prHID;

if (date != 0) {
    prHID = pHTID;
    if (!PINERROR) {
        pxID = null;
        //	pHID=null;
    }
} else {
    prHID = pHID;
    pPERMIT = null;
    pxCID = null;
    pHTID = null;
}
if (!PINERROR) {
    pE = null;
    pF = null;
}

console.log("MPIN Single Pass ");
timeValue = MPIN_ZZZ.GET_TIME();
console.log("Epoch " + timeValue);

rtn = MPIN_ZZZ.CLIENT(sha, date, CLIENT_ID, rng, X, pin, TOKEN, SEC, pxID, pxCID, pPERMIT, timeValue, Y);

if (rtn != 0) {
    console.error("FAILURE: CLIENT rtn: " + rtn);
    process.exit(-1);
}
if (FULL) {
    HCID = MPIN_ZZZ.HASH_ID(sha, CLIENT_ID);
    MPIN_ZZZ.GET_G1_MULTIPLE(rng, 1, R, HCID, Z); /* Also Send Z=r.ID to Server, remember random r */
}

rtn = MPIN_ZZZ.SERVER(sha, date, pHID, pHTID, Y, SST, pxID, pxCID, SEC, pE, pF, CLIENT_ID, timeValue);
if (rtn != 0) {
    console.error("FAILURE: SERVER rtn: " + rtn);
    process.exit(-1);
}

if (FULL) {
    HSID = MPIN_ZZZ.HASH_ID(sha, CLIENT_ID);
    MPIN_ZZZ.GET_G1_MULTIPLE(rng, 0, W, prHID, T); /* Also send T=w.ID to client, remember random w  */
}

if (rtn == MPIN_ZZZ.BAD_PIN) {
    console.log("Server says - Bad Pin. I don't know you. Feck off.");
    if (PINERROR) {
        var err = MPIN_ZZZ.KANGAROO(E, F);
        if (err != 0) {
            console.log("(Client PIN is out by " + err + ")");
            process.exit(-1);
        }
    }
} else {
    console.log("Server says - PIN is good! You really are " + IDstr);
    if (FULL) {
        H = MPIN_ZZZ.HASH_ALL(sha, HCID, pxID, pxCID, SEC, Y, Z, T);
        MPIN_ZZZ.CLIENT_KEY(sha, G1, G2, pin, R, X, H, T, CK);

        console.log("Client Key =  0x" + MPIN_ZZZ.bytestostring(CK));
        H = MPIN_ZZZ.HASH_ALL(sha, HSID, pxID, pxCID, SEC, Y, Z, T);
        MPIN_ZZZ.SERVER_KEY(sha, Z, SST, W, H, pHID, pxID, pxCID, SK);
        console.log("Server Key =  0x" + MPIN_ZZZ.bytestostring(SK));
    }
}
console.log('SUCCESS')