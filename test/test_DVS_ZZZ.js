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

var expect = chai.expect;

describe('TEST DVS ZZZ', function() {

    var rng = new RAND();
    var sha = MPIN_ZZZ.HASH_TYPE;

    before(function(done) {
        var RAW = [];
        rng.clean();
        for (i = 0; i < 100; i++) RAW[i] = i;
        rng.seed(100, RAW);
        done();
    });

    it('test Good Signature', function(done) {
        this.timeout(0);

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

        /* Trusted Authority set-up */
        MPIN_ZZZ.RANDOM_GENERATE(rng, S);

        /* Create Client Identity */
        var IDstr = "testuser@miracl.com";
        var CLIENT_ID = MPIN_ZZZ.stringtobytes(IDstr);

        /* Generate random public key and z */
        res = MPIN_ZZZ.GET_DVS_KEYPAIR(rng,Z,Pa);
        expect(res).to.be.equal(0);

        /* Append Pa to ID */
        for (var i = 0; i < Pa.length; i++)
            CLIENT_ID.push(Pa[i]);

        /* Hash Client ID */
        HCID = MPIN_ZZZ.HASH_ID(sha, CLIENT_ID);

        /* Client and Server are issued secrets by DTA */
        MPIN_ZZZ.GET_SERVER_SECRET(S, SST);
        MPIN_ZZZ.GET_CLIENT_SECRET(S, HCID, TOKEN);

        /* Compute client secret for key escrow less scheme z.CS */
        res = MPIN_ZZZ.GET_G1_MULTIPLE(null,0,Z,TOKEN,TOKEN);
        expect(res).to.be.equal(0);

        /* Client extracts PIN from secret to create Token */
        var pin = 1234;
        res = MPIN_ZZZ.EXTRACT_PIN(sha, CLIENT_ID, pin, TOKEN);
        expect(res).to.be.equal(0);

        var date = 0;
        var timeValue = MPIN_ZZZ.GET_TIME();

        var message = "Message to sign";

        res = MPIN_ZZZ.CLIENT(sha, 0, CLIENT_ID, rng, X, pin, TOKEN, SEC, U, null, null, timeValue, Y1, message);
        expect(res).to.be.equal(0);

        /* Server  */
        res = MPIN_ZZZ.SERVER(sha, 0, xID, null, Y2, SST, U, null, SEC, null, null, CLIENT_ID, timeValue, message, Pa);
        expect(res).to.be.equal(0);
        done();
    });

    it('test Bad Signature', function(done) {
        this.timeout(0);

        var res;

        var S = [];
        var SST = [];
        var TOKEN = [];
        var SEC = [];
        var xID = [];
        var X = [];
        var Y1 = [];
        var Y2 = [];
        var Z1 = [];
        var Z2 = [];
        var Pa1 = [];
        var Pa2 = [];
        var U = [];

        /* Trusted Authority set-up */
        MPIN_ZZZ.RANDOM_GENERATE(rng, S);

        /* Create Client Identity */
        var IDstr = "testuser@miracl.com";
        var CLIENT_ID = MPIN_ZZZ.stringtobytes(IDstr);

        /* Generate random public key and z */
        res = MPIN_ZZZ.GET_DVS_KEYPAIR(rng,Z1,Pa1);
        expect(res).to.be.equal(0);

        /* Generate random public key and z */
        res = MPIN_ZZZ.GET_DVS_KEYPAIR(rng,Z2,Pa2);
        expect(res).to.be.equal(0);

        /* Append Pa1 to ID */
        for (var i = 0; i < Pa1.length; i++)
            CLIENT_ID.push(Pa1[i]);

        /* Hash Client ID */
        HCID = MPIN_ZZZ.HASH_ID(sha, CLIENT_ID);

        /* Client and Server are issued secrets by DTA */
        MPIN_ZZZ.GET_SERVER_SECRET(S, SST);
        MPIN_ZZZ.GET_CLIENT_SECRET(S, HCID, TOKEN);

        /* Compute client secret for key escrow less scheme z.CS */
        res = MPIN_ZZZ.GET_G1_MULTIPLE(null,0,Z1,TOKEN,TOKEN);
        expect(res).to.be.equal(0);

        /* Client extracts PIN from secret to create Token */
        var pin = 1234;
        res = MPIN_ZZZ.EXTRACT_PIN(sha, CLIENT_ID, pin, TOKEN);
        expect(res).to.be.equal(0);

        var date = 0;
        var timeValue = MPIN_ZZZ.GET_TIME();

        var message = "Message to sign";

        res = MPIN_ZZZ.CLIENT(sha, 0, CLIENT_ID, rng, X, pin, TOKEN, SEC, U, null, null, timeValue, Y1, message);
        expect(res).to.be.equal(0);

        /* Server  */
        res = MPIN_ZZZ.SERVER(sha, 0, xID, null, Y2, SST, U, null, SEC, null, null, CLIENT_ID, timeValue, message, Pa2);
        expect(res).to.be.equal(MPIN_ZZZ.BAD_PIN);
        done();
    });

});