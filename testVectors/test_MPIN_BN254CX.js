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

eval(fs.readFileSync('/home/alessandro/Dev/milagro-crypto-js/target/build_BN254CX/src/BIG_256.js') + '');
eval(fs.readFileSync('/home/alessandro/Dev/milagro-crypto-js/target/build_BN254CX/src/DBIG_256.js') + '');
eval(fs.readFileSync('/home/alessandro/Dev/milagro-crypto-js/target/build_BN254CX/src/ROM_CURVE_BN254CX.js') + '');
eval(fs.readFileSync('/home/alessandro/Dev/milagro-crypto-js/target/build_BN254CX/src/ROM_FIELD_BN254CX.js') + '');
eval(fs.readFileSync('/home/alessandro/Dev/milagro-crypto-js/target/build_BN254CX/src/UInt64.js') + '');
eval(fs.readFileSync('/home/alessandro/Dev/milagro-crypto-js/target/build_BN254CX/src/RAND.js') + '');
eval(fs.readFileSync('/home/alessandro/Dev/milagro-crypto-js/target/build_BN254CX/src/FP_BN254CX.js') + '');
eval(fs.readFileSync('/home/alessandro/Dev/milagro-crypto-js/target/build_BN254CX/src/FP2_BN254CX.js') + '');
eval(fs.readFileSync('/home/alessandro/Dev/milagro-crypto-js/target/build_BN254CX/src/FP4_BN254CX.js') + '');
eval(fs.readFileSync('/home/alessandro/Dev/milagro-crypto-js/target/build_BN254CX/src/FP12_BN254CX.js') + '');
eval(fs.readFileSync('/home/alessandro/Dev/milagro-crypto-js/target/build_BN254CX/src/HASH256.js') + '');
eval(fs.readFileSync('/home/alessandro/Dev/milagro-crypto-js/target/build_BN254CX/src/HASH512.js') + '');
eval(fs.readFileSync('/home/alessandro/Dev/milagro-crypto-js/target/build_BN254CX/src/ECP_BN254CX.js') + '');
eval(fs.readFileSync('/home/alessandro/Dev/milagro-crypto-js/target/build_BN254CX/src/ECP2_BN254CX.js') + '');
eval(fs.readFileSync('/home/alessandro/Dev/milagro-crypto-js/target/build_BN254CX/src/MPIN_BN254CX.js') + '');
eval(fs.readFileSync('/home/alessandro/Dev/milagro-crypto-js/target/build_BN254CX/src/PAIR_BN254CX.js') + '');

var expect = chai.expect;

hextobytes = function (value_hex) {
    // "use strict";
    var len, byte_value, i;

    len = value_hex.length;
    byte_value = [];

    for (i = 0; i < len; i += 2) {
        byte_value[(i / 2)] = parseInt(value_hex.substr(i, 2), 16);
    }
    return byte_value;
};


describe('TEST MPIN BN254CX', function() {

    var rng = new RAND();

    before(function(done) {
        var RAW = [];
        rng.clean();
        for (i = 0; i < 100; i++) RAW[i] = i;
        rng.seed(100, RAW);
        done();
    });

    it('test MPin Pass1 BN254CX', function(done) {
        this.timeout(0);
        // Load test vectors
        var vectors = require('/home/alessandro/Dev/milagro-crypto-js/testVectors/MPIN_PASS1_BN254CX.json');

        var sha = MPIN_BN254CX.HASH_TYPE;
        var xID = [];
        var xCID = [];
        var SEC = [];
        var Y = [];

        var pxID = xID;
        var pxCID = xCID;

	for(var vector in vectors)
  		{
        	var rtn = MPIN_BN254CX.CLIENT_1(sha, vectors[vector].DATE, hextobytes(vectors[vector].MPIN_ID_HEX), null, hextobytes(vectors[vector].X), vectors[vector].PIN2, hextobytes(vectors[vector].TOKEN), SEC, pxID, pxCID, hextobytes(vectors[vector].TIME_PERMIT));
        	expect(rtn).to.be.equal(0);
            expect(MPIN_BN254CX.bytestostring(pxID)).to.be.equal(vectors[vector].U);
        	expect(MPIN_BN254CX.bytestostring(pxCID)).to.be.equal(vectors[vector].UT);
        }
    });

	it('test MPin Pass2 BN254CX', function(done) {
        this.timeout(0);
        // Load test vectors
        var vectors = require('/home/alessandro/Dev/milagro-crypto-js/testVectors/MPIN_PASS1_BN254CX.json');

        var sha = MPIN_BN254CX.HASH_TYPE;
        var xID = [];
        var xCID = [];
        var SEC = [];
        var Y = [];

        var pxID = xID;
        var pxCID = xCID;

	for(var vector in vectors)
  		{
        	var rtn = MPIN_BN254CX.CLIENT_1(sha, vectors[vector].DATE, hextobytes(vectors[vector].MPIN_ID_HEX), null, hextobytes(vectors[vector].X), vectors[vector].PIN2, hextobytes(vectors[vector].TOKEN), SEC, pxID, pxCID, hextobytes(vectors[vector].TIME_PERMIT));
        	expect(rtn).to.be.equal(0);
            expect(MPIN_BN254CX.bytestostring(pxID)).to.be.equal(vectors[vector].U);
        	expect(MPIN_BN254CX.bytestostring(pxCID)).to.be.equal(vectors[vector].UT);
        }
    });
});










// // Set OTP switch
// var requestOTP = 1;
// // Set WID
// var accessNumber = 123456;

// for(var vector in vectors)
//   {
//     console.log("Test "+vectors[vector].test_no);
//     if (DEBUG){console.log("X "+vectors[vector].X);}
//     if (DEBUG){console.log("Y "+vectors[vector].Y);}
//     if (DEBUG){console.log("SEC "+vectors[vector].SEC);}
//     MPINAuth.X = MPINAuth.hextobytes(vectors[vector].X);
//     MPINAuth.SEC = MPINAuth.hextobytes(vectors[vector].SEC);
//     var pass2 = MPINAuth.pass2Request(vectors[vector].Y, requestOTP, accessNumber);