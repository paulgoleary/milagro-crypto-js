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


/* Test ECP ARITHMETICS - test driver and function exerciser for ECP API Functions */

// Here we test only some curves, but those tests cover all the fields FP.

var chai = require('chai');

var CTX = require("../src/ctx");

var expect = chai.expect;

var all_curves = ['ED25519', 'BN254', 'ANSSI', 'BLS383', 'BN254CX', 'BRAINPOOL', 'GOLDILOCKS', 'HIFIVE', 'NIST256'];

// to fix C41417 NIST384 NIST521

var readFP = function(string, ctx) {

    while (string.length != ctx.BIG.MODBYTES*2) string = "00"+string;
    var fp = new ctx.FP(0);
    var big = ctx.BIG.fromBytes(new Buffer(string, "hex"));
    fp.bcopy(big);

    return fp;
}
describe('TEST FP ARITHMETICS', function() {

	var j = all_curves.length - 1;

    for (var i = all_curves.length - 1; i >= 0; i--) {


        it('test '+all_curves[i], function(done) {
            this.timeout(0);
            var ctx = new CTX(all_curves[j]);
            var vectors = require('../testVectors/fp/'+all_curves[j]+'.json');
            j = j-1;

            for (var k = 0; k <= vectors.length - 1; k++) {

            	// test commutativity of addition
                var fp1 = readFP(vectors[k].FP1,ctx);
                var fp2 = readFP(vectors[k].FP2,ctx);
                var fpadd = readFP(vectors[k].FPadd,ctx);
                var a1 = new ctx.FP(0);
                var a2 = new ctx.FP(0);
                a1.copy(fp1);
                a2.copy(fp2);
                a1.add(a2);
                expect(a1.toString()).to.equal(fpadd.toString());
                a1.copy(fp1);
                a2.add(a1);
				expect(a2.toString()).to.equal(fpadd.toString());

				// test associativity of addition
	            a2.add(fpadd);
	            a1.copy(fp1);
                a1.add(fpadd);
                a1.add(fp2);
	            expect(a1.toString()).to.equal(a2.toString());

	            // test subtraction
	            var fpsub = readFP(vectors[k].FPsub, ctx);
	            a1.copy(fp1);
	            a2.copy(fp2);
	            a1.sub(a2);
                a1.reduce();
	            expect(a1.toString()).to.equal(fpsub.toString());

                // test multiplication
                var fpmul = readFP(vectors[k].FPmulmod, ctx);
                a1.copy(fp1);
                a2.copy(fp2);
                a1.mul(a2);
                a1.reduce();
                expect(a1.toString()).to.equal(fpmul.toString());

                // test small multiplication
                var fpimul = readFP(vectors[k].FPsmallmul, ctx);
                a2.imul(0);
                a2.reduce();
                expect(a2.iszilch()).to.equal(true);
                for (var vi = 1; vi <= 10; vi++) {
                    a1.copy(fp1);
                    a2.copy(fp1);
                    a1.imul(vi);
                    for (var vj = 1; vj < vi; vj++) {
                        a2.add(fp1);
                    }
                    expect(a1.toString()).to.equal(a2.toString());
                }
                expect(a1.toString()).to.equal(fpimul.toString());

                // test square
                var fpsqr = readFP(vectors[k].FPsqr, ctx);
                a1.copy(fp1);
                a1.sqr();
                a1.reduce();
                expect(a1.toString()).to.equal(fpsqr.toString());

                // test negative of a FP
                var fpneg = readFP(vectors[k].FPneg, ctx);
                a1.copy(fp1);
                a1.neg();
                a1.reduce();
                expect(a1.toString()).to.equal(fpneg.toString());

                // test division by 2
                var fpdiv2 = readFP(vectors[k].FPdiv2, ctx);
                a1.copy(fp1);
                a1.div2();
                a1.reduce();
                expect(a1.toString()).to.equal(fpdiv2.toString());

                // test inverse
                var fpinv = readFP(vectors[k].FPinv, ctx);
                a1.copy(fp1);
                a1.inverse();
                a1.reduce();
                expect(a1.toString()).to.equal(fpinv.toString());

                // test power
                var fppow = readFP(vectors[k].FPpow, ctx);
                a1.copy(fp1);
                a2.copy(fp2);
                var pow = a2.redc();
                pow.norm();
                a1 = a1.pow(pow);
                a1.reduce();
                expect(a1.toString()).to.equal(fppow.toString());


            }
            done();
        });

    }
});