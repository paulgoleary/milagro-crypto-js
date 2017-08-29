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

var chai = require('chai');

var CTX = require("../src/ctx");

var expect = chai.expect;

var all_curves = ['ED25519', 'GOLDILOCKS', 'NIST256', 'BRAINPOOL', 'ANSSI', 'HIFIVE', 'C25519', 'BN254', 'BN254CX', 'BLS383'];

// To fix: C41417 NIST384 NIST521 MF254W MF254E MF254M MF256W MF256E MS255W MS255E MS255M MS256W MS256E MS256M

var readPoint = function(string, ctx) {
    
    var P = new ctx.ECP(0);
	var cos = string.split(":")

    var x = ctx.BIG.fromBytes(new Buffer(cos[0], "hex"));
    var y = ctx.BIG.fromBytes(new Buffer(cos[1], "hex"));
    P.setxy(x,y);

    return P;
}

describe('TEST ECP ARITHMETICS', function() {

	var j = all_curves.length - 1;

    for (var i = all_curves.length - 1; i >= 0; i--) {


        it('test '+all_curves[i], function(done) {
            this.timeout(0);
            var ctx = new CTX(all_curves[j]);
            var vectors = require('../testVectors/ecp/'+all_curves[j]+'.json');
            j = j-1;

            for (var k = 0; k <= vectors.length - 1; k++) {

                var P1 = readPoint(vectors[k].ECP1,ctx);
                var Paux1 = new ctx.ECP(0);
                var Paux2 = new ctx.ECP(0);
                Paux1.copy(P1);

                if (ctx.ECP.CURVETYPE != ctx.ECP.MONTGOMERY) {
                    // test that y^2 = RHS
                    var x = Paux1.getx();
                    var y = Paux1.gety();
                    y.sqr();
                    var res = ctx.ECP.RHS(x);

                    expect(res.toString()+" "+k).to.equal(y.toString()+" "+k);
                }

                if (ctx.ECP.CURVETYPE != ctx.ECP.MONTGOMERY) {
		            // test commutativity of the sum
		            var P2 = readPoint(vectors[k].ECP2,ctx);
		            var Psum = readPoint(vectors[k].ECPsum,ctx);
		            var Paux2 = new ctx.ECP(0);
		            Paux1.copy(P1);
		            Paux2.copy(P2);
		            Paux1.add(P2);
		            Paux1.affine();
		            Paux2.add(P1);
		            Paux2.affine();
		            expect(Paux1.toString()).to.equal(Psum.toString());
		            expect(Paux2.toString()).to.equal(Psum.toString());

		            // test associativity of the sum
		            Paux2.copy(P2);
		            Paux2.add(Psum);
		            Paux2.add(P1);
		            Paux2.affine();
		            Paux1.add(Psum)
		            Paux1.affine();
		            expect(Paux1.toString()).to.equal(Paux2.toString());

	                // test negative of a point
	                var Pneg = readPoint(vectors[k].ECPneg,ctx);
	                Paux1.copy(P1);
	                Paux1.neg();
	                Paux1.affine();
	                expect(Paux1.toString()).to.equal(Pneg.toString());

	                // test subtraction between points
	                var Psub = readPoint(vectors[k].ECPsub,ctx);
	                Paux1.copy(P1);
	                Paux1.sub(P2);
	                Paux1.affine();
	                expect(Paux1.toString()).to.equal(Psub.toString());
            	}

                // test doubling
                var Pdbl = readPoint(vectors[k].ECPdbl,ctx);
                Paux1.copy(P1);
                Paux1.dbl();
                Paux1.affine();
                expect(Paux1.toString()).to.equal(Pdbl.toString());

                // test scalar multiplication
                var Pmul = readPoint(vectors[k].ECPmul,ctx);
                var Scalar1 = ctx.BIG.fromBytes(new Buffer(vectors[k].BIGscalar1, "hex"));
                Paux1.copy(P1);
                Paux1 = Paux1.mul(Scalar1);
                Paux1.affine();
                expect(Paux1.toString()).to.equal(Pmul.toString());

                if (ctx.ECP.CURVETYPE != ctx.ECP.MONTGOMERY) {
	                // test multiplication by small integer
	                var Ppinmul = readPoint(vectors[k].ECPpinmul,ctx);
	                var Scalar1 = ctx.BIG.fromBytes(new Buffer(vectors[k].BIGscalar1, "hex"));
	                Paux1.copy(P1);
	                Paux1 = Paux1.pinmul(1234,14);
	                Paux1.affine();
	                expect(Paux1.toString()).to.equal(Ppinmul.toString());

	                // test mul2
	                var Pmul2 = readPoint(vectors[k].ECPmul2,ctx);
	                var Scalar2 = ctx.BIG.fromBytes(new Buffer(vectors[k].BIGscalar2, "hex"));
	                Paux1.copy(P1);
	                Paux2.copy(P2);
	                Paux1.affine();
	                Paux1 = Paux1.mul2(Scalar1,Paux2,Scalar2);
	                expect(Paux1.toString()).to.equal(Pmul2.toString());
	            }

                // test wrong coordinates and infinity point
                var Pwrong = readPoint(vectors[k].ECPwrong,ctx);
                var Pinf = readPoint(vectors[k].ECPinf,ctx);
                expect(Pwrong.is_infinity()).to.equal(true);
                expect(Pinf.is_infinity()).to.equal(true);
            }
            done();
        });

    }
});