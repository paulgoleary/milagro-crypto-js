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


/* Test HASH function - test driver and function exerciser for SHA256, SHA384, SHA512 API Functions */

var CTX = require("../index");

var chai = require('chai');

var expect = chai.expect;

var ctx = new CTX();

var hextobytes = ctx.Utils.hextobytes;
var bytestohex = ctx.Utils.bytestohex;


var hashit = function(sha, B) {
    var R = [];

    if (sha == ctx.HASH256.len) {
        var H = new ctx.HASH256();
        H.process_array(B);
        R = H.hash();
    }
    else if (sha == ctx.HASH384.len) {
        var H = new ctx.HASH384();
        H.process_array(B);
        R = H.hash();
    }
    else if (sha == ctx.HASH512.len) {
        var H = new ctx.HASH512();
        H.process_array(B);
        R = H.hash();
    }
    if (R.length == 0) return null;
    return R;
}

describe('TEST HASH', function() {

    it('test SHA256', function(done) {
        this.timeout(0);

        var vectors = require('../testVectors/sha/SHA256.json');
        var dig;

        for (var vector in vectors) {
            dig = hashit(ctx.HASH256.len, hextobytes(vectors[vector].IN));
            expect(bytestohex(dig)).to.be.equal(vectors[vector].OUT);
        }
        done();
    });

    it('test SHA384', function(done) {
        this.timeout(0);

        var vectors = require('../testVectors/sha/SHA384.json');
        var dig;

        for (var vector in vectors) {
            dig = hashit(ctx.HASH384.len, hextobytes(vectors[vector].IN));
            expect(bytestohex(dig)).to.be.equal(vectors[vector].OUT);
        }
        done();
    });

    it('test SHA512', function(done) {
        this.timeout(0);

        var vectors = require('../testVectors/sha/SHA512.json');
        var dig;

        for (var vector in vectors) {
            dig = hashit(ctx.HASH512.len, hextobytes(vectors[vector].IN));
            expect(bytestohex(dig)).to.be.equal(vectors[vector].OUT);
        }
        done();
    });

});