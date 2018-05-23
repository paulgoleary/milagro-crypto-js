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

/* Example Hash functions */

var CTX = require("../../index");

var ctx = new CTX();

var hashit = function(sha, B) {
    var R = [],
        H;

    if (sha == ctx.HASH256.len) {
        H = new ctx.HASH256();
    } else if (sha == ctx.HASH384.len) {
        H = new ctx.HASH384();
    } else if (sha == ctx.HASH512.len) {
        H = new ctx.HASH512();
    }

    H.process_array(B);
    R = H.hash();

    if (R.length == 0) {
        return null;
    }

    return R;
};

var to_hash = "test hash";

console.log("String to hash: ", to_hash);

var hashed = hashit(ctx.HASH256.len, ctx.Utils.hextobytes(to_hash));
console.log("SHA256: ", ctx.Utils.bytestohex(hashed));
hashed = hashit(ctx.HASH384.len, ctx.Utils.hextobytes(to_hash));
console.log("SHA384: ", ctx.Utils.bytestohex(hashed));
hashed = hashit(ctx.HASH512.len, ctx.Utils.hextobytes(to_hash));
console.log("SHA512: ", ctx.Utils.bytestohex(hashed));
