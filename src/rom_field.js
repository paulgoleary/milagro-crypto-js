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

module.exports.ROM_FIELD_254MF = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_254MF = {
        // MF254 modulus
        Modulus: [0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x3F80],
        MConst: 0x3F81,

    };
    ROM_FIELD_254MF.ctx = ctx;
    return ROM_FIELD_254MF;
};
module.exports.ROM_FIELD_25519 = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_25519 = {
        // 25519 Curve Modulus
        Modulus: [0xFFFFED, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x7FFF],
        MConst: 19,
    };
    ROM_FIELD_25519.ctx = ctx;
    return ROM_FIELD_25519;
};
module.exports.ROM_FIELD_255MS = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_255MS = {
        // MS255 modulus
        Modulus: [0xFFFD03, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x7FFF],
        MConst: 0x2FD,
    };
    ROM_FIELD_255MS.ctx = ctx;
    return ROM_FIELD_255MS;
};
module.exports.ROM_FIELD_256MF = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_256MF = {
        // MF256 modulus
        Modulus: [0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFA7],
        MConst: 0xFFA8,
    };
    ROM_FIELD_256MF.ctx = ctx;
    return ROM_FIELD_256MF;
};
module.exports.ROM_FIELD_256MS = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_256MS = {
        // MS256 modulus
        Modulus: [0xFFFF43, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFF],
        MConst: 0xBD,
    };
    ROM_FIELD_256MS.ctx = ctx;
    return ROM_FIELD_256MS;
};
module.exports.ROM_FIELD_ANSSI = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_ANSSI = {
        // ANSSI modulus
        Modulus: [0x6E9C03, 0xF353D8, 0x6DE8FC, 0xABC8CA, 0x61ADBC, 0x435B39, 0xE8CE42, 0x10126D, 0x3AD58F, 0x178C0B, 0xF1FD],
        MConst: 0x4E1155,

    };
    ROM_FIELD_ANSSI.ctx = ctx;
    return ROM_FIELD_ANSSI;
};
module.exports.ROM_FIELD_BLS383 = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_BLS383 = {
        // BLS383 Modulus 
        Modulus: [0x2D556B, 0x556A55, 0x75EAB2, 0x23AFBA, 0x1BB01, 0x2BAEA4, 0x5CC20F, 0x758B67, 0x20F99, 0x640A63, 0x69A3A8, 0x6009AA, 0x2A7852, 0x20B8AA, 0x7DD718, 0x104054, 0x7AC5],
        MConst: 0x23D0BD,
        Fra: [0x34508B, 0x4B3525, 0x4D0CAE, 0x503777, 0x463DB7, 0x3BF78E, 0xD072C, 0x2AE9A0, 0x69D32D, 0x282C73, 0x1730DB, 0xCD9F8, 0x6AB98B, 0x7DC9B0, 0x1CBCC8, 0x7D8CC3, 0x5A5],
        Frb: [0x7904E0, 0xA352F, 0x28DE04, 0x537843, 0x3B7D49, 0x6FB715, 0x4FBAE2, 0x4AA1C7, 0x183C6C, 0x3BDDEF, 0x5272CD, 0x532FB2, 0x3FBEC7, 0x22EEF9, 0x611A4F, 0x12B391, 0x751F],
    };
    ROM_FIELD_BLS383.ctx = ctx;
    return ROM_FIELD_BLS383;
};
module.exports.ROM_FIELD_BN254 = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_BN254 = {
        // BN254 Modulus 
        Modulus: [0x13, 0x0, 0x13A700, 0x0, 0x210000, 0x861, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
        MConst: 0x9435E5,
        Fra: [0x2A6DE9, 0xE6C06F, 0xC2E17D, 0x4D3F77, 0x97492, 0x953F85, 0x50A846, 0xB6499B, 0x2E7C8C, 0x761921, 0x1B37],
        Frb: [0xD5922A, 0x193F90, 0x50C582, 0xB2C088, 0x178B6D, 0x6AC8DC, 0x2F57B9, 0x3EAB2, 0xD18375, 0xEE691E, 0x9EB],
    };
    ROM_FIELD_BN254.ctx = ctx;
    return ROM_FIELD_BN254;
};
module.exports.ROM_FIELD_BN254CX = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_BN254CX = {
        // BN254CX Modulus 
        Modulus: [0x1B55B3, 0x23EF5C, 0xE1BE66, 0x18093E, 0x3FD6EE, 0x66D324, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
        MConst: 0x789E85,
        Fra: [0xC80EA3, 0x83355, 0x215BD9, 0xF173F8, 0x677326, 0x189868, 0x8AACA7, 0xAFE18B, 0x3A0164, 0x82FA6, 0x1359],
        Frb: [0x534710, 0x1BBC06, 0xC0628D, 0x269546, 0xD863C7, 0x4E3ABB, 0xD9CDBC, 0xDC53, 0x3628A9, 0xF7D062, 0x10A6],
    };
    ROM_FIELD_BN254CX.ctx = ctx;
    return ROM_FIELD_BN254CX;
};
module.exports.ROM_FIELD_BRAINPOOL = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_BRAINPOOL = {
        // Brainpool modulus
        Modulus: [0x6E5377, 0x481D1F, 0x282013, 0xD52620, 0x3BF623, 0x8D726E, 0x909D83, 0x3E660A, 0xEEA9BC, 0x57DBA1, 0xA9FB],
        MConst: 0xFD89B9,
    };
    ROM_FIELD_BRAINPOOL.ctx = ctx;
    return ROM_FIELD_BRAINPOOL;
};
module.exports.ROM_FIELD_C41417 = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_FIELD_C41417 = {
        // C41417 modulus
        Modulus: [0x7FFFEF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF],
        MConst: 0x11,
    };
    ROM_FIELD_C41417.ctx = ctx;
    return ROM_FIELD_C41417;
};
module.exports.ROM_FIELD_GOLDILOCKS = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_GOLDILOCKS = {
        // GOLDILOCKS modulus
        Modulus: [0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7DFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FF],
        MConst: 0x1,

    };
    ROM_FIELD_GOLDILOCKS.ctx = ctx;
    return ROM_FIELD_GOLDILOCKS;
};
module.exports.ROM_FIELD_HIFIVE = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_HIFIVE = {
        // HIFIVE modulus
        Modulus: [0x7FFFFD, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3FFF],
        MConst: 0x3,

    };
    ROM_FIELD_HIFIVE.ctx = ctx;
    return ROM_FIELD_HIFIVE;
};
module.exports.ROM_FIELD_NIST256 = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_NIST256 = {
        // NIST256 Modulus 
        Modulus: [0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x0, 0x0, 0x0, 0x0, 0x1, 0xFFFF00, 0xFFFF],
        MConst: 0x1,

    };
    ROM_FIELD_NIST256.ctx = ctx;
    return ROM_FIELD_NIST256;
};
module.exports.ROM_FIELD_NIST384 = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_NIST384 = {
        // NIST384 modulus
        Modulus: [0x7FFFFF, 0x1FF, 0x0, 0x0, 0x7FFFF0, 0x7FDFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0xFFFF],
        MConst: 0x1,
    };
    ROM_FIELD_NIST384.ctx = ctx;
    return ROM_FIELD_NIST384;
};
module.exports.ROM_FIELD_NIST521 = function(ctx) {

    /* Fixed Data in ROM - Field and Curve parameters */
    var ROM_FIELD_NIST521 = {
        // NIST521 modulus
        Modulus: [0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFF],
        MConst: 0x1,
    };
    ROM_FIELD_NIST521.ctx = ctx;
    return ROM_FIELD_NIST521;
};