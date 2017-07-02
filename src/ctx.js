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

var romField = require('./rom_field');
var romCurve = require('./rom_curve');
var aes = require('./aes');
var gcm = require('./gcm');
var uint64 = require('./uint64');
var hash256 = require('./hash256');
var hash384 = require('./hash384');
var hash512 = require('./hash512');
var rand = require('./rand');
var big = require('./big');
var fp = require('./fp');
var ecp = require('./ecp');
var ecdh = require('./ecdh');

var ff = require('./ff');
var rsa = require('./rsa');

var fp2 = require('./fp2');
var fp4 = require('./fp4');
var fp12 = require('./fp12');
var ecp2 = require('./ecp2');
var pair = require('./pair');
var mpin = require('./mpin');

CTX = function(config) {
    this.config = config;
    this.AES = aes.AES(this);
    this.GCM = gcm.GCM(this);
    this.UInt64 = uint64.UInt64(this);
    this.HASH256 = hash256.HASH256(this);
    this.HASH384 = hash384.HASH384(this);
    this.HASH512 = hash512.HASH512(this);
    this.RAND = rand.RAND(this);

    if (config === undefined)
        return;
    else {

        // Set RSA parameters
        if (config['TFF'] !== undefined) {
            this.BIG = big.BIG(this);
            this.DBIG = big.DBIG(this);
            this.FF = ff.FF(this);
            this.RSA = rsa.RSA(this);
            this.rsa_public_key = rsa.rsa_public_key(this);
            this.rsa_private_key = rsa.rsa_private_key(this);
        };

        // Set Elliptic Curve parameters
        if (config['CURVE'] !== undefined) {

            this.ROM_CURVE = romCurve['ROM_CURVE_' + config['CURVE']](this);
            this.ROM_FIELD = romField['ROM_FIELD_' + config['FIELD']](this);
            this.BIG = big.BIG(this);
            this.DBIG = big.DBIG(this);
            this.FP = fp.FP(this);
            this.ECP = ecp.ECP(this);
            this.ECDH = ecdh.ECDH(this);

            if (config['@PF'] != 0) {
                this.FP2 = fp2.FP2(this);
                this.FP4 = fp4.FP4(this);
                this.FP12 = fp12.FP12(this);
                this.ECP2 = ecp2.ECP2(this);
                this.PAIR = pair.PAIR(this);
                this.MPIN = mpin.MPIN(this);
            };
        };
    };
};

module.exports = CTX;