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

var CTXLIST = {
    "ED25519": {
        "BITS": "256",
        "FIELD": "25519",
        "CURVE": "ED25519",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 255,
        "@M8": 5,
        "@MT": 1,
        "@CT": 1,
        "@PF": 0
    },

    "C25519": {
        "BITS": "256",
        "FIELD": "25519",
        "CURVE": "C25519",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 255,
        "@M8": 5,
        "@MT": 1,
        "@CT": 2,
        "@PF": 0
    },

    "NIST256": {
        "BITS": "256",
        "FIELD": "NIST256",
        "CURVE": "NIST256",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 256,
        "@M8": 7,
        "@MT": 0,
        "@CT": 0,
        "@PF": 0
    },

    "NIST384": {
        "BITS": "384",
        "FIELD": "NIST384",
        "CURVE": "NIST384",
        "@NB": 48,
        "@BASE": 56,
        "@NBT": 384,
        "@M8": 7,
        "@MT": 0,
        "@CT": 0,
        "@PF": 0
    },

    "BRAINPOOL": {
        "BITS": "256",
        "FIELD": "BRAINPOOL",
        "CURVE": "BRAINPOOL",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 256,
        "@M8": 7,
        "@MT": 0,
        "@CT": 0,
        "@PF": 0
    },

    "ANSSI": {
        "BITS": "256",
        "FIELD": "ANSSI",
        "CURVE": "ANSSI",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 256,
        "@M8": 7,
        "@MT": 0,
        "@CT": 0,
        "@PF": 0
    },

    "HIFIVE": {
        "BITS": "336",
        "FIELD": "HIFIVE",
        "CURVE": "HIFIVE",
        "@NB": 42,
        "@BASE": 23,
        "@NBT": 336,
        "@M8": 5,
        "@MT": 1,
        "@CT": 1,
        "@PF": 0
    },

    "GOLDILOCKS": {
        "BITS": "448",
        "FIELD": "GOLDILOCKS",
        "CURVE": "GOLDILOCKS",
        "@NB": 56,
        "@BASE": 23,
        "@NBT": 448,
        "@M8": 7,
        "@MT": 2,
        "@CT": 1,
        "@PF": 0
    },

    "C41417": {
        "BITS": "416",
        "FIELD": "C41417",
        "CURVE": "C41417",
        "@NB": 52,
        "@BASE": 23,
        "@NBT": 414,
        "@M8": 7,
        "@MT": 1,
        "@CT": 1,
        "@PF": 0
    },

    "NIST521": {
        "BITS": "528",
        "FIELD": "NIST521",
        "CURVE": "NIST521",
        "@NB": 66,
        "@BASE": 23,
        "@NBT": 521,
        "@M8": 7,
        "@MT": 1,
        "@CT": 0,
        "@PF": 0
    },

    "MF254W": {
        "BITS": "256",
        "FIELD": "254MF",
        "CURVE": "MF254W",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 254,
        "@M8": 7,
        "@MT": 3,
        "@CT": 0,
        "@PF": 0
    },

    "MF254E": {
        "BITS": "256",
        "FIELD": "254MF",
        "CURVE": "MF254E",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 254,
        "@M8": 7,
        "@MT": 3,
        "@CT": 1,
        "@PF": 0
    },

    "MF254M": {
        "BITS": "256",
        "FIELD": "254MF",
        "CURVE": "MF254M",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 254,
        "@M8": 7,
        "@MT": 3,
        "@CT": 2,
        "@PF": 0
    },

    "MF256W": {
        "BITS": "256",
        "FIELD": "256MF",
        "CURVE": "MF256W",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 256,
        "@M8": 7,
        "@MT": 3,
        "@CT": 0,
        "@PF": 0
    },

    "MF256E": {
        "BITS": "256",
        "FIELD": "256MF",
        "CURVE": "MF256E",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 256,
        "@M8": 7,
        "@MT": 3,
        "@CT": 1,
        "@PF": 0
    },

    "MF256M": {
        "BITS": "256",
        "FIELD": "256MF",
        "CURVE": "MF256M",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 256,
        "@M8": 7,
        "@MT": 3,
        "@CT": 2,
        "@PF": 0
    },

    "MS255W": {
        "BITS": "256",
        "FIELD": "255MS",
        "CURVE": "MS255W",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 255,
        "@M8": 3,
        "@MT": 1,
        "@CT": 0,
        "@PF": 0
    },

    "MS255E": {
        "BITS": "256",
        "FIELD": "255MS",
        "CURVE": "MS255E",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 255,
        "@M8": 3,
        "@MT": 1,
        "@CT": 1,
        "@PF": 0
    },

    "MS255M": {
        "BITS": "256",
        "FIELD": "255MS",
        "CURVE": "MS255M",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 255,
        "@M8": 3,
        "@MT": 1,
        "@CT": 2,
        "@PF": 0
    },

    "MS256W": {
        "BITS": "256",
        "FIELD": "256MS",
        "CURVE": "MS256W",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 256,
        "@M8": 3,
        "@MT": 1,
        "@CT": 0,
        "@PF": 0
    },

    "MS256E": {
        "BITS": "256",
        "FIELD": "256MS",
        "CURVE": "MS256E",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 256,
        "@M8": 3,
        "@MT": 1,
        "@CT": 1,
        "@PF": 0
    },

    "MS256M": {
        "BITS": "256",
        "FIELD": "256MS",
        "CURVE": "MS256M",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 256,
        "@M8": 3,
        "@MT": 1,
        "@CT": 2,
        "@PF": 0
    },

    "BN254": {
        "BITS": "256",
        "FIELD": "BN254",
        "CURVE": "BN254",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 254,
        "@M8": 3,
        "@MT": 0,
        "@CT": 0,
        "@PF": 1
    },

    "BN254CX": {
        "BITS": "256",
        "FIELD": "BN254CX",
        "CURVE": "BN254CX",
        "@NB": 32,
        "@BASE": 24,
        "@NBT": 254,
        "@M8": 3,
        "@MT": 0,
        "@CT": 0,
        "@PF": 1
    },

    "BLS383": {
        "BITS": "384",
        "FIELD": "BLS383",
        "CURVE": "BLS383",
        "@NB": 48,
        "@BASE": 23,
        "@NBT": 383,
        "@M8": 3,
        "@MT": 0,
        "@CT": 0,
        "@PF": 2
    },

    "RSA2048": {
        "BITS": "1024",
        "TFF": "2048",
        "@NB": 128,
        "@BASE": 22,
        "@ML": 2,
    },

    "RSA3072": {
        "BITS": "384",
        "TFF": "3072",
        "@NB": 48,
        "@BASE": 23,
        "@ML": 8,
    },

    "RSA4096": {
        "BITS": "512",
        "TFF": "4096",
        "@NB": 64,
        "@BASE": 23,
        "@ML": 8,
    },
}

module.exports = CTXLIST;