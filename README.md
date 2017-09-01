# MCJS - *Milagro Crypto JavaScript*

[![Master Branch](https://img.shields.io/badge/-master:-gray.svg)](https://github.com/miracl/milagro-crypto-js/tree/master)
[![Master Build Status](https://secure.travis-ci.org/miracl/milagro-crypto-js.png?branch=master)](https://travis-ci.org/miracl/milagro-crypto-js?branch=master)
[![Coverage Status](https://coveralls.io/repos/github/miracl/milagro-crypto-js/badge.svg?branch=master)](https://coveralls.io/github/miracl/milagro-crypto-js?branch=master)

[![Develop Branch](https://img.shields.io/badge/-develop:-gray.svg)](https://github.com/miracl/milagro-crypto-js/tree/develop)
[![Develop Build Status](https://secure.travis-ci.org/miracl/milagro-crypto-js.png?branch=develop)](https://travis-ci.org/miracl/milagro-crypto-js?branch=develop)
[![Coverage Status](https://coveralls.io/repos/github/miracl/milagro-crypto-js/badge.svg?branch=develop)](https://coveralls.io/github/miracl/milagro-crypto-js?branch=develop)


* **category**:    Library
* **copyright**:   2016 MIRACL UK LTD
* **license**:     ASL 2.0 - http://www.apache.org/licenses/LICENSE-2.0
* **link**:        https://github.com/miracl/milagro-crypto-js
* **introduction**: [AMCL.pdf](doc/AMCL.pdf)

## Description

*MCJS - Milagro Crypto JavaScript*

* MCJS is a standards compliant JavaScript cryptographic library with no external dependencies except for the random seed source.

* MCJS is a refactor of the *JavaScript* code of [AMCL](https://github.com/miracl/amcl). For a detailed explanation about this library please read: [doc/AMCL.pdf](doc/AMCL.pdf). For info about the refactoring process contact support@miracl.com.

* MCJS supports the standards for RSA, ECDH, ECIES, ECDSA and M-PIN, AES-GCM encryption/decryption, SHA256, SHA384 and SHA512 hash functions and a cryptographically secure random number generator.

* MCJS is [Node.js](https://nodejs.org/en/) compatible. A conversion script is provided to make the library browser compatible(see some examples below)

## Install and run  tests

[Node.js](https://nodejs.org/en/) and [npm](https://www.npmjs.com/) are required in order to build the library and run the tests. Install also the node.js modules required with the command

```
npm install
```

Run all the tests with the following command

```
npm test
```

## Quick Start
#### Elliptic Curves
Suppose you want to implement ECDH with NIST256 elliptic curve. First you need to initialize the context:

```
var CTX = require("milagro-crypto-js");

var ctx = new CTX("NIST256");
```
then you can call the functions as follows:
```
ctx.ECDH.KEY_PAIR_GENERATE(...);
ctx.ECDH.ECPSVDP_DH(...);
```
If you need to use more than one elliptic curve in the same script you only need to initialize two different contexts, for example
```
var ctx1 = new CTX("NIST256");
var ctx2 = new CTX("C25519");
```
The following is the list of all elliptic curves supported by MCJS
```
['ED25519','GOLDILOCKS','NIST256','NIST384','NIST521','BRAINPOOL','ANSSI','HIFIVE','C25519','C41417','MF254W','MF254E','MF254M','MF256W','MF256E','MF256M','MS255W','MS255E','MS255M','MS256W','MS256E','MS256M','BN254','BN254CX','BLS383'];
```
#### RSA
This library supports also RSA encryption/decryption and RSA signature. The following is a quick example on how to use RSA. First initialize the context
```
var CTX = require("milagro-crypto-js");

var ctx = new CTX("RSA2048");
```
then you can call the RSA functions as follows:
```
ctx.RSA.ENCRYPT(...);
ctx.RSA.DECRYPT(...);
```
The following is the list of all the RSA security level supported by *MCJS*
```
['RSA2048','RSA3072','RSA4096'];
```
#### Other functions
MCJS supports SHA256, SHA384, SHA512, AES-GCM encryption and Marsaglia & Zaman random number generator. Those functions are contained in every context initialized with RSA or with an elliptic curve. If you want to create a context supporting only those general functions then initialize it with no parameter as follows:
```
var CTX = require("milagro-crypto-js");

var ctx = new CTX();
```
In the `/example` directory there are many simple script that show how to use this library.


## Run examples

[Node.js](https://nodejs.org/en/) examples are provided - please see `./examples/node`. Use the following commands to run an example

```
node ./examples/node/example_ECC_NIST256.js
```

#### Browsers

A script is provided in  `./example/browser` that converts the Node.js code to be compatible with browsers. There is an example conversion in this directory. 
In order to run the example open the index.html file in a browser and check the console output
