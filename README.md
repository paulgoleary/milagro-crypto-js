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

* MCJS is a refact of the *JavaScript* code of [AMCL](https://github.com/miracl/amcl). For a detailed explanation about this library please read: [doc/AMCL.pdf](doc/AMCL.pdf). For info about the refactoring process contact support@miracl.com.

* MCJS is [Nodejs](https://nodejs.org/en/) compatible but it can be used for browsers too through the use of the tool [Browserify](http://browserify.org/) (see some examples below)

* NOTE: This product includes software developed at *[The Apache Software Foundation](http://www.apache.org/)*.

## Install and run  tests

[Nodejs](https://nodejs.org/en/) and [npm](https://www.npmjs.com/) are required in order to properly build the library and run tests. Install also the node.js modules required with the command
```
npm install
```
Run all the tests with the following command
```
npm test
```

## Quick Start
#### Elliptic Curves
Suppose you want to implement ECDH with NIST254 elliptic curve. First you need to initialize the context:

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
This library supports also RSA encryption/decryption and RSA signature. The following is a quick example to use RSA, first initialize the context
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
['RSA2048','RSA3072','RSA4096']
```
#### Other functions
MCJS supports SHA256, SHA384, SHA512, AES-GCM encryption and Marsaglia & Zaman random number generator. Those functions are contained in every context initialized with RSA or with an elliptic curve. If you want to create a context supporting only those general functions then initialize it with no parameter as follows:
```
var CTX = require("milagro-crypto-js");

var ctx = new CTX();
```
In the `/example` directory there are many simple script that show how to use this library.


## Run examples
We provide also some script examples for [nodejs](https://nodejs.org/en/). In order to try, for example, the script on ECC functions type the following commands
```
node ./examples/example_ECC_NIST256.js
```
#### Browsers
In the `./example/browser` directory we converted all the example scripts with [Browserify](http://browserify.org/).
