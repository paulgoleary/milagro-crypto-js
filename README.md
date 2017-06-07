# AMCL - *Apache Milagro Crypto JavaScript Library*

[![Master Branch](https://img.shields.io/badge/-master:-gray.svg)](https://github.com/miracl/milagro-crypto-js/tree/master)
[![Master Build Status](https://secure.travis-ci.org/miracl/milagro-crypto-js.png?branch=master)](https://travis-ci.org/miracl/milagro-crypto-js?branch=master)

[![Develop Branch](https://img.shields.io/badge/-develop:-gray.svg)](https://github.com/miracl/milagro-crypto-js/tree/develop)
[![Develop Build Status](https://secure.travis-ci.org/miracl/milagro-crypto-js.png?branch=develop)](https://travis-ci.org/miracl/milagro-crypto-js?branch=develop)


* **category**:    Library
* **copyright**:   2016 MIRACL UK LTD
* **license**:     ASL 2.0 - http://www.apache.org/licenses/LICENSE-2.0
* **link**:        https://github.com/miracl/milagro-crypto-js
* **introduction**: [AMCL.pdf](doc/AMCL.pdf)

## Description

*AMCJL - Apache Milagro Crypto JavaScript Library*

AMCJL is a standards compliant JavaScript cryptographic library with no external dependencies except for the random seed source, specifically designed to support the Internet of Things (IoT).

AMCJL contains the *JavaScript* code of [AMCL](https://github.com/miracl/amcl). For a detailed explanation about this library please read: [doc/AMCL.pdf](doc/AMCL.pdf).

NOTE: This product includes software developed at *[The Apache Software Foundation](http://www.apache.org/)*.

## Requirement for building and testing

[Nodejs](https://nodejs.org/en/) and [npm](https://www.npmjs.com/) are required in order to properly build the library and run tests. Install also the following node.js modules (root permissions may be required)
```
npm install -g jake jake-utils
npm install fs colors assert crypto
```

## Build

The library can be build using [jake](https://www.npmjs.com/package/jake). Type

```
jake -T
```
to see all the options. In order to build the library with the default pairing friendly elliptic curve `BN254CX`, the curve `NIST256` and with the support for `RSA2048` type
```
jake build
```
To build supporting other curves or other RSA options you an use the command ```jake build:choice[...]```. For example to build the library supporting the curves `BLS383` and `C25519` with `RSA4096` type
```
jake build:choice[BLS383,C25519,RSA4096]
```
To see te list of all the build options type
``` 
jake list
```


## Run tests
To run the tests type the following command. NOTE: it may take a while!!!

```
jake test
```
If you made more than one build, then you must to specify which build you want to test, for example
```
jake test:choice[BLS383,C25519,RSA4096]
```

