# AMCL - *Apache Milagro Crypto JavaScript Library*

* **category**:    Library
* **copyright**:   2016 MIRACL UK LTD
* **license**:     ASL 2.0 - http://www.apache.org/licenses/LICENSE-2.0
* **link**:        https://github.com/miracl/milagro-crypto-js
* **introduction**: [AMCL.pdf](doc/AMCL.pdf)

## Description

*AMCJL - Apache Milagro Crypto JavaScript Library*

AMCJL is a standards compliant JavaScript cryptographic library with no external dependencies, specifically designed to support the Internet of Things (IoT).

For a detailed explanation about this library please read: [doc/AMCL.pdf](doc/AMCL.pdf)

AMCL is provided in *JavaScript* language

NOTE: This product includes software developed at *[The Apache Software Foundation](http://www.apache.org/)*.

## Requirement for testing

1. Nodejs

## Run tests

```bash
$ git clone https://github.com/miracl/milagro-crypto-js
$ cd tests
$ ./run_test.sh
```
## Information

AMCL is very simple to build for JavaScript.

First - decide the modulus type and curve type you want to use. Edit ROM.js 
where indicated. You might want to use one of the curves whose details are
already in there.

Three example API files are provided, MPIN.js which 
supports our M-Pin (tm) protocol, ECDH.js which supports elliptic 
curve key exchange, digital signature and public key crypto, and RSA.js
which supports RSA encryption. The first  can be tested using the 
TestMPIN.html driver programs, the second can be tested using TestECDH.html, 
and the third using TestRSA.html

In the ROM.js file you must provide the curve constants. Several examples
are provided there, if you are willing to use one of these.

For quick jumpstart:-

Run Chrome browser and navigate to TestECDH.html

or TestMPIN.html

or BenchtestEC.html

or BenchtestPAIR.html

You might need to wait a couple of minutes for the output to appear.
