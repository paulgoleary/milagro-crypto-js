#!/bin/bash
#
# build.sh
#
# Convert Node.js source and example code to browser compatible code 
#
# @author Kealan McCusker <kealan.mccusker@miracl.com>
# ------------------------------------------------------------------------------

# NOTES:

# EXAMPLE USAGE:
# ./build.sh -f ./examples/example_RSA2048_ECDSA_NIST256.js

# set -x 
usage()
{
cat << EOF
usage: $0 [-h] [-f infile]

OPTIONS:
   -f      Node.js example file 
   -h      Print usage
EOF
}

while getopts ":hf:" OPTION
do
     case $OPTION in
         f)
             EXAMPLE=$OPTARG 
             if [ ! -f $EXAMPLE ]; then
               echo "ERROR: $EXAMPLE not found"
               exit 1
             fi
             ;;
         h)
             usage 
             exit 1 
             ;;
         :) 
             echo "ERROR: Missing required argument"
             usage
             exit 1
             ;;
         \?)
             echo "ERROR: Invalid option: -$OPTARG"
             usage
             exit 1
             ;;
     esac
done


if [[ -z ${EXAMPLE} ]] 
  then
    usage
    exit 1
fi


function build_src {
  echo "copy and format library source files"
  rm -rf src/browser
  mkdir src/browser
  cp ./src/node/*.js ./src/browser
  
  sed -i -e "s/module.exports = .*//g" ./src/browser/*.js
  sed -i -e "s/module.exports.//g" ./src/browser/*.js
  sed -i -e "/require(.*)/d" ./src/browser/*.js
  sed -i -e "s/aes.//g" ./src/browser/ctx.js
  sed -i -e "s/gcm.//g" ./src/browser/ctx.js
  sed -i -e "s/uint64.//g" ./src/browser/ctx.js
  sed -i -e "s/hash256.//g" ./src/browser/ctx.js
  sed -i -e "s/hash384.//g" ./src/browser/ctx.js
  sed -i -e "s/hash512.//g" ./src/browser/ctx.js
  sed -i -e "s/sha3.//g" ./src/browser/ctx.js
  sed -i -e "s/newhope.//g" ./src/browser/ctx.js
  sed -i -e "s/nhs.//g" ./src/browser/ctx.js
  sed -i -e "s/rand.//g" ./src/browser/ctx.js
  sed -i -e "s/big.//g" ./src/browser/ctx.js
  sed -i -e "s/ff.//g" ./src/browser/ctx.js
  sed -i -e "s/rsa.RSA/RSA/g" ./src/browser/ctx.js
  sed -i -e "s/rsa.rsa_public_key/rsa_public_key/g" ./src/browser/ctx.js
  sed -i -e "s/rsa.rsa_private_key/rsa_private_key/g" ./src/browser/ctx.js
  sed -i -e "s/romCurve.//g" ./src/browser/ctx.js
  sed -i -e "s/romField.//g" ./src/browser/ctx.js
  sed -i -e "s/ecp2.ECP2/ECP2/g" ./src/browser/ctx.js
  sed -i -e "s/ecp.ECP/ECP/g" ./src/browser/ctx.js
  sed -i -e "s/ecdh.//g" ./src/browser/ctx.js
  sed -i -e "s/ fp.FP/ FP/g" ./src/browser/ctx.js
  sed -i -e "s/ fp2.FP2/ FP2/g" ./src/browser/ctx.js
  sed -i -e "s/ fp4.FP4/ FP4/g" ./src/browser/ctx.js
  sed -i -e "s/ fp12.FP12/ FP12/g" ./src/browser/ctx.js
  sed -i -e "s/pair.//g" ./src/browser/ctx.js
  sed -i -e "s/mpin.//g" ./src/browser/ctx.js
}

function build_example {
  echo "copy and format ${EXAMPLE}"
  cp $EXAMPLE example.js
  sed -i -e "/require(.*)/d" ./example.js
  sed -i -e "/eval(.*)/d" ./example.js
  sed -i -e "/return (-1)/d" ./example.js
}

build_src
build_example
