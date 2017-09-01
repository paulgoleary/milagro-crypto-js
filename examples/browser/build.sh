#!/usr/bin/bash
#
# build.sh
#
# Convert to browser compatible code 
#
# @author Kealan McCusker <kealan.mccusker@miracl.com>
# ------------------------------------------------------------------------------

# NOTES:

# EXAMPLE USAGE:
# ./build.sh -f ../node/example_RSA2048_ECDSA_NIST256.js

# set -x 
usage()
{
cat << EOF
usage: $0 options

OPTIONS:
   -f      example file (required)
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
  rm -rf src
  mkdir src
  cp ../../src/*.js ./src
  
  sed -i -e "s/module.exports = .*//g" ./src/*.js
  sed -i -e "s/module.exports.//g" ./src/*.js
  sed -i -e "/require(.*)/d" ./src/*.js
  sed -i -e "s/aes.//g" ./src/ctx.js
  sed -i -e "s/gcm.//g" ./src/ctx.js
  sed -i -e "s/uint64.//g" ./src/ctx.js
  sed -i -e "s/hash256.//g" ./src/ctx.js
  sed -i -e "s/hash384.//g" ./src/ctx.js
  sed -i -e "s/hash512.//g" ./src/ctx.js
  sed -i -e "s/rand.//g" ./src/ctx.js
  sed -i -e "s/big.//g" ./src/ctx.js
  sed -i -e "s/ff.//g" ./src/ctx.js
  sed -i -e "s/rsa.RSA/RSA/g" ./src/ctx.js
  sed -i -e "s/rsa.rsa_public_key/rsa_public_key/g" ./src/ctx.js
  sed -i -e "s/rsa.rsa_private_key/rsa_private_key/g" ./src/ctx.js
  sed -i -e "s/romCurve.//g" ./src/ctx.js
  sed -i -e "s/romField.//g" ./src/ctx.js
  sed -i -e "s/ecp2.ECP2/ECP2/g" ./src/ctx.js
  sed -i -e "s/ecp.ECP/ECP/g" ./src/ctx.js
  sed -i -e "s/ecdh.//g" ./src/ctx.js
  sed -i -e "s/ fp.FP/ FP/g" ./src/ctx.js
  sed -i -e "s/ fp2.FP2/ FP2/g" ./src/ctx.js
  sed -i -e "s/ fp4.FP4/ FP4/g" ./src/ctx.js
  sed -i -e "s/ fp12.FP12/ FP12/g" ./src/ctx.js
  sed -i -e "s/pair.//g" ./src/ctx.js
  sed -i -e "s/mpin.//g" ./src/ctx.js
}

function build_example {
  echo "copy and format ${EXAMPLE}"
  cp $EXAMPLE example.js
  sed -i -e "/require(.*)/d" ./example.js
  sed -i -e "/eval(.*)/d" ./example.js
  sed -i -e "/return (-1)/d" ./example.js
}

function build_index {
  echo "Write example html file"
  echo "<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">" > index.html
  echo "<html>" >> index.html
  echo "  <head>" >> index.html
  echo "    <title>Browser test</title>" >> index.html
  
  for file in ./src/*.js
  do
    echo "    <script src="${file}"></script>" >> index.html
  done
  echo "    <script src="./example.js"></script>" >> index.html
  
  echo "  </head>" >> index.html
  echo "" >> index.html
  echo "  <body>" >> index.html
  echo "    <h1>Browser test</h1>" >> index.html
  echo "  </body>" >> index.html
  echo "</html>" >> index.html
}

build_src
build_example
