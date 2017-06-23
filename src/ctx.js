var romField = require('./rom_field');
var romCurve = require('./rom_curve');
var aes = require('./aes');
var uint64 = require('./uint64');
var hash256 = require('./hash256');
var hash384 = require('./hash384');
var hash512 = require('./hash512');
var rand = require('./rand');
var big = require('./big');
var fp = require('./fp');
var ecp = require('./ecp');
var ecdh = require('./ecdh');

var fp2 = require('./fp2');
var fp4 = require('./fp4');
var fp12 = require('./fp12');
var ecp2 = require('./ecp2');
var pair = require('./pair');
var mpin = require('./mpin');

CTX = function(config) {
  this.config = config;
  this.ROM_CURVE = romCurve['ROM_CURVE_' + config['ZZZ']](this);
  this.ROM_FIELD = romField['ROM_FIELD_' + config['YYY']](this);
  this.AES = aes.AES(this);
  this.UInt64 = uint64.UInt64(this);
  this.HASH256 = hash256.HASH256(this);
  this.HASH384 = hash384.HASH384(this);
  this.HASH512 = hash512.HASH512(this);
  this.RAND = rand.RAND(this);
  this.BIG = big.BIG(this);
  this.DBIG = big.DBIG(this);
  this.FP = fp.FP(this);
  this.ECP = ecp.ECP(this);
  this.ECDH = ecdh.ECDH(this);

  if (config['@PF'] != 0) {;
    this.FP2 = fp2.FP2(this);
    this.FP4 = fp4.FP4(this);
    this.FP12 = fp12.FP12(this);
    this.ECP2 = ecp2.ECP2(this);
    this.PAIR = pair.PAIR(this);
    this.MPIN = mpin.MPIN(this);
  };
};

module.exports = CTX;
