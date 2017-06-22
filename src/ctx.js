CTX = function(config) {;
  this.config = config;

  var aes = require('./aes');
  this.AES = aes.AES(this);

  var rand = require('./rand');
  this.RAND = rand.RAND(this);

  var uint64 = require('./uint64');
  this.UInt64 = uint64.UInt64(this);

  var hash256 = require('./hash256');
  this.HASH256 = hash256.HASH256(this);

  var hash384 = require('./hash384');
  this.HASH384 = hash384.HASH384(this);

  var hash512 = require('./hash512');
  this.HASH512 = hash512.HASH512(this);

  var big = require('./big');
  this.BIG = big.BIG(this);
  this.DBIG = big.DBIG(this);

  var ecdh = require('./ecdh');
  this.ECDH = ecdh.ECDH(this);

  var ecp = require('./ecp');
  this.ECP = ecp.ECP(this);

  var fp = require('./fp');
  this.FP = fp.FP(this);

  if (config['@PF'] != '0') {;
    var ecp2 = require('./ecp2');
    this.ECP2 = ecp2.ECP2(this);

    var fp12 = require('./fp12');
    this.FP12 = fp12.FP12(this);

    var fp4 = require('./fp4');
    this.FP4 = fp4.FP4(this);

    var fp2 = require('./fp2');
    this.FP2 = fp2.FP2(this);

    var mpin = require('./mpin');
    this.MPIN = mpin.MPIN(this);

    var pair = require('./pair');
    this.PAIR = pair.PAIR(this);
  };

  var curve = 'ROM_CURVE_' + config['ZZZ'];
  var romCurve = require('./' + curve.toLowerCase());
  this.ROM_CURVE = romCurve[curve](this);

  var field = 'ROM_FIELD_' + config['YYY'];
  var romField = require('./' + field.toLowerCase());
  this.ROM_FIELD = romField[field](this);

};

module.exports = CTX;
