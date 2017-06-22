var fresh = require('fresh-require')

CTX = function(config) {
  this.config = config;

  var imp = fresh("./big", require)
  imp.ctx = this;
  this.BIG = imp.BIG;
  this.BIG.MODBYTES = config["@NB"];
  this.BIG.BASEBITS = config["@BASE"];
  this.DBIG = imp.DBIG

  imp = fresh("./ecdh", require)
  imp.ctx = this;
  this.ECDH = imp.ECDH();

  imp = fresh("./ecp", require)
  imp.ctx = this;
  this.ECP = imp.ECP;
  this.ECP.CURVETYPE = config["@CT"];
  this.ECP.CURVE_PAIRING_TYPE = config["@PF"];

  imp = fresh("./fp", require)
  imp.ctx = this;
  this.FP = imp.FP;
  this.FP.MODBITS = config["@NBT"];
  this.FP.MOD8 = config["@M8"];
  this.FP.MODTYPE = config["@MT"];

  if (config["@PF"] != "0") {
    imp = fresh("./ecp2", require)
    imp.ctx = this;
    this.ECP2 = imp.ECP2;

    imp = fresh("./fp12", require)
    imp.ctx = this;
    this.FP12 = imp.FP12;

    imp = fresh("./fp4", require)
    imp.ctx = this;
    this.FP4 = imp.FP4;

    imp = fresh("./fp2", require)
    imp.ctx = this;
    this.FP2 = imp.FP2;

    imp = fresh("./mpin", require)
    imp.ctx = this;
    this.MPIN = imp.MPIN;

    imp = fresh("./pair", require)
    imp.ctx = this;
    this.PAIR = imp.PAIR;
  }

  imp = require("./rom_curve");
  imp.ctx = this;
  this.ROM_CURVE = imp["ROM_CURVE_"+config["ZZZ"]];

  imp = require("./rom_field");
  imp.ctx = this;
  this.ROM_FIELD = imp["ROM_FIELD_"+config["YYY"]];

}

module.exports = CTX;
