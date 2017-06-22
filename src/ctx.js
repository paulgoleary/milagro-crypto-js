var fresh = require('fresh-require')

CTX = function(config) {
  this.config = config

  var imp = fresh("./allbig", require)
  this.BIG = imp.BIG
  this.BIG.ctx = this
  this.BIG.MODBYTES = config["@NB"];
  this.BIG.BASEBITS = config["@BASE"];
  
  this.DBIG = imp.DBIG
  this.DBIG.ctx = this

  imp = fresh("./ecdh", require)
  this.ECDH = imp.ECDH
  this.ECDH.ctx = this

  imp = fresh("./ecp", require)
  this.ECP = imp.ECP
  this.ECP.ctx = this
  this.ECP.CURVETYPE = config["@CT"]; //
  this.ECP.CURVE_PAIRING_TYPE = config["@PF"]; //

  imp = fresh("./fp", require)
  this.FP = imp.FP
  this.FP.ctx = this
  this.FP.MODBITS = config["@NBT"];
  this.FP.MOD8 = config["@M8"];
  this.FP.MODTYPE = config["@MT"]; //

  if (config["@PF"] != "0") {
	  imp = fresh("./ecp2", require)
	  this.ECP2 = imp.ECP2
	  this.ECP2.ctx = this

	  imp = fresh("./fp12", require)
	  this.FP12 = imp.FP12
	  this.FP12.ctx = this

	  imp = fresh("./fp4", require)
	  this.FP4 = imp.FP4
	  this.FP4.ctx = this

	  imp = fresh("./fp2", require)
	  this.FP2 = imp.FP2
	  this.FP2.ctx = this

	  imp = fresh("./mpin", require)
    this.MPIN = imp.MPIN
	  this.MPIN.ctx = this

	  imp = fresh("./pair", require)
	  this.PAIR = imp.PAIR
	  this.PAIR.ctx = this
	}
}
