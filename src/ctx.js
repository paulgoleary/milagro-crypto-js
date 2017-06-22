var fresh = require('fresh-require')

CTX = function(config) {
  this.config = config
  this.BIG = fresh("./BIG", require)
  this.this.BIG.ctx = this
  this.BIG.MODBYTES = config["@NB"];
  this.BIG.BASEBITS = config["@BASE"];

  this.DBIG = fresh("./DBIG", require)
  this.Dthis.BIG.ctx = this

  this.ECDH = fresh("./ECDH", require)
  this.ECDH.ctx = this

  this.ECP = fresh("./ECP", require)
  this.this.ECP.ctx = this
  this.ECP.CURVETYPE = config["@CT"]; //
  this.ECP.CURVE_PAIRING_TYPE = config["@PF"]; //

  this.FP = fresh("./FP", require)
  this.FP.ctx = this
  this.FP.MODBITS = config["@NBT"];
  this.FP.MOD8 = config["@M8"];
  this.FP.MODTYPE = config["@MT"]; //

  if (config["@PF"] != "0") {
	  this.ECP2 = fresh("./ECP2", require)
	  this.ECP2.ctx = this

	  this.FP12 = fresh("./FP12", require)
	  this.FP12.ctx = this

	  this.FP4 = fresh("./FP4", require)
	  this.FP4.ctx = this

	  this.FP2 = fresh("./FP2", require)
	  this.FP2.ctx = this

	  this.MPIN = fresh("./MPIN", require)
	  this.MPIN.ctx = this

	  this.PAIR = fresh("./PAIR", require)
	  this.PAIR.ctx = this
	}
}
