require('jake-utils');

var FILE = require("file"),
	fs = require("fs"),
	path = require("path"),
	jake = require('jake');

var srcdir = './src';
var targetdir = './target';


function Replace(namefile,oldtext,newtext) {
	for (i = 0; i < 500; i++) {
		replace({
	    replacements: [
	        {pattern: oldtext, replacement: newtext}
	        ],
	    src: [namefile]
	    });
	}
}

function addToInclude(fname,tempTarg) {
	var incfile = read(tempTarg+'/include.html')
	if (!(fname in incfile)) {
		fs.appendFileSync(tempTarg+'/include.html', '<script type=\"text/javascript\" src=\"'+fname+'\"></script>\n');
	}
}

function copyROMfiles(curve,field,tempTarg) {
	jake.cpR(path.join(srcdir,'ROM_CURVE_'+curve+'.js'), path.join(tempTarg, 'ROM_CURVE_'+curve+'.js'));
	jake.cpR(path.join(srcdir,'ROM_FIELD_'+field+'.js'), path.join(tempTarg, 'ROM_FIELD_'+field+'.js'));
}

function copyCommonFiles(tempTarg){
	jake.cpR(path.join(srcdir,'AES.js'), path.join(tempTarg, 'AES.js'));
	jake.cpR(path.join(srcdir,'GCM.js'), path.join(tempTarg, 'GCM.js'));
	jake.cpR(path.join(srcdir,'HASH256.js'), path.join(tempTarg, 'HASH256.js'));
	jake.cpR(path.join(srcdir,'HASH384.js'), path.join(tempTarg, 'HASH384.js'));
	jake.cpR(path.join(srcdir,'HASH512.js'), path.join(tempTarg, 'HASH512.js'));
	jake.cpR(path.join(srcdir,'RAND.js'), path.join(tempTarg, 'RAND.js'));
	jake.cpR(path.join(srcdir,'UInt64.js'), path.join(tempTarg, 'UInt64.js'));
	jake.cpR(path.join(srcdir,'include.html'), path.join(tempTarg, 'include.html'));
}

function rsaset(tb,tff,nb,base,ml,tempTarg) {

	fname='BIG_'+tb+'.js';
	jake.cpR(path.join(srcdir,'BIG_XXX.js'), path.join(tempTarg, fname));
	Replace(path.join(tempTarg, fname),'XXX',tb);
	Replace(path.join(tempTarg, fname),'@NB@',nb);
	Replace(path.join(tempTarg, fname),'@BASE@',base);
	addToInclude(fname,tempTarg)

	fname='DBIG_'+tb+'.js';
	jake.cpR(path.join(srcdir,'DBIG_XXX.js'), path.join(tempTarg, fname));

	Replace(path.join(tempTarg, fname),'XXX',tb);
	addToInclude(fname,tempTarg)


	fname='FF_'+tff+'.js';
	jake.cpR(path.join(srcdir,'FF_WWW.js'), path.join(tempTarg, fname));

	Replace(path.join(tempTarg, fname),'WWW',tff);
	Replace(path.join(tempTarg, fname),'XXX',tb);
	Replace(path.join(tempTarg, fname),'@ML@',ml);
	addToInclude(fname,tempTarg)

	fname='RSA_'+tff+'.js';
	jake.cpR(path.join(srcdir,'RSA_WWW.js'), path.join(tempTarg, fname));

	Replace(path.join(tempTarg, fname),'WWW',tff);
	Replace(path.join(tempTarg, fname),'XXX',tb);
	addToInclude(fname,tempTarg)
}

function curveset(tb,tf,tc,nb,base,nbt,m8,mt,ct,pf,tempTarg) {

	fname='BIG_'+tb+'.js';
	jake.cpR(path.join(srcdir,'BIG_XXX.js'), path.join(tempTarg, fname));

	Replace(path.join(tempTarg, fname),'XXX',tb);
	Replace(path.join(tempTarg, fname),'@NB@',nb);
	Replace(path.join(tempTarg, fname),'@BASE@',base);
	addToInclude(fname,tempTarg)

	fname='DBIG_'+tb+'.js';
	jake.cpR(path.join(srcdir,'DBIG_XXX.js'), path.join(tempTarg, fname));

	Replace(path.join(tempTarg, fname),'XXX',tb);
	addToInclude(fname,tempTarg)

	fname='FP_'+tf+'.js';
	jake.cpR(path.join(srcdir,'FP_YYY.js'), path.join(tempTarg, fname));

	Replace(path.join(tempTarg, fname),'XXX',tb);
	Replace(path.join(tempTarg, fname),'YYY',tf);
	Replace(path.join(tempTarg, fname),'@NBT@',nbt);
	Replace(path.join(tempTarg, fname),'@M8@',m8);
	Replace(path.join(tempTarg, fname),'@MT@',mt);
	addToInclude(fname,tempTarg)

	fname='ECP_'+tc+'.js';
	jake.cpR(path.join(srcdir,'ECP_ZZZ.js'), path.join(tempTarg, fname));

	Replace(path.join(tempTarg, fname),'XXX',tb);
	Replace(path.join(tempTarg, fname),'YYY',tf);
	Replace(path.join(tempTarg, fname),'ZZZ',tc);
	Replace(path.join(tempTarg, fname),'@CT@',ct);
	Replace(path.join(tempTarg, fname),'@PF@',pf);
	addToInclude(fname,tempTarg)

	fname='ECDH_'+tc+'.js';
	jake.cpR(path.join(srcdir,'ECDH_ZZZ.js'), path.join(tempTarg, fname));

	Replace(path.join(tempTarg, fname),'ZZZ',tc);
	Replace(path.join(tempTarg, fname),'YYY',tf);
	Replace(path.join(tempTarg, fname),'XXX',tb);
	addToInclude(fname,tempTarg)

	fname='ROM_FIELD_'+tf+'.js';
	addToInclude(fname,tempTarg)
	fname='ROM_CURVE_'+tc+'.js';
	addToInclude(fname,tempTarg)

	if (pf != 'NOT' ) {
		fname='FP2_'+tf+'.js';
		jake.cpR(path.join(srcdir,'FP2_YYY.js'), path.join(tempTarg, fname));
		Replace(path.join(tempTarg, fname),'YYY',tf);
		Replace(path.join(tempTarg, fname),'XXX',tb);
		addToInclude(fname,tempTarg)
	}
		fname='FP4_'+tf+'.js';
		jake.cpR(path.join(srcdir,'FP4_YYY.js'), path.join(tempTarg, fname));
		Replace(path.join(tempTarg, fname),'YYY',tf);
		Replace(path.join(tempTarg, fname),'XXX',tb);
		addToInclude(fname,tempTarg)

		fname='FP12_'+tf+'.js';
		jake.cpR(path.join(srcdir,'FP12_YYY.js'), path.join(tempTarg, fname));
		Replace(path.join(tempTarg, fname),'YYY',tf);
		Replace(path.join(tempTarg, fname),'XXX',tb);
		addToInclude(fname,tempTarg)

		fname='ECP2_'+tc+'.js';
		jake.cpR(path.join(srcdir,'ECP2_ZZZ.js'), path.join(tempTarg, fname));
		Replace(path.join(tempTarg, fname),'YYY',tf);
		Replace(path.join(tempTarg, fname),'XXX',tb);
		Replace(path.join(tempTarg, fname),'ZZZ',tc);
		addToInclude(fname,tempTarg)

		fname='PAIR_'+tc+'.js';
		jake.cpR(path.join(srcdir,'PAIR_ZZZ.js'), path.join(tempTarg, fname));
		Replace(path.join(tempTarg, fname),'YYY',tf);
		Replace(path.join(tempTarg, fname),'XXX',tb);
		Replace(path.join(tempTarg, fname),'ZZZ',tc);
		addToInclude(fname,tempTarg)

		fname='MPIN_'+tc+'.js';
		jake.cpR(path.join(srcdir,'MPIN_ZZZ.js'), path.join(tempTarg, fname));
		Replace(path.join(tempTarg, fname),'YYY',tf);
		Replace(path.join(tempTarg, fname),'XXX',tb);
		Replace(path.join(tempTarg, fname),'ZZZ',tc);
		addToInclude(fname,tempTarg)
}

desc('default');
task('default', function () {
  console.log('type `jake -T` to see the list of all thew tasks.');
});

namespace('build', function () {
	desc('Build library supporting multiple curves. For example jake build:choice[BN254,P256]');
	task('choice', function () {
		var tempTarg = targetdir+"/build_"+arguments[0];
		for (var i=1; i<arguments.length; i++)
			tempTarg += "_"+arguments[i];
		console.log('Create target directory'+tempTarg);
		jake.mkdirP(tempTarg);
		copyCommonFiles(tempTarg);
		for (var i=0; i<arguments.length; i++){
			console.log(arguments[i]);
			if (arguments[i] == 'ED25519') {
				curveset('256','25519','ED25519','32','24','255','5','PSEUDO_MERSENNE','EDWARDS','NOT',tempTarg);
				copyROMfiles('ED25519','25519',tempTarg);
			}
			if (arguments[i] == 'C25519') {
				curveset('256','25519','C25519','32','24','255','5','PSEUDO_MERSENNE','MONTGOMERY','NOT',tempTarg);
				copyROMfiles('C25519','25519',tempTarg);
			}
			if (arguments[i] == 'NIST256') {
				curveset('256','NIST256','NIST256','32','24','256','7','NOT_SPECIAL','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('NIST256','NIST256',tempTarg);
			}
			if (arguments[i] == 'BRAINPOOL') {
				curveset('256','BRAINPOOL','BRAINPOOL','32','24','256','7','NOT_SPECIAL','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('BRAINPOOL','BRAINPOOL',tempTarg);
			}
			if (arguments[i] == 'ANSSI') {
				curveset('256','ANSSI','ANSSI','32','24','256','7','NOT_SPECIAL','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('ANSSI','ANSSI',tempTarg);
			}
			if (arguments[i] == 'HIFIVE') {
				curveset('336','HIFIVE','HIFIVE','42','23','336','5','PSEUDO_MERSENNE','EDWARDS','NOT',tempTarg);
				copyROMfiles('HIFIVE','HIFIVE',tempTarg);
			}
			if (arguments[i] == 'GOLDILOCKS') {
				curveset('448','GOLDILOCKS','GOLDILOCKS','56','23','448','7','GENERALISED_MERSENNE','EDWARDS','NOT',tempTarg);
				copyROMfiles('GOLDILOCKS','GOLDILOCKS',tempTarg);
			}
			if (arguments[i] == 'NIST384') {
				curveset('384','NIST384','NIST384','48','','28','56','384','7','NOT_SPECIAL','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('NIST384','NIST384',tempTarg);
			}
			if (arguments[i] == 'C41417') {
				curveset('416','C41417','C41417','52','23','414','7','PSEUDO_MERSENNE','EDWARDS','NOT',tempTarg);
				copyROMfiles('C41417','C41417',tempTarg);
			}
			if (arguments[i] == 'NIST521') {
				curveset('528','NIST521','NIST521','66','23','521','7','PSEUDO_MERSENNE','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('NIST521','NIST521',tempTarg);
			}
			if (arguments[i] == 'MF254W') {
				curveset('256','254MF','MF254W','32','24','254','7','MONTGOMERY_FRIENDLY','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('254MF','MF254W',tempTarg);
			}
			if (arguments[i] == 'MF254E') {
				curveset('256','254MF','MF254E','32','24','254','7','MONTGOMERY_FRIENDLY','EDWARDS','NOT',tempTarg);
				copyROMfiles('254MF','MF254E',tempTarg);
			}
			if (arguments[i] == 'MF254M') {
				curveset('256','254MF','MF254M','32','24','254','7','MONTGOMERY_FRIENDLY','MONTGOMERY','NOT',tempTarg);
				copyROMfiles('254MF','MF254M',tempTarg);
			}
			if (arguments[i] == 'MF256W') {
				curveset('256','256MF','MF256W','32','24','256','7','MONTGOMERY_FRIENDLY','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('256MF','MF256W',tempTarg);
			}
			if (arguments[i] == 'MF256E') {
				curveset('256','256MF','MF256E','32','24','256','7','MONTGOMERY_FRIENDLY','EDWARDS','NOT',tempTarg);
				copyROMfiles('256MF','MF256E',tempTarg);
			}
			if (arguments[i] == 'MF256M') {
				curveset('256','256MF','MF256M','32','24','256','7','MONTGOMERY_FRIENDLY','MONTGOMERY','NOT',tempTarg);
				copyROMfiles('256MF','MF256M',tempTarg);
			}
			if (arguments[i] == 'MS255W') {
				curveset('256','255MS','MS255W','32','24','255','3','PSEUDO_MERSENNE','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('255MS','MS255W',tempTarg);
			}
			if (arguments[i] == 'MS255E') {
				curveset('256','255MS','MS255E','32','24','255','3','PSEUDO_MERSENNE','EDWARDS','NOT',tempTarg);
				copyROMfiles('255MS','MS255E',tempTarg);
			}
			if (arguments[i] == 'MS255M') {
				curveset('256','255MS','MS255M','32','24','255','3','PSEUDO_MERSENNE','MONTGOMERY','NOT',tempTarg);
				copyROMfiles('255MS','MS255M',tempTarg);
			}
			if (arguments[i] == 'MS256W') {
				curveset('256','256MS','MS256W','32','24','256','3','PSEUDO_MERSENNE','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('256MS','MS256W',tempTarg);
			}
			if (arguments[i] == 'MS256E') {
				curveset('256','256MS','MS256E','32','24','256','3','PSEUDO_MERSENNE','EDWARDS','NOT',tempTarg);
				copyROMfiles('256MS','MS256E',tempTarg);
			}
			if (arguments[i] == 'MS256M') {
				curveset('256','256MS','MS256M','32','24','256','3','PSEUDO_MERSENNE','MONTGOMERY','NOT',tempTarg);
				copyROMfiles('256MS','MS256M',tempTarg);
			}
			if (arguments[i] == 'BN254') {
				curveset('256','BN254','BN254','32','24','254','3','NOT_SPECIAL','WEIERSTRASS','BN',tempTarg);
				copyROMfiles('BN254','BN254',tempTarg);
			}
			if (arguments[i] == 'BN254CX') {
				curveset('256','BN254CX','BN254CX','32','24','254','3','NOT_SPECIAL','WEIERSTRASS','BN',tempTarg);
				copyROMfiles('BN254CX','BN254CX',tempTarg);
			}
			if (arguments[i] == 'BLS383') {
				curveset('384','BLS383','BLS383','48','23','383','3','NOT_SPECIAL','WEIERSTRASS','BLS',tempTarg);
				copyROMfiles('BLS383','BLS383',tempTarg);
			}
			if (arguments[i] == 'RSA2048') {
				rsaset('1024','2048','128','22','2',tempTarg);
			}
			if (arguments[i] == 'RSA3072') {
				rsaset('384','3072','48','23','8',tempTarg);
			}
			if (arguments[i] == 'RSA4096') {
				rsaset('512','4096','64','23','8',tempTarg);
			}
		}
	});
	desc('Build with default curve BN254CX and RSA4096');
	task('default', function () {
		var tempTarg = targetdir+'/build_BN254CX_RSA4096';
		console.log('Create target directory'+tempTarg);
		jake.mkdirP(tempTarg);
		copyCommonFiles(tempTarg);
		curveset('256','BN254CX','BN254CX','32','24','254','3','NOT_SPECIAL','WEIERSTRASS','BN',tempTarg);
		copyROMfiles('BN254CX','BN254CX',tempTarg);
		rsaset('512','4096','64','23','8',tempTarg);
	});
});

task('list', function () {
	desc('See the list of all curves');
	console.log('\nList of all curves available and RSA configurations\n');
	console.log('Elliptic Curves');
	console.log('ED25519');
	console.log('C25519');
	console.log('NIST256');
	console.log('BRAINPOOL');
	console.log('ANSSI');
	console.log('HIFIVE');
	console.log('GOLDILOCKS');
	console.log('NIST384');
	console.log('C41417');
	console.log('NIST521');
	console.log('MF254W (WEIERSTRASS)');
	console.log('MF254E (EDWARDS)');
	console.log('MF254M (MONTGOMERY)');
	console.log('MF256W (WEIERSTRASS)');
	console.log('MF256E (EDWARDS)');
	console.log('MF256M (MONTGOMERY)');
	console.log('MS255W (WEIERSTRASS)');
	console.log('MS255E (EDWARDS)');
	console.log('MS255M (MONTGOMERY)');
	console.log('MS256W (WEIERSTRASS)');
	console.log('MS256E (EDWARDS)');
	console.log('MS256M (MONTGOMERY)\n');

	console.log('Pairing-Friendly Elliptic Curves');
	console.log('BN254');
	console.log('BN254CX');
	console.log('BLS383\n');

	console.log('RSA configurations');
	console.log('RSA2048');
	console.log('RSA3072');
	console.log('RSA4096\n');
});