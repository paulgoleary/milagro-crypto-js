require('jake-utils');
require('colors');

var fs = require("fs"),
	jake = require('jake');

var cwd = process.cwd(),
	srcdir = cwd + '/src',
	testdir = cwd + '/test',
    targetdir = cwd + '/target',
    testingdir = '/Testing',
    includefile = '/include.html',
    targetsrcdir = '/src',
    targettestdir = '/test';

jake.addListener('complete', function () {
  process.exit();
});

// Replace pattern into files.
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

// Add file into include file
function addToInclude(fname,tempTarg) {
	var incfile = read(tempTarg+'/include.html')
	if (!(fname in incfile)) {
		fs.appendFileSync(tempTarg+includefile, '<script type=\"text/javascript\" src=\"'+fname+'\"></script>\n');
	}
}

// Copy file in common with all the configurations
function copyCommonFiles(tempTarg){
	console.log('Copying common files'.blue);
	tempTarg += targetsrcdir+'/';
	jake.cpR(srcdir+'/AES.js',tempTarg+'/AES.js');
	jake.cpR(srcdir+'/GCM.js',tempTarg+'/GCM.js');
	jake.cpR(srcdir+'/HASH256.js',tempTarg+'/HASH256.js');
	jake.cpR(srcdir+'/HASH384.js',tempTarg+'/HASH384.js');
	jake.cpR(srcdir+'/HASH512.js',tempTarg+'/HASH512.js');
	jake.cpR(srcdir+'/RAND.js',tempTarg+'/RAND.js');
	jake.cpR(srcdir+'/UInt64.js',tempTarg+'/UInt64.js');
	jake.cpR(srcdir+'/include.html',tempTarg+'/include.html');
}

// Copy ROM files according with the curve and the field in use
function copyROMfiles(curve,field,tempTarg) {
	tempTarg += targetsrcdir+'/';
	jake.cpR(srcdir+'/ROM_CURVE_'+curve+'.js',tempTarg+'/ROM_CURVE_'+curve+'.js');
	jake.cpR(srcdir+'/ROM_FIELD_'+field+'.js',tempTarg+'/ROM_FIELD_'+field+'.js');
}

// Copy and set parameters for files according with the RSA building option.
function rsaset(tb,tff,nb,base,ml,tempTarg) {

	tempTarg += targetsrcdir+'/';
	fname='BIG_'+tb+'.js';
	jake.cpR(srcdir+'/BIG_XXX.js', tempTarg+fname);
	Replace(tempTarg+fname,'XXX',tb);
	Replace(tempTarg+fname,'@NB@',nb);
	Replace(tempTarg+fname,'@BASE@',base);
	addToInclude(fname,tempTarg)

	fname='DBIG_'+tb+'.js';
	jake.cpR(srcdir+'/DBIG_XXX.js', tempTarg+fname);

	Replace(tempTarg+fname,'XXX',tb);
	addToInclude(fname,tempTarg)


	fname='FF_'+tff+'.js';
	jake.cpR(srcdir+'/FF_WWW.js', tempTarg+fname);

	Replace(tempTarg+fname,'WWW',tff);
	Replace(tempTarg+fname,'XXX',tb);
	Replace(tempTarg+fname,'@ML@',ml);
	addToInclude(fname,tempTarg)

	fname='RSA_'+tff+'.js';
	jake.cpR(srcdir+'/RSA_WWW.js', tempTarg+fname);

	Replace(tempTarg+fname,'WWW',tff);
	Replace(tempTarg+fname,'XXX',tb);
	addToInclude(fname,tempTarg)
}

// Copy and set parameters for files according with the curve chosen.
function curveset(tb,tf,tc,nb,base,nbt,m8,mt,ct,pf,tempTarg) {

	tempTarg += targetsrcdir+'/';
	fname='BIG_'+tb+'.js';
	jake.cpR(srcdir+'/BIG_XXX.js', tempTarg+fname);

	Replace(tempTarg+fname,'XXX',tb);
	Replace(tempTarg+fname,'@NB@',nb);
	Replace(tempTarg+fname,'@BASE@',base);
	addToInclude(fname,tempTarg)

	fname='DBIG_'+tb+'.js';
	jake.cpR(srcdir+'/DBIG_XXX.js', tempTarg+fname);

	Replace(tempTarg+fname,'XXX',tb);
	addToInclude(fname,tempTarg)

	fname='FP_'+tf+'.js';
	jake.cpR(srcdir+'/FP_YYY.js', tempTarg+fname);

	Replace(tempTarg+fname,'XXX',tb);
	Replace(tempTarg+fname,'YYY',tf);
	Replace(tempTarg+fname,'@NBT@',nbt);
	Replace(tempTarg+fname,'@M8@',m8);
	Replace(tempTarg+fname,'@MT@',mt);
	addToInclude(fname,tempTarg)

	fname='ECP_'+tc+'.js';
	jake.cpR(srcdir+'/ECP_ZZZ.js', tempTarg+fname);

	Replace(tempTarg+fname,'XXX',tb);
	Replace(tempTarg+fname,'YYY',tf);
	Replace(tempTarg+fname,'ZZZ',tc);
	Replace(tempTarg+fname,'@CT@',ct);
	Replace(tempTarg+fname,'@PF@',pf);
	addToInclude(fname,tempTarg)

	fname='ECDH_'+tc+'.js';
	jake.cpR(srcdir+'/ECDH_ZZZ.js', tempTarg+fname);

	Replace(tempTarg+fname,'ZZZ',tc);
	Replace(tempTarg+fname,'YYY',tf);
	Replace(tempTarg+fname,'XXX',tb);
	addToInclude(fname,tempTarg)

	fname='ROM_FIELD_'+tf+'.js';
	addToInclude(fname,tempTarg)
	fname='ROM_CURVE_'+tc+'.js';
	addToInclude(fname,tempTarg)

	if (pf != 'NOT' ) {
		fname='FP2_'+tf+'.js';
		jake.cpR(srcdir+'/FP2_YYY.js', tempTarg+fname);
		Replace(tempTarg+fname,'YYY',tf);
		Replace(tempTarg+fname,'XXX',tb);
		addToInclude(fname,tempTarg)

		fname='FP4_'+tf+'.js';
		jake.cpR(srcdir+'/FP4_YYY.js', tempTarg+fname);
		Replace(tempTarg+fname,'YYY',tf);
		Replace(tempTarg+fname,'XXX',tb);
		addToInclude(fname,tempTarg)

		fname='FP12_'+tf+'.js';
		jake.cpR(srcdir+'/FP12_YYY.js', tempTarg+fname);
		Replace(tempTarg+fname,'YYY',tf);
		Replace(tempTarg+fname,'XXX',tb);
		addToInclude(fname,tempTarg)

		fname='ECP2_'+tc+'.js';
		jake.cpR(srcdir+'/ECP2_ZZZ.js', tempTarg+fname);
		Replace(tempTarg+fname,'YYY',tf);
		Replace(tempTarg+fname,'XXX',tb);
		Replace(tempTarg+fname,'ZZZ',tc);
		addToInclude(fname,tempTarg)

		fname='PAIR_'+tc+'.js';
		jake.cpR(srcdir+'/PAIR_ZZZ.js', tempTarg+fname);
		Replace(tempTarg+fname,'YYY',tf);
		Replace(tempTarg+fname,'XXX',tb);
		Replace(tempTarg+fname,'ZZZ',tc);
		addToInclude(fname,tempTarg)

		fname='MPIN_'+tc+'.js';
		jake.cpR(srcdir+'/MPIN_ZZZ.js', tempTarg+fname);
		Replace(tempTarg+fname,'YYY',tf);
		Replace(tempTarg+fname,'XXX',tb);
		Replace(tempTarg+fname,'ZZZ',tc);
		addToInclude(fname,tempTarg)
	}
}

// Copy and set parameters for files according with the curve chosen.
function testset(tb,tf,tc,tempTarg) {

	fname = tempTarg+targettestdir+'/'+'test_ECDH_'+tc+'.js';
	jake.cpR(testdir+'/test_ECDH_.js', fname);

	Replace(fname,'XXX',tb);
	Replace(fname,'YYY',tf);
	Replace(fname,'ZZZ',tc);
	Replace(fname,'@SWD',tempTarg+targetsrcdir);
}

function checkinput(option) {

	if ((option != 'ED25519') && (option != 'GOLDILOCKS') && (option != 'NIST256') && (option != 'BRAINPOOL') && (option != 'ANSSI') &&
		(option != 'HIFIVE') && (option != 'C25519') && (option != 'NIST384') && (option != 'C41417') && (option != 'NIST521') &&
		(option != 'MF254W') && (option != 'MF254E') && (option != 'MF254M') && (option != 'MF256W') && (option != 'MF256E') &&
		(option != 'MF256M') && (option != 'MS255W') && (option != 'MS255E') && (option != 'MS255M') && (option != 'MS256W') &&
		(option != 'MS256E') && (option != 'MS256M') && (option != 'BN254') && (option != 'BN254CX') && (option != 'BLS383') &&
		(option != 'RSA2048') && (option != 'RSA3072') && (option != 'RSA4096')) {
		return -1;
	} else {
		return 0;
	}
}

desc('Default'.blue);
task('default', function () {
  console.log('Type `jake -T` to see the list of all thew tasks.');
});

// Build with editable options
namespace('build', function () {
	desc('Build library supporting multiple curves. For example jake build:choice[BN254,P256,RSA2048]'.blue);
	task('choice', function () {
		var tempTarg = targetdir+"/build";
		for (var i=0; i<arguments.length; i++) {
			if  (checkinput(arguments[i]) != 0)
				fail('Invalid input');
			tempTarg += "_"+arguments[i];
		}
		console.log('Building library with building options'.red);
		console.log('Create target directory'+tempTarg);
		jake.mkdirP(tempTarg+targetsrcdir);
		jake.mkdirP(tempTarg+targettestdir);
		copyCommonFiles(tempTarg);
		for (var i=0; i<arguments.length; i++){
			console.log(('Creating files for '+arguments[i]).blue);
			if (arguments[i] == 'ED25519') {
				curveset('256','25519','ED25519','32','24','255','5','PSEUDO_MERSENNE','EDWARDS','NOT',tempTarg);
				copyROMfiles('ED25519','25519',tempTarg);
				testset('256','25519','ED25519',tempTarg);
			}
			if (arguments[i] == 'C25519') {
				curveset('256','25519','C25519','32','24','255','5','PSEUDO_MERSENNE','MONTGOMERY','NOT',tempTarg);
				copyROMfiles('C25519','25519',tempTarg);
				testset('256','25519','C25519',tempTarg);
			}
			if (arguments[i] == 'NIST256') {
				curveset('256','NIST256','NIST256','32','24','256','7','NOT_SPECIAL','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('NIST256','NIST256',tempTarg);
				testset('256','NIST256','NIST256',tempTarg);
			}
			if (arguments[i] == 'BRAINPOOL') {
				curveset('256','BRAINPOOL','BRAINPOOL','32','24','256','7','NOT_SPECIAL','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('BRAINPOOL','BRAINPOOL',tempTarg);
				testset('256','BRAINPOOL','BRAINPOOL',tempTarg);
			}
			if (arguments[i] == 'ANSSI') {
				curveset('256','ANSSI','ANSSI','32','24','256','7','NOT_SPECIAL','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('ANSSI','ANSSI',tempTarg);
				testset('256','ANSSI','ANSSI',tempTarg);
			}
			if (arguments[i] == 'HIFIVE') {
				curveset('336','HIFIVE','HIFIVE','42','23','336','5','PSEUDO_MERSENNE','EDWARDS','NOT',tempTarg);
				copyROMfiles('HIFIVE','HIFIVE',tempTarg);
				testset('336','HIFIVE','HIFIVE',tempTarg);
			}
			if (arguments[i] == 'GOLDILOCKS') {
				curveset('448','GOLDILOCKS','GOLDILOCKS','56','23','448','7','GENERALISED_MERSENNE','EDWARDS','NOT',tempTarg);
				copyROMfiles('GOLDILOCKS','GOLDILOCKS',tempTarg);
				testset('448','GOLDILOCKS','GOLDILOCKS',tempTarg);
			}
			if (arguments[i] == 'NIST384') {
				curveset('384','NIST384','NIST384','48','','28','56','384','7','NOT_SPECIAL','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('NIST384','NIST384',tempTarg);
				testset('384','NIST384','NIST384',tempTarg);
			}
			if (arguments[i] == 'C41417') {
				curveset('416','C41417','C41417','52','23','414','7','PSEUDO_MERSENNE','EDWARDS','NOT',tempTarg);
				copyROMfiles('C41417','C41417',tempTarg);
				testset('416','','',tempTarg);
			}
			if (arguments[i] == 'NIST521') {
				curveset('528','NIST521','NIST521','66','23','521','7','PSEUDO_MERSENNE','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('NIST521','NIST521',tempTarg);
				testset('528','NIST521','NIST521',tempTarg);
			}
			if (arguments[i] == 'MF254W') {
				curveset('256','254MF','MF254W','32','24','254','7','MONTGOMERY_FRIENDLY','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('254MF','MF254W',tempTarg);
				testset('256','254MF','MF254W',tempTarg);
			}
			if (arguments[i] == 'MF254E') {
				curveset('256','254MF','MF254E','32','24','254','7','MONTGOMERY_FRIENDLY','EDWARDS','NOT',tempTarg);
				copyROMfiles('254MF','MF254E',tempTarg);
				testset('256','254MF','MF254E',tempTarg);
			}
			if (arguments[i] == 'MF254M') {
				curveset('256','254MF','MF254M','32','24','254','7','MONTGOMERY_FRIENDLY','MONTGOMERY','NOT',tempTarg);
				copyROMfiles('254MF','MF254M',tempTarg);
				//testset('','','',tempTarg);
			}
			if (arguments[i] == 'MF256W') {
				curveset('256','256MF','MF256W','32','24','256','7','MONTGOMERY_FRIENDLY','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('256MF','MF256W',tempTarg);
				testset('256','256MF','MF256W',tempTarg);
			}
			if (arguments[i] == 'MF256E') {
				curveset('256','256MF','MF256E','32','24','256','7','MONTGOMERY_FRIENDLY','EDWARDS','NOT',tempTarg);
				copyROMfiles('256MF','MF256E',tempTarg);
				testset('256','256MF','MF256E',tempTarg);
			}
			if (arguments[i] == 'MF256M') {
				curveset('256','256MF','MF256M','32','24','256','7','MONTGOMERY_FRIENDLY','MONTGOMERY','NOT',tempTarg);
				copyROMfiles('256MF','MF256M',tempTarg);
				testset('256','256MF','MF256M',tempTarg);
			}
			if (arguments[i] == 'MS255W') {
				curveset('256','255MS','MS255W','32','24','255','3','PSEUDO_MERSENNE','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('255MS','MS255W',tempTarg);
				testset('256','255MS','MS255W',tempTarg);
			}
			if (arguments[i] == 'MS255E') {
				curveset('256','255MS','MS255E','32','24','255','3','PSEUDO_MERSENNE','EDWARDS','NOT',tempTarg);
				copyROMfiles('255MS','MS255E',tempTarg);
				testset('256','255MS','MS255E',tempTarg);
			}
			if (arguments[i] == 'MS255M') {
				curveset('256','255MS','MS255M','32','24','255','3','PSEUDO_MERSENNE','MONTGOMERY','NOT',tempTarg);
				copyROMfiles('255MS','MS255M',tempTarg);
				testset('256','255MS','MS255M',tempTarg);
			}
			if (arguments[i] == 'MS256W') {
				curveset('256','256MS','MS256W','32','24','256','3','PSEUDO_MERSENNE','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('256MS','MS256W',tempTarg);
				testset('256','256MS','MS256W',tempTarg);
			}
			if (arguments[i] == 'MS256E') {
				curveset('256','256MS','MS256E','32','24','256','3','PSEUDO_MERSENNE','EDWARDS','NOT',tempTarg);
				copyROMfiles('256MS','MS256E',tempTarg);
				testset('256','256MS','MS256E',tempTarg);
			}
			if (arguments[i] == 'MS256M') {
				curveset('256','256MS','MS256M','32','24','256','3','PSEUDO_MERSENNE','MONTGOMERY','NOT',tempTarg);
				copyROMfiles('256MS','MS256M',tempTarg);
				testset('256','256MS','MS256M',tempTarg);
			}
			if (arguments[i] == 'BN254') {
				curveset('256','BN254','BN254','32','24','254','3','NOT_SPECIAL','WEIERSTRASS','BN',tempTarg);
				copyROMfiles('BN254','BN254',tempTarg);
				testset('256','BN254','BN254',tempTarg);
			}
			if (arguments[i] == 'BN254CX') {
				curveset('256','BN254CX','BN254CX','32','24','254','3','NOT_SPECIAL','WEIERSTRASS','BN',tempTarg);
				copyROMfiles('BN254CX','BN254CX',tempTarg);
				testset('256','BN254CX','BN254CX',tempTarg);
			}
			if (arguments[i] == 'BLS383') {
				curveset('384','BLS383','BLS383','48','23','383','3','NOT_SPECIAL','WEIERSTRASS','BLS',tempTarg);
				copyROMfiles('BLS383','BLS383',tempTarg);
				testset('384','BLS383','BLS383',tempTarg);
				testset('384','BLS383','BLS383',tempTarg);
			}
			if (arguments[i] == 'RSA2048') {
				rsaset('1024','2048','128','22','2',tempTarg);
				//testset('','','',tempTarg);
			}
			if (arguments[i] == 'RSA3072') {
				rsaset('384','3072','48','23','8',tempTarg);
				//testset('','','',tempTarg);
			}
			if (arguments[i] == 'RSA4096') {
				rsaset('512','4096','64','23','8',tempTarg);
			}
		}
	});
});

// Build with default curve BN254CX and RSA2048 
desc('Build library with default curve BN254CX and RSA2048'.blue);
task('build', function () {
	console.log('Build library with default curve BN254CX and RSA2048'.red);
	var tempTarg = targetdir+'/build_BN254CX_RSA2048';
	console.log('Create target directory'+tempTarg);
	jake.mkdirP(tempTarg+targetsrcdir);
	jake.mkdirP(tempTarg+testdir);
	copyCommonFiles(tempTarg);
	curveset('256','BN254CX','BN254CX','32','24','254','3','NOT_SPECIAL','WEIERSTRASS','BN',tempTarg);
	copyROMfiles('BN254CX','BN254CX',tempTarg);
	rsaset('1024','2048','128','22','2',tempTarg);
	complete();
});

// List all the building options
task('list', function () {
	desc('See the list of all curves'.blue);
	console.log('\nList of all curves available and RSA configurations\n');
	console.log('Elliptic Curves'.red);
	console.log('ED25519');
	console.log('C25519');
	console.log('C41417');
	console.log('NIST256');
	console.log('NIST384');
	console.log('NIST521');
	console.log('BRAINPOOL');
	console.log('ANSSI');
	console.log('HIFIVE');
	console.log('GOLDILOCKS');
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

	console.log('Pairing-Friendly Elliptic Curves'.red);
	console.log('BN254');
	console.log('BN254CX');
	console.log('BLS383\n');

	console.log('RSA configurations'.red);
	console.log('RSA2048');
	console.log('RSA3072');
	console.log('RSA4096\n');
});

// Clean up target directory
desc('Clean up target directory'.blue);
task('clean', function () {
	jake.rmRf(targetdir);
	jake.mkdirP(targetdir);
});

// Run tests
desc('Run tests'.blue);
task('test', {async: true}, function () {
	var outputfile, cmd, tempTarg = '';
	fs.readdir(targetdir, function(err, builds) {
	    for (var i=0; i<builds.length; i++) {
	        tempTarg = targetdir+'/'+ builds[i];
	        console.log(('Testing '+tempTarg+' ...').blue);
	        jake.mkdirP(tempTarg+testingdir);
	        outputfile = tempTarg+testingdir+'/LastTest.txt';
	        fs.readdir(tempTarg+targettestdir, function(errors, tests) {
	        	if (tests == null) {
	        		console.log('Nothing to test');
	        	}
	        	console.log(tempTarg+targettestdir);
	        	for (var j=0; j<tests.length; j++) {
	        		cmd = 'node '+tempTarg+targettestdir+'/'+tests[i]+' >> '+outputfile+' 2>&1';
	        		console.log(cmd);
	        		jake.exec(cmd,{printStdout: true});
	        	}
	        });       	
	    }
	});
});
