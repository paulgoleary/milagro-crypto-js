require('colors');

var fs = require('fs'),
	jake = require('jake');

var cwd = process.cwd(),
	srcdir = cwd + '/src',
	testdir = cwd + '/test',
    targetdir = cwd + '/target',
    testingdir = '/Testing',
    includefile = '/include.html',
    targetsrcdir = '/src',
    targettestdir = '/test',
    lasttestlog = '/LastTest.txt',
    failedtestlog = '/FailedTest.txt';

jake.addListener('complete', function () {
  process.exit();
});

// Replace pattern into files.
function Replace(namefile,oldtext,newtext) {
    // load the html file
    var fileContent = fs.readFileSync(namefile,'utf8');

    // replacePath is your match[1]
    fileContent = fileContent.replace(oldtext,newtext);

    // this will overwrite the original html file, change the path for test
    fs.writeFileSync(namefile, fileContent);
}

// Add file into include file
function addToInclude(fname,tempTarg) {
	var incfile = fs.readFileSync(tempTarg+'/include.html','utf8')
	if (!(incfile.includes(fname))) {
		fs.appendFileSync(tempTarg+includefile, '<script type=\'text/javascript\' src=\''+fname+'\'></script>\n');
	}
}

// Copy file in common with all the configurations
function copyCommonFiles(tempTarg){
	jake.logger.log('Copying common files'.blue);
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
	Replace(tempTarg+fname,/XXX/g,tb);
	Replace(tempTarg+fname,/@NB@/g,nb);
	Replace(tempTarg+fname,/@BASE@/g,base);
	addToInclude(fname,tempTarg)

	fname='DBIG_'+tb+'.js';
	jake.cpR(srcdir+'/DBIG_XXX.js', tempTarg+fname);

	Replace(tempTarg+fname,/XXX/g,tb);
	addToInclude(fname,tempTarg)


	fname='FF_'+tff+'.js';
	jake.cpR(srcdir+'/FF_WWW.js', tempTarg+fname);

	Replace(tempTarg+fname,/WWW/g,tff);
	Replace(tempTarg+fname,/XXX/g,tb);
	Replace(tempTarg+fname,/@ML@/g,ml);
	addToInclude(fname,tempTarg)

	fname='RSA_'+tff+'.js';
	jake.cpR(srcdir+'/RSA_WWW.js', tempTarg+fname);

	Replace(tempTarg+fname,/WWW/g,tff);
	Replace(tempTarg+fname,/XXX/g,tb);
	addToInclude(fname,tempTarg)
}

// Copy and set parameters for files according with the curve chosen.
function curveset(tb,tf,tc,nb,base,nbt,m8,mt,ct,pf,tempTarg) {

	tempTarg += targetsrcdir+'/';
	fname='BIG_'+tb+'.js';
	jake.cpR(srcdir+'/BIG_XXX.js', tempTarg+fname);

	Replace(tempTarg+fname,/XXX/g,tb);
	Replace(tempTarg+fname,/@NB@/g,nb);
	Replace(tempTarg+fname,/@BASE@/g,base);
	addToInclude(fname,tempTarg)

	fname='DBIG_'+tb+'.js';
	jake.cpR(srcdir+'/DBIG_XXX.js', tempTarg+fname);

	Replace(tempTarg+fname,/XXX/g,tb);
	addToInclude(fname,tempTarg)

	fname='FP_'+tf+'.js';
	jake.cpR(srcdir+'/FP_YYY.js', tempTarg+fname);

	Replace(tempTarg+fname,/XXX/g,tb);
	Replace(tempTarg+fname,/YYY/g,tf);
	Replace(tempTarg+fname,/@NBT@/g,nbt);
	Replace(tempTarg+fname,/@M8@/g,m8);
	Replace(tempTarg+fname,/@MT@/g,mt);
	addToInclude(fname,tempTarg)

	fname='ECP_'+tc+'.js';
	jake.cpR(srcdir+'/ECP_ZZZ.js', tempTarg+fname);

	Replace(tempTarg+fname,/XXX/g,tb);
	Replace(tempTarg+fname,/YYY/g,tf);
	Replace(tempTarg+fname,/ZZZ/g,tc);
	Replace(tempTarg+fname,/@CT@/g,ct);
	Replace(tempTarg+fname,/@PF@/g,pf);
	addToInclude(fname,tempTarg)

	fname='ECDH_'+tc+'.js';
	jake.cpR(srcdir+'/ECDH_ZZZ.js', tempTarg+fname);

	Replace(tempTarg+fname,/ZZZ/g,tc);
	Replace(tempTarg+fname,/YYY/g,tf);
	Replace(tempTarg+fname,/XXX/g,tb);
	addToInclude(fname,tempTarg)

	fname='ROM_FIELD_'+tf+'.js';
	addToInclude(fname,tempTarg)
	fname='ROM_CURVE_'+tc+'.js';
	addToInclude(fname,tempTarg)

	if (pf != 'NOT' ) {
		fname='FP2_'+tf+'.js';
		jake.cpR(srcdir+'/FP2_YYY.js', tempTarg+fname);
		Replace(tempTarg+fname,/YYY/g,tf);
		Replace(tempTarg+fname,/XXX/g,tb);
		addToInclude(fname,tempTarg)

		fname='FP4_'+tf+'.js';
		jake.cpR(srcdir+'/FP4_YYY.js', tempTarg+fname);
		Replace(tempTarg+fname,/YYY/g,tf);
		Replace(tempTarg+fname,/XXX/g,tb);
		addToInclude(fname,tempTarg)

		fname='FP12_'+tf+'.js';
		jake.cpR(srcdir+'/FP12_YYY.js', tempTarg+fname);
		Replace(tempTarg+fname,/YYY/g,tf);
		Replace(tempTarg+fname,/XXX/g,tb);
		addToInclude(fname,tempTarg)

		fname='ECP2_'+tc+'.js';
		jake.cpR(srcdir+'/ECP2_ZZZ.js', tempTarg+fname);
		Replace(tempTarg+fname,/YYY/g,tf);
		Replace(tempTarg+fname,/XXX/g,tb);
		Replace(tempTarg+fname,/ZZZ/g,tc);
		addToInclude(fname,tempTarg)

		fname='PAIR_'+tc+'.js';
		jake.cpR(srcdir+'/PAIR_ZZZ.js', tempTarg+fname);
		Replace(tempTarg+fname,/YYY/g,tf);
		Replace(tempTarg+fname,/XXX/g,tb);
		Replace(tempTarg+fname,/ZZZ/g,tc);
		addToInclude(fname,tempTarg)

		fname='MPIN_'+tc+'.js';
		jake.cpR(srcdir+'/MPIN_ZZZ.js', tempTarg+fname);
		Replace(tempTarg+fname,/YYY/g,tf);
		Replace(tempTarg+fname,/XXX/g,tb);
		Replace(tempTarg+fname,/ZZZ/g,tc);
		addToInclude(fname,tempTarg)
	}
}

// Copy and set parameters for test files according with the curve chosen.
function curvetestset(tb,tf,tc,pf,tempTarg) {

	if (pf == 'NOT'){
		fname = tempTarg+targettestdir+'/'+'test_ECDH_'+tc+'.js';
		jake.cpR(testdir+'/test_ECDH_ZZZ.js', fname);

		Replace(fname,/XXX/g,tb);
		Replace(fname,/YYY/g,tf);
		Replace(fname,/ZZZ/g,tc);
		Replace(fname,/@SWD/g,tempTarg+targetsrcdir);
	}
	if (pf != 'NOT'){
		fname = tempTarg+targettestdir+'/'+'test_MPIN_'+tc+'.js';
		jake.cpR(testdir+'/test_MPIN_ZZZ.js', fname);

		Replace(fname,/XXX/g,tb);
		Replace(fname,/YYY/g,tf);
		Replace(fname,/ZZZ/g,tc);
		Replace(fname,/@SWD/g,tempTarg+targetsrcdir);

		fname = tempTarg+targettestdir+'/'+'test_MPIN_TP_'+tc+'.js';
		jake.cpR(testdir+'/test_MPIN_TP_ZZZ.js', fname);

		Replace(fname,/XXX/g,tb);
		Replace(fname,/YYY/g,tf);
		Replace(fname,/ZZZ/g,tc);
		Replace(fname,/@SWD/g,tempTarg+targetsrcdir);

		fname = tempTarg+targettestdir+'/'+'test_MPIN_FULL_'+tc+'.js';
		jake.cpR(testdir+'/test_MPIN_FULL_ZZZ.js', fname);

		Replace(fname,/XXX/g,tb);
		Replace(fname,/YYY/g,tf);
		Replace(fname,/ZZZ/g,tc);
		Replace(fname,/@SWD/g,tempTarg+targetsrcdir);

		fname = tempTarg+targettestdir+'/'+'test_MPIN_ONE_PASS_'+tc+'.js';
		jake.cpR(testdir+'/test_MPIN_ONE_PASS_ZZZ.js', fname);

		Replace(fname,/XXX/g,tb);
		Replace(fname,/YYY/g,tf);
		Replace(fname,/ZZZ/g,tc);
		Replace(fname,/@SWD/g,tempTarg+targetsrcdir);
	}
}

// Copy and set parameters for files according with the RSA configuration chosen.
function rsatestset(tb,tff,tempTarg) {

	fname = tempTarg+targettestdir+'/'+'test_RSA_'+tff+'.js';
	jake.cpR(testdir+'/test_RSA_WWW.js', fname);

	Replace(fname,/XXX/g,tb);
	Replace(fname,/WWW/g,tff);
	Replace(fname,/@SWD/g,tempTarg+targetsrcdir);
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

// run a single test
function testrun(target,test,callback) {
	var nametest = test.replace(/_/g,' ').replace('.js','');
	var outputfile = target+testingdir+lasttestlog;
	var cmd ='node '+target+targettestdir+'/'+test+' >> '+outputfile+' 2>&1';
	process.stdout.write(nametest+' ... ');
	var ex = jake.createExec(cmd);
	ex.addListener('error', function(msg,code) {
		process.stdout.write('Failed\n');
		fs.appendFileSync(target+testingdir+failedtestlog, nametest+'\n');
		callback();
		return;
	});
	ex.addListener('cmdEnd',function(arg) {
		process.stdout.write('OK\n');
		callback();
		return;
	});
	ex.run();
}

desc('Default'.blue);
task('default', function () {
  jake.logger.log('Type `jake -T` to see the list of all thew tasks.');
});

// Build with editable options
namespace('build', function () {
	desc('Build library supporting multiple curves. For example jake build:choice[BN254CX,NIST256,RSA2048]'.blue);
	task('choice', function () {
		var tempTarg = targetdir+'/build';
		for (var i=0; i<arguments.length; i++) {
			if  (checkinput(arguments[i]) != 0)
			{
				jake.logger.error('ERROR: Invalid input');
				complete();
			}
			tempTarg += '_'+arguments[i];
		}
		jake.logger.log('Building library with building options'.red);
		jake.logger.log('Create target directory'+tempTarg);
		jake.mkdirP(tempTarg+targetsrcdir);
		jake.mkdirP(tempTarg+targettestdir);
		copyCommonFiles(tempTarg);
		for (var i=0; i<arguments.length; i++){
			jake.logger.log(('Creating files for '+arguments[i]).blue);
			if (arguments[i] == 'ED25519') {
				curveset('256','25519','ED25519','32','24','255','5','PSEUDO_MERSENNE','EDWARDS','NOT',tempTarg);
				copyROMfiles('ED25519','25519',tempTarg);
				curvetestset('256','25519','ED25519','NOT',tempTarg);
			}
			if (arguments[i] == 'C25519') {
				curveset('256','25519','C25519','32','24','255','5','PSEUDO_MERSENNE','MONTGOMERY','NOT',tempTarg);
				copyROMfiles('C25519','25519',tempTarg);
				curvetestset('256','25519','C25519','NOT',tempTarg);
			}
			if (arguments[i] == 'NIST256') {
				curveset('256','NIST256','NIST256','32','24','256','7','NOT_SPECIAL','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('NIST256','NIST256',tempTarg);
				curvetestset('256','NIST256','NIST256','NOT',tempTarg);
			}
			if (arguments[i] == 'NIST384') {
				curveset('384','NIST384','NIST384','48','56','384','7','NOT_SPECIAL','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('NIST384','NIST384',tempTarg);
				curvetestset('384','NIST384','NIST384','NOT',tempTarg);
			}
			if (arguments[i] == 'BRAINPOOL') {
				curveset('256','BRAINPOOL','BRAINPOOL','32','24','256','7','NOT_SPECIAL','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('BRAINPOOL','BRAINPOOL',tempTarg);
				curvetestset('256','BRAINPOOL','BRAINPOOL','NOT',tempTarg);
			}
			if (arguments[i] == 'ANSSI') {
				curveset('256','ANSSI','ANSSI','32','24','256','7','NOT_SPECIAL','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('ANSSI','ANSSI',tempTarg);
				curvetestset('256','ANSSI','ANSSI','NOT',tempTarg);
			}
			if (arguments[i] == 'HIFIVE') {
				curveset('336','HIFIVE','HIFIVE','42','23','336','5','PSEUDO_MERSENNE','EDWARDS','NOT',tempTarg);
				copyROMfiles('HIFIVE','HIFIVE',tempTarg);
				curvetestset('336','HIFIVE','HIFIVE','NOT',tempTarg);
			}
			if (arguments[i] == 'GOLDILOCKS') {
				curveset('448','GOLDILOCKS','GOLDILOCKS','56','23','448','7','GENERALISED_MERSENNE','EDWARDS','NOT',tempTarg);
				copyROMfiles('GOLDILOCKS','GOLDILOCKS',tempTarg);
				curvetestset('448','GOLDILOCKS','GOLDILOCKS','NOT',tempTarg);
			}
			if (arguments[i] == 'C41417') {
				curveset('416','C41417','C41417','52','23','414','7','PSEUDO_MERSENNE','EDWARDS','NOT',tempTarg);
				copyROMfiles('C41417','C41417',tempTarg);
				curvetestset('416','','','NOT',tempTarg);
			}
			if (arguments[i] == 'NIST521') {
				curveset('528','NIST521','NIST521','66','23','521','7','PSEUDO_MERSENNE','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('NIST521','NIST521',tempTarg);
				curvetestset('528','NIST521','NIST521','NOT',tempTarg);
			}
			if (arguments[i] == 'MF254W') {
				curveset('256','254MF','MF254W','32','24','254','7','MONTGOMERY_FRIENDLY','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('254MF','MF254W',tempTarg);
				curvetestset('256','254MF','MF254W','NOT',tempTarg);
			}
			if (arguments[i] == 'MF254E') {
				curveset('256','254MF','MF254E','32','24','254','7','MONTGOMERY_FRIENDLY','EDWARDS','NOT',tempTarg);
				copyROMfiles('254MF','MF254E',tempTarg);
				curvetestset('256','254MF','MF254E','NOT',tempTarg);
			}
			if (arguments[i] == 'MF254M') {
				curveset('256','254MF','MF254M','32','24','254','7','MONTGOMERY_FRIENDLY','MONTGOMERY','NOT',tempTarg);
				copyROMfiles('254MF','MF254M',tempTarg);
				curvetestset('256','254MF','MF254M','NOT',tempTarg);
			}
			if (arguments[i] == 'MF256W') {
				curveset('256','256MF','MF256W','32','24','256','7','MONTGOMERY_FRIENDLY','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('256MF','MF256W',tempTarg);
				curvetestset('256','256MF','MF256W','NOT',tempTarg);
			}
			if (arguments[i] == 'MF256E') {
				curveset('256','256MF','MF256E','32','24','256','7','MONTGOMERY_FRIENDLY','EDWARDS','NOT',tempTarg);
				copyROMfiles('256MF','MF256E',tempTarg);
				curvetestset('256','256MF','MF256E','NOT',tempTarg);
			}
			if (arguments[i] == 'MF256M') {
				curveset('256','256MF','MF256M','32','24','256','7','MONTGOMERY_FRIENDLY','MONTGOMERY','NOT',tempTarg);
				copyROMfiles('256MF','MF256M',tempTarg);
				curvetestset('256','256MF','MF256M','NOT',tempTarg);
			}
			if (arguments[i] == 'MS255W') {
				curveset('256','255MS','MS255W','32','24','255','3','PSEUDO_MERSENNE','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('255MS','MS255W',tempTarg);
				curvetestset('256','255MS','MS255W','NOT',tempTarg);
			}
			if (arguments[i] == 'MS255E') {
				curveset('256','255MS','MS255E','32','24','255','3','PSEUDO_MERSENNE','EDWARDS','NOT',tempTarg);
				copyROMfiles('255MS','MS255E',tempTarg);
				curvetestset('256','255MS','MS255E','NOT',tempTarg);
			}
			if (arguments[i] == 'MS255M') {
				curveset('256','255MS','MS255M','32','24','255','3','PSEUDO_MERSENNE','MONTGOMERY','NOT',tempTarg);
				copyROMfiles('255MS','MS255M',tempTarg);
				curvetestset('256','255MS','MS255M','NOT',tempTarg);
			}
			if (arguments[i] == 'MS256W') {
				curveset('256','256MS','MS256W','32','24','256','3','PSEUDO_MERSENNE','WEIERSTRASS','NOT',tempTarg);
				copyROMfiles('256MS','MS256W',tempTarg);
				curvetestset('256','256MS','MS256W','NOT',tempTarg);
			}
			if (arguments[i] == 'MS256E') {
				curveset('256','256MS','MS256E','32','24','256','3','PSEUDO_MERSENNE','EDWARDS','NOT',tempTarg);
				copyROMfiles('256MS','MS256E',tempTarg);
				curvetestset('256','256MS','MS256E','NOT',tempTarg);
			}
			if (arguments[i] == 'MS256M') {
				curveset('256','256MS','MS256M','32','24','256','3','PSEUDO_MERSENNE','MONTGOMERY','NOT',tempTarg);
				copyROMfiles('256MS','MS256M',tempTarg);
				curvetestset('256','256MS','MS256M','NOT',tempTarg);
			}
			if (arguments[i] == 'BN254') {
				curveset('256','BN254','BN254','32','24','254','3','NOT_SPECIAL','WEIERSTRASS','BN',tempTarg);
				copyROMfiles('BN254','BN254',tempTarg);
				curvetestset('256','BN254','BN254','BN',tempTarg);
			}
			if (arguments[i] == 'BN254CX') {
				curveset('256','BN254CX','BN254CX','32','24','254','3','NOT_SPECIAL','WEIERSTRASS','BN',tempTarg);
				copyROMfiles('BN254CX','BN254CX',tempTarg);
				curvetestset('256','BN254CX','BN254CX','BN',tempTarg);
			}
			if (arguments[i] == 'BLS383') {
				curveset('384','BLS383','BLS383','48','23','383','3','NOT_SPECIAL','WEIERSTRASS','BLS',tempTarg);
				copyROMfiles('BLS383','BLS383',tempTarg);
				curvetestset('384','BLS383','BLS383','BLS',tempTarg);
			}
			if (arguments[i] == 'RSA2048') {
				rsaset('1024','2048','128','22','2',tempTarg);
				rsatestset('1024','2048',tempTarg);
			}
			if (arguments[i] == 'RSA3072') {
				rsaset('384','3072','48','23','8',tempTarg);
				rsatestset('384','3072',tempTarg);
			}
			if (arguments[i] == 'RSA4096') {
				rsaset('512','4096','64','23','8',tempTarg);
				rsatestset('512','4096',tempTarg);
			}
		}
	});
});

// Build with default curve BN254CX and RSA2048 
desc('Build library with default curves BN254CX and NIST256, and RSA2048'.blue);
task('build', function () {
	jake.logger.log('Build library with default curves BN254CX and NIST256, and RSA2048'.red);
	var tempTarg = targetdir+'/build_BN254CX_RSA2048';
	jake.logger.log('Create target directory'+tempTarg);
	jake.mkdirP(tempTarg+targetsrcdir);
	jake.mkdirP(tempTarg+targettestdir);
	copyCommonFiles(tempTarg);
	jake.logger.log(('Creating files for BN254CX').blue);
	curveset('256','BN254CX','BN254CX','32','24','254','3','NOT_SPECIAL','WEIERSTRASS','BN',tempTarg);
	copyROMfiles('BN254CX','BN254CX',tempTarg);
	curvetestset('256','BN254CX','BN254CX','BN',tempTarg);
	jake.logger.log(('Creating files for NIST256').blue);
	curveset('256','NIST256','NIST256','32','24','256','7','NOT_SPECIAL','WEIERSTRASS','NOT',tempTarg);
	copyROMfiles('NIST256','NIST256',tempTarg);
	curvetestset('256','NIST256','NIST256','NOT',tempTarg);
	jake.logger.log(('Creating files for RSA2048').blue);
	rsaset('1024','2048','128','22','2',tempTarg);
	rsatestset('1024','2048',tempTarg);
	complete();
});

// List all the building options
task('list', function () {
	desc('See the list of all curves'.blue);
	jake.logger.log('\nList of all curves available and RSA configurations\n');
	jake.logger.log('Elliptic Curves'.red);
	jake.logger.log('ED25519');
	jake.logger.log('C25519');
	jake.logger.log('C41417');
	jake.logger.log('NIST256');
	jake.logger.log('NIST384');
	jake.logger.log('NIST521');
	jake.logger.log('BRAINPOOL');
	jake.logger.log('ANSSI');
	jake.logger.log('HIFIVE');
	jake.logger.log('GOLDILOCKS');
	jake.logger.log('MF254W (WEIERSTRASS)');
	jake.logger.log('MF254E (EDWARDS)');
	jake.logger.log('MF254M (MONTGOMERY)');
	jake.logger.log('MF256W (WEIERSTRASS)');
	jake.logger.log('MF256E (EDWARDS)');
	jake.logger.log('MF256M (MONTGOMERY)');
	jake.logger.log('MS255W (WEIERSTRASS)');
	jake.logger.log('MS255E (EDWARDS)');
	jake.logger.log('MS255M (MONTGOMERY)');
	jake.logger.log('MS256W (WEIERSTRASS)');
	jake.logger.log('MS256E (EDWARDS)');
	jake.logger.log('MS256M (MONTGOMERY)\n');

	jake.logger.log('Pairing-Friendly Elliptic Curves'.red);
	jake.logger.log('BN254');
	jake.logger.log('BN254CX');
	jake.logger.log('BLS383\n');

	jake.logger.log('RSA configurations'.red);
	jake.logger.log('RSA2048');
	jake.logger.log('RSA3072');
	jake.logger.log('RSA4096\n');
});

// Clean up target directory
desc('Clean up target directory'.blue);
task('clean', function () {
	jake.rmRf(targetdir);
	jake.mkdirP(targetdir);
});

var j = 0;
var looptests = function(arr,tempTarg) 
{
    testrun(tempTarg,arr[j],function()
    {
        j++;
        if(j < arr.length) // any more items in array? continue looptests
        {
            looptests(arr,tempTarg);   
        }
        if(j == arr.length) {
        	var failed = fs.readFileSync(tempTarg+testingdir+failedtestlog,'utf8');
			if (failed == null)
			{
				jake.logger.log('SUCCESS: all tests passed!');
				complete();
			}
			else
			{
				jake.fail('The following tests failed: \n'+failed,-1);
			}
        }
    }); 
}

// Run test on single build
desc('Run tests'.blue);
task('test', {async: true}, function ()
{
	var tempTarg = '';
	fs.readdir(targetdir, function(err, builds)
	{
		if (builds == null)
		{
	    	jake.logger.error('Nothing to test');
	    	fail("Abort");
	    }
	    if (builds.length != 1)
	    {
	    	jake.logger.log('Please specify wich build you want to test (jake build:choice[...])');
	    	jake.logger.log('Builds available: ');
	    	jake.logger.log(builds);
	    	complete();
	    }
	    tempTarg = targetdir+'/'+ builds[0];
	    jake.logger.log(('Start testing '+tempTarg).blue);
        jake.mkdirP(tempTarg+testingdir);
        jake.rmRf(tempTarg+testingdir+lasttestlog);
        jake.rmRf(tempTarg+testingdir+failedtestlog);
        fs.readdir(tempTarg+targettestdir, function(errors, tests)
        {
        	if (tests == null)
        	{
        		jake.logger.log('Nothing to test');
        		complete();
        	}
			looptests(tests,tempTarg);
        });
	});
});

// Run tests when multiple build
namespace('test', function ()
{
	desc('Test specific build. For example jake test:choice[BN254CX,RSA2048]'.blue);
	task('choice', {async: true}, function ()
	{
		var tempTarg = targetdir+'/build';
		for (var i=0; i<arguments.length; i++)
			tempTarg += '_'+arguments[i];
		fs.readdir(targetdir, function(err, builds)
		{
			//if (tempTarg.replace(targetdir+'/','') in builds)
			if (builds.indexOf(tempTarg.replace(targetdir+'/',''))>-1)
			{
				jake.logger.log(('Start testing '+tempTarg).blue);
		        jake.mkdirP(tempTarg+testingdir);
		        jake.rmRf(tempTarg+testingdir+lasttestlog);
		        jake.rmRf(tempTarg+testingdir+failedtestlog);
		        fs.readdir(tempTarg+targettestdir, function(errors, tests)
		        {
		        	if (tests == null)
		        	{
		        		jake.logger.error('Nothing to test');
		        		complete();
		        	}
					looptests(tests,tempTarg);
		        });
			}
			else
			{
				jake.logger.error('ERROR: Invalid '+tempTarg.replace(targetdir+'/','')+'. Builds available to test:');
				jake.logger.log(builds);
				complete();
			}
		});
	});
});