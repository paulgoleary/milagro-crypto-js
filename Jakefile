require('colors');

var fs = require('fs'),
    jake = require('jake');

var cwd = process.cwd(),
    srcdir = cwd + '/src',
    testdir = cwd + '/test',
    targetdir = cwd + '/target',
    testvectordir = cwd + '/testVectors',
    examplesdir = cwd + '/examples',

    builddir = targetdir + '/build';
    buildsrcdir = builddir + '/src',
    buildtestingdir = builddir + '/Testing',
    buildtestdir = builddir + '/test',
    buildexamplesdir = builddir + '/examples',
    lasttestlog = '/LastTest.txt';

jake.addListener('complete', function () {
  process.exit(0);
});

// Replace pattern in a file.
function replace(namefile,oldtext,newtext) {
    var fileContent = fs.readFileSync(namefile,'utf8');
    fileContent = fileContent.replace(oldtext,newtext);
    fs.writeFileSync(namefile, fileContent);
}

// Add exports line to file
function addExport(jsFilename, className) {
	var code = fs.readFileSync(jsFilename,'utf8')
  var exportline = 'module.exports.' + className + ' = ' + className + ';';
	if (!(code.includes(exportline))) {
		fs.appendFileSync(jsFilename, exportline + '\n');
	}
}

// run tests with mocha
function testrun(target) {
	//var cmd = 'mocha --reporter mocha-circleci-reporter '+target+targettestdir;
	var cmd = 'cd '+target+' && npm test';
	var ex = jake.createExec(cmd,{printStdout: true});
	console.log(cmd);
	ex.addListener('error', function(msg,code) {
		process.exit(code);
	});
	ex.addListener('cmdEnd',function(arg) {
		complete();
	});
	ex.run();
}

desc('Default'.blue);
task('default', function () {
  jake.logger.log('Type `jake -T` to see the list of all thew tasks.');
});




// Build with default curve BN254CX and RSA2048 
desc('Build library'.blue);
task('build', function () {
	jake.logger.log('Build library'.red);
  jake.rmRf(builddir);
	jake.mkdirP(buildsrcdir);
	jake.mkdirP(buildtestdir);
	jake.mkdirP(buildexamplesdir);
 
  jake.cpR(srcdir + '/amcl', builddir);
  fs.renameSync(builddir + '/amcl', buildsrcdir);
  jake.cpR(srcdir + '/ctx.js', buildsrcdir);
  jake.cpR(srcdir + '/curves.js', buildsrcdir);

  // concatenate all ROM_CURVE files
  var romCurveFile = buildsrcdir + '/ROM_CURVE_ZZZ.js';
  fs.readdirSync(buildsrcdir).forEach(file => {
      var path = buildsrcdir + '/' + file; 
      match = /^(ROM_CURVE.*).js$/.exec(file);
      if(match != null) {
        var curveName = match[1];
        var data = fs.readFileSync(path);
        fs.appendFileSync(romCurveFile, data);
        addExport(romCurveFile, curveName); // add export line
        fs.unlink(path);
      }
  });

  // concatenate all ROM_FIELD files
  var romFieldFile = buildsrcdir + '/ROM_FIELD_YYY.js';
  fs.readdirSync(buildsrcdir).forEach(file => {
      var path = buildsrcdir + '/' + file; 
      match = /^(ROM_FIELD.*).js$/.exec(file);
      if(match != null) {
        var fieldName = match[1];
        var data = fs.readFileSync(path);
        fs.appendFileSync(romFieldFile, data);
        addExport(romFieldFile, fieldName); // add export line
        fs.unlink(path);
      }
  });

  fs.readdirSync(buildsrcdir).forEach(file => {

      var path = buildsrcdir + '/' + file; 
      match = /^(.*_(?:WWW|XXX|YYY|ZZZ)).js$/.exec(file);
      if(match != null) {
        var className = match[1];

        addExport(path, className); // add export line
        
        replace(path, /@[^@]+@/g, 'undefined'); // replace '@var@' placeholders

        // find any references to this class in all other files
        var refRegex = new RegExp('([^A-Z\.])' + className, 'g')
        fs.readdirSync(buildsrcdir).forEach(refFile => {
          var refPath = buildsrcdir + '/' + refFile; 
          if(file != refFile) {
            // TODO dont replace within comment blocks
            replace(refPath, refRegex, '$1module.exports.ctx.' + className);
          }
        });
      }
  });

  fs.readdirSync(buildsrcdir).forEach(file => {

      var path = buildsrcdir + '/' + file; 

      // remove all the suffixes from the code
      replace(path, /_(?:WWW|XXX|YYY|ZZZ)/g, '');

      // rename the file without the suffix
      match = /^(.*)_(?:WWW|XXX|YYY|ZZZ).js$/.exec(file);
      if(match != null) {
        var className = match[1];
        fs.renameSync(path, buildsrcdir + '/' + className + '.js');
      }
  });

  fs.readdirSync(buildsrcdir).forEach(file => {
      var path = buildsrcdir + '/' + file; 
      fs.renameSync(path, buildsrcdir + '/' + file.toLowerCase());
  });

  // concatenate BIG_XXX.js and DBIG_XXX.js into BIG_XXX.js and delete DBIG_XXX.js
  var dbig = fs.readFileSync(buildsrcdir + '/dbig.js');
  fs.appendFileSync(buildsrcdir + '/big.js', dbig);
  fs.unlink(buildsrcdir + '/dbig.js');

	complete();
});

// Clean up target directory
desc('Clean up target directory'.blue);
task('clean', function () {
	jake.rmRf(targetdir);
	jake.mkdirP(targetdir);
});

// Run test on single build
desc('Run tests'.blue);
task('test', {async: true}, function ()
{
	var tempTarg = '';
	fs.readdir(targetdir, function(err, builds)
	{
		if ((builds == null) || (builds.length == 0))
		{
	    	jake.logger.error('Nothing to test');
	    	process.exit("Abort");
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
        if (fs.existsSync(tempTarg+testingdir+lasttestlog))
        	fs.unlinkSync(tempTarg+testingdir+lasttestlog);
        testrun(tempTarg);
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
				if (fs.existsSync(tempTarg+testingdir+lasttestlog))
        			fs.unlinkSync(tempTarg+testingdir+lasttestlog);
		        fs.readdir(tempTarg+targettestdir, function(errors, tests)
		        {
		        	if (tests == null)
		        	{
		        		jake.logger.error('Nothing to test');
		        		complete();
		        	}
					testrun(tempTarg);
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

// Run test on single build
desc('Build and run all tests in a docker'.blue);
task('dockerbuild', {async: true}, function ()
{
	var cmd = 'docker build --no-cache '+ cwd;
	jake.exec(cmd, {printStdout: true});
	complete();
});

// Format code using js-beautify
desc('Format code using js-beautify'.blue);
task('format', {async: true}, function ()
{
	var cmd = ['js-beautify -r '+srcdir+'/*js && js-beautify -r '+testdir+'/*js && js-beautify -r '+examplesdir+'/*js']
	jake.exec(cmd, {printStdout: true});
	complete();
});

// Format code using js-beautify
desc('Print the version of the repo'.blue);
task('version', {async: true}, function ()
{
	var cmd = ['cat VERSION']
	jake.exec(cmd, {printStdout: true});
	complete();
});
