var fs = require('fs');

module.exports = function(config) {

  // Use ENV vars on Travis and sauce.json locally to get credentials
  if (!process.env.SAUCE_USERNAME) {
    if (!fs.existsSync('sauce.json')) {
      console.log('Create a sauce.json with your credentials based on the sauce-sample.json file.');
      process.exit(1);
    } else {
      process.env.SAUCE_USERNAME = require('./sauce').username;
      process.env.SAUCE_ACCESS_KEY = require('./sauce').accessKey;
    }
  }

  // Browsers to run on Sauce Labs
  var customLaunchers = {
    'SL_Chrome_Win': {
      base: 'SauceLabs',
      browserName: 'chrome',
      platform: 'Windows 7'
    },
    'SL_Firefox_linux': {
      base: 'SauceLabs',
      browserName: 'firefox',
      platform: 'Linux'
    },
    'SL_Chrome_Linux': {
      base: 'SauceLabs',
      browserName: 'chrome',
      platform: 'Linux'
    },
    'SL_IOS_Safari': {
      base: 'SauceLabs',
      browserName: 'iphone',
      version: '8.1'
    },
    'SL_IE': {
      base: 'SauceLabs',
      browserName: 'internet explorer',
      version: '11',
      platform: 'Windows 8.1'
    }
  };

  config.set({

    // base path that will be used to resolve all patterns (eg. files, exclude)
    basePath: '',


    // frameworks to use
    // available frameworks: https://npmjs.org/browse/keyword/karma-adapter
    frameworks: ['jasmine'],


    // list of files / patterns to load in the browser
    files: [
      'src/*.js',
      'test/*.js'
    ],


    // test results reporter to use
    // possible values: 'dots', 'progress'
    // available reporters: https://npmjs.org/browse/keyword/karma-reporter
    reporters: ['dots', 'saucelabs'],


    // web server port
    port: 9876,

    colors: true,

    // level of logging
    // possible values: config.LOG_DISABLE || config.LOG_ERROR || config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG
    logLevel: config.LOG_WARN,

    sauceLabs: {
      testName: 'SimpleCrypto'
    },
    captureTimeout: 220000,
    customLaunchers: customLaunchers,

    // start these browsers
    // available browser launchers: https://npmjs.org/browse/keyword/karma-launcher
    browsers: Object.keys(customLaunchers),
    singleRun: true
  });
};
