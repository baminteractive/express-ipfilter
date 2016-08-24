/*!
 * Express - IP Filter
 * Copyright(c) 2014 Bradley and Montgomery Inc.
 * MIT Licensed
 */

'use strict';

/**
 * Module dependencies.
 */

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol ? "symbol" : typeof obj; };

var _ = require('lodash');
var iputil = require('ip');
var rangeCheck = require('range_check');

/**
 * express-ipfilter:
 *
 * IP Filtering middleware;
 *
 * Examples:
 *
 *      var ipfilter = require('ipfilter'),
 *          ips = ['127.0.0.1'];
 *
 *      app.use(ipfilter(ips));
 *
 * Options:
 *
 *  - `mode` whether to deny or grant access to the IPs provided. Defaults to 'deny'.
 *  - `log` console log actions. Defaults to true.
 *  - `errorCode` the HTTP status code to use when denying access. Defaults to 401.
 *  - `errorMessage` the error message to use when denying access. Defaults to 'Unauthorized'.
 *  - 'excluding' routes that should be excluded from ip filtering
 *
 * @param [Array] IP addresses
 * @param {Object} options
 * @api public
 */
module.exports = function ipfilter(ips, opts) {
  ips = ips || false;

  var logger = function logger(message) {
    console.log(message);
  };
  var settings = _.defaults(opts || {}, {
    mode: 'deny',
    log: true,
    logF: logger,
    redirect: null,
    errorCode: 401,
    errorMessage: 'Unauthorized',
    allowPrivateIPs: false,
    allowForward: false,
    allowCloudflare: false,
    allowCodio: false,
    excluding: []
  });

  var getClientIp = function getClientIp(req) {
    var ipAddress;

    var forwardedIpsStr = '';

    if (settings.allowForward) {
      forwardedIpsStr = req.headers['x-forwarded-for'];
    }

    //Allow getting cloudflare connecting client IP
    var cloudFlareConnectingIp = '';
    if (settings.allowCloudflare) {
      cloudFlareConnectingIp = req.headers['cf-connecting-ip'];
    }

    //Allow getting codio connecting client IP
    var codioConnectingIp = '';
    if (settings.allowCodio) {
      codioConnectingIp = req.headers['x-real-ip'];
    }

    if (forwardedIpsStr) {
      var forwardedIps = forwardedIpsStr.split(',');
      ipAddress = forwardedIps[0];
    }

    if (!ipAddress) {
      ipAddress = req.connection.remoteAddress;
    }

    if (cloudFlareConnectingIp) {
      ipAddress = cloudFlareConnectingIp;
    }

    if (codioConnectingIp) {
      ipAddress = codioConnectingIp;
    }

    if (!ipAddress) {
      return '';
    }

    if (ipAddress.indexOf(':') !== -1 && ipAddress.indexOf('::') === -1) {
      ipAddress = ipAddress.split(':')[0];
    }

    return ipAddress;
  };

  var matchClientIp = function matchClientIp(ip) {
    var mode = settings.mode.toLowerCase();

    var result = _.invoke(ips, testIp, ip, mode);

    if (mode === 'allow') {
      return _.some(result);
    } else {
      return _.every(result);
    }
  };

  var testIp = function testIp(ip, mode) {
    var constraint = this;

    // Check if it is an array or a string
    if (typeof constraint === 'string') {
      if (rangeCheck.validRange(constraint)) {
        return testCidrBlock(ip, constraint, mode);
      } else {
        return testExplicitIp(ip, constraint, mode);
      }
    }

    if ((typeof constraint === 'undefined' ? 'undefined' : _typeof(constraint)) === 'object') {
      return testRange(ip, constraint, mode);
    }
  };

  var testExplicitIp = function testExplicitIp(ip, constraint, mode) {
    if (ip === constraint) {
      return mode === 'allow';
    } else {
      return mode === 'deny';
    }
  };

  var testCidrBlock = function testCidrBlock(ip, constraint, mode) {
    if (rangeCheck.inRange(ip, constraint)) {
      return mode === 'allow';
    } else {
      return mode === 'deny';
    }
  };

  var testRange = function testRange(ip, constraint, mode) {
    var filteredSet = _.filter(ips, function (constraint) {
      if (constraint.length > 1) {
        var startIp = iputil.toLong(constraint[0]);
        var endIp = iputil.toLong(constraint[1]);
        var longIp = iputil.toLong(ip);
        return longIp >= startIp && longIp <= endIp;
      } else {
        return ip === constraint[0];
      }
    });

    if (filteredSet.length > 0) {
      return mode === 'allow';
    } else {
      return mode === 'deny';
    }
  };

  return function (req, res, next) {
    if (settings.excluding.length > 0) {
      var results = _.filter(settings.excluding, function (exclude) {
        var regex = new RegExp(exclude);
        return regex.test(req.url);
      });

      if (results.length > 0) {
        if (settings.log) {
          logger('Access granted for excluded path: ' + results[0]);
        }
        if (settings.redirect && req.accepts('html')) {
          res.statusCode = settings.errorCode;
          return res.sendFile(settings.redirect);
        }
        return next();
      }
    }

    var ip = getClientIp(req);
    // If no IPs were specified, skip
    // this middleware
    if (!ips || !ips.length) {
      return next();
    }

    if (matchClientIp(ip, req)) {
      // Grant access
      if (settings.log) {
        settings.logF('Access granted to IP address: ' + ip);
      }
      if (settings.redirect && req.accepts('html')) {
        res.statusCode = settings.errorCode;
        return res.sendFile(settings.redirect);
      }
      return next();
    }

    // Deny access
    if (settings.log) {
      settings.logF('Access denied to IP address: ' + ip);
    }
    if (settings.redirect && req.accepts('html')) {
      res.statusCode = settings.errorCode;
      return res.sendFile(settings.redirect);
    }

    res.statusCode = settings.errorCode;
    return res.send(settings.errorMessage);
  };
};
//# sourceMappingURL=ipfilter.js.map
