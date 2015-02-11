/*!
 * Express - IP Filter
 * Copyright(c) 2014 Bradley and Montgomery Inc.
 * MIT Licensed
 */

'use strict';

/**
 * Module dependencies.
 */
var _ = require('lodash'),
iputil = require('ip'),
Netmask = require('netmask').Netmask;

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
 *  - `allowPrivateIPs` whether to grant access to any IP using the private IP address space unless explicitly denied. Defaults to false.
 *  - 'cidr' whether ips are ips with a submnet mask.  Defaults to 'false'.
 *  - 'ranges' whether ranges are supplied as ips
 *  - 'excluding' routes that should be excluded from ip filtering
 *
 * @param [Array] IP addresses
 * @param {Object} options
 * @api public
 */
module.exports = function ipfilter(ips, opts) {
    ips = ips || false;

    var logger = function(message){ console.log(message);};
    var settings = _.defaults( opts || {}, {
        mode: 'deny',
        log: true,
        logF: logger,
        errorCode: 401,
        errorMessage: 'Unauthorized',
        allowPrivateIPs: false,
        excluding: []
    });

    var getClientIp = function(req) {
        var ipAddress;

        var forwardedIpsStr = req.headers['x-forwarded-for'];
        //Allow getting cloudflare connecting client IP
        var cloudFlareConnectingIp=req.headers['cf-connecting-ip'];

        if (forwardedIpsStr) {
            var forwardedIps = forwardedIpsStr.split(',');
            ipAddress = forwardedIps[0];
        }

        if (!ipAddress) {
            ipAddress = req.connection.remoteAddress;
        }
        if(cloudFlareConnectingIp !== undefined){
            ipAddress=cloudFlareConnectingIp;
        }

        if(!ipAddress){
            return '';
        }

        if(ipAddress.indexOf(':') !== -1){
            ipAddress = ipAddress.split(':')[0];
        }

        return ipAddress;
    };

    var matchClientIp = function(ip){
        var mode = settings.mode.toLowerCase();

        var result = _.invoke(ips,testIp,ip,mode);

        if(mode === 'allow'){
            return _.some(result);
        }else{
            return _.every(result);
        }
    };

    var testIp = function(ip,mode){
        var constraint = this;

        // Check if it is an array or a string
        if(typeof constraint === 'string'){
            var cidrRegex = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$/;
            if(cidrRegex.test(constraint)){
                return testCidrBlock(ip,constraint,mode);
            }else{
                return testExplicitIp(ip,constraint,mode);
            }
        }

        if(typeof constraint === 'object'){
            return testRange(ip,constraint,mode);
        }
    };

    var testExplicitIp = function(ip,constraint,mode){
        if(ip === constraint){
            return mode === 'allow';
        }else{
            return mode === 'deny';
        }
    };

    var testCidrBlock = function(ip,constraint,mode){
        var block = new Netmask(constraint);

        if(block.contains(ip)){
            return mode === 'allow';
        }else{
            return mode === 'deny';
        }
    };

    var testRange = function(ip,constraint,mode){
        var filteredSet = _.filter(ips,function(constraint){
            if(constraint.length > 1){
                var startIp = iputil.toLong(constraint[0]);
                var endIp = iputil.toLong(constraint[1]);
                var longIp = iputil.toLong(ip);
                return  longIp >= startIp && longIp <= endIp;
            }else{
                return ip === constraint[0];
            }
        });

        if(filteredSet.length > 0){
            return mode === 'allow';
        }else{
            return mode === 'deny';
        }
    };

    return function(req, res, next) {
        if(settings.excluding.length > 0){
            var results = _.filter(settings.excluding,function(exclude){
                var regex = new RegExp(exclude);
                return regex.test(req.url);
            });

            if(results.length > 0){
                if(settings.log){
                    console.log('Access granted for excluded path: ' + results[0]);
                }
                return next();
            }
        }

        var ip = getClientIp(req);
        // If no IPs were specified, skip
        // this middleware
        if(!ips || !ips.length) { return next(); }

        if(matchClientIp(ip,req)) {
            // Grant access
            if(settings.log) {
                settings.logF('Access granted to IP address: ' + ip);
            }

            return next();
        }

        // Deny access
        if(settings.log) {
            settings.logF('Access denied to IP address: ' + ip);
        }

        res.statusCode = settings.errorCode;
        return res.end(settings.errorMessage);
    };
};
