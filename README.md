express-ipfilter: A light-weight IP address based filtering system
=================================================================================

This package provides easy IP based access control. This can be achieved either by blacklisting certain IPs and whitelisting all others, or whitelisting certain IPs and blacklisting all others.

[![Circle CI](https://circleci.com/gh/baminteractive/express-ipfilter/tree/master.svg?style=svg)](https://circleci.com/gh/baminteractive/express-ipfilter/tree/master)

## Version
0.2.1

## Installation

Recommended installation is with npm. To add node-ipfilter to your project, do:

    npm install express-ipfilter

## Usage with Express

> NOTE: Starting with version 0.1.0, allow forwarded IP addresses through headers (forward, Cloudflare, Codio) are disabled by **default**. You must explicitly enable them by adding them to the `allowedHeaders` list.

Blacklisting certain IP addresses, while allowing all other IPs:

```javascript
// Init dependencies
var express = require('express'),
    ipfilter = require('express-ipfilter').IpFilter;

// Blacklist the following IPs
var ips = ['127.0.0.1'];

// Create the server
app.use(ipfilter(ips));
app.listen(3000);
```

Whitelisting certain IP addresses, while denying all other IPs:

```javascript
// Init dependencies
// Init dependencies
var express = require('express'),
    ipfilter = require('express-ipfilter').IpFilter;

// Whitelist the following IPs
var ips = ['127.0.0.1'];

// Create the server
app.use(ipfilter(ips, {mode: 'allow'}));

module.exports = app;
```

Using CIDR subnet masks for ranges:

```javascript
var ips = ['127.0.0.1/24'];

// Create the server
app.use(ipfilter(ips, {mode: 'allow'}));

module.exports = app;
```

Using IP ranges:

```javascript
var ips = [['127.0.0.1','127.0.0.10']];

// Create the server
app.use(ipfilter(ips, {mode: 'allow'}));

module.exports = app;
```

> See the example app for an example of how to handle errors.

## Options

| Property      | Description   | Type  | Default|
| ------------- |-------------| -----|--------|
| mode   | whether to *deny* or *allow* to the IPs provided | string|deny|
| log   | console log actions | boolean|true|
| logLevel | level of logging (*all*,*deny*,*allow*) | string | all
| allowedHeaders | an array of strings for header names that are acceptable for retrieving an IP address | array | [] |
| excluding   | routes that should be excluded from ip filtering | array|[]|
| disableStackTrace | whether to enable or disable the error message and stack trace | boolean|false|

## Contributing

### Building from source

You can run `grunt` to build the source.  This will run `eslint` and `babel` against `src/ipfilter.js`.

There is an included `example` project that will load the package from the local build for testing.

### Running Tests

Run tests by using

`grunt test`

This will run `eslint`,`babel`, and `mocha` and output coverage data into `coverage`.  Any pull request you submit needs to be accompanied by a test.

## Changelog

0.2.1
* Add log level property.

0.2.0
* Changed how error handling works
* Removed settings for specific vendor ip addresses and added `allowedHeaders` to support those header-based IP addresses.
* You must now specifically require `IpFilter`, i.e. `var ipfilter = require('express-ipfilter').IpFilter;`
* If you want to handle errors you must require the error type as well `var IpDeniedError = require('express-ipfilter').IpDeniedError;`

0.1.1
* Added a favicon to the example to supress the 404 error looking for it.

0.1.0
* Changed default behavior of the library to disable reading forwarded IP headers. They must now be explicitly enabled.
* Using `res.send` when a failure occurs to allow for different formats of `errorMessage`

0.0.25
* Switched from netmask to range_check (uses ipaddr.js)
* Added support for IPv6 CIDR
* Fixed issue with mixed IPv4 and IPv6 rules

0.0.24
* Added lib to version control

0.0.23
* added codio x-real-ip header

0.0.22

* Added IPv6 Support
* Added build tools
* Added test coverage and reporting

0.0.20

* Added a setting to explicitly allow CloudFlare and Forwarded IPs.  By default they are set to not allow these headers.  Thanks to @longstone!

0.0.19

* Added detection for CloudFlare forwarded ips - https://github.com/baminteractive/express-ipfilter/commit/9aa43af14f5a003bad3145eef658f429808818f9 (@lafama)

0.0.18

* Fixing bug when array of CIDR blocks are used

0.0.16

* Fixing bug when no IP address can be determined

0.0.15

* Minor bug fix

0.0.14

* Adding the ability to have exclusion urls

0.0.12

* Diagnostic Options

0.0.11

* Bug Fix for port logic

0.0.10

* Added support for IPs with port numbers

0.0.9

* Fixing deploy issues

0.0.8

* Auto deploys for npm

0.0.7

* Add support ip ranges.

0.0.6

* Fixed a bug when using console output

0.0.5

* Added ability to block by subnet mask (i.e. 127.0.0.1/24)
* Added tests for cidr functionality

0.0.4

* Add tests
* Update docs
* Refactor, and restyle

0.0.1

* First revision

## Credits

BaM Interactive - [code.bamideas.com](http://code.bamideas.com)
