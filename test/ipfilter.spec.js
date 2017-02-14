/* global describe, it, beforeEach */

'use strict';

var ipfilter = require('../index').IpFilter;
var IpDeniedError = require('../index').IpDeniedError;
var assert = require('assert');

describe('enforcing IP address blacklist restrictions', function () {

  beforeEach(function () {
    this.ipfilter = ipfilter(['127.0.0.1'], { log: false, allowedHeaders: ['x-forwarded-for'] });
    this.req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    };
  });

  it('should allow all non-blacklisted ips', function (done) {
    this.req.connection.remoteAddress = '127.0.0.2';
    this.ipfilter(this.req, {}, function () {
      done();
    });
  });

  it('should allow all non-blacklisted IPv6 ips', function (done) {
    this.req.connection.remoteAddress = '::1';
    this.ipfilter(this.req, {}, function () {
      done();
    });
  });

  it('should allow all non-blacklisted IPv4 ips through the IPv6 standard', function (done) {
    this.req.connection.remoteAddress = '::ffff:127.0.0.2';
    this.ipfilter(this.req, {}, function () {
      done();
    });
  });

  it('should allow all non-blacklisted forwarded ips', function (done) {
    this.req.headers['x-forwarded-for'] = '127.0.0.2';
    this.ipfilter(this.req, {}, function () {
      done();
    });
  });

  it('should deny all blacklisted ips', function (done) {
    this.req.connection.remoteAddress = '127.0.0.1';
    checkError(this.ipfilter, this.req, done);
  });

  it('should deny an IPv4 ip transmitted as IPv6', function(done){
    this.req.connection.remoteAddress = '::ffff:127.0.0.1';
    checkError(this.ipfilter, this.req, done);
  });

  it('should deny all blacklisted forwarded ips', function (done) {
    this.req.headers['x-forwarded-for'] = '127.0.0.1';
    checkError(this.ipfilter, this.req, done);
  });
});

describe('enforcing IP address whitelist restrictions', function () {

  beforeEach(function () {
    this.ipfilter = ipfilter(['127.0.0.1'], { log: false, mode: 'allow', allowedHeaders: ['x-forwarded-for'] });
    this.req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    };
  });

  it('should allow whitelisted ips', function (done) {
    this.req.connection.remoteAddress = '127.0.0.1';
    this.ipfilter(this.req, {}, function () {
      done();
    });
  });

  it('should allow whitelisted forwarded ips', function (done) {
    this.req.headers['x-forwarded-for'] = '127.0.0.1';
    this.ipfilter(this.req, {}, function () {
      done();
    });
  });

  it('should allow whitelisted port ips', function (done) {
    this.req.connection.remoteAddress = '127.0.0.1:84849';
    this.ipfilter(this.req, {}, function () {
      done();
    });
  });

  it('should deny all non-whitelisted ips', function (done) {
    this.req.connection.remoteAddress = '127.0.0.2';
    checkError(this.ipfilter, this.req, done);
  });

  it('should deny all non-whitelisted forwarded ips', function (done) {
    this.req.headers['x-forwarded-for'] = '127.0.0.2';
    checkError(this.ipfilter, this.req, done);
  });
});

describe('using cidr block', function () {
  describe('enforcing whitelist restrictions', function () {
    beforeEach(function () {
      // Ip range: 127.0.0.1 - 127.0.0.14
      this.ipfilter = ipfilter(['127.0.0.1/28'], { log: false, mode: 'allow', allowedHeaders: ['x-forwarded-for'] });
      this.req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      };
    });

    it('should allow whitelisted ips', function (done) {
      this.req.connection.remoteAddress = '127.0.0.1';
      this.ipfilter(this.req, {}, function () {
        done();
      });
    });

    it('should allow whitelisted forwarded ips', function (done) {
      this.req.headers['x-forwarded-for'] = '127.0.0.1';
      this.ipfilter(this.req, {}, function () {
        done();
      });
    });

    it('should deny all non-whitelisted ips', function (done) {
      this.req.connection.remoteAddress = '127.0.0.17';
      checkError(this.ipfilter, this.req, done);
    });

    it('should deny all non-whitelisted forwarded ips', function (done) {
      this.req.headers['x-forwarded-for'] = '127.0.0.17';
      checkError(this.ipfilter, this.req, done);
    });
  });

  describe('enforcing IP address blacklist restrictions', function () {

    beforeEach(function () {
      this.ipfilter = ipfilter(['127.0.0.1/28'], { log: false, allowedHeaders: ['x-forwarded-for'] });
      this.req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      };
    });

    it('should allow all non-blacklisted ips', function (done) {
      this.req.connection.remoteAddress = '127.0.0.17';
      this.ipfilter(this.req, {}, function () {
        done();
      });
    });

    it('should allow all non-blacklisted forwarded ips', function (done) {
      this.req.headers['x-forwarded-for'] = '127.0.0.17';
      this.ipfilter(this.req, {}, function () {
        done();
      });
    });

    it('should deny all blacklisted ips', function (done) {
      this.req.connection.remoteAddress = '127.0.0.1';
      checkError(this.ipfilter, this.req, done);
    });

    it('should deny all blacklisted forwarded ips', function (done) {
      this.req.headers['x-forwarded-for'] = '127.0.0.1';
      checkError(this.ipfilter, this.req, done);
    });
  });

  describe('enforcing private ip restrictions', function () {
    beforeEach(function () {
      this.ipfilter = ipfilter(['127.0.0.1/28'], { log: false, allowPrivateIPs: true });
      this.req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      };
    });

    it('should allow all private ips', function (done) {
      this.req.connection.remoteAddress = '10.0.0.0';
      this.ipfilter(this.req, {}, function () {
        done();
      });
    });
  });
});

describe('using ranges', function () {
  describe('enforcing whitelist restrictions', function () {
    beforeEach(function () {
      // Ip range: 127.0.0.1 - 127.0.0.14
      this.ipfilter = ipfilter([['127.0.0.1', '127.0.0.3']], { log: false, mode: 'allow', allowedHeaders: ['x-forwarded-for'] });
      this.req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      };
    });

    it('should allow whitelisted ips', function (done) {
      this.req.connection.remoteAddress = '127.0.0.1';
      this.ipfilter(this.req, {}, function () {
        done();
      });
    });

    it('should allow whitelisted ips with port numbers', function (done) {
      this.req.connection.remoteAddress = '127.0.0.1:93923';
      this.ipfilter(this.req, {}, function () {
        done();
      });
    });

    it('should allow whitelisted forwarded ips', function (done) {
      this.req.headers['x-forwarded-for'] = '127.0.0.1';
      this.ipfilter(this.req, {}, function () {
        done();
      });
    });

    it('should deny all non-whitelisted ips', function (done) {
      this.req.connection.remoteAddress = '127.0.0.17';
      checkError(this.ipfilter, this.req, done);
    });

    it('should deny all non-whitelisted forwarded ips', function (done) {
      this.req.headers['x-forwarded-for'] = '127.0.0.17';
      checkError(this.ipfilter, this.req, done);
    });
  });

  describe('enforcing ip restrictions with only one ip in the range', function () {
    beforeEach(function () {
      // Ip range: 127.0.0.1 - 127.0.0.14
      this.ipfilter = ipfilter([['127.0.0.1']], { log: false, mode: 'allow' });
      this.req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      };
    });

    it('should allow whitelisted ips', function (done) {
      this.req.connection.remoteAddress = '127.0.0.1';
      this.ipfilter(this.req, {}, function () {
        done();
      });
    });

    it('should deny all non-whitelisted ips', function (done) {
      this.req.connection.remoteAddress = '127.0.0.17';
      checkError(this.ipfilter, this.req, done);
    });
  });

  describe('enforcing IP address blacklist restrictions', function () {

    beforeEach(function () {
      this.ipfilter = ipfilter([['127.0.0.1', '127.0.0.3']], { log: false, allowedHeaders: ['x-forwarded-for'] });
      this.req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      };
    });

    it('should allow all non-blacklisted ips', function (done) {
      this.req.connection.remoteAddress = '127.0.0.17';
      this.ipfilter(this.req, {}, function () {
        done();
      });
    });

    it('should allow all non-blacklisted forwarded ips', function (done) {
      this.req.headers['x-forwarded-for'] = '127.0.0.17';
      this.ipfilter(this.req, {}, function () {
        done();
      });
    });

    it('should deny all blacklisted ips', function (done) {
      this.req.connection.remoteAddress = '127.0.0.1';
      checkError(this.ipfilter, this.req, done);
    });

    it('should deny all blacklisted forwarded ips', function (done) {
      this.req.headers['x-forwarded-for'] = '127.0.0.1';
      checkError(this.ipfilter, this.req, done);
    });
  });

  describe('enforcing private ip restrictions', function () {
    beforeEach(function () {
      this.ipfilter = ipfilter([['127.0.0.1', '127.0.0.3']], { log: false, allowPrivateIPs: true });
      this.req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      };
    });

    it('should allow all private ips', function (done) {
      this.req.connection.remoteAddress = '10.0.0.0';
      this.ipfilter(this.req, {}, function () {
        done();
      });
    });
  });
});

describe('disabling forward headers', function () {

  beforeEach(function () {
    this.ipfilter = ipfilter(['127.0.0.1'], { log: false, allowedHeaders: [] });
    this.req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    };
  });

  it('should deny all non-blacklisted forwarded ips', function (done) {
    this.req.connection.remoteAddress = '127.0.0.1';
    this.req.headers['x-forwarded-for'] = '127.0.0.2';
    checkError(this.ipfilter, this.req, done);
  });
});

describe('enabling cloudflare headers', function () {

  beforeEach(function () {
    this.ipfilter = ipfilter(['127.0.0.1'], { log: false, allowedHeaders: ['cf-connecting-ip'] });
    this.req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    };
  });

  it('should allow all non-blacklisted forwarded ips', function (done) {
    this.req.connection.remoteAddress = '127.0.0.1';
    this.req.headers['cf-connecting-ip'] = '127.0.0.2';
    this.ipfilter(this.req, {}, function () {
      done();
    });
  });
});

describe('disabling cloudflare headers', function () {

  beforeEach(function () {
    this.ipfilter = ipfilter(['127.0.0.1'], { log: false, allowedHeaders: [] });
    this.req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    };
  });

  it('should deny all non-blacklisted forwarded ips', function (done) {
    this.req.connection.remoteAddress = '127.0.0.1';
    this.req.headers['cf-connecting-ip'] = '127.0.0.2';
    checkError(this.ipfilter, this.req, done);
  });
});

describe('excluding certain routes from filtering', function () {
  beforeEach(function () {
    this.ipfilter = ipfilter(['127.0.0.1'], { log: false, mode: 'allow', excluding: ['/foo.*'] });
    this.req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      },
      url: '/foo?bar=123'
    };
  });

  it('should allow requests to excluded paths', function (done) {
    this.req.connection.remoteAddress = '190.0.0.0';
    this.ipfilter(this.req, {}, function () {
      done();
    });
  });

  it('should deny requests to other paths', function (done) {
    this.req.url = '/bar';
    this.req.connection.remoteAddress = '190.0.0.0';
    checkError(this.ipfilter, this.req, done);
  });
});

describe('no ip address can be found', function () {
  beforeEach(function () {
    this.ipfilter = ipfilter(['127.0.0.1'], { log: false, mode: 'allow', excluding: ['/foo.*'] });
    this.req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    };
  });

  it('should deny requests', function (done) {
    this.req.url = '/bar';
    this.req.connection.remoteAddress = '';
    checkError(this.ipfilter, this.req, done);
  });
});

describe('external logger function', function () {

  it('should log to a passed logger exactly one message', function (done) {
    var messages = [];
    var logF = function logFF(message) {
      messages.push(message);
    };
    this.ipfilter = ipfilter(['127.0.0.1'], { log: true, logF: logF });
    this.req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: '127.0.0.1'
      }
    };

    var next = function(){
      assert.equal(1, messages.length);
      done();
    };

    this.ipfilter(this.req, function(){}, next);
  });

  it('should log to a passed logger the correct message', function (done) {
    var messages = [];
    var logF = function logFF(message) {
      messages.push(message);
    };
    this.ipfilter = ipfilter(['127.0.0.1'], { log: true, logF: logF });
    this.req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    };

    this.req.connection.remoteAddress = '127.0.0.1';

    var next = function(){
      assert.equal('Access denied to IP address: 127.0.0.1', messages[0]);
      done();
    };

    this.ipfilter(this.req, function(){}, next);

  });
});

describe('LogLevel function', function () {


  it('should log deny if log level is set to default', function (done) {
    var messages = [];
    var logF = function logFF(message) {
      messages.push(message);
    };
    this.ipfilter = ipfilter(['127.0.0.1'], { log: true, logF: logF });
    this.req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    };

    this.req.connection.remoteAddress = '127.0.0.1';

    var next = function(){
      assert.equal('Access denied to IP address: 127.0.0.1', messages[0]);
      done();
    };

    this.ipfilter(this.req, function(){}, next);
  });

  it('should log allow if log level is set to default', function (done) {
    var messages = [];
    var logF = function logFF(message) {
      messages.push(message);
    };
    this.ipfilter = ipfilter(['127.0.0.1'], { log: true, logF: logF });
    this.req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    };

    this.req.connection.remoteAddress = '127.0.0.2';

    var next = function(){
      assert.equal('Access granted to IP address: 127.0.0.2', messages[0]);
      done();
    };

    this.ipfilter(this.req, function(){}, next);
  });

  it('should log deny if log level is set to all', function (done) {
    var messages = [];
    var logF = function logFF(message) {
      messages.push(message);
    };
    this.ipfilter = ipfilter(['127.0.0.1'], { log: true, logF: logF, logLevel: 'all' });
    this.req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    };

    this.req.connection.remoteAddress = '127.0.0.1';

    var next = function(){
      assert.equal('Access denied to IP address: 127.0.0.1', messages[0]);
      done();
    };

    this.ipfilter(this.req, function(){}, next);
  });

  it('should log allow if log level is set to all', function (done) {
    var messages = [];
    var logF = function logFF(message) {
      messages.push(message);
    };
    this.ipfilter = ipfilter(['127.0.0.1'], { log: true, logF: logF, logLevel: 'all' });
    this.req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    };

    this.req.connection.remoteAddress = '127.0.0.2';

    var next = function(){
      assert.equal('Access granted to IP address: 127.0.0.2', messages[0]);
      done();
    };

    this.ipfilter(this.req, function(){}, next);
  });

  it('should log allow if log level is set to allow', function (done) {
    var messages = [];
    var logF = function logFF(message) {
      messages.push(message);
    };
    this.ipfilter = ipfilter(['127.0.0.1'], { log: true, logF: logF, logLevel: 'allow' });
    this.req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    };

    this.req.connection.remoteAddress = '127.0.0.2';

    var next = function(){
      assert.equal('Access granted to IP address: 127.0.0.2', messages[0]);
      done();
    };

    this.ipfilter(this.req, function(){}, next);
  });


  it('should not log deny if log level is set to allow', function (done) {
    var messages = [];
    var logF = function logFF(message) {
      messages.push(message);
    };
    this.ipfilter = ipfilter(['127.0.0.1'], { log: true, logF: logF, logLevel: 'allow' });
    this.req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    };

    this.req.connection.remoteAddress = '127.0.0.1';

    var next = function(){
      assert.equal(0, messages.length);
      done();
    };

    this.ipfilter(this.req, function(){}, next);
  });

  it('should not log allow if log level is set to deny', function (done) {
    var messages = [];
    var logF = function logFF(message) {
      messages.push(message);
    };
    this.ipfilter = ipfilter(['127.0.0.1'], { log: true, logF: logF, logLevel: 'deny' });
    this.req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    };

    this.req.connection.remoteAddress = '127.0.0.2';

    var next = function(){
      assert.equal(0, messages.length, messages[0]);
      done();
    };

    this.ipfilter(this.req, function(){}, next);
  });

  it('should not log allow if log level is set to deny and a exclude path is set', function (done) {
    var messages = [];
    var logF = function logFF(message) {
      console.log(message,'it happend!');
      messages.push(message);
    };
    this.ipfilter = ipfilter(['127.0.0.1'], { log: true, logF: logF, logLevel: 'deny', excluding: [ '/health' ]});
    this.req = {
      url: '/health/foo/bar',
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    };

    this.req.connection.remoteAddress = '127.0.0.1';

    var next = function(){
      assert.equal(0, messages.length, messages[0]);
      done();
    };

    this.ipfilter(this.req, function(){}, next);
  });

  it('should log deny if log level is set to deny', function (done) {
    var messages = [];
    var logF = function logFF(message) {
      messages.push(message);
    };
    this.ipfilter = ipfilter(['127.0.0.1'], { log: true, logF: logF, logLevel: 'deny' });
    this.req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    };

    this.req.connection.remoteAddress = '127.0.0.1';

    var next = function(){
      assert.equal('Access denied to IP address: 127.0.0.1', messages[0]);
      done();
    };

    this.ipfilter(this.req, function(){}, next);
  });
});



describe('an array of cidr blocks', function () {
  describe('blacklist', function () {
    beforeEach(function () {
      this.ipfilter = ipfilter(['72.30.0.0/26', '127.0.0.1/24'], { mode: 'deny', log: false });
      this.req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      };
    });

    it('should deny all blacklisted ips', function (done) {
      this.req.connection.remoteAddress = '127.0.0.1';
      checkError(this.ipfilter, this.req, done);
    });
  });

  describe('whitelist', function () {
    beforeEach(function () {
      this.ipfilter = ipfilter(['72.30.0.0/26', '127.0.0.1/24'], { mode: 'allow', log: false });
      this.req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      };
    });

    it('should allow all whitelisted ips', function (done) {
      this.req.connection.remoteAddress = '127.0.0.1';
      this.ipfilter(this.req, {}, function () {
        done();
      });
    });
  });
});

describe('mixing different types of filters', function () {
  describe('with a whitelist', function () {
    beforeEach(function () {
      this.ipfilter = ipfilter(['127.0.0.1', '192.168.1.3/28', ['127.0.0.3', '127.0.0.35']], { cidr: true, mode: 'allow', log: false });
      this.req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      };
    });

    it('should allow explicit ips', function (done) {
      this.req.connection.remoteAddress = '127.0.0.1';
      this.ipfilter(this.req, {}, function () {
        done();
      });
    });

    it('should allow ips in a cidr block', function (done) {
      this.req.connection.remoteAddress = '192.168.1.1';
      this.ipfilter(this.req, {}, function () {
        done();
      });
    });

    it('should allow ips in a range', function (done) {
      this.req.connection.remoteAddress = '127.0.0.20';
      this.ipfilter(this.req, {}, function () {
        done();
      });
    });
  });

  describe('with a blacklist', function () {
    beforeEach(function () {
      this.ipfilter = ipfilter(['127.0.0.1', '192.168.1.3/28', ['127.0.0.3', '127.0.0.35']], { mode: 'deny', log: false });
      this.req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      };
    });

    it('should deny explicit ips', function (done) {
      this.req.connection.remoteAddress = '127.0.0.1';
      checkError(this.ipfilter, this.req, done);
    });

    it('should deny ips in a cidr block', function (done) {
      this.req.connection.remoteAddress = '192.168.1.15';
      checkError(this.ipfilter, this.req, done);
    });

    it('should deny ips in a range', function (done) {
      this.req.connection.remoteAddress = '127.0.0.15';
      checkError(this.ipfilter, this.req, done);
    });
  });
});

//codio Tests
describe('enforcing codio based client IP address', function () {
  describe('blacklist restrictions', function () {
    beforeEach(function () {
      this.ipfilter = ipfilter(['127.0.0.1'], { log: false, allowedHeaders: ['x-real-ip'] });
      this.req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      };
    });

    it('should allow all non-blacklisted forwarded ips', function (done) {
      this.req.headers['x-real-ip'] = '127.0.0.2';
      this.ipfilter(this.req, {}, function () {
        done();
      });
    });

    it('should deny all blacklisted forwarded ips', function (done) {
      this.req.headers['x-real-ip'] = '127.0.0.1';
      checkError(this.ipfilter, this.req, done);
    });
  });

  describe('whitelist restrictions', function () {
    beforeEach(function () {
      this.ipfilter = ipfilter(['127.0.0.1'], { log: false, mode: 'allow', allowedHeaders: ['x-real-ip'] });
      this.req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      };
    });

    it('should allow whitelisted forwarded ips', function (done) {
      this.req.headers['x-real-ip'] = '127.0.0.1';
      this.ipfilter(this.req, {}, function () {
        done();
      });
    });
    it('should deny all non-whitelisted forwarded ips', function (done) {
      this.req.headers['x-real-ip'] = '127.0.0.2';
      checkError(this.ipfilter, this.req, done);
    });
  });

  describe('while disabled', function () {
    beforeEach(function () {
      this.ipfilter = ipfilter(['127.0.0.1'], { log: false, mode: 'allow', allowedHeaders: ['x-real-ip'] });
      this.req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      };
    });

    it('should allow all whitelisted forwarded ips', function (done) {
      this.req.headers['x-real-ip'] = '127.0.0.2';
      this.req.connection.remoteAddress = '127.0.0.1';
      this.ipfilter(this.req, {}, function () {
        done();
      });
    });
  });
});

describe('mixing different types of filters with IPv4 and IPv6', function () {

  var ips = ['127.0.0.1', '192.168.1.3/28', '2001:4860:8006::62', '2001:4860:8007::62/64', ['127.0.0.3', '127.0.0.35']];

  describe('with a whitelist', function () {

    beforeEach(function () {
      this.ipfilter = ipfilter(ips, { cidr: true, mode: 'allow', log: false });
      this.req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      };
    });

    it('should allow explicit IPv4 ips', function (done) {
      this.req.connection.remoteAddress = '127.0.0.1';
      this.ipfilter(this.req, {}, function () {
        done();
      });
    });

    it('should allow IPv4 ips in a cidr block', function (done) {
      this.req.connection.remoteAddress = '192.168.1.1';
      this.ipfilter(this.req, {}, function () {
        done();
      });
    });

    it('should allow IPv4 ips in a range', function (done) {
      this.req.connection.remoteAddress = '127.0.0.20';
      this.ipfilter(this.req, {}, function () {
        done();
      });
    });

    it('should allow explicit IPv6 ips', function (done) {
      this.req.connection.remoteAddress = '2001:4860:8006::62';
      this.ipfilter(this.req, {}, function () {
        done();
      });
    });

    it('should allow IPv6 ips in a cidr block', function (done) {
      this.req.connection.remoteAddress = '2001:4860:8007:0::62';
      this.ipfilter(this.req, {}, function () {
        done();
      });
    });
  });

  describe('with a blacklist', function () {
    beforeEach(function () {
      this.ipfilter = ipfilter(ips, { mode: 'deny', log: false });
      this.req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      };
    });

    it('should deny explicit ips', function (done) {
      this.req.connection.remoteAddress = '127.0.0.1';
      checkError(this.ipfilter, this.req, done);
    });

    it('should deny ips in a cidr block', function (done) {
      this.req.connection.remoteAddress = '192.168.1.15';
      checkError(this.ipfilter, this.req, done);
    });

    it('should deny explicit IPv6 ips', function (done) {
      this.req.connection.remoteAddress = '2001:4860:8006::62';
      checkError(this.ipfilter, this.req, done);
    });

    it('should deny IPv6 ips in a cidr block', function (done) {
      this.req.connection.remoteAddress = '2001:4860:8007:0::62';
      checkError(this.ipfilter, this.req, done);
    });

    it('should deny ips in a range', function (done) {
      this.req.connection.remoteAddress = '127.0.0.15';
      checkError(this.ipfilter, this.req, done);
    });
  });
});


describe('using a custom ip detection function', function(){
  beforeEach(function () {
    function detectIp(req){
      var ipAddress;

      ipAddress = req.connection.remoteAddress.replace(/\//g, '.');

      return ipAddress;
    }

    this.ipfilter = ipfilter(['127.0.0.1'], { detectIp: detectIp, log: false, allowedHeaders: ['x-forwarded-for'] });
    this.req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    };
  });

  it('should find the ip correctly', function(done){
    this.req.connection.remoteAddress = '127/0/0/1';
    checkError(this.ipfilter, this.req, done);
  });
});

function checkError(ipfilter, req, done){
  var next = function next(err) {
    assert (err instanceof IpDeniedError);
    done();
  };

  ipfilter(req, function(){}, next);
}
//# sourceMappingURL=ipfilter.spec.js.map
