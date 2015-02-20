'use strict';
/* global describe, it, beforeEach */

var
ipfilter = require('./index'),
assert = require('assert');

describe('enforcing IP address blacklist restrictions', function(){

    beforeEach(function(){
        this.ipfilter = ipfilter([ '127.0.0.1' ], { log: false });
        this.req = {
            session: {},
            headers: [],
            connection: {
                remoteAddress: ''
            }
        };
    });

    it('should allow all non-blacklisted ips', function( done ){
        this.req.connection.remoteAddress = '127.0.0.2';
        this.ipfilter( this.req, {}, function(){
            done();
        });
    });

    it('should allow all non-blacklisted forwarded ips', function( done ){
        this.req.headers['x-forwarded-for'] = '127.0.0.2';
        this.ipfilter( this.req, {}, function(){
            done();
        });
    });

    it('should deny all blacklisted ips', function( done ){
        this.req.connection.remoteAddress = '127.0.0.1';
        var res = {
            end: function(){
                assert.equal( 401, res.statusCode );
                done();
            }
        };

        this.ipfilter( this.req, res, function(){});
    });

    it('should deny all blacklisted forwarded ips', function( done ){
        this.req.headers['x-forwarded-for'] = '127.0.0.1';
        var res = {
            end: function(){
                assert.equal( 401, res.statusCode );
                done();
            }
        };

        this.ipfilter( this.req, res, function(){});
    });
});

describe('enforcing IP address whitelist restrictions', function(){

    beforeEach(function(){
        this.ipfilter = ipfilter([ '127.0.0.1' ], { log: false, mode: 'allow' });
        this.req = {
            session: {},
            headers: [],
            connection: {
                remoteAddress: ''
            }
        };
    });

    it('should allow whitelisted ips', function( done ){
        this.req.connection.remoteAddress = '127.0.0.1';
        this.ipfilter( this.req, {}, function(){
            done();
        });
    });

    it('should allow whitelisted forwarded ips', function( done ){
        this.req.headers['x-forwarded-for'] = '127.0.0.1';
        this.ipfilter( this.req, {}, function(){
            done();
        });
    });

    it('should allow whitelisted port ips',function(done){
        this.req.connection.remoteAddress = '127.0.0.1:84849';
        this.ipfilter( this.req, {}, function(){
            done();
        });
    });

    it('should deny all non-whitelisted ips', function( done ){
        this.req.connection.remoteAddress = '127.0.0.2';
        var res = {
            end: function(){
                assert.equal( 401, res.statusCode );
                done();
            }
        };

        this.ipfilter( this.req, res, function(){});
    });

    it('should deny all non-whitelisted forwarded ips', function( done ){
        this.req.headers['x-forwarded-for'] = '127.0.0.2';
        var res = {
            end: function(){
                assert.equal( 401, res.statusCode );
                done();
            }
        };

        this.ipfilter( this.req, res, function(){});
    });
});

describe('using cidr block',function(){
    describe('enforcing whitelist restrictions',function(){
        beforeEach(function(){
            // Ip range: 127.0.0.1 - 127.0.0.14
            this.ipfilter = ipfilter([ '127.0.0.1/28' ], { log: false, mode: 'allow' });
            this.req = {
                session: {},
                headers: [],
                connection: {
                    remoteAddress: ''
                }
            };
        });

        it('should allow whitelisted ips', function( done ){
            this.req.connection.remoteAddress = '127.0.0.1';
            this.ipfilter( this.req, {}, function(){
                done();
            });
        });

        it('should allow whitelisted forwarded ips', function( done ){
            this.req.headers['x-forwarded-for'] = '127.0.0.1';
            this.ipfilter( this.req, {}, function(){
                done();
            });
        });

        it('should deny all non-whitelisted ips', function( done ){
            this.req.connection.remoteAddress = '127.0.0.17';
            var res = {
                end: function(){
                    assert.equal( 401, res.statusCode );
                    done();
                }
            };

            this.ipfilter( this.req, res, function(){});
        });

        it('should deny all non-whitelisted forwarded ips', function( done ){
            this.req.headers['x-forwarded-for'] = '127.0.0.17';
            var res = {
                end: function(){
                    assert.equal( 401, res.statusCode );
                    done();
                }
            };

            this.ipfilter( this.req, res, function(){});
        });
    });

    describe('enforcing IP address blacklist restrictions', function(){

        beforeEach(function(){
            this.ipfilter = ipfilter([ '127.0.0.1/28' ], { log: false });
            this.req = {
                session: {},
                headers: [],
                connection: {
                    remoteAddress: ''
                }
            };
        });

        it('should allow all non-blacklisted ips', function( done ){
            this.req.connection.remoteAddress = '127.0.0.17';
            this.ipfilter( this.req, {}, function(){
                done();
            });
        });

        it('should allow all non-blacklisted forwarded ips', function( done ){
            this.req.headers['x-forwarded-for'] = '127.0.0.17';
            this.ipfilter( this.req, {}, function(){
                done();
            });
        });

        it('should deny all blacklisted ips', function( done ){
            this.req.connection.remoteAddress = '127.0.0.1';
            var res = {
                end: function(){
                    assert.equal( 401, res.statusCode );
                    done();
                }
            };

            this.ipfilter( this.req, res, function(){});
        });

        it('should deny all blacklisted forwarded ips', function( done ){
            this.req.headers['x-forwarded-for'] = '127.0.0.1';
            var res = {
                end: function(){
                    assert.equal( 401, res.statusCode );
                    done();
                }
            };

            this.ipfilter( this.req, res, function(){});
        });
    });

    describe('enforcing private ip restrictions',function(){
        beforeEach(function(){
            this.ipfilter = ipfilter([ '127.0.0.1/28' ], { log: false, allowPrivateIPs: true });
            this.req = {
                session: {},
                headers: [],
                connection: {
                    remoteAddress: ''
                }
            };
        });

        it('should allow all private ips', function( done ){
            this.req.connection.remoteAddress = '10.0.0.0';
            this.ipfilter( this.req, {}, function(){
                done();
            });
        });
    });
});

describe('using ranges',function(){
    describe('enforcing whitelist restrictions',function(){
        beforeEach(function(){
            // Ip range: 127.0.0.1 - 127.0.0.14
            this.ipfilter = ipfilter([ ['127.0.0.1','127.0.0.3'] ], { log: false, mode: 'allow' });
            this.req = {
                session: {},
                headers: [],
                connection: {
                    remoteAddress: ''
                }
            };
        });

        it('should allow whitelisted ips', function( done ){
            this.req.connection.remoteAddress = '127.0.0.1';
            this.ipfilter( this.req, {}, function(){
                done();
            });
        });

        it('should allow whitelisted ips with port numbers', function( done ){
            this.req.connection.remoteAddress = '127.0.0.1:93923';
            this.ipfilter( this.req, {}, function(){
                done();
            });
        });

        it('should allow whitelisted forwarded ips', function( done ){
            this.req.headers['x-forwarded-for'] = '127.0.0.1';
            this.ipfilter( this.req, {}, function(){
                done();
            });
        });

        it('should deny all non-whitelisted ips', function( done ){
            this.req.connection.remoteAddress = '127.0.0.17';
            var res = {
                end: function(){
                    assert.equal( 401, res.statusCode );
                    done();
                }
            };

            this.ipfilter( this.req, res, function(){});
        });

        it('should deny all non-whitelisted forwarded ips', function( done ){
            this.req.headers['x-forwarded-for'] = '127.0.0.17';
            var res = {
                end: function(){
                    assert.equal( 401, res.statusCode );
                    done();
                }
            };

            this.ipfilter( this.req, res, function(){});
        });
    });

    describe('enforcing ip restrictions with only one ip in the range',function(){
        beforeEach(function(){
            // Ip range: 127.0.0.1 - 127.0.0.14
            this.ipfilter = ipfilter([ ['127.0.0.1'] ], { log: false, mode: 'allow' });
            this.req = {
                session: {},
                headers: [],
                connection: {
                    remoteAddress: ''
                }
            };
        });

        it('should allow whitelisted ips', function( done ){
            this.req.connection.remoteAddress = '127.0.0.1';
            this.ipfilter( this.req, {}, function(){
                done();
            });
        });

        it('should deny all non-whitelisted ips', function( done ){
            this.req.connection.remoteAddress = '127.0.0.17';
            var res = {
                end: function(){
                    assert.equal( 401, res.statusCode );
                    done();
                }
            };

            this.ipfilter( this.req, res, function(){});
        });
    });

    describe('enforcing IP address blacklist restrictions', function(){

        beforeEach(function(){
            this.ipfilter = ipfilter([ ['127.0.0.1','127.0.0.3'] ], { log: false });
            this.req = {
                session: {},
                headers: [],
                connection: {
                    remoteAddress: ''
                }
            };
        });

        it('should allow all non-blacklisted ips', function( done ){
            this.req.connection.remoteAddress = '127.0.0.17';
            this.ipfilter( this.req, {}, function(){
                done();
            });
        });

        it('should allow all non-blacklisted forwarded ips', function( done ){
            this.req.headers['x-forwarded-for'] = '127.0.0.17';
            this.ipfilter( this.req, {}, function(){
                done();
            });
        });

        it('should deny all blacklisted ips', function( done ){
            this.req.connection.remoteAddress = '127.0.0.1';
            var res = {
                end: function(){
                    assert.equal( 401, res.statusCode );
                    done();
                }
            };

            this.ipfilter( this.req, res, function(){});
        });

        it('should deny all blacklisted forwarded ips', function( done ){
            this.req.headers['x-forwarded-for'] = '127.0.0.1';
            var res = {
                end: function(){
                    assert.equal( 401, res.statusCode );
                    done();
                }
            };

            this.ipfilter( this.req, res, function(){});
        });
    });

    describe('enforcing private ip restrictions',function(){
        beforeEach(function(){
            this.ipfilter = ipfilter([ ['127.0.0.1','127.0.0.3'] ], { log: false, allowPrivateIPs: true });
            this.req = {
                session: {},
                headers: [],
                connection: {
                    remoteAddress: ''
                }
            };
        });

        it('should allow all private ips', function( done ){
            this.req.connection.remoteAddress = '10.0.0.0';
            this.ipfilter( this.req, {}, function(){
                done();
            });
        });
    });
});

describe('excluding certain routes from filtering',function(){
    beforeEach(function(){
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

    it('should allow requests to excluded paths', function( done ){
        this.req.connection.remoteAddress = '190.0.0.0';
        this.ipfilter( this.req, {}, function(){
            done();
        });
    });

    it('should deny requests to other paths', function(done){
        this.req.url = '/bar';
        this.req.connection.remoteAddress = '190.0.0.0';
        var res = {
            end: function(){
                assert.equal( 401, res.statusCode );
                done();
            }
        };

        this.ipfilter( this.req, res, function(){});
    });
});

describe('no ip address can be found',function(){
    beforeEach(function(){
        this.ipfilter = ipfilter(['127.0.0.1'], { log: false, mode: 'allow', excluding: ['/foo.*'] });
        this.req = {
            session: {},
            headers: [],
            connection: {
                remoteAddress: ''
            }
        };
    });

    it('should deny requests', function(done){
        this.req.url = '/bar';
        this.req.connection.remoteAddress = '';
        var res = {
            end: function(){
                assert.equal( 401, res.statusCode );
                done();
            }
        };

        this.ipfilter( this.req, res, function(){});
    });
});

describe('external logger function', function () {

    it('should log to a passed logger exactly one message', function (done) {
        var messages = [];
        var logF = function logFF(message) {
            messages.push(message);
        };
        this.ipfilter = ipfilter(['127.0.0.1'], {log: true, logF: logF});
        this.req = {
            session: {},
            headers: [],
            connection: {
                remoteAddress: ''
            }
        };

        this.req.connection.remoteAddress = '127.0.0.1';
        var res = {
            end: function () {
                assert.equal(1, messages.length);
                done();
            }
        };

        this.ipfilter(this.req, res, function () {
        });
    });

    it('should log to a passed logger the correct message', function (done) {
        var messages = [];
        var logF = function logFF(message) {
            messages.push(message);
        };
        this.ipfilter = ipfilter(['127.0.0.1'], {log: true, logF: logF});
        this.req = {
            session: {},
            headers: [],
            connection: {
                remoteAddress: ''
            }
        };


        this.req.connection.remoteAddress = '127.0.0.1';
        var res = {
            end: function () {
                assert.equal('Access denied to IP address: 127.0.0.1', messages[0]);
                done();
            }
        };

        this.ipfilter(this.req, res, function () {
        });
    });

});

describe('an array of cidr blocks',function(){
    describe('blacklist',function(){
        beforeEach(function(){
            this.ipfilter = ipfilter(['72.30.0.0/26', '127.0.0.1/24'], { mode: 'deny', log: false });
            this.req = {
                session: {},
                headers: [],
                connection: {
                    remoteAddress: ''
                }
            };
        });

        it('should deny all blacklisted ips', function( done ){
            this.req.connection.remoteAddress = '127.0.0.1';
            var res = {
                end: function(){
                    assert.equal( 401, res.statusCode );
                    done();
                }
            };

            this.ipfilter( this.req, res, function(){});
        });
    });

    describe('whitelist',function(){
        beforeEach(function(){
            this.ipfilter = ipfilter(['72.30.0.0/26', '127.0.0.1/24'], { mode: 'allow', log: false });
            this.req = {
                session: {},
                headers: [],
                connection: {
                    remoteAddress: ''
                }
            };
        });

        it('should allow all whitelisted ips', function( done ){
            this.req.connection.remoteAddress = '127.0.0.1';
            this.ipfilter( this.req, {}, function(){
                done();
            });
        });
    });
});

describe('mixing different types of filters',function(){
    describe('with a whitelist', function () {
        beforeEach(function(){
            this.ipfilter = ipfilter(['127.0.0.1', '192.168.1.3/28', ['127.0.0.3', '127.0.0.35']], { cidr: true, mode: 'allow', log: false });
            this.req = {
                session: {},
                headers: [],
                connection: {
                    remoteAddress: ''
                }
            };
        });

        it('should allow explicit ips',function(done){
            this.req.connection.remoteAddress = '127.0.0.1';
            this.ipfilter( this.req, {}, function(){
                done();
            });
        });

        it('should allow ips in a cidr block',function(done){
            this.req.connection.remoteAddress = '192.168.1.1';
            this.ipfilter( this.req, {}, function(){
                done();
            });
        });

        it('should allow ips in a range',function(done){
            this.req.connection.remoteAddress = '127.0.0.20';
            this.ipfilter( this.req, {}, function(){
                done();
            });
        });
    });

    describe('with a blacklist', function(){
        beforeEach(function(){
            this.ipfilter = ipfilter(['127.0.0.1', '192.168.1.3/28', ['127.0.0.3', '127.0.0.35']], { mode: 'deny', log: false });
            this.req = {
                session: {},
                headers: [],
                connection: {
                    remoteAddress: ''
                }
            };
        });

        it('should deny explicit ips',function(done){
            this.req.connection.remoteAddress = '127.0.0.1';
            var res = {
                end: function(){
                    assert.equal( 401, res.statusCode );
                    done();
                }
            };

            this.ipfilter( this.req, res, function(){});
        });

        it('should deny ips in a cidr block',function(done){
            this.req.connection.remoteAddress = '192.168.1.15';
            var res = {
                end: function(){
                    assert.equal( 401, res.statusCode );
                    done();
                }
            };

            this.ipfilter( this.req, res, function(){});
        });

        it('should deny ips in a range',function(done){
            this.req.connection.remoteAddress = '127.0.0.15';
            var res = {
                end: function(){
                    assert.equal( 401, res.statusCode );
                    done();
                }
            };

            this.ipfilter( this.req, res, function(){});
        });
    });
});

//CloudFlare Tests
describe('enforcing cloudflare based client IP address blacklist restrictions', function(){

    beforeEach(function(){
        this.ipfilter = ipfilter([ '127.0.0.1' ], { log: false });
        this.req = {
            session: {},
            headers: [],
            connection: {
                remoteAddress: ''
            }
        };
    });

    it('should allow all non-blacklisted forwarded ips', function( done ){
        this.req.headers['cf-connecting-ip'] = '127.0.0.2';
        this.ipfilter( this.req, {}, function(){
            done();
        });
    });

    it('should deny all blacklisted forwarded ips', function( done ){
        this.req.headers['cf-connecting-ip'] = '127.0.0.1';
        var res = {
            end: function(){
                assert.equal( 401, res.statusCode );
                done();
            }
        };

        this.ipfilter( this.req, res, function(){});
    });

});
describe('enforcing cloudflare based client IP address whitelist restrictions', function(){
    beforeEach(function(){
        this.ipfilter = ipfilter([ '127.0.0.1' ], { log: false, mode: 'allow' });
        this.req = {
            session: {},
            headers: [],
            connection: {
                remoteAddress: ''
            }
        };
    });

    it('should allow whitelisted forwarded ips', function( done ){
        this.req.headers['cf-connecting-ip'] = '127.0.0.1';
        this.ipfilter( this.req, {}, function(){
            done();
        });
    });
    it('should deny all non-whitelisted forwarded ips', function( done ){
        this.req.headers['cf-connecting-ip'] = '127.0.0.2';
        var res = {
            end: function(){
                assert.equal( 401, res.statusCode );
                done();
            }
        };

        this.ipfilter( this.req, res, function(){});
    });

})
