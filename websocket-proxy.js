var util= require('util');
var sip	= require('./sip.js');

var contexts = {};

function makeContextId(msg) {
	var v = msg.headers.via[0];
	return [v.params.branch, v.protocol, v.host, v.port, msg.headers['call-id'], msg.headers.cseq.seq];
}

function Proxy(options, route) {
	var self = this;
	var trans;

	self.stop = function() { if (trans) trans.stop(); delete trans; };

	self.handler = function(req, rem) {
		if (req.method === 'CANCEL') {
			var ctx = contexts[makeContextId(req)];
			if (ctx) {
				trans.send(trans.makeResponse(req, 200));
				ctx.cancelled = true;
				if (ctx.cancellers)
					Object.keys(ctx.cancellers).forEach(function(c) { ctx.cancellers[c](); });
			}
			else
				trans.send(sip.makeResponse(req, 481));
			return;
		}

		var id = makeContextId(req);
		contexts[id] = { cancellers: {} };

		try {
			route(self, sip.copyMessage(req), rem);
		} catch(e) {
			delete contexts[id];
			throw e;
		}
	}

	self.send = function(msg, callback) {
  		var ctx = contexts[makeContextId(msg)];
		if (!ctx) return trans.send.apply(trans, arguments);
		return msg.method
			? self.forwardRequest(ctx, msg, callback || self.defaultCallback)
			: self.forwardResponse(ctx, msg);
	}
 
	self.forwardRequest = function(ctx, req, callback) {
		self.send(req, function(res, rem) {
			var via = res.headers.via[0];
			if (+res.status < 200) {
				ctx.cancellers[via.params.branch] = function() { self.sendCancel(req, via); };
				if (ctx.cancelled) self.sendCancel(req, via);
		    }
			else
				delete ctx.cancellers[via.params.branch];

			callback(res, rem);
		});
	}

	self.forwardResponse = function(ctx, res, callback) {
		if (+res.status >= 200) delete contexts[makeContextId(res)];
		trans.send(res);
	}

	self.defaultCallback = function(res) {
		res.headers.via.shift();
		self.send(res);
	}

	self.sendCancel = function(req, via) {
		trans.send({
			method	: 'CANCEL',
			uri		: req.uri,
			headers	: {
				via		: [via],
				to		: req.headers.to,
				from	: req.headers.from,
				'call-id': req.headers['call-id'],
				cseq	: {method: 'CANCEL', seq: req.headers.cseq.seq}
			}
		});
	}


	trans = sip.create({ws:true, tcp:false, udp:false, address:options.address, port:options.port},
			self.handler);
	self.trans = trans;
}

module.exports = Proxy;

