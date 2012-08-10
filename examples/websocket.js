var sip = require('sip');
var WSProxy = require('sip/websocket-proxy');

// Where to listen for WebSocket connections
var websocket = {address:'0.0.0.0', port:5062};
// Where to bind the SIP tranport
var sipbind = {address:'0.0.0.0', port:5060};

// Create SIP transport
var trans = sip.create({ws:false, tcp:false, udp:true, address:sipbind.address, port:sipbind.port},
		handler);

// Create WebSocket proxy
var proxy = new WSProxy(websocket, route);


console.log("Listening for WebSocket connections on: "+websocket.address+":"+websocket.port);
console.log("SIP transport bound on: "+sipbind.address+":"+sipbind.port);


function handler(req, rem) {
	// Incoming out-of-dialog request from remote SIP UAC
	// ...
	// which we aren't supporting right now
}

function route(proxy, req, rem) {
	var client = 'WS://'+rem.address+':'+rem.port;
	console.log('Client request ['+req.method+' '+req.uri+'] from '+client);
//	req.uri = req.headers.contact[0].uri;
	proxy.send(sip.makeResponse(req, 100, 'Trying'));

	trans.send(req, function(res) {
		console.log('Response ['+res.status+' '+res.reason+'] to '+client);
		res.headers.via.shift();
		proxy.send(res);
	});
}



