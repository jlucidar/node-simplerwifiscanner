var exec = require('child_process').exec;
var linuxProvider = '/sbin/iwlist';

function parseIwlist(str) {
    var out = str.replace(/^\s+/mg, '');
    out = out.split('\n');
    var cells = [];
    var line;
    var info = {};
    var fields = {
        'mac' : /^Cell \d+ - Address: (.*)/,
        'ssid' : /^ESSID:"(.*)"/,
        //'protocol' : /^Protocol:(.*)/,
        //'mode' : /^Mode:(.*)/,
        //'frequency' : /^Frequency:(.*)/,
        'encryption_key' : /Encryption key:(.*)/,
        //'bitrates' : /Bit Rates:(.*)/,
        //'quality' : /Quality(?:=|\:)([^\s]+)/,
        'signal_level' : /Signal level(?:=|\:)([-\w]+)/,
	'wpa' : /^(IE: IEEE 802.11i\/WPA2 Version 1)|(IE: WPA Version 1)/         
    };

    for (var i=0,l=out.length; i<l; i++) {
        line = out[i].trim();

        if (!line.length) {
            continue;
        }
        if (line.match("Scan completed :")) {
            continue;
        }
        if (line.match("Interface doesn't support scanning.")) {
            continue;
        }

        if (line.match(fields.mac)) {
	    info.security = "none";
	    if (info.encryption_key === "on" ){
		info.security = "wep";
		if (info.wpa){
		    info.security = "wpa";
		}
	    }
	    delete info.encryption_key;
	    delete info.wpa;
            cells.push(info);
            info = {};
        }

        for (var field in fields) {
            if (line.match(fields[field])) {
		var value = (fields[field].exec(line)[1]);
                info[field] = value ? value.trim() : undefined;
            }
        }
    }
    info.security = "none";
    if (info.encryption_key === "on" ){
	info.security = "wep";
	if (info.wpa){
	    info.security = "wpa";
	}
    }
    delete info.encryption_key;
    delete info.wpa;
    cells.push(info);
    cells.shift();
    return cells;
}

function scan(callback){
    exec(linuxProvider + ' scan', function(err, stdout, stderr){
        if (err) {
            errClbk(err, null);
            return;
        }
        callback(null, parseIwlist(stdout));
    });
}

exports.scan = scan;
exports.utility = linuxProvider;
