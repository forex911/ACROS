const fs = require('fs');
const child_process = require('child_process');
const http = require('http');
const https = require('https');
const net = require('net');

const jobId = process.argv[2] || process.env.AEGIS_JOB_ID || "unknown";
const targetFile = process.argv[3];

function sendTelemetry(eventType, data) {
    const msg = {
        "__telemetry__": true,
        "job_id": jobId,
        "event_type": eventType,
        "data": data,
        "timestamp": new Date().toISOString()
    };
    console.log(JSON.stringify(msg));
}

// ── Hook child_process ──────────────────────────────────────────
const originalExec = child_process.exec;
child_process.exec = function(command, options, callback) {
    sendTelemetry("PROCESS_CREATE", { "cmdline": command });
    return originalExec.apply(this, arguments);
};

const originalSpawn = child_process.spawn;
child_process.spawn = function(command, args, options) {
    const cmdline = [command].concat(args || []).join(' ');
    sendTelemetry("PROCESS_CREATE", { "cmdline": cmdline });
    return originalSpawn.apply(this, arguments);
};

const originalExecFile = child_process.execFile;
child_process.execFile = function(file, args, options, callback) {
    const cmdline = [file].concat(args || []).join(' ');
    sendTelemetry("PROCESS_CREATE", { "cmdline": cmdline });
    return originalExecFile.apply(this, arguments);
};

// ── Hook fs ─────────────────────────────────────────────────────
const originalCreateWriteStream = fs.createWriteStream;
fs.createWriteStream = function(path, options) {
    sendTelemetry("FILE_WRITE", { "file_path": path.toString() });
    return originalCreateWriteStream.apply(this, arguments);
};

const originalWriteFileSync = fs.writeFileSync;
fs.writeFileSync = function(file, data, options) {
    sendTelemetry("FILE_WRITE", { "file_path": file.toString() });
    return originalWriteFileSync.apply(this, arguments);
};

const originalWriteFile = fs.writeFile;
fs.writeFile = function(file, data, options, callback) {
    sendTelemetry("FILE_WRITE", { "file_path": file.toString() });
    return originalWriteFile.apply(this, arguments);
};

// ── Hook net / http ─────────────────────────────────────────────
const originalNetConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function(...args) {
    let port, host;
    if (typeof args[0] === 'object' && args[0] !== null) {
        port = args[0].port;
        host = args[0].host || 'localhost';
    } else {
        port = args[0];
        host = args[1];
    }
    
    if (host && port) {
        sendTelemetry("SOCKET_CONNECT", { "dest_ip": host.toString(), "dest_port": parseInt(port), "protocol": "TCP" });
    }
    return originalNetConnect.apply(this, args);
};

// We don't necessarily need to hook http.get/request if we hooked net.connect, 
// but http/https abstractions are useful for capturing full URLs.
const originalHttpGet = http.get;
http.get = function(...args) {
    let url = typeof args[0] === 'string' ? args[0] : (args[0].href || args[0].hostname);
    sendTelemetry("NETWORK_CONNECT", { "url": url });
    return originalHttpGet.apply(this, args);
};
const originalHttpsGet = https.get;
https.get = function(...args) {
    let url = typeof args[0] === 'string' ? args[0] : (args[0].href || args[0].hostname);
    sendTelemetry("NETWORK_CONNECT", { "url": url });
    return originalHttpsGet.apply(this, args);
};

// ── Execute Target ──────────────────────────────────────────────
if (!targetFile) {
    console.error("Usage: node sandbox_wrapper.js <job_id> <target_file.js>");
    process.exit(1);
}

try {
    require(targetFile);
} catch (e) {
    console.error("Error executing script:", e);
}
