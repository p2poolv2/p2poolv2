const jayson = require('jayson');
const http = require('http');

// JSON-RPC 1.0 server
const server = new jayson.Server({
    hello: function (args, callback) {
        callback(null, 'hey');
    },
    getblocktemplate: function (args, callback) {
        // Placeholder block template
        callback(null, {
            version: 536870912,
            previousblockhash: '0000000000000000000placeholder',
            transactions: [],
            coinbaseaux: {},
            coinbasevalue: 5000000000,
            target: '00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            mintime: 1620000000,
            mutable: ['time', 'transactions', 'prevblock'],
            noncerange: '00000000ffffffff',
            sigoplimit: 80000,
            sizelimit: 1000000,
            curtime: Math.floor(Date.now() / 1000),
            bits: '1d00ffff',
            height: 1000000
        });
    },
    submitblock: function (args, callback) {
        callback(null, null);
    }
}, { version: 1 }); // Enforce JSON-RPC 1.0

const PORT = 8332;

// Custom HTTP server to accept text/plain as JSON
http.createServer((req, res) => {
    let data = '';
    req.on('data', chunk => { data += chunk; });
    req.on('end', () => {
        // Accept both application/json and text/plain
        const contentType = req.headers['content-type'] || '';
        if (contentType.includes('text/plain')) {
            try {
                req.body = JSON.parse(data);
            } catch (e) {
                res.writeHead(400);
                return res.end('Invalid JSON');
            }
            // jayson expects req.body to be set
            server.call(req.body, (err, response) => {
                if (err) {
                    res.writeHead(500);
                    return res.end('Server error');
                }
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify(response));
            });
        } else {
            // fallback to jayson default handler
            console.log("Bitcoind RPC accepts text/plain");
        }
    });
}).listen(PORT, () => {
    console.log(`Mock bitcoind JSON-RPC server listening on port ${PORT}`);
});
