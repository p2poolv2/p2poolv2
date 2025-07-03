const jayson = require('jayson');
const http = require('http');
const fs = require('fs');
const path = require('path');

const gbtPath = path.join(__dirname, '../../tests/test_data/gbt/signet/gbt-no-transactions.json');
const gbt = JSON.parse(fs.readFileSync(gbtPath, 'utf8'));

// JSON-RPC 1.0 server
const server = new jayson.Server({
    hello: function (args, callback) {
        callback(null, 'hey');
    },
    getblocktemplate: function (args, callback) {
        callback(null, gbt);
    },
    submitblock: function (args, callback) {
        callback(null, null);
    }
});

const PORT = 48332;

// Custom HTTP server to accept text/plain as JSON
http.createServer((req, res) => {
    let data = '';
    req.on('data', chunk => { data += chunk; });
    req.on('end', () => {
        console.log(`Received request: ${data}`);
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
            // Default: handle as application/json
            try {
                req.body = JSON.parse(data);
            } catch (e) {
                res.writeHead(400);
                return res.end('Invalid JSON');
            }
            server.call(req.body, (err, response) => {
                if (err) {
                    res.writeHead(500);
                    return res.end('Server error');
                }
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify(response));
            });
        }
    });
}).listen(PORT, () => {
    console.log(`Mock bitcoind JSON-RPC server listening on port ${PORT}`);
});
