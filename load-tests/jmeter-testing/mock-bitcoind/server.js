const http = require('http');
const fs = require('fs');
const path = require('path');

const gbtPath = path.join(
    __dirname,
    "../../../p2poolv2_tests/test_data/gbt/signet/gbt-no-transactions.json",
);
const gbt = JSON.parse(fs.readFileSync(gbtPath, "utf8"));

const methods = {
    getblocktemplate: function () {
        return gbt;
    },
    submitblock: function () {
        return null;
    },
    getdifficulty: function () {
        return 1.0;
    }
};

const PORT = 48332;

http.createServer((req, res) => {
    let data = '';
    req.on('data', chunk => { data += chunk; });
    req.on('end', () => {
        console.log(`Received request: ${data}`);

        let parsed;
        try {
            parsed = JSON.parse(data);
        } catch (e) {
            res.writeHead(400);
            return res.end('Invalid JSON');
        }

        const method = parsed.method;
        const id = parsed.id;
        const handler = methods[method];

        let response;
        if (handler) {
            response = { result: handler(parsed.params), error: null, id: id };
        } else {
            response = { result: null, error: { code: -32601, message: `Method not found: ${method}` }, id: id };
        }

        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(response));
    });
}).listen(PORT, () => {
    console.log(`Mock bitcoind JSON-RPC server listening on port ${PORT}`);
});
