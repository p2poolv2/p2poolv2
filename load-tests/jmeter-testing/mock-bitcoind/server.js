const net = require('net');
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
    },
    getbestblockhash: function () {
        return gbt.previousblockhash;
    },
    validateaddress: function (params) {
        const address = params && params[0] ? params[0] : "";
        return {
            isvalid: true,
            address: address,
            scriptPubKey: "",
            isscript: false,
            iswitness: true
        };
    }
};

const PORT = 48332;

// Raw TCP server that handles HTTP/JSON-RPC manually.
// CKPool uses LF-only line endings and non-blocking reads, so the
// entire HTTP response (headers + body) must be sent as a single
// write to avoid CKPool's recv getting EAGAIN between headers and body.
net.createServer({ noDelay: true }, (socket) => {
    let buffer = Buffer.alloc(0);

    socket.on('data', (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);

        // Find end of HTTP headers (support both CRLF and LF)
        let headerEnd = buffer.indexOf('\r\n\r\n');
        let headerEndLen = 4;
        if (headerEnd === -1) {
            headerEnd = buffer.indexOf('\n\n');
            headerEndLen = 2;
        }
        if (headerEnd === -1) {
            return;
        }

        const headersText = buffer.subarray(0, headerEnd).toString();
        const bodyStart = headerEnd + headerEndLen;

        // Extract Content-Length
        const match = headersText.match(/content-length:\s*(\d+)/i);
        const contentLength = match ? parseInt(match[1], 10) : 0;

        if (buffer.length - bodyStart < contentLength) {
            return;
        }

        const body = buffer.subarray(bodyStart, bodyStart + contentLength).toString();
        buffer = buffer.subarray(bodyStart + contentLength);

        console.log(`Received request: ${body}`);

        let parsed;
        try {
            parsed = JSON.parse(body);
        } catch (e) {
            const errResp = 'HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 12\r\n\r\nInvalid JSON';
            socket.end(errResp);
            return;
        }

        const method = parsed.method;
        const id = parsed.id;
        const handler = methods[method];

        let rpcResponse;
        if (handler) {
            rpcResponse = { result: handler(parsed.params), error: null, id: id };
        } else {
            rpcResponse = { result: null, error: { code: -32601, message: `Method not found: ${method}` }, id: id };
        }

        const jsonBody = JSON.stringify(rpcResponse);
        const jsonBodyWithNewline = jsonBody + '\n';
        const httpResponse = `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${jsonBodyWithNewline.length}\r\nConnection: close\r\n\r\n${jsonBodyWithNewline}`;
        socket.write(httpResponse, () => {
            // Delay close to ensure data is flushed to the client
            setTimeout(() => socket.end(), 50);
        });
    });

    socket.on('error', () => {});
}).listen(PORT, () => {
    console.log(`Mock bitcoind JSON-RPC server listening on port ${PORT}`);
});
