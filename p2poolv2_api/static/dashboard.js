// Convert Bitcoin compact target (bits) to work.
// Work = 2^256 / (target + 1) where target is decoded from the compact format.
function workFromBits(bits) {
    var exponent = bits >> 24;
    var mantissa = BigInt(bits & 0x7fffff);
    var shift = 8 * (exponent - 3);
    var target =
        shift >= 0 ? mantissa << BigInt(shift) : mantissa >> BigInt(-shift);
    var two256 = 1n << 256n;
    return two256 / (target + 1n);
}

function dashboard() {
    return {
        username: "",
        password: "",
        error: "",
        loading: false,
        authenticated: false,
        credentials: "",
        chainInfo: null,
        chainError: "",
        shares: [],
        sharesError: "",
        sharesPage: 0,
        sharesPerPage: 10,
        selectedShare: null,
        selectedUncle: null,
        websocket: null,
        wsConnected: false,

        async login() {
            this.error = "";
            this.loading = true;
            this.credentials = btoa(this.username + ":" + this.password);

            try {
                const response = await fetch("/chain_info", {
                    headers: { Authorization: "Basic " + this.credentials },
                });

                if (!response.ok) {
                    if (response.status === 401) {
                        this.error = "Invalid username or password.";
                    } else {
                        this.error = "Server error: " + response.status;
                    }
                    this.credentials = "";
                    this.loading = false;
                    return;
                }

                this.chainInfo = await response.json();
                this.authenticated = true;
                this.password = "";
                this.fetchShares();
                this.connectWebSocket();
            } catch (err) {
                this.error = "Connection failed: " + err.message;
                this.credentials = "";
            }

            this.loading = false;
        },

        connectWebSocket() {
            var protocol =
                window.location.protocol === "https:" ? "wss:" : "ws:";
            var token = encodeURIComponent(this.credentials);
            var url =
                protocol + "//" + window.location.host + "/ws?token=" + token;

            this.websocket = new WebSocket(url);

            this.websocket.onopen = () => {
                this.wsConnected = true;
                this.websocket.send(
                    JSON.stringify({ action: "subscribe", topic: "shares" }),
                );
            };

            this.websocket.onmessage = (event) => {
                var message = JSON.parse(event.data);
                this.handleWsMessage(message);
            };

            this.websocket.onclose = () => {
                this.wsConnected = false;
            };

            this.websocket.onerror = () => {
                this.wsConnected = false;
                this.chainError = "WebSocket connection failed.";
            };
        },

        handleWsMessage(message) {
            if (message.topic === "Share") {
                var share = message.data;
                this.shares.unshift(share);
                if (this.shares.length > 1000) {
                    this.shares.length = 1000;
                }
                if (this.chainInfo) {
                    this.chainInfo.chain_tip_height = share.height;
                    this.chainInfo.chain_tip_blockhash = share.blockhash;
                    var work = workFromBits(share.bits);
                    var currentWork = BigInt(this.chainInfo.total_work);
                    this.chainInfo.total_work =
                        "0x" +
                        (currentWork + work).toString(16).padStart(64, "0");
                }
            }
        },

        get pagedShares() {
            var start = this.sharesPage * this.sharesPerPage;
            var page = this.shares.slice(start, start + this.sharesPerPage);
            var rows = [];
            for (var idx = 0; idx < page.length; idx++) {
                var share = page[idx];
                rows.push({ share: share, isUncle: false });
                for (
                    var uncleIdx = 0;
                    uncleIdx < share.uncles.length;
                    uncleIdx++
                ) {
                    rows.push({ share: share.uncles[uncleIdx], isUncle: true });
                }
            }
            return rows;
        },

        get totalSharesPages() {
            return Math.max(
                1,
                Math.ceil(this.shares.length / this.sharesPerPage),
            );
        },

        previousSharesPage() {
            if (this.sharesPage > 0) {
                this.sharesPage = this.sharesPage - 1;
            }
        },

        nextSharesPage() {
            if (this.sharesPage < this.totalSharesPages - 1) {
                this.sharesPage = this.sharesPage + 1;
            }
        },

        selectShare(share) {
            this.selectedShare = share;
        },

        selectUncle(uncle) {
            this.selectedUncle = uncle;
        },

        async fetchChainInfo() {
            this.chainError = "";

            try {
                var response = await fetch("/chain_info", {
                    headers: { Authorization: "Basic " + this.credentials },
                });

                if (!response.ok) {
                    if (response.status === 401) {
                        this.authenticated = false;
                        this.credentials = "";
                        this.error = "Session expired. Please login again.";
                        this.closeWebSocket();
                        return;
                    }
                    this.chainError =
                        "Failed to fetch chain info: " + response.status;
                    return;
                }

                this.chainInfo = await response.json();
            } catch (err) {
                this.chainError = "Connection failed: " + err.message;
            }
        },

        async fetchShares() {
            this.sharesError = "";

            try {
                var response = await fetch("/shares?num=100", {
                    headers: { Authorization: "Basic " + this.credentials },
                });

                if (!response.ok) {
                    this.sharesError =
                        "Failed to fetch shares: " + response.status;
                    return;
                }

                var data = await response.json();
                this.shares = data.shares;
            } catch (err) {
                this.sharesError = "Connection failed: " + err.message;
            }
        },

        formatHash(hash) {
            if (!hash) return "N/A";
            if (hash.length <= 16) return hash;
            return (
                hash.substring(0, 8) + "..." + hash.substring(hash.length - 8)
            );
        },

        formatTimestamp(timestamp) {
            if (!timestamp) return "N/A";
            return new Date(timestamp * 1000).toLocaleString();
        },

        closeWebSocket() {
            if (this.websocket) {
                this.websocket.onclose = null;
                this.websocket.close();
                this.websocket = null;
                this.wsConnected = false;
            }
        },

        logout() {
            this.closeWebSocket();
            this.authenticated = false;
            this.credentials = "";
            this.chainInfo = null;
            this.shares = [];
            this.sharesError = "";
            this.selectedShare = null;
            this.selectedUncle = null;
            this.username = "";
            this.password = "";
            this.error = "";
            this.chainError = "";
        },
    };
}
