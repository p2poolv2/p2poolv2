// Convert Bitcoin compact target (bits) to work.
// Work = 2^256 / (target + 1) where target is decoded from the compact format.
function updateTitleWithHeight(height) {
    if (height != null) {
        document.title = "(" + height + ") P2Poolv2 Dashboard";
    }
}

function workFromBits(bits) {
    var exponent = bits >> 24;
    var mantissa = BigInt(bits & 0x7fffff);
    var shift = 8 * (exponent - 3);
    var target =
        shift >= 0 ? mantissa << BigInt(shift) : mantissa >> BigInt(-shift);
    var two256 = 1n << 256n;
    return two256 / (target + 1n);
}

// Convert Bitcoin compact target (bits) to difficulty.
// Difficulty = target_at_difficulty_1 / target_from_bits
// where target_at_difficulty_1 = 0x00000000FFFF << 208 (the "pool difficulty 1" target).
function difficultyFromBits(bits) {
    var exponent = bits >> 24;
    var mantissa = BigInt(bits & 0x7fffff);
    var shift = 8 * (exponent - 3);
    var target =
        shift >= 0 ? mantissa << BigInt(shift) : mantissa >> BigInt(-shift);
    if (target === 0n) return "0";
    var diff1Target = 0xffffn << 208n;
    var difficulty = diff1Target / target;
    return formatDifficulty(Number(difficulty));
}

function formatDifficulty(value) {
    var suffixes = ["", "K", "M", "G", "T", "P", "E"];
    if (value < 10000) return value.toLocaleString();
    var tier = 0;
    var scaled = value;
    while (scaled >= 1000 && tier < suffixes.length - 1) {
        scaled = scaled / 1000;
        tier = tier + 1;
    }
    var formatted =
        scaled >= 100
            ? scaled.toFixed(0)
            : scaled >= 10
              ? scaled.toFixed(1)
              : scaled.toFixed(2);
    return formatted + suffixes[tier];
}

function dashboard() {
    return {
        menuOpen: false,
        username: "",
        password: "",
        error: "",
        loading: false,
        checking: true,
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

        async init() {
            try {
                var response = await fetch("/chain_info");
                if (response.ok) {
                    this.chainInfo = await response.json();
                    updateTitleWithHeight(this.chainInfo.chain_tip_height);
                    this.authenticated = true;
                    this.checking = false;
                    this.fetchShares();
                    this.connectWebSocket();
                    return;
                }
            } catch (err) {
                this.error = "Connection failed: " + err.message;
            }
            this.checking = false;
        },

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
                updateTitleWithHeight(this.chainInfo.chain_tip_height);
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
                    updateTitleWithHeight(share.height);
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
                updateTitleWithHeight(this.chainInfo.chain_tip_height);
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
            if (hash.length <= 12) return hash;
            return hash.substring(0, 10);
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
