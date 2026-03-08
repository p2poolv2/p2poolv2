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
                this.websocket.send(
                    JSON.stringify({ action: "subscribe", topic: "uncles" }),
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
                console.log("share received");
            }
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
            this.username = "";
            this.password = "";
            this.error = "";
            this.chainError = "";
        },
    };
}
