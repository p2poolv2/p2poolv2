// Convert Bitcoin compact target (bits) to work.
// Work = 2^256 / (target + 1) where target is decoded from the compact format.
function workFromBits(bits) {
  const exponent = bits >>> 24;
  const mantissa = BigInt(bits & 0x7fffff);
  const shift = 8 * (exponent - 3);
  const target =
    shift >= 0 ? mantissa << BigInt(shift) : mantissa >> BigInt(-shift);
  const two256 = 1n << 256n;
  return two256 / (target + 1n);
}

// Sync SHA-256 over a byte array; crypto.subtle is async, so base58check
// cannot use it. Returns a new 32-byte array.
function cashSha256(bytes) {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  const h = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ];
  const len = bytes.length;
  const withOne = len + 1;
  const total = withOne + ((56 - (withOne % 64) + 64) % 64) + 8;
  const msg = new Array(total).fill(0);
  for (let i = 0; i < len; i++) msg[i] = bytes[i] & 0xff;
  msg[len] = 0x80;
  const bitLen = len * 8;
  for (let i = 0; i < 8; i++) {
    msg[total - 1 - i] = Math.floor(bitLen / Math.pow(2, 8 * i)) & 0xff;
  }
  const w = new Array(64);
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] =
        ((msg[off + 4 * i] << 24) |
          (msg[off + 4 * i + 1] << 16) |
          (msg[off + 4 * i + 2] << 8) |
          msg[off + 4 * i + 3]) >>>
        0;
    }
    for (let i = 16; i < 64; i++) {
      const a15 = w[i - 15];
      const a2 = w[i - 2];
      const s0 = (((a15 >>> 7) | (a15 << 25)) ^ ((a15 >>> 18) | (a15 << 14)) ^ (a15 >>> 3)) >>> 0;
      const s1 = (((a2 >>> 17) | (a2 << 15)) ^ ((a2 >>> 19) | (a2 << 13)) ^ (a2 >>> 10)) >>> 0;
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let a = h[0];
    let b = h[1];
    let c = h[2];
    let d = h[3];
    let e = h[4];
    let f = h[5];
    let g = h[6];
    let hh = h[7];
    for (let i = 0; i < 64; i++) {
      const S1 = (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = (S0 + maj) >>> 0;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0;
    h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0;
    h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0;
    h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0;
    h[7] = (h[7] + hh) >>> 0;
  }
  const out = new Array(32);
  for (let i = 0; i < 8; i++) {
    out[4 * i] = (h[i] >>> 24) & 0xff;
    out[4 * i + 1] = (h[i] >>> 16) & 0xff;
    out[4 * i + 2] = (h[i] >>> 8) & 0xff;
    out[4 * i + 3] = h[i] & 0xff;
  }
  return out;
}

// Decode a legacy base58check address to {version, hash}, or null on any
// bad character, too short, or checksum mismatch.
function b58DecodeLegacy(s) {
  const alphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let value = 0n;
  for (let i = 0; i < s.length; i++) {
    const idx = alphabet.indexOf(s[i]);
    if (idx < 0) return null;
    value = value * 58n + BigInt(idx);
  }
  let hex = value === 0n ? "" : value.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const raw = [];
  for (let i = 0; i < hex.length; i += 2) {
    raw.push(parseInt(hex.substr(i, 2), 16));
  }
  let zeros = 0;
  while (zeros < s.length && s[zeros] === "1") zeros++;
  const bytes = new Array(zeros).fill(0).concat(raw);
  if (bytes.length < 5) return null;
  const payload = bytes.slice(0, bytes.length - 4);
  const checksum = bytes.slice(bytes.length - 4);
  const dbl = cashSha256(cashSha256(payload));
  for (let i = 0; i < 4; i++) {
    if (dbl[i] !== checksum[i]) return null;
  }
  return { version: payload[0], hash: payload.slice(1) };
}

// CashAddr polymod checksum (GF(2^5) BCH code per the CashAddr spec).
function cashAddrPolymod(values) {
  let c = 1n;
  for (let i = 0; i < values.length; i++) {
    const c0 = c >> 35n;
    c = ((c & 0x07ffffffffn) << 5n) ^ BigInt(values[i]);
    if (c0 & 0x01n) c ^= 0x98f2bc8e61n;
    if (c0 & 0x02n) c ^= 0x79b76d99e2n;
    if (c0 & 0x04n) c ^= 0xf33e5fb3c4n;
    if (c0 & 0x08n) c ^= 0xae2eabe2a8n;
    if (c0 & 0x10n) c ^= 0x1e4f43e470n;
  }
  return c ^ 1n;
}

// Re-chunk a byte array into `to`-bit groups, optionally padding the last.
function cashConvertBits(data, from, to, pad) {
  let acc = 0;
  let bits = 0;
  const ret = [];
  const maxv = (1 << to) - 1;
  for (let i = 0; i < data.length; i++) {
    const value = data[i];
    if (value < 0 || value >> from) return null;
    acc = (acc << from) | value;
    bits += from;
    while (bits >= to) {
      bits -= to;
      ret.push((acc >> bits) & maxv);
    }
  }
  if (pad && bits > 0) ret.push((acc << (to - bits)) & maxv);
  return ret;
}

// Encode a 20-byte hash as a CashAddr string, or null on bad input.
// type is 0 for P2PKH, 1 for P2SH.
function cashAddrEncode(prefix, type, hash) {
  if (!hash || hash.length !== 20) return null;
  const version = (type << 3) | 0;
  const payload = cashConvertBits([version].concat(hash), 8, 5, true);
  if (!payload) return null;
  const expanded = [];
  for (let i = 0; i < prefix.length; i++) {
    expanded.push(prefix.charCodeAt(i) & 0x1f);
  }
  expanded.push(0);
  const checksumInput = expanded
    .concat(payload)
    .concat([0, 0, 0, 0, 0, 0, 0, 0]);
  const checksum = cashAddrPolymod(checksumInput);
  const chars = [];
  for (let i = 0; i < 8; i++) {
    chars.push(Number((checksum >> BigInt(5 * (7 - i))) & 31n));
  }
  const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  const body = payload.concat(chars).map(function (v) {
    return charset[v];
  }).join("");
  return prefix + ":" + body;
}

function dashv1() {
  return {
    auth: { user: "", pass: "", error: "", busy: false },
    authHeader: "",
    authenticated: false,
    route: { name: "home", param: "" },
    chainInfo: null,
    metrics: {},
    shares: [],
    miner: null,
    minerQuery: "",
    minerLoading: false,
    minerError: "",
    minerShares: [],
    hsSeries: [],
    minerConnSeries: [],
    poolSeries: [],
    netSeries: [],
    netDiffSeries: [],
    legendOn: { pool: true, local: true, net: false, diff: false, shares: false, miners: false, netdiff: false, blocks: false },
    hoverT: null,
    hoverX: 0,
    chartRange: "1h",
    lastShareHeight: null,
    workBaseline: null,
    prevCounters: {},
    prevWorkTotal: null,
    knownAddresses: [],
    knownWorkers: [],
    minerAnchor: null,
    poolAnchor: null,
    expanded: {},
    autoRefresh: true,
    nextPollSecs: 15,
    sharesPage: 0,
    sharesPerPage: 10,
    selectedShare: null,
    selectedUncle: null,
    selectedBlock: null,
    websocket: null,
    wsConnected: false,
    wsRetryTimer: null,
    lastUpdated: null,
    pollError: "",
    timer: null,
    touchClearTimer: null,

    init() {
      this.loadHsSeries();
      this.loadMinerConnSeries();
      this.loadPoolSeries();
      this.loadNetSeries();
      this.loadNetDiffSeries();
      this.loadLegendOn();
      const saved = sessionStorage.getItem("dashv1-auth");
      if (saved) {
        this.authHeader = saved;
        this.authenticated = true;
        this.startPolling();
        this.connectWebSocket();
        const failRestore = (message) => {
          this.closeWebSocket();
          if (this.timer) {
            clearInterval(this.timer);
            this.timer = null;
          }
          this.authenticated = false;
          this.authHeader = "";
          sessionStorage.removeItem("dashv1-auth");
          this.metrics = {};
          this.chainInfo = null;
          this.shares = [];
          this.pollError = "";
          this.auth.error = message;
        };
        this.verifyAuth()
          .then((ok) => {
            if (!ok) {
              failRestore("Signed out: the API rejected the stored credentials.");
            }
          })
          .catch((error) => {
            failRestore("Session check failed: " + error.message);
          });
      }
      this.readRoute();
      window.addEventListener("hashchange", () => {
        this.readRoute();
        this.refreshView();
      });
    },

    readRoute() {
      const raw = location.hash.replace(/^#\/?/, "");
      if (raw === "" || raw === "/") {
        this.route = { name: "home", param: "" };
      } else if (raw === "blocks") {
        this.route = { name: "blocks", param: "" };
      } else if (raw === "miners") {
        this.route = { name: "miners", param: "" };
      } else if (raw === "help") {
        this.route = { name: "help", param: "" };
      } else if (raw.startsWith("miner/")) {
        const addr = decodeURIComponent(raw.slice("miner/".length)).trim();
        this.route = { name: "miner", param: addr };
        if (addr && addr !== this.minerQuery) {
          this.minerQuery = addr;
          this.loadMiner();
        }
      } else {
        this.route = { name: "home", param: "" };
      }
      if (!this.authenticated) return;
      this.applyDocTitle();
    },

    applyDocTitle() {
      if (!this.authenticated) return;
      const titles = {
        home: "Dashboard",
        blocks: "Blocks",
        miners: "Miners",
        miner: "Miner",
        help: "Help",
      };
      let prefix = "";
      if (this.chainInfo && this.chainInfo.chain_tip_height != null) {
        const tip = this.chainInfo.chain_tip_blockhash
          ? this.chainInfo.chain_tip_blockhash.substring(0, 3)
          : "";
        prefix = tip
          ? this.chainInfo.chain_tip_height + " \u00b7 " + tip + " \u00b7 "
          : this.chainInfo.chain_tip_height + " \u00b7 ";
      }
      document.title =
        prefix + (titles[this.route.name] || "Dashboard") + " - P2Pool v2 chipnet";
    },

    async api(path) {
      const resp = await fetch(path, {
        headers: { Authorization: this.authHeader },
      });
      if (resp.status === 401) {
        this.logout("Signed out: API rejected the credentials (401).");
        throw new Error("unauthorized");
      }
      if (!resp.ok) throw new Error("HTTP " + resp.status + " on " + path);
      return resp;
    },

    async verifyAuth() {
      const resp = await fetch("/chain_info", {
        headers: { Authorization: this.authHeader },
      });
      return resp.ok;
    },

    async login() {
      this.auth.busy = true;
      this.auth.error = "";
      const header =
        "Basic " + btoa(this.auth.user.trim() + ":" + this.auth.pass);
      try {
        const resp = await fetch("/chain_info", {
          headers: { Authorization: header },
        });
        if (!resp.ok) {
          this.auth.error =
            resp.status === 401
              ? "Invalid username or password."
              : "Unexpected response: HTTP " + resp.status;
          return;
        }
        this.authHeader = header;
        sessionStorage.setItem("dashv1-auth", header);
        this.authenticated = true;
        this.auth.pass = "";
        this.startPolling();
        this.connectWebSocket();
      } catch (e) {
        this.auth.error = "Connection failed: " + e.message;
      } finally {
        this.auth.busy = false;
      }
    },

    logout(message) {
      this.closeWebSocket();
      this.authenticated = false;
      this.authHeader = "";
      sessionStorage.removeItem("dashv1-auth");
      this.metrics = {};
      this.chainInfo = null;
      this.shares = [];
      this.miner = null;
      this.lastShareHeight = null;
      this.workBaseline = null;
      this.prevCounters = {};
      this.prevWorkTotal = null;
      this.knownAddresses = [];
      this.knownWorkers = [];
      this.minerAnchor = null;
      this.poolAnchor = null;
      this.minerConnSeries = [];
      this.poolSeries = [];
      this.netSeries = [];
      this.netDiffSeries = [];
      this.hoverT = null;
      this.hoverX = 0;
      try {
        localStorage.removeItem("dashv1-mc");
        localStorage.removeItem("dashv1-po");
        localStorage.removeItem("dashv1-net");
        localStorage.removeItem("dashv1-nd");
      } catch (e) {
        /* storage unavailable: keep in-memory clear only */
      }
      this.expanded = {};
      this.sharesPage = 0;
      this.selectedShare = null;
      this.selectedUncle = null;
      this.selectedBlock = null;
      this.pollError = "";
      if (this.timer) {
        clearInterval(this.timer);
        this.timer = null;
      }
      if (message) this.auth.error = message;
    },

    startPolling() {
      if (this.timer) clearInterval(this.timer);
      this.nextPollSecs = 15;
      this.poll();
      this.timer = setInterval(() => {
        if (!this.autoRefresh) return;
        this.nextPollSecs = Math.max(0, this.nextPollSecs - 1);
        if (this.nextPollSecs <= 0) this.poll();
      }, 1000);
    },

    manualRefresh() {
      this.poll();
    },

    refreshLabel() {
      if (!this.autoRefresh) return "Refresh";
      const secs = String(this.nextPollSecs).padStart(2, "0");
      return "Refresh " + secs + "s";
    },

    toggleAutoRefresh() {
      this.autoRefresh = !this.autoRefresh;
      if (this.autoRefresh) {
        this.nextPollSecs = 15;
        this.poll();
      }
    },

    async poll() {
      try {
        await this.refreshAll();
        this.pollError = "";
        this.lastUpdated = new Date();
      } catch (e) {
        if (e.message !== "unauthorized") {
          this.pollError = "Refresh failed: " + (e.message || e);
        }
      } finally {
        this.nextPollSecs = 15;
      }
    },

    async refreshAll() {
      const [metricsText, chainResp] = await Promise.all([
        this.api("/metrics").then((r) => r.text()),
        this.api("/chain_info").then((r) => r.json()),
      ]);
      this.metrics = this.parseMetrics(metricsText);
      this.chainInfo = chainResp;
      const counters = this.snapshotWork();
      this.updateWorkWindow(counters);
      this.updateAnchors();
      this.updateHsSeries();
      this.updateMinerConnSeries();
      const views = [this.refreshView()];
      await Promise.all(views);
      this.updatePoolSeries();
      this.updateNetSeries();
      this.updateNetDiffSeries();
      this.prevCounters = counters;
    },

    async refreshView() {
      if (!this.authenticated) return;
      const resp = await this.api("/shares?num=100");
      const data = await resp.json();
      this.shares = data.shares || [];
      this.trackShareTip();
      if (this.route.name === "miner" && this.minerQuery) {
        await this.loadMiner({ silent: true });
      }
    },

    trackShareTip() {
      if (!this.shares.length) return;
      const tip = this.shares[0].height;
      if (this.lastShareHeight === null) {
        this.lastShareHeight = tip;
        return;
      }
      if (tip > this.lastShareHeight) {
        this.lastShareHeight = tip;
        const cur = this.snapshotWork();
        const pre = {};
        for (const key in cur) {
          const prev = this.prevCounters[key];
          pre[key] =
            prev === undefined ? 0 : prev <= cur[key] ? prev : cur[key];
        }
        this.workBaseline = pre;
      }
    },

    snapshotWork() {
      const out = {};
      const series = this.metricSeries("user_shares_valid_total");
      for (let i = 0; i < series.length; i++) {
        out[series[i].labels.btcaddress || ""] = series[i].value;
      }
      const workerSeries = this.metricSeries("worker_shares_valid_total");
      for (let i = 0; i < workerSeries.length; i++) {
        const s = workerSeries[i];
        out[
          (s.labels.btcaddress || "") + "|" + (s.labels.workername || "")
        ] = s.value;
      }
      return out;
    },

    updateWorkWindow(current) {
      let total = 0;
      for (const addr in current) {
        if (addr.indexOf("|") < 0) total += current[addr];
      }
      if (this.prevWorkTotal !== null && total < this.prevWorkTotal) {
        this.workBaseline = null;
        this.minerAnchor = null;
        this.poolAnchor = null;
        this.hsSeries = [];
        this.prevCounters = {};
      }
      this.prevWorkTotal = total;
      for (const key in current) {
        const addr = key.indexOf("|") < 0 ? key : key.slice(0, key.indexOf("|"));
        if (this.knownAddresses.indexOf(addr) < 0) {
          this.knownAddresses.push(addr);
        }
        if (key.indexOf("|") >= 0 && this.knownWorkers.indexOf(key) < 0) {
          this.knownWorkers.push(key);
        }
      }
      if (this.workBaseline === null) this.workBaseline = current;
    },

    updateAnchors() {
      const now = Date.now() / 1000;
      const series = this.metricSeries("user_shares_valid_total");
      const current = {};
      for (let i = 0; i < series.length; i++) {
        current[series[i].labels.btcaddress || ""] = series[i].value;
      }
      if (this.minerAnchor === null) {
        this.minerAnchor = { t: now, byAddress: current };
      } else {
        const addrs = Object.keys(current);
        for (let i = 0; i < addrs.length; i++) {
          const prev = this.minerAnchor.byAddress[addrs[i]];
          if (prev === undefined || current[addrs[i]] < prev) {
            this.minerAnchor.byAddress[addrs[i]] = current[addrs[i]];
          }
        }
      }
      const diff = this.metricNum("accepted_difficulty_total");
      if (this.poolAnchor === null) {
        this.poolAnchor = { t: now, diff: diff };
      } else if (diff < this.poolAnchor.diff) {
        this.poolAnchor = { t: now, diff: diff };
      }
    },

    addrWorkFrom(key, current) {
      if (!this.workBaseline) return 0;
      const base =
        this.workBaseline[key] !== undefined ? this.workBaseline[key] : 0;
      if (current === undefined) current = 0;
      return Math.max(0, current - base);
    },

    minerWork(addr) {
      const series = this.metricSeries("user_shares_valid_total");
      let current;
      for (let i = 0; i < series.length; i++) {
        if ((series[i].labels.btcaddress || "") === addr) {
          current = series[i].value;
        }
      }
      return this.addrWorkFrom(addr, current) / 4294967296;
    },

    workerWork(key) {
      const bar = key.indexOf("|");
      const addr = key.slice(0, bar);
      const workername = key.slice(bar + 1);
      const series = this.metricSeries("worker_shares_valid_total");
      let current;
      for (let i = 0; i < series.length; i++) {
        if (
          series[i].labels.btcaddress === addr &&
          series[i].labels.workername === workername
        ) {
          current = series[i].value;
        }
      }
      return this.addrWorkFrom(key, current) / 4294967296;
    },

    async loadMiner(opts) {
      const silent = !!(opts && opts.silent);
      const addr = this.minerQuery.trim();
      if (!addr) {
        if (!silent) this.minerError = "Enter an address first.";
        return;
      }
      if (!silent) {
        this.minerLoading = true;
        this.minerError = "";
      }
      try {
        const resp = await this.api("/miner?address=" + encodeURIComponent(addr));
        this.miner = await resp.json();
        if (this.route.name === "miner" && this.route.param !== addr) {
          location.hash = "#/miner/" + addr;
        }
      } catch (e) {
        if (e.message !== "unauthorized") {
          this.miner = null;
          this.minerError =
            e.message.indexOf("HTTP 4") === 0
              ? "Address not found in this pool's window (HTTP 4xx). Check the cashaddr."
              : "Lookup failed: " + e.message;
        }
      } finally {
        if (!silent) this.minerLoading = false;
      }
      this.minerShares = this.recentSharesFor(addr);
    },

    recentSharesFor(addr) {
      const key = (addr || "").trim();
      if (!key) return [];
      return this.shares.filter(function (s) {
        return s.miner_bitcoin_address === key || s.miner_address === key;
      });
    },

    parseMetrics(text) {
      const out = {};
      const labelRe = /([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"/g;
      for (const line of text.split("\n")) {
        if (!line || line.charAt(0) === "#") continue;
        const idx = line.lastIndexOf(" ");
        if (idx <= 0) continue;
        const namePart = line.slice(0, idx);
        const value = parseFloat(line.slice(idx + 1));
        if (!isFinite(value)) continue;
        let name = namePart;
        const labels = {};
        const brace = namePart.indexOf("{");
        if (brace >= 0) {
          name = namePart.slice(0, brace);
          const labelStr = namePart.slice(brace + 1, namePart.lastIndexOf("}"));
          let m;
          labelRe.lastIndex = 0;
          while ((m = labelRe.exec(labelStr)) !== null) {
            labels[m[1]] = m[2].replace(/\\"/g, '"').replace(/\\\\/g, "\\");
          }
        }
        if (!out[name]) out[name] = [];
        out[name].push({ labels: labels, value: value });
      }
      return out;
    },

    metricSeries(name) {
      return this.metrics[name] || [];
    },

    metricNum(name) {
      const s = this.metricSeries(name);
      return s.length ? s[0].value : 0;
    },

    updateHsSeries() {
      if (!this.poolAnchor) return;
      const now = Date.now() / 1000;
      const diff = this.metricNum("accepted_difficulty_total");
      if (diff < this.poolAnchor.diff) return;
      const last = this.hsSeries.length
        ? this.hsSeries[this.hsSeries.length - 1]
        : null;
      if (last && now - last.t < 60) return;
      this.hsSeries.push({ t: now, diff: diff });
      if (this.hsSeries.length > 1440) this.hsSeries.shift();
      this.persistHsSeries();
    },

    persistHsSeries() {
      try {
        localStorage.setItem("dashv1-hs", JSON.stringify(this.hsSeries));
      } catch (e) {
        /* storage unavailable or quota: keep in-memory only */
      }
    },

    loadHsSeries() {
      try {
        const raw = JSON.parse(localStorage.getItem("dashv1-hs") || "[]");
        if (!Array.isArray(raw)) return;
        const out = [];
        for (let i = 0; i < raw.length; i++) {
          const s = raw[i];
          if (s && isFinite(s.t) && isFinite(s.diff)) out.push(s);
        }
        this.hsSeries = out;
      } catch (e) {
        /* corrupted payload: start fresh */
      }
    },

    connectedCount() {
      const seen = {};
      const series = this.metricSeries("user_shares_valid_total");
      for (let i = 0; i < series.length; i++) {
        seen[series[i].labels.btcaddress || ""] = 1;
      }
      return Object.keys(seen).length;
    },

    updateMinerConnSeries() {
      const now = Date.now() / 1000;
      const n = this.connectedCount();
      const last = this.minerConnSeries.length
        ? this.minerConnSeries[this.minerConnSeries.length - 1]
        : null;
      if (last && last.n === n && now - last.t < 60) return;
      this.minerConnSeries.push({ t: now, n: n });
      if (this.minerConnSeries.length > 2880) this.minerConnSeries.shift();
      this.persistMinerConnSeries();
    },

    persistMinerConnSeries() {
      try {
        localStorage.setItem(
          "dashv1-mc",
          JSON.stringify(this.minerConnSeries),
        );
      } catch (e) {
        /* storage unavailable or quota: keep in-memory only */
      }
    },

    loadMinerConnSeries() {
      try {
        const raw = JSON.parse(localStorage.getItem("dashv1-mc") || "[]");
        if (!Array.isArray(raw)) return;
        const out = [];
        for (let i = 0; i < raw.length; i++) {
          const s = raw[i];
          if (s && isFinite(s.t) && isFinite(s.n)) out.push({ t: s.t, n: s.n });
        }
        this.minerConnSeries = out;
      } catch (e) {
        /* corrupted payload: start fresh */
      }
    },

    updatePoolSeries() {
      const hr = this.chainHashrate();
      if (!(hr > 0)) return;
      const now = Date.now() / 1000;
      const last = this.poolSeries.length
        ? this.poolSeries[this.poolSeries.length - 1]
        : null;
      if (last && now - last.t < 60) return;
      this.poolSeries.push({ t: now, hr: hr });
      if (this.poolSeries.length > 2880) this.poolSeries.shift();
      this.persistPoolSeries();
    },

    persistPoolSeries() {
      try {
        localStorage.setItem("dashv1-po", JSON.stringify(this.poolSeries));
      } catch (e) {
        /* storage unavailable or quota: keep in-memory only */
      }
    },

    loadPoolSeries() {
      try {
        const raw = JSON.parse(localStorage.getItem("dashv1-po") || "[]");
        if (!Array.isArray(raw)) return;
        const out = [];
        for (let i = 0; i < raw.length; i++) {
          const s = raw[i];
          if (s && isFinite(s.t) && isFinite(s.hr)) out.push({ t: s.t, hr: s.hr });
        }
        this.poolSeries = out;
      } catch (e) {
        /* corrupted payload: start fresh */
      }
    },

    updateNetSeries() {
      const hr = this.netHashrate();
      if (!(hr > 0)) return;
      const now = Date.now() / 1000;
      const last = this.netSeries.length
        ? this.netSeries[this.netSeries.length - 1]
        : null;
      if (last && last.hr === hr && now - last.t < 60) return;
      this.netSeries.push({ t: now, hr: hr });
      if (this.netSeries.length > 2880) this.netSeries.shift();
      this.persistNetSeries();
    },

    persistNetSeries() {
      try {
        localStorage.setItem("dashv1-net", JSON.stringify(this.netSeries));
      } catch (e) {
        /* storage unavailable or quota: keep in-memory only */
      }
    },

    loadNetSeries() {
      try {
        const raw = JSON.parse(localStorage.getItem("dashv1-net") || "[]");
        if (!Array.isArray(raw)) return;
        const out = [];
        for (let i = 0; i < raw.length; i++) {
          const s = raw[i];
          if (s && isFinite(s.t) && isFinite(s.hr)) out.push({ t: s.t, hr: s.hr });
        }
        this.netSeries = out;
      } catch (e) {
        /* corrupted payload: start fresh */
      }
    },

    updateNetDiffSeries() {
      const nd = this.metricNum("network_difficulty");
      if (!(nd > 0)) return;
      const now = Date.now() / 1000;
      const last = this.netDiffSeries.length
        ? this.netDiffSeries[this.netDiffSeries.length - 1]
        : null;
      if (last && last.nd === nd && now - last.t < 60) return;
      this.netDiffSeries.push({ t: now, nd: nd });
      if (this.netDiffSeries.length > 2880) this.netDiffSeries.shift();
      this.persistNetDiffSeries();
    },

    persistNetDiffSeries() {
      try {
        localStorage.setItem("dashv1-nd", JSON.stringify(this.netDiffSeries));
      } catch (e) {
        /* storage unavailable or quota: keep in-memory only */
      }
    },

    loadNetDiffSeries() {
      try {
        const raw = JSON.parse(localStorage.getItem("dashv1-nd") || "[]");
        if (!Array.isArray(raw)) return;
        const out = [];
        for (let i = 0; i < raw.length; i++) {
          const s = raw[i];
          if (s && isFinite(s.t) && isFinite(s.nd)) out.push({ t: s.t, nd: s.nd });
        }
        this.netDiffSeries = out;
      } catch (e) {
        /* corrupted payload: start fresh */
      }
    },

    toggleLegend(key) {
      if (!(key in this.legendOn)) return;
      this.legendOn[key] = !this.legendOn[key];
      try {
        localStorage.setItem("dashv1-legend", JSON.stringify(this.legendOn));
      } catch (e) {
        /* storage unavailable: keep in-memory toggle only */
      }
    },

    resetLegend() {
      this.legendOn = {
        pool: true, local: true, net: false, diff: false,
        shares: false, miners: false, netdiff: false, blocks: false,
      };
      try {
        localStorage.setItem("dashv1-legend", JSON.stringify(this.legendOn));
      } catch (e) {
        /* storage unavailable: keep in-memory reset only */
      }
    },

    loadLegendOn() {
      try {
        const raw = JSON.parse(localStorage.getItem("dashv1-legend") || "null");
        if (raw && typeof raw === "object") {
          if (raw.pool === true || raw.pool === false) this.legendOn.pool = raw.pool;
          if (raw.local === true || raw.local === false)
            this.legendOn.local = raw.local;
          if (raw.net === true || raw.net === false) this.legendOn.net = raw.net;
          if (raw.diff === true || raw.diff === false) this.legendOn.diff = raw.diff;
          if (raw.shares === true || raw.shares === false)
            this.legendOn.shares = raw.shares;
          if (raw.miners === true || raw.miners === false)
            this.legendOn.miners = raw.miners;
          if (raw.netdiff === true || raw.netdiff === false)
            this.legendOn.netdiff = raw.netdiff;
          if (raw.blocks === true || raw.blocks === false)
            this.legendOn.blocks = raw.blocks;
        }
      } catch (e) {
        /* corrupted payload: keep defaults */
      }
    },

    minerHashrate(addr) {
      if (!this.minerAnchor) return 0;
      const t0 = this.minerAnchor.t;
      const prev = this.minerAnchor.byAddress[addr];
      if (prev === undefined) return 0;
      const series = this.metricSeries("user_shares_valid_total");
      let current;
      for (let i = 0; i < series.length; i++) {
        if ((series[i].labels.btcaddress || "") === addr) {
          current = series[i].value;
        }
      }
      if (current === undefined) current = prev;
      const dt = Date.now() / 1000 - t0;
      if (dt < 60 || current < prev) return 0;
      return (current - prev) / dt;
    },

    avgShareDifficulty() {
      const diff = this.metricNum("accepted_difficulty_total");
      const count = this.metricNum("shares_accepted_total");
      if (count <= 0) return 0;
      return diff / count;
    },

    minerTimeToShareSecs(addr) {
      const hs = this.minerHashrate(addr);
      const diff = this.avgShareDifficulty();
      if (hs <= 0 || diff <= 0) return 0;
      return (diff * 4294967296) / hs;
    },

    minerLastSeen(addr) {
      const series = this.metricSeries("worker_last_share_at");
      let latest = 0;
      for (let i = 0; i < series.length; i++) {
        if (series[i].labels.btcaddress !== addr) continue;
        if (series[i].value > latest) latest = series[i].value;
      }
      return latest;
    },

    minerWorkers(addr) {
      const sharesSeries = this.metricSeries("worker_shares_valid_total");
      const bestSeries = this.metricSeries("worker_best_share");
      const seenSeries = this.metricSeries("worker_last_share_at");
      const bestBy = {};
      const seenBy = {};
      let i;
      for (i = 0; i < bestSeries.length; i++) {
        bestBy[
          bestSeries[i].labels.btcaddress + "|" + bestSeries[i].labels.workername
        ] = bestSeries[i].value;
      }
      for (i = 0; i < seenSeries.length; i++) {
        seenBy[
          seenSeries[i].labels.btcaddress +
            "|" +
            seenSeries[i].labels.workername
        ] = seenSeries[i].value;
      }
      const out = [];
      const seen = {};
      for (i = 0; i < sharesSeries.length; i++) {
        const s = sharesSeries[i];
        if (s.labels.btcaddress !== addr) continue;
        const key = addr + "|" + s.labels.workername;
        seen[key] = true;
        out.push({
          name: s.labels.workername || "unnamed",
          shares: this.workerWork(key),
          best: bestBy[key] || 0,
          lastShare: seenBy[key] || 0,
        });
      }
      for (i = 0; i < this.knownWorkers.length; i++) {
        const key = this.knownWorkers[i];
        if (seen[key] || key.indexOf(addr + "|") !== 0) continue;
        const workername = key.slice(addr.length + 1);
        out.push({
          name: workername || "unnamed",
          shares: this.workerWork(key),
          best: bestBy[key] || 0,
          lastShare: seenBy[key] || 0,
        });
      }
      out.sort(function (a, b) {
        return b.shares - a.shares;
      });
      return out;
    },

    toggleMiner(addr) {
      this.expanded[addr] = !this.expanded[addr];
    },

    get pagedShares() {
      const start = this.sharesPage * this.sharesPerPage;
      const page = this.shares.slice(start, start + this.sharesPerPage);
      const rows = [];
      for (let idx = 0; idx < page.length; idx++) {
        const share = page[idx];
        rows.push({ share: share, isUncle: false });
        for (
          let uncleIdx = 0;
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

    connectWebSocket() {
      this.closeWebSocket();
      if (!this.authenticated || !this.authHeader) return;
      const protocol =
        window.location.protocol === "https:" ? "wss:" : "ws:";
      const token = encodeURIComponent(this.authHeader.slice(6));
      const url =
        protocol + "//" + window.location.host + "/ws?token=" + token;
      try {
        this.websocket = new WebSocket(url);
      } catch (e) {
        this.scheduleWsRetry();
        return;
      }
      this.websocket.onopen = () => {
        this.wsConnected = true;
        if (this.wsRetryTimer) {
          clearTimeout(this.wsRetryTimer);
          this.wsRetryTimer = null;
        }
        this.websocket.send(
          JSON.stringify({ action: "subscribe", topic: "shares" }),
        );
      };
      this.websocket.onmessage = (event) => {
        let message;
        try {
          message = JSON.parse(event.data);
        } catch (e) {
          return;
        }
        this.handleWsMessage(message);
      };
      this.websocket.onclose = () => {
        this.wsConnected = false;
        this.websocket = null;
        this.scheduleWsRetry();
      };
      this.websocket.onerror = () => {
        this.wsConnected = false;
      };
    },

    scheduleWsRetry() {
      if (!this.authenticated || this.wsRetryTimer) return;
      this.wsRetryTimer = setTimeout(() => {
        this.wsRetryTimer = null;
        this.connectWebSocket();
      }, 5000);
    },

    closeWebSocket() {
      if (this.wsRetryTimer) {
        clearTimeout(this.wsRetryTimer);
        this.wsRetryTimer = null;
      }
      if (this.websocket) {
        this.websocket.onclose = null;
        this.websocket.onmessage = null;
        this.websocket.onerror = null;
        try {
          this.websocket.close();
        } catch (e) {
          /* socket already closed */
        }
        this.websocket = null;
      }
      this.wsConnected = false;
    },

    handleWsMessage(message) {
      if (message.topic !== "Share") return;
      this.handleWsShare(message.data);
    },

    handleWsShare(share) {
      if (!share || !share.blockhash) return;
      let seen = false;
      for (let i = 0; i < this.shares.length; i++) {
        if (this.shares[i].blockhash === share.blockhash) {
          seen = true;
          break;
        }
      }
      if (!seen) {
        this.shares.unshift(share);
        if (this.shares.length > 1000) {
          this.shares.length = 1000;
        }
      }
      if (this.chainInfo) {
        this.chainInfo.chain_tip_height = share.height;
        this.chainInfo.chain_tip_blockhash = share.blockhash;
        if (!seen && share.bits) {
          const work = workFromBits(share.bits);
          const currentWork = BigInt(this.chainInfo.total_work || "0x0");
          this.chainInfo.total_work =
            "0x" +
            (currentWork + work).toString(16).padStart(64, "0");
        }
      }
      this.applyDocTitle();
      this.trackShareTip();
    },

    // Local hashrate over the last hour: accepted-difficulty delta between
    // hsSeries snapshots inside the window. Matches chainHashrate()'s 1h
    // window so Local/P2POOL/Remote compare like for like. Falls back to
    // the lifetime average when fewer than two snapshots fall in the window.
    poolHashrate() {
      const now = Date.now() / 1000;
      const cutoff = now - 3600;
      const s = this.hsSeries;
      let first = -1;
      for (let i = 0; i < s.length; i++) {
        if (s[i].t >= cutoff) {
          first = i;
          break;
        }
      }
      if (first >= 0 && first < s.length - 1) {
        const a = s[first];
        const b = s[s.length - 1];
        const dt = b.t - a.t;
        const dd = b.diff - a.diff;
        if (dt > 0) return dd > 0 ? (dd * 4294967296) / dt : 0;
      }
      return this.lifetimeHashrate();
    },

    lifetimeHashrate() {
      const start = this.metricNum("start_time_seconds");
      const diff = this.metricNum("accepted_difficulty_total");
      if (start > 0 && diff > 0) {
        const dt = Date.now() / 1000 - start;
        if (dt > 60) return (diff * 4294967296) / dt;
      }
      return 0;
    },

    // Hover tooltip for the Local KPI: names the exact window behind the
    // number. 2+ snapshots in the last hour -> span between first/last used;
    // otherwise the lifetime fallback reports "since start / uptime".
    localWindowHint() {
      const hr = this.poolHashrate();
      if (hr === 0) return "";
      const now = Date.now() / 1000;
      const cutoff = now - 3600;
      const s = this.hsSeries;
      let first = -1;
      for (let i = 0; i < s.length; i++) {
        if (s[i].t >= cutoff) {
          first = i;
          break;
        }
      }
      if (first >= 0 && first < s.length - 1) {
        const span = s[s.length - 1].t - s[first].t;
        if (span > 0) {
          return (s.length - first) + "-sample window / " + this.fmtDuration(span);
        }
      }
      const start = this.metricNum("start_time_seconds");
      if (start > 0) {
        return "since start / " + this.fmtDuration(now - start);
      }
      return "";
    },

    chainWindowShares() {
      const shares = this.shares;
      if (!shares || !shares.length) return [];
      const cutoff = Date.now() / 1000 - 3600;
      const out = [];
      for (let i = 0; i < shares.length; i++) {
        if (shares[i].timestamp < cutoff) break;
        out.push(shares[i]);
      }
      if (out.length < 2) return shares;
      return out;
    },

    chainHashrate() {
      const shares = this.chainWindowShares();
      if (!shares || shares.length < 2) return 0;
      let work = 0;
      for (let i = 0; i < shares.length; i++) {
        const bits = shares[i].bits;
        if (!isFinite(bits) || bits <= 0) continue;
        work += this.difficultyFromBits(bits >>> 0) * 4294967296;
      }
      const newest = shares[0].timestamp;
      const oldest = shares[shares.length - 1].timestamp;
      const span = newest - oldest;
      if (!(span > 0) || work <= 0) return 0;
      return work / span;
    },

    remoteHashrate() {
      const chain = this.chainHashrate();
      const local = this.poolHashrate();
      return chain > local ? chain - local : 0;
    },

    chainWindowNote() {
      const shares = this.chainWindowShares();
      if (!shares || shares.length < 2) return "Share chain: collecting...";
      const span = shares[0].timestamp - shares[shares.length - 1].timestamp;
      return (
        "Share chain, last " + shares.length + " shares / " + this.fmtDuration(span)
      );
    },

    chainWindowHint() {
      const shares = this.chainWindowShares();
      if (!shares || shares.length < 2) return "";
      const span = shares[0].timestamp - shares[shares.length - 1].timestamp;
      return (
        shares.length + "-share window / " + this.fmtDuration(span)
      );
    },

    blockEffortPct() {
      const net = this.metricNum("network_difficulty");
      const work = this.metricNum("work_since_last_block");
      if (net <= 0) return 0;
      return (100 * work) / net;
    },

    timeToBlockSecs() {
      const net = this.metricNum("network_difficulty");
      const hs = this.lifetimeHashrate();
      if (net <= 0 || hs <= 0) return 0;
      return (net * 4294967296) / hs;
    },

    netHashrate() {
      const net = this.metricNum("network_difficulty");
      return (net * 4294967296) / 600;
    },

    shareEfficiencyPct() {
      const acc = this.metricNum("shares_accepted_total");
      const rej = this.metricNum("shares_rejected_total");
      const total = acc + rej;
      if (total <= 0) return 0;
      return (100 * acc) / total;
    },

    uptimeSeconds() {
      const start = this.metricNum("start_time_seconds");
      return start > 0 ? Date.now() / 1000 - start : 0;
    },

    // Convert a legacy base58 miner label to CashAddr so the #/miner/ link
    // resolves; already-cashaddr labels pass through, failures return raw.
    // `network` uses bitcoin core names (main, testnet4, signet, regtest)
    // but the live metric has historically emitted "test".
    minerCash(minerLabel, networkLabel) {
      if (!minerLabel) return minerLabel;
      if (minerLabel.indexOf(":") >= 0) return minerLabel;
      const decoded = b58DecodeLegacy(minerLabel);
      if (!decoded) return minerLabel;
      const prefix =
        networkLabel === "main" ? "bitcoincash"
        : networkLabel === "regtest" ? "bchreg"
        : "bchtest";
      const type = decoded.version === 0x05 || decoded.version === 0xc4 ? 1 : 0;
      const cashaddr = cashAddrEncode(prefix, type, decoded.hash);
      return cashaddr || minerLabel;
    },

    blockList() {
      const series = this.metricSeries("bitcoin_block_found_time_seconds");
      const self = this;
      return series
        .map(function (x) {
          return {
            height: parseInt(x.labels.height, 10) || 0,
            hash: x.labels.blockhash || "",
            miner: self.minerCash(x.labels.miner || "", x.labels.network || ""),
            legacy: x.labels.miner || "",
            network: x.labels.network || "",
            time: x.value,
          };
        })
        .sort(function (a, b) {
          return b.height - a.height;
        });
    },

    lastBlockSubtitle() {
      const blocks = this.blockList();
      if (!blocks.length) return "";
      return "Last " + this.fmtTimeAgo(blocks[0].time);
    },

    minerList() {
      const series = this.metricSeries("user_shares_valid_total");
      const current = {};
      for (let i = 0; i < series.length; i++) {
        current[series[i].labels.btcaddress || ""] = series[i].value;
      }
      let total = 0;
      const rows = [];
      const list = this.knownAddresses.slice();
      for (let i = 0; i < list.length; i++) {
        if (current[list[i]] === undefined) current[list[i]] = 0;
      }
      for (const addr in current) {
        const work = this.minerWork(addr);
        total += work;
        rows.push({ address: addr, shares: work });
      }
      for (let i = 0; i < rows.length; i++) {
        rows[i].pct = total > 0 ? (100 * rows[i].shares) / total : 0;
      }
      rows.sort(function (a, b) {
        return b.shares - a.shares;
      });
      return rows;
    },

    chartWindowSecs() {
      return this.chartRange === "1h"
        ? 3600
        : this.chartRange === "6h"
          ? 6 * 3600
          : 24 * 3600;
    },

    localSpanSecs() {
      return this.chartRange === "1h"
        ? 300
        : this.chartRange === "6h"
          ? 900
          : 1800;
    },

    localRateAt(hs, i, span) {
      const target = hs[i].t - span;
      let base = null;
      for (let j = i - 1; j >= 0; j--) {
        if (hs[j].t <= target) {
          base = hs[j];
          break;
        }
      }
      if (!base) {
        if (i === 0) return null;
        base = hs[i - 1];
      }
      const dt = hs[i].t - base.t;
      if (!(dt > 0)) return null;
      const rate = ((hs[i].diff - base.diff) * 4294967296) / dt;
      if (hs[i].diff !== base.diff) return rate;
      // Flat span window (no share in span): extend back to the nearest
      // earlier sample with strictly less work instead of reporting 0.
      for (let j = i - 1; j >= 0; j--) {
        if (hs[j].diff < hs[i].diff) {
          const extDt = hs[i].t - hs[j].t;
          if (extDt > 0) {
            return ((hs[i].diff - hs[j].diff) * 4294967296) / extDt;
          }
          break;
        }
      }
      return rate;
    },

    chartSamples() {
      const windowSecs = this.chartWindowSecs();
      const span = this.localSpanSecs();
      const now = Date.now() / 1000;
      const hs = this.hsSeries;
      const idxs = [];
      for (let i = 0; i < hs.length; i++) {
        if (hs[i].t >= now - windowSecs) idxs.push(i);
      }
      if (idxs.length < 2) return [];
      const pts = [];
      for (let k = 0; k < idxs.length; k++) {
        const hr = this.localRateAt(hs, idxs[k], span);
        if (hr === null) continue;
        pts.push({ t: hs[idxs[k]].t, hs: hr });
      }
      if (pts.length < 2) return [];
      const max = Math.max.apply(
        null,
        pts.map(function (p) {
          return p.hs;
        }),
      );
      if (max <= 0) return pts;
      let sum = 0;
      for (let i = 0; i < pts.length; i++) sum += pts[i].hs;
      const mean = sum / pts.length;
      for (let i = 0; i < pts.length; i++) {
        if (pts[i].hs > mean * 3) pts[i].hs = mean * 3;
      }
      return pts;
    },

    chartRangeNote() {
      return "smoothed";
    },

    rawMaxOf(samples) {
      let max = 0;
      for (let i = 0; i < samples.length; i++) {
        if (samples[i].hs > max) max = samples[i].hs;
      }
      return max;
    },

    chartMaxOf(samples) {
      const max = this.rawMaxOf(samples);
      return max > 0 ? max * 1.15 : 1;
    },

    visibleHashSeries() {
      const out = [];
      if (this.legendOn.pool) out.push({ key: "pool", samples: this.poolSamples() });
      if (this.legendOn.local) out.push({ key: "local", samples: this.chartSamples() });
      if (this.legendOn.net) out.push({ key: "net", samples: this.netSamples() });
      return out;
    },

    combinedMax() {
      let max = 0;
      const vis = this.visibleHashSeries();
      for (let i = 0; i < vis.length; i++) {
        const m = this.rawMaxOf(vis[i].samples);
        if (m > max) max = m;
      }
      return max > 0 ? max * 1.15 : 1;
    },

    hashChartVisibleCount() {
      const vis = this.visibleHashSeries();
      let n = 0;
      for (let i = 0; i < vis.length; i++) {
        if (vis[i].samples.length >= 2) n++;
      }
      if (this.legendOn.diff && this.diffSamples().length >= 2) n++;
      if (this.legendOn.shares && this.shareDotPoints().length >= 1) n++;
      if (this.legendOn.miners && this.mchartSamples().length >= 2) n++;
      if (this.legendOn.netdiff && this.netDiffSamples().length >= 2) n++;
      if (this.legendOn.blocks && this.blockDotPoints().length >= 1) n++;
      return n;
    },

    hashEmptyNote() {
      if (
        !this.legendOn.pool &&
        !this.legendOn.local &&
        !this.legendOn.net &&
        !this.legendOn.diff &&
        !this.legendOn.shares &&
        !this.legendOn.miners &&
        !this.legendOn.netdiff &&
        !this.legendOn.blocks
      ) {
        return "All series hidden. Click a legend chip to show one.";
      }
      if (
        this.hsSeries.length < 2 &&
        this.poolSeries.length < 2 &&
        this.netSeries.length < 2
      ) {
        return "Collecting samples... chart appears after the second minute of uptime.";
      }
      return "Not enough samples in this range yet.";
    },

    poolSamples() {
      const windowSecs = this.chartWindowSecs();
      const now = Date.now() / 1000;
      const out = [];
      const s = this.poolSeries;
      for (let i = 0; i < s.length; i++) {
        if (s[i].t >= now - windowSecs) out.push({ t: s[i].t, hs: s[i].hr });
      }
      if (out.length < 2) return [];
      return out;
    },

    netSamples() {
      const windowSecs = this.chartWindowSecs();
      const now = Date.now() / 1000;
      const out = [];
      const s = this.netSeries;
      for (let i = 0; i < s.length; i++) {
        if (s[i].t >= now - windowSecs) out.push({ t: s[i].t, hs: s[i].hr });
      }
      if (out.length < 2) return [];
      return out;
    },

    diffSamples() {
      const { t0, t1 } = this.chartDomain();
      const out = [];
      const s = this.shares;
      for (let i = 0; i < s.length; i++) {
        if (!s[i].bits) continue;
        if (s[i].timestamp >= t0 && s[i].timestamp <= t1) {
          out.push({ t: s[i].timestamp, hs: this.difficultyFromBits(s[i].bits) });
        }
      }
      out.sort((a, b) => a.t - b.t);
      return out;
    },

    diffMaxOf() {
      const samples = this.diffSamples();
      let max = 0;
      for (let i = 0; i < samples.length; i++) {
        if (samples[i].hs > max) max = samples[i].hs;
      }
      return max > 0 ? max * 1.15 : 1;
    },

    lineDiff() {
      if (!this.legendOn.diff) return "";
      const samples = this.diffSamples();
      if (samples.length < 2) return "";
      const { t0, t1 } = this.chartDomain();
      return this.chartLineFrom(samples, this.diffMaxOf(), t0, t1);
    },

    netDiffSamples() {
      const { t0, t1 } = this.chartDomain();
      const out = [];
      const s = this.netDiffSeries;
      for (let i = 0; i < s.length; i++) {
        if (s[i].t >= t0 && s[i].t <= t1) out.push({ t: s[i].t, hs: s[i].nd });
      }
      out.sort((a, b) => a.t - b.t);
      return out;
    },

    netDiffMaxOf() {
      const samples = this.netDiffSamples();
      let max = 0;
      for (let i = 0; i < samples.length; i++) {
        if (samples[i].hs > max) max = samples[i].hs;
      }
      const current = this.metricNum("network_difficulty");
      if (current > max) max = current;
      return max > 0 ? max * 1.15 : 1;
    },

    lineNetDiff() {
      if (!this.legendOn.netdiff) return "";
      const samples = this.netDiffSamples();
      if (samples.length < 2) return "";
      const { t0, t1 } = this.chartDomain();
      return this.chartLineFrom(samples, this.netDiffMaxOf(), t0, t1);
    },

    netDiffAt(t) {
      const samples = this.netDiffSamples();
      const n = samples.length;
      if (n === 0) return this.metricNum("network_difficulty") || null;
      if (t <= samples[0].t) return samples[0].hs;
      if (t >= samples[n - 1].t) return samples[n - 1].hs;
      for (let i = 1; i < n; i++) {
        if (t <= samples[i].t) {
          const span = samples[i].t - samples[i - 1].t;
          if (span <= 0) return samples[i].hs;
          const frac = (t - samples[i - 1].t) / span;
          return (
            samples[i - 1].hs + frac * (samples[i].hs - samples[i - 1].hs)
          );
        }
      }
      return samples[n - 1].hs;
    },

    chartDomain() {
      const now = Date.now() / 1000;
      return { t0: now - this.chartWindowSecs(), t1: now };
    },

    chartCoordsOf(samples, max, t0, t1) {
      const n = samples.length;
      if (n < 2) return [];
      const span = t1 - t0 > 0 ? t1 - t0 : 1;
      const pts = [];
      for (let i = 0; i < n; i++) {
        const x = ((samples[i].t - t0) / span) * 548 + 48;
        const y = 158 - (samples[i].hs / max) * 150;
        pts.push([x, y]);
      }
      return pts;
    },

    linePool() {
      if (!this.legendOn.pool) return "";
      const samples = this.poolSamples();
      const { t0, t1 } = this.chartDomain();
      return this.chartLineFrom(samples, this.combinedMax(), t0, t1);
    },

    lineLocal() {
      if (!this.legendOn.local) return "";
      const samples = this.chartSamples();
      const { t0, t1 } = this.chartDomain();
      return this.chartLineFrom(samples, this.combinedMax(), t0, t1);
    },

    areaLocal() {
      if (!this.legendOn.local) return "";
      const samples = this.chartSamples();
      const max = this.combinedMax();
      const { t0, t1 } = this.chartDomain();
      return this.chartAreaFrom(samples, this.chartLineFrom(samples, max, t0, t1), max, t0, t1);
    },

    lineNet() {
      if (!this.legendOn.net) return "";
      const samples = this.netSamples();
      const { t0, t1 } = this.chartDomain();
      return this.chartLineFrom(samples, this.combinedMax(), t0, t1);
    },

    areaPool() {
      if (!this.legendOn.pool) return "";
      const samples = this.poolSamples();
      const max = this.combinedMax();
      const { t0, t1 } = this.chartDomain();
      return this.chartAreaFrom(samples, this.chartLineFrom(samples, max, t0, t1), max, t0, t1);
    },

    areaNet() {
      if (!this.legendOn.net) return "";
      const samples = this.netSamples();
      const max = this.combinedMax();
      const { t0, t1 } = this.chartDomain();
      return this.chartAreaFrom(samples, this.chartLineFrom(samples, max, t0, t1), max, t0, t1);
    },

    chartLineFrom(samples, max, t0, t1) {
      const pts = this.chartCoordsOf(samples, max, t0, t1);
      if (pts.length < 2) return "";
      let d = "M " + pts[0][0].toFixed(1) + " " + pts[0][1].toFixed(1);
      for (let i = 1; i < pts.length; i++) {
        d += " L " + pts[i][0].toFixed(1) + " " + pts[i][1].toFixed(1);
      }
      return d;
    },

    chartAreaFrom(samples, lineD, max, t0, t1) {
      const pts = this.chartCoordsOf(samples, max, t0, t1);
      if (pts.length < 2) return "";
      let d = lineD;
      d +=
        " L " +
        pts[pts.length - 1][0].toFixed(1) +
        " 158 L " +
        pts[0][0].toFixed(1) +
        " 158 Z";
      return d;
    },

    nowSec() {
      void this.lastUpdated;
      return Date.now() / 1000;
    },

    fmtAxisTime(t) {
      const d = new Date(t * 1000);
      const hh = String(d.getHours()).padStart(2, "0");
      const mm = String(d.getMinutes()).padStart(2, "0");
      return hh + ":" + mm;
    },

    fmtAbsStamp(unix) {
      const d = new Date(unix * 1000);
      const mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][d.getMonth()];
      const day = String(d.getDate());
      const hh = String(d.getHours()).padStart(2, "0");
      const mm = String(d.getMinutes()).padStart(2, "0");
      const ss = String(d.getSeconds()).padStart(2, "0");
      return mon + " " + day + ", " + hh + ":" + mm + ":" + ss;
    },

    chartStartLabel() {
      return this.fmtAxisTime(this.nowSec() - this.chartWindowSecs());
    },

    chartNowLabel() {
      return this.fmtAxisTime(this.nowSec());
    },

    yAxisTicks() {
      const max = this.combinedMax();
      const fracs = [0.75, 0.5, 0.25];
      const out = [];
      for (let i = 0; i < fracs.length; i++) {
        out.push({
          y: 158 - fracs[i] * 150,
          label: this.fmtHashrate(max * fracs[i]),
        });
      }
      return out;
    },

    xAxisTicks() {
      const secs = this.chartWindowSecs();
      let agos;
      if (secs <= 3600) agos = [2700, 1800, 900];
      else if (secs <= 21600) agos = [14400, 7200];
      else agos = [64800, 43200, 21600];
      const now = this.nowSec();
      const out = [];
      for (let i = 0; i < agos.length; i++) {
        const x = 48 + (1 - agos[i] / secs) * 548;
        out.push({ x: x, label: this.fmtAxisTime(now - agos[i]) });
      }
      return out;
    },

    tickGridHtml() {
      const yt = this.yAxisTicks();
      const xt = this.xAxisTicks();
      let html = "";
      for (let i = 0; i < yt.length; i++) {
        if (Math.abs(yt[i].y - 83) > 0.5) {
          html +=
            '<line x1="48" y1="' +
            yt[i].y +
            '" x2="600" y2="' +
            yt[i].y +
            '" stroke="#3a3d40" stroke-width="1" stroke-dasharray="4 4" vector-effect="non-scaling-stroke" opacity="0.45" />';
        }
      }
      for (let i = 0; i < xt.length; i++) {
        const x = xt[i].x.toFixed(1);
        html +=
          '<line x1="' +
          x +
          '" y1="8" x2="' +
          x +
          '" y2="158" stroke="#3a3d40" stroke-width="1" stroke-dasharray="4 4" vector-effect="non-scaling-stroke" opacity="0.45" />';
      }
      return html;
    },

    tickLabelsHtml() {
      const yt = this.yAxisTicks();
      const xt = this.xAxisTicks();
      let html = "";
      for (let i = 0; i < yt.length; i++) {
        html +=
          '<text class="chart-axis chart-axis-tick" x="4" y="' +
          (yt[i].y - 4) +
          '">' +
          yt[i].label +
          "</text>";
      }
      for (let i = 0; i < xt.length; i++) {
        html +=
          '<text class="chart-axis chart-axis-tick" x="' +
          xt[i].x.toFixed(1) +
          '" y="168" text-anchor="middle">' +
          xt[i].label +
          "</text>";
      }
      return html;
    },

    mchartSamples() {
      const windowSecs = this.chartWindowSecs();
      const now = Date.now() / 1000;
      const out = [];
      const s = this.minerConnSeries;
      for (let i = 0; i < s.length; i++) {
        if (s[i].t >= now - windowSecs) out.push({ t: s[i].t, hs: s[i].n });
      }
      if (out.length < 2) return [];
      return out;
    },

    mchartLine() {
      if (!this.legendOn.miners) return "";
      const samples = this.mchartSamples();
      const { t0, t1 } = this.chartDomain();
      return this.chartLineFrom(samples, this.chartMaxOf(samples), t0, t1);
    },

    shareDotPoints() {
      const { t0, t1 } = this.chartDomain();
      const diffMax = this.diffMaxOf();
      const out = [];
      const s = this.shares;
      for (let i = 0; i < s.length; i++) {
        const share = s[i];
        if (!share.bits) continue;
        if (share.timestamp < t0 || share.timestamp > t1) continue;
        const span = t1 - t0 > 0 ? t1 - t0 : 1;
        out.push({
          blockhash: share.blockhash,
          time: share.timestamp,
          x: ((share.timestamp - t0) / span) * 548 + 48,
          cy: 158 - (this.difficultyFromBits(share.bits) / diffMax) * 150,
        });
      }
      return out;
    },

    shareDots() {
      if (!this.legendOn.shares) return "";
      const pts = this.shareDotPoints();
      const t = this.hoverT;
      let html = "";
      for (let i = 0; i < pts.length; i++) {
        const hot = t !== null && Math.abs(pts[i].time - t) <= 90;
        if (hot) {
          html +=
            '<circle class="share-glow" cx="' +
            pts[i].x.toFixed(1) +
            '" cy="' +
            pts[i].cy.toFixed(1) +
            '" r="6" fill="none" stroke="#ffffff" stroke-width="2.5" vector-effect="non-scaling-stroke" pointer-events="none"></circle>';
        }
        html +=
          '<circle class="share-hit" cx="' +
          pts[i].x.toFixed(1) +
          '" cy="' +
          pts[i].cy.toFixed(1) +
          '" r="9" fill="transparent" data-blockhash="' +
          pts[i].blockhash +
          '"></circle>' +
          '<circle class="share-dot' +
          (hot ? " share-dot-hot" : "") +
          '" cx="' +
          pts[i].x.toFixed(1) +
          '" cy="' +
          pts[i].cy.toFixed(1) +
          '" r="2.5" fill="#ffffff" data-blockhash="' +
          pts[i].blockhash +
          '"></circle>';
      }
      return html;
    },

    shareDotClick(event) {
      const target =
        event.target && event.target.closest
          ? event.target.closest("circle[data-blockhash]")
          : null;
      if (!target) return;
      const blockhash = target.getAttribute("data-blockhash");
      const share = this.shares.find((s) => s.blockhash === blockhash);
      if (share) this.selectShare(share);
    },

    blockDotClick(event) {
      const target =
        event.target && event.target.closest
          ? event.target.closest("circle[data-blockhash]")
          : null;
      if (!target) return;
      const blockhash = target.getAttribute("data-blockhash");
      const block = this.blockList().find((b) => b.hash === blockhash);
      if (block) this.selectedBlock = block;
    },

    blockDotPoints() {
      const { t0, t1 } = this.chartDomain();
      const max = this.netDiffMaxOf();
      const out = [];
      const b = this.blockList();
      for (let i = 0; i < b.length; i++) {
        const block = b[i];
        if (!block.time || block.time < t0 || block.time > t1) continue;
        const nd = this.netDiffAt(block.time);
        if (!(nd > 0)) continue;
        const span = t1 - t0 > 0 ? t1 - t0 : 1;
        out.push({
          hash: block.hash,
          height: block.height,
          time: block.time,
          x: ((block.time - t0) / span) * 548 + 48,
          cy: 158 - (nd / max) * 150,
        });
      }
      return out;
    },

    blockDots() {
      if (!this.legendOn.blocks) return "";
      const pts = this.blockDotPoints();
      const t = this.hoverT;
      let html = "";
      for (let i = 0; i < pts.length; i++) {
        const hot = t !== null && Math.abs(pts[i].time - t) <= 90;
        if (hot) {
          html +=
            '<circle class="block-glow" cx="' +
            pts[i].x.toFixed(1) +
            '" cy="' +
            pts[i].cy.toFixed(1) +
            '" r="7" fill="none" stroke="#0ac18e" stroke-width="3" vector-effect="non-scaling-stroke" pointer-events="none"></circle>';
        }
        html +=
          '<circle class="block-hit" cx="' +
          pts[i].x.toFixed(1) +
          '" cy="' +
          pts[i].cy.toFixed(1) +
          '" r="9" fill="transparent" data-blockhash="' +
          pts[i].hash +
          '"></circle>' +
          '<circle class="block-dot' +
          (hot ? " block-dot-hot" : "") +
          '" cx="' +
          pts[i].x.toFixed(1) +
          '" cy="' +
          pts[i].cy.toFixed(1) +
          '" r="3" fill="#0ac18e" stroke="#0f172a" stroke-width="1" vector-effect="non-scaling-stroke" data-blockhash="' +
          pts[i].hash +
          '"><title>' +
          "Block " +
          pts[i].height +
          " - " +
          this.fmtHash(pts[i].hash) +
          " - " +
          this.fmtTimeAgo(pts[i].time) +
          "</title></circle>";
      }
      return html;
    },

    chartHoverMove(event) {
      if (this.touchClearTimer) {
        clearTimeout(this.touchClearTimer);
        this.touchClearTimer = null;
      }
      const src = event.touches && event.touches[0] ? event.touches[0] : event;
      const rect = event.currentTarget.getBoundingClientRect();
      const x = Math.min(rect.width, Math.max(0, src.clientX - rect.left));
      this.hoverX = x;
      const { t0, t1 } = this.chartDomain();
      const frac = rect.width > 0 ? x / rect.width : 0;
      this.hoverT = t0 + frac * (t1 - t0);
    },

    chartHoverLeave() {
      if (this.touchClearTimer) {
        clearTimeout(this.touchClearTimer);
        this.touchClearTimer = null;
      }
      this.hoverT = null;
    },

    touchEndHover() {
      if (this.touchClearTimer) clearTimeout(this.touchClearTimer);
      this.touchClearTimer = setTimeout(() => {
        this.touchClearTimer = null;
        this.hoverT = null;
      }, 150);
    },

    nearestSample(series, t, tol) {
      let useTol = tol;
      if (series.length >= 2) {
        const gap =
          (series[series.length - 1].t - series[0].t) / (series.length - 1);
        if (gap * 2 > useTol) useTol = gap * 2;
      }
      let best = null;
      let bestDist = useTol;
      for (let i = 0; i < series.length; i++) {
        const d = Math.abs(series[i].t - t);
        if (d < bestDist) {
          bestDist = d;
          best = series[i];
        }
      }
      return best;
    },

    hoverLocalHr(t) {
      const s = this.hsSeries;
      let tol = 90;
      if (s.length >= 2) {
        const gap = (s[s.length - 1].t - s[0].t) / (s.length - 1);
        if (gap * 2 > tol) tol = gap * 2;
      }
      let bestIdx = -1;
      let bestDist = tol;
      for (let i = 1; i < s.length; i++) {
        const d = Math.abs(s[i].t - t);
        if (d < bestDist) {
          bestDist = d;
          bestIdx = i;
        }
      }
      if (bestIdx < 0) return null;
      return this.localRateAt(s, bestIdx, this.localSpanSecs());
    },

    hoverTipHtml() {
      if (this.hoverT === null) return "";
      const t = this.hoverT;
      const dot = (color) => '<span class="tip-dot" style="background:' + color + '"></span>';
      const rows = ["<b>" + this.fmtAbsStamp(t) + "</b>", "<b>" + this.fmtTimeAgo(t) + "</b>"];
      if (this.legendOn.pool) {
        const s = this.nearestSample(this.poolSeries, t, 90);
        rows.push(dot("#008de4") + "Pool: " + (s ? this.fmtHashrate(s.hr) : "-"));
      }
      if (this.legendOn.local) {
        const hr = this.hoverLocalHr(t);
        rows.push(dot("#22d3ee") + "Local: " + (hr === null ? "-" : this.fmtHashrate(hr)));
      }
      if (this.legendOn.net) {
        const s = this.nearestSample(this.netSeries, t, 90);
        rows.push(dot("#8b5cf6") + "Network: " + (s ? this.fmtHashrate(s.hr) : "-"));
      }
      if (this.legendOn.diff) {
        const samples = this.diffSamples();
        rows.push(dot("#ffffff") + "Difficulty: " + this.hoverDiffAt(samples, t));
      }
      if (this.legendOn.shares) {
        const heights = [];
        for (let i = 0; i < this.shares.length; i++) {
          if (
            Math.abs(this.shares[i].timestamp - t) <= 90 &&
            this.shares[i].height != null
          ) {
            heights.push(this.shares[i].height);
          }
        }
        heights.sort((a, b) => a - b);
        rows.push(
          dot("#ffffff") +
            "Share: " +
            (heights.length ? heights.map((h) => this.fmtInt(h)).join(", ") : "-"),
        );
      }
      if (this.legendOn.miners) {
        const m = this.nearestSample(this.minerConnSeries, t, 90);
        rows.push(dot("#f59e0b") + "Miners: " + (m ? this.fmtInt(m.n) : "-"));
      }
      if (this.legendOn.netdiff) {
        const s = this.nearestSample(this.netDiffSeries, t, 90);
        rows.push(dot("#0ac18e") + "Net Diff: " + (s ? this.fmtDiff(s.nd) : "-"));
      }
      if (this.legendOn.blocks) {
        const pts = this.blockDotPoints();
        const heights = [];
        for (let i = 0; i < pts.length; i++) {
          if (Math.abs(pts[i].time - t) <= 90 && pts[i].height != null) {
            heights.push(pts[i].height);
          }
        }
        heights.sort((a, b) => a - b);
        const label = heights.length
          ? "Block: " + heights.map((h) => this.fmtInt(h)).join(", ")
          : "Block: -";
        rows.push(dot("#0ac18e") + label);
      }
      return rows.join("<br>");
    },

    hoverDiffAt(samples, t) {
      const n = samples.length;
      if (n === 0) return "-";
      if (t < samples[0].t || t > samples[n - 1].t) return "-";
      for (let i = 1; i < n; i++) {
        if (t <= samples[i].t) {
          const span = samples[i].t - samples[i - 1].t;
          if (span <= 0) return this.fmtDiff(samples[i].hs);
          const frac = (t - samples[i - 1].t) / span;
          const value =
            samples[i - 1].hs + frac * (samples[i].hs - samples[i - 1].hs);
          return this.fmtDiff(value);
        }
      }
      return this.fmtDiff(samples[n - 1].hs);
    },

    hoverStyle() {
      const left = this.hoverX > 180 ? this.hoverX - 176 : this.hoverX + 12;
      return "left: " + left.toFixed(0) + "px; top: 8px;";
    },

    tracerSnapSample(samples, t) {
      const n = samples.length;
      if (n < 2) return null;
      if (t < samples[0].t) return samples[0];
      if (t > samples[n - 1].t) return samples[n - 1];
      let best = samples[0];
      let bestDist = Math.abs(samples[0].t - t);
      for (let i = 1; i < n; i++) {
        const d = Math.abs(samples[i].t - t);
        if (d < bestDist) {
          bestDist = d;
          best = samples[i];
        }
      }
      return best;
    },

    tracerSeries() {
      const out = [];
      if (this.legendOn.local)
        out.push({ color: "#22d3ee", samples: this.chartSamples(), max: this.combinedMax() });
      if (this.legendOn.pool)
        out.push({ color: "#008de4", samples: this.poolSamples(), max: this.combinedMax() });
      if (this.legendOn.net)
        out.push({ color: "#8b5cf6", samples: this.netSamples(), max: this.combinedMax() });
      if (this.legendOn.miners) {
        const s = this.mchartSamples();
        out.push({ color: "#f59e0b", samples: s, max: this.chartMaxOf(s) });
      }
      if (this.legendOn.diff && this.legendOn.shares)
        out.push({ color: "#ffffff", samples: this.diffSamples(), max: this.diffMaxOf() });
      if (this.legendOn.netdiff)
        out.push({ color: "#0ac18e", samples: this.netDiffSamples(), max: this.netDiffMaxOf() });
      return out;
    },

    tracerDots() {
      if (this.hoverT === null) return "";
      const t = this.hoverT;
      const { t0, t1 } = this.chartDomain();
      const span = t1 - t0 > 0 ? t1 - t0 : 1;
      const series = this.tracerSeries();
      let html = "";
      for (let i = 0; i < series.length; i++) {
        const snap = this.tracerSnapSample(series[i].samples, t);
        if (snap === null) continue;
        const x = ((snap.t - t0) / span) * 548 + 48;
        const y = 158 - (snap.hs / series[i].max) * 150;
        const stroke = series[i].color === "#ffffff" ? "#000000" : "#ffffff";
        html +=
          '<circle class="tracer-dot" cx="' +
          x.toFixed(1) +
          '" cy="' +
          y.toFixed(1) +
          '" r="3.5" fill="' +
          series[i].color +
          '" stroke="' +
          stroke +
          '" stroke-width="1.5" vector-effect="non-scaling-stroke"></circle>';
      }
      return html;
    },

    difficultyFromBits(bits) {
      const exponent = bits >>> 24;
      const mantissa = BigInt(bits & 0x7fffff);
      const shift = 8 * (exponent - 3);
      const target =
        shift >= 0 ? mantissa << BigInt(shift) : mantissa >> BigInt(-shift);
      if (target === 0n) return 0;
      const diff1 = 0xffffn << 208n;
      return Number(diff1 / target);
    },

    stratumTarget() {
      return location.hostname + ":3333";
    },

    p2pMultiaddr() {
      return "/ip4/" + location.hostname + "/tcp/6884";
    },

    exampleUsername() {
      return "bchtest:qqmt9aztcrcms0aulp6v809n8fmgfx4dmgauqtmaxr.myminer";
    },

    examplePassword() {
      return "x,p2p=tp2pool:qqmt9aztcrcms0aulp6v809n8fmgfx4dmg8nuakndu";
    },

    sharesNote() {
      return this.shares.length
        ? "heights " +
            (this.shares.length ? this.shares[this.shares.length - 1].height : 0) +
            " - " +
            (this.shares.length ? this.shares[0].height : 0)
        : "";
    },

    footerStatus() {
      if (this.pollError) return "Connection lost - retrying";
      const updated = this.lastUpdated
        ? " - last update " + this.fmtClock(this.lastUpdated)
        : "";
      if (!this.autoRefresh) return "Auto-refresh paused" + updated;
      return "Auto-refresh" + updated;
    },

    fmtInt(v) {
      if (v === null || v === undefined || !isFinite(v)) return "0";
      return Math.round(v).toLocaleString("en-US");
    },

    fmtBigint(v) {
      if (v === null || v === undefined) return "-";
      const s = String(v);
      return s.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    },

    fmtDiff(value) {
      if (!isFinite(value) || value <= 0) return "0";
      const suffixes = ["", "K", "M", "G", "T", "P", "E"];
      if (value < 10000) {
        return value.toLocaleString("en-US", { maximumFractionDigits: 2 });
      }
      let tier = 0;
      let scaled = value;
      while (scaled >= 1000 && tier < suffixes.length - 1) {
        scaled /= 1000;
        tier++;
      }
      const digits = scaled >= 100 ? 0 : scaled >= 10 ? 1 : 2;
      return scaled.toFixed(digits) + suffixes[tier];
    },

    fmtHashrate(hs) {
      if (!isFinite(hs) || hs <= 0) return "0 H/s";
      const units = ["H/s", "KH/s", "MH/s", "GH/s", "TH/s", "PH/s"];
      let unit = 0;
      let v = hs;
      while (v >= 1000 && unit < units.length - 1) {
        v /= 1000;
        unit++;
      }
      const digits = v >= 100 ? 0 : v >= 10 ? 1 : 2;
      return v.toFixed(digits) + " " + units[unit];
    },

    fmtHash(h) {
      if (!h) return "-";
      if (h.length <= 16) return h;
      return h.slice(0, 8) + "..." + h.slice(-6);
    },

    fmtWork(work) {
      if (!work) return "-";
      const s = String(work);
      if (s.length <= 14) return s;
      return s.slice(0, 10) + "..." + s.slice(-6);
    },

    fmtStamp(unix) {
      if (!unix) return "N/A";
      return new Date(unix * 1000).toLocaleString();
    },

    fmtAddr(a) {
      if (!a) return "-";
      if (a.length <= 22) return a;
      return a.slice(0, 14) + "..." + a.slice(-6);
    },

    fmtPct(frac) {
      if (!isFinite(frac)) return "0%";
      return (frac * 100).toFixed(2) + "%";
    },

    fmtTimeAgo(unix) {
      if (!unix) return "-";
      const delta = Date.now() / 1000 - unix;
      return this.fmtDuration(delta) + " ago";
    },

    fmtDuration(seconds) {
      const s = Math.max(0, Math.floor(seconds));
      if (s < 60) return s + "s";
      const m = Math.floor(s / 60);
      if (m < 60) return m + "m " + (s % 60) + "s";
      const h = Math.floor(m / 60);
      if (h < 24) return h + "h " + (m % 60) + "m";
      const d = Math.floor(h / 24);
      return d + "d " + (h % 24) + "h";
    },

    fmtUptime(seconds) {
      return this.fmtDuration(seconds);
    },

    fmtClock(date) {
      return date.toLocaleTimeString("en-US", { hour12: false });
    },
  };
}
