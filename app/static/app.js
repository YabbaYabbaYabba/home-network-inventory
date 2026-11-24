"use strict";
/* Network Inventory front end: no frameworks, no third-party code. */

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const ICONS = {
  router: "M3 15a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2zM7 16.5h.01M11 16.5h.01M8 13 6 6M16 13l2-7",
  server: "M4 3.5h16v7H4zM4 13.5h16v7H4zM8 7h.01M8 17h.01",
  laptop: "M5 5h14v10H5zM2 19h20",
  phone: "M8 2h8a2 2 0 0 1 2 2v16a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2zM11 18h2",
  tv: "M3 5h18v12H3zM8 21h8M12 17v4",
  bulb: "M9 18h6M10 22h4M12 2a7 7 0 0 0-4 12.7V16h8v-1.3A7 7 0 0 0 12 2z",
  camera: "M3 7h4l2-3h6l2 3h4v12H3zM12 16.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7z",
  printer: "M6 9V3h12v6M6 18H4v-7h16v7h-2M6 14h12v7H6z",
  question: "M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3M12 17h.01M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z",
  globe: "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20",
  wifi: "M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0M2 9a15 15 0 0 1 20 0M12 19.5h.01",
  wired: "M4 4h16v11H4zM8 15v5h8v-5M8 8v3M12 8v3M16 8v3",
  mesh: "M3 15a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2zM12 13V8M8.5 6.5a5 5 0 0 1 7 0M6 4a8.5 8.5 0 0 1 12 0",
};
const svgIcon = (k, color) => `<svg viewBox="0 0 24 24" stroke="${esc(color || "currentColor")}"><path d="${ICONS[k] || ICONS.question}"/></svg>`;

const S = {
  state: null, version: null, live: null, view: "map", sel: null,
  devFilter: "online", evFilter: "important", hidden: new Set(),
  showOffline: false, labels: true, ips: true, traffic: true, hover: null,
};
const byMac = () => Object.fromEntries((S.state?.devices || []).map((d) => [d.mac, d]));
const groupInfo = (id) => (S.state?.groups || []).find((g) => g.id === id) || { id, label: id, color: "#94a3b8", icon: "question" };
const iconFor = (d) => (d.is_router ? "router" : d.mesh_node ? "mesh" : groupInfo(d.group).icon);

// ------------------------------------------------------------------ formatting
function fmtRate(bps) {
  if (bps == null) return "–";
  const m = bps / 1e6;
  if (m >= 100) return m.toFixed(0);
  if (m >= 10) return m.toFixed(1);
  if (m >= 0.01) return m.toFixed(2);
  return "0";
}
const mbps = (bps) => (bps || 0) / 1e6;
function ago(ts) {
  if (!ts) return "never";
  const s = Date.now() / 1000 - ts;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}
function when(ts) {
  if (!ts) return "–";
  const d = new Date(ts * 1000), now = new Date();
  const t = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  if (d.toDateString() === now.toDateString()) return t;
  return `${d.toLocaleDateString([], { day: "numeric", month: "short" })} ${t}`;
}
const connLabel = (c) => (c === "wired" ? "Wired" : c ? c + " Wi-Fi" : "–");

// ------------------------------------------------------------------ API
async function api(path, body) {
  const opt = body === undefined ? {} : {
    method: "POST", body: JSON.stringify(body),
    headers: { "Content-Type": "application/json", "X-Requested-With": "inventory" },
  };
  const r = await fetch(path, opt);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
  return j;
}

async function loadState(force) {
  try {
    const j = await api(`/api/state${S.version && !force ? `?v=${S.version}` : ""}`);
    if (j.unchanged) {
      S.state.router = j.router; S.state.scan = j.scan;
    } else {
      S.state = j; S.version = j.version;
    }
    render();
  } catch (e) {
    setPill("bad", "App offline");
  }
}

async function loadLive() {
  if (S.view !== "map" || document.hidden) return;
  try {
    S.live = await api("/api/live");
    recordHistory(S.live.ifaces);
    applyLive();
  } catch (e) { /* keep last */ }
}

// ------------------------------------------------------------------ top-level render
function setPill(cls, text) {
  $("#pill").className = `pill ${cls}`;
  $("#pill-text").textContent = text;
}

function render() {
  const st = S.state;
  if (!st) return;
  const devs = st.devices;
  const on = devs.filter((d) => d.online).length;
  const r = st.router;
  $("#sub").textContent = `${r.model ? "ASUS " + r.model : "ASUS router"} · ${on} online · ${devs.length} known`;
  if (r.paused) setPill("warn", "Paused");
  else if (r.ok) setPill("ok", "Live");
  else if (r.ok === false) setPill("bad", "Router error");
  else setPill("", "Connecting");
  const unrev = devs.filter((d) => !d.approved).length;
  $("#review-badge").hidden = !unrev;
  $("#review-badge").textContent = unrev;
  renderBanners();
  if (S.view === "map") renderMap();
  if (S.view === "devices") renderDevices();
  if (S.view === "review") renderReview();
  if (S.view === "activity") renderEvents();
  if (S.view === "router") renderRouter();
  if (S.sel && !$("#sheet").hidden) refreshSheetHeader();
  $("#footer").innerHTML = `Updated ${esc(when(st.now))}`;
}

function renderBanners() {
  const st = S.state, r = st.router, sc = st.scan;
  const out = [];
  if (r.cert_pending) {
    out.push(`<div class="banner"><b>The router's certificate changed.</b> New SHA-256 fingerprint:<div class="mono">${esc(r.cert_pending)}</div>
      ${r.cert_fixed ? "It is pinned with ROUTER_CERT_SHA256 in .env, so update that after checking." :
        `Check it in the router (Administration → System → HTTPS certificate) before trusting it.<br><button class="btn small" data-act="trust">Trust new certificate</button>`}</div>`);
  } else if (r.paused) {
    out.push(`<div class="banner warn">Router reading is paused until ${esc(when(r.paused_until))}, so you can log in to the router's web page. <button class="btn small" data-act="resume">Resume now</button></div>`);
  } else if (r.ok === false && r.error) {
    const retry = r.next_try > Date.now() / 1000 ? ` Next try ${esc(when(r.next_try))}.` : "";
    out.push(`<div class="banner">${esc(r.error)}${retry} <button class="btn small" data-act="resume">Retry now</button></div>`);
  }
  if (sc.error) out.push(`<div class="banner warn">${esc(sc.error)}</div>`);
  if (!st.baseline) out.push(`<div class="banner info">Building the first inventory. Every device found now goes to <b>Review</b>. Alerts start after this first pass.</div>`);
  $("#banners").innerHTML = out.join("");
}

document.addEventListener("click", async (e) => {
  const b = e.target.closest("[data-act]");
  if (!b) return;
  const act = b.dataset.act;
  b.disabled = true;
  try {
    if (act === "trust") await api("/api/router", { action: "trust_cert" });
    if (act === "resume") await api("/api/router", { action: "resume" });
    if (act === "pause") await api("/api/router", { action: "pause", minutes: 15 });
    if (act === "scan") await api("/api/router", { action: "scan" });
    if (act === "approve") await api(`/api/device/${b.dataset.mac}`, { approved: true });
    if (act === "approve-all" && confirm("Approve every device in the review list?")) await api("/api/approve-all", {});
  } catch (err) { alert(err.message); }
  b.disabled = false;
  await loadState(true);
});

// ------------------------------------------------------------------ tabs
function showView(v) {
  S.view = v;
  $$("#tabs button").forEach((b) => b.classList.toggle("on", b.dataset.view === v));
  $$(".view").forEach((el) => (el.hidden = el.id !== `view-${v}`));
  try { localStorage.setItem("view", v); } catch (e) { /* private mode */ }
  render();
  if (v === "map") { S.fitNext = true; loadLive(); }
}
$("#tabs").addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) showView(b.dataset.view); });

// ------------------------------------------------------------------ MAP
const HUB_ORDER = ["wired", "2.4 GHz", "5 GHz", "5 GHz-2", "6 GHz", "6 GHz-2"];
const VB = { x: -500, y: -500, w: 1000, h: 1000 };
let mapKey = "";

// What the map shows. Kept in this browser only.
const MAP_PREFS = ["labels", "ips", "traffic", "showOffline"];
try {
  const p = JSON.parse(localStorage.getItem("mapPrefs") || "{}");
  for (const k of MAP_PREFS) if (typeof p[k] === "boolean") S[k] = p[k];
} catch (e) { /* private mode */ }
function saveMapPrefs() {
  try { localStorage.setItem("mapPrefs", JSON.stringify(Object.fromEntries(MAP_PREFS.map((k) => [k, S[k]])))); } catch (e) { /* ignore */ }
}

// Each kind of link has its own colour (see .b-* in style.css).
const BANDS = [
  { cls: "b-wired", label: "Wired", test: (k) => k === "wired" },
  { cls: "b-24", label: "2.4 GHz", test: (k) => k.startsWith("2.4") },
  { cls: "b-5", label: "5 GHz", test: (k) => k.startsWith("5") },
  { cls: "b-6", label: "6 GHz", test: (k) => k.startsWith("6") },
  { cls: "b-mesh", label: "AiMesh", test: (k) => k.startsWith("mesh:") },
];
const bandOf = (k) => BANDS.find((b) => b.test(k || "")) || { cls: "b-other", label: "Other" };
const SPARK = { wan: "#38bdf8", wired: "#94a3b8", "2.4 GHz": "#fbbf24", "5 GHz": "#a78bfa", "5 GHz-2": "#a78bfa", "6 GHz": "#f472b6", "6 GHz-2": "#f472b6" };

function hubOf(d, macs) {
  if (d.mesh_parent && macs[d.mesh_parent]) return `mesh:${d.mesh_parent}`;
  return d.conn || "unknown";
}

function labelLines() {
  return (S.labels ? 1 : 0) + (S.ips ? 1 : 0) + (S.traffic ? 1 : 0);
}

function layout() {
  const st = S.state, macs = byMac();
  const devs = st.devices.filter((d) => !d.is_router && (S.showOffline || d.online) && !S.hidden.has(d.group));
  const meshNodes = st.devices.filter((d) => d.mesh_node && (S.showOffline || d.online));
  const hubs = new Map();
  for (const m of meshNodes) hubs.set(`mesh:${m.mac}`, { key: `mesh:${m.mac}`, dev: m, items: [] });
  for (const d of devs) {
    if (d.mesh_node) continue;
    const k = hubOf(d, macs);
    if (!hubs.has(k)) hubs.set(k, { key: k, items: [] });
    hubs.get(k).items.push(d);
  }
  const rank = (k) => (k.startsWith("mesh:") ? 50 : HUB_ORDER.includes(k) ? HUB_ORDER.indexOf(k) : 90);
  const list = [...hubs.values()].filter((h) => h.items.length || h.dev).sort((a, b) => rank(a.key) - rank(b.key));
  const gorder = st.groups.map((g) => g.id);
  for (const h of list) h.items.sort((a, b) => gorder.indexOf(a.group) - gorder.indexOf(b.group) || (a.name || "").localeCompare(b.name || ""));

  // sectors around the router, leaving a gap at the top for the Internet
  const gap = (56 * Math.PI) / 180;
  const total = 2 * Math.PI - gap;
  const weights = list.map((h) => Math.max(h.items.length, 3));
  const wsum = weights.reduce((a, b) => a + b, 0) || 1;
  let a0 = -Math.PI / 2 + gap / 2;
  // more label lines need more room between devices and between rings
  const lines = labelLines();
  const RH = 175, R0 = 330, RING = 66 + 14 * lines, SP = 78 + (S.ips ? 22 : 0);
  const box = { x0: -60, x1: 60, y0: -300, y1: 80 };
  const grow = (x, y) => { box.x0 = Math.min(box.x0, x); box.x1 = Math.max(box.x1, x); box.y0 = Math.min(box.y0, y); box.y1 = Math.max(box.y1, y); };
  for (let i = 0; i < list.length; i++) {
    const h = list[i];
    const span = (total * weights[i]) / wsum;
    h.a0 = a0; h.a1 = a0 + span; h.mid = a0 + span / 2;
    h.x = RH * Math.cos(h.mid); h.y = RH * Math.sin(h.mid);
    grow(h.x, h.y);
    // rings of devices beyond the hub
    let r = R0, idx = 0;
    const pad = Math.min(0.08, span * 0.08);
    while (idx < h.items.length) {
      const usable = Math.max(span - 2 * pad, 0.05);
      const cap = Math.max(1, Math.floor((usable * r) / SP));
      const n = Math.min(cap, h.items.length - idx);
      const step = n > 1 ? Math.min(SP / r, usable / (n - 1)) : 0;
      const start = h.mid - (step * (n - 1)) / 2;
      for (let j = 0; j < n; j++) {
        const ang = start + j * step;
        const d = h.items[idx + j];
        d._x = r * Math.cos(ang); d._y = r * Math.sin(ang); d._hub = h;
        grow(d._x, d._y);
      }
      idx += n;
      r += RING;
    }
    a0 += span;
  }
  // room for the labels around the outermost nodes
  const lh = 30 + 14 * lines;
  box.x0 -= 70; box.x1 += 70; box.y0 -= lh; box.y1 += lh;
  return { hubs: list, box };
}

const hubLabel = (h) => (h.dev ? h.dev.name : h.key === "wired" ? "Wired" : h.key === "unknown" ? "Not connected" : h.key);
const hubIcon = (h) => (h.dev ? "mesh" : h.key === "wired" ? "wired" : h.key === "unknown" ? "question" : "wifi");

function iconPath(k, x, y, s, cls, color) {
  return `<path class="ic ${cls || ""}" ${color ? `stroke="${esc(color)}"` : ""} d="${ICONS[k] || ICONS.question}" transform="translate(${(x - 12 * s).toFixed(1)} ${(y - 12 * s).toFixed(1)}) scale(${s})"/>`;
}

// A stack of text lines on a rounded background. sizeLabels() fits the background once the text is in the page.
// lines: [{ text, cls, attrs }]; below = stack grows down from y, otherwise it ends at y.
function label(x, y, below, lines) {
  if (!lines.length) return "";
  const first = below ? y : y - (lines.length - 1) * 14;
  return `<g class="lbl"><rect class="lbl-bg" rx="7"/>${lines.map((l, i) =>
    `<text class="${l.cls || ""}" x="${x.toFixed(1)}" y="${(first + i * 14).toFixed(1)}" ${l.attrs || ""}>${esc(l.text || "")}</text>`).join("")}</g>`;
}
function sizeLabels() {
  for (const g of $$("#map .lbl")) {
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    for (const t of g.querySelectorAll("text")) {
      if (!t.textContent) continue;
      const b = t.getBBox();
      if (!b.width) continue;
      x0 = Math.min(x0, b.x); y0 = Math.min(y0, b.y); x1 = Math.max(x1, b.x + b.width); y1 = Math.max(y1, b.y + b.height);
    }
    const r = g.firstElementChild;
    if (x0 === Infinity) { r.setAttribute("width", 0); continue; }
    r.setAttribute("x", (x0 - 7).toFixed(1)); r.setAttribute("y", (y0 - 3).toFixed(1));
    r.setAttribute("width", (x1 - x0 + 14).toFixed(1)); r.setAttribute("height", (y1 - y0 + 6).toFixed(1));
  }
}

function renderMap() {
  const st = S.state;
  renderLegend();
  renderToggles();
  const L = layout();
  S.layout = L;
  const routerDev = st.devices.find((d) => d.is_router);
  const parts = [];
  // guide rings
  parts.push(`<circle class="ring" r="175"/><circle class="ring" r="330"/>`);
  // internet link
  parts.push(`<line class="link b-wan" id="ln-wan" x1="0" y1="-60" x2="0" y2="-215" stroke-width="3"/>`);
  parts.push(`<path class="flow down" id="fl-wan-d" d="M-4 -215 L-4 -60"/><path class="flow up" id="fl-wan-u" d="M4 -215 L4 -60"/>`);
  for (const h of L.hubs) {
    const band = bandOf(h.key), hk = esc(h.key);
    const wifi = band.cls !== "b-wired" && band.cls !== "b-mesh";
    parts.push(`<line class="link ${band.cls} ${wifi ? "wifi" : ""}" data-hub="${hk}" x1="0" y1="0" x2="${h.x.toFixed(1)}" y2="${h.y.toFixed(1)}" stroke-width="2.5"/>`);
    parts.push(`<path class="flow down ${band.cls}" data-hub="${hk}" data-flow="hub:${hk}:d" d="M0 0 L${h.x.toFixed(1)} ${h.y.toFixed(1)}"/>`);
    parts.push(`<path class="flow up ${band.cls}" data-hub="${hk}" data-flow="hub:${hk}:u" d="M0 0 L${h.x.toFixed(1)} ${h.y.toFixed(1)}"/>`);
    for (const d of h.items) {
      // under a mesh node, colour the last hop by how the device connects to that node
      const db = h.dev ? bandOf(d.conn) : band;
      const dwifi = db.cls !== "b-wired" && db.cls !== "b-other";
      parts.push(`<line class="link thin ${db.cls} ${dwifi ? "wifi" : ""} ${d.online ? "" : "offline"}" data-hub="${hk}" data-dev="${d.mac}" x1="${h.x.toFixed(1)}" y1="${h.y.toFixed(1)}" x2="${d._x.toFixed(1)}" y2="${d._y.toFixed(1)}" stroke-width="1.3"/>`);
      parts.push(`<path class="flow down ${db.cls}" data-hub="${hk}" data-dev="${d.mac}" data-flow="dev:${d.mac}:d" d="M${h.x.toFixed(1)} ${h.y.toFixed(1)} L${d._x.toFixed(1)} ${d._y.toFixed(1)}"/>`);
    }
  }
  // device nodes
  for (const h of L.hubs) {
    for (const d of h.items) {
      const g = groupInfo(d.group);
      const ang = Math.atan2(d._y, d._x);
      const below = Math.sin(ang) > -0.35;
      const lines = [];
      if (S.labels) lines.push({ text: trunc(d.name, 18), cls: "name" });
      if (S.ips && d.ip) lines.push({ text: d.ip, cls: "ip" });
      if (!d.online) lines.push({ text: d.last_seen ? `offline · ${ago(d.last_seen)}` : "offline", cls: "sm" });
      else if (S.traffic) lines.push({ text: "", cls: "sm", attrs: `data-rate="${d.mac}"` });
      parts.push(`<g class="node ${d.online ? "" : "offline"} ${S.sel === d.mac ? "sel" : ""}" data-mac="${d.mac}" data-hub="${esc(h.key)}" data-dev="${d.mac}">
        <circle class="bg" cx="${d._x.toFixed(1)}" cy="${d._y.toFixed(1)}" r="19" fill="${g.color}24" stroke="${g.color}"/>
        ${iconPath(iconFor(d), d._x, d._y, 0.85, "", g.color)}
        ${d.approved ? "" : `<circle class="unrev" cx="${(d._x + 14).toFixed(1)}" cy="${(d._y - 14).toFixed(1)}" r="4.5"><title>Needs review</title></circle>`}
        ${label(d._x, below ? d._y + 37 : d._y - 31, below, lines)}
      </g>`);
    }
  }
  // hubs
  for (const h of L.hubs) {
    const band = bandOf(h.key);
    const tag = h.dev ? `class="node hub ${band.cls}" data-mac="${h.dev.mac}"` : `class="hub ${band.cls}"`;
    const below = Math.sin(h.mid) > -0.3;
    const lines = [{ text: `${trunc(hubLabel(h), 22)} · ${h.items.length}`, cls: "name" }];
    if (S.ips && h.dev?.ip) lines.push({ text: h.dev.ip, cls: "ip" });
    if (S.traffic) lines.push({ text: "", cls: "rate d", attrs: `data-hubrate="${esc(h.key)}:d"` });
    parts.push(`<g ${tag} data-hub="${esc(h.key)}"><circle class="bg" cx="${h.x.toFixed(1)}" cy="${h.y.toFixed(1)}" r="20"/>
      ${iconPath(hubIcon(h), h.x, h.y, 0.85, "hub-ic")}
      ${label(h.x, below ? h.y + 38 : h.y - 30, below, lines)}
    </g>`);
  }
  // internet + router
  parts.push(`<g class="hub b-wan"><circle class="bg" cx="0" cy="-245" r="26"/>${iconPath("globe", 0, -245, 1.05, "hub-ic")}
    ${label(0, -283, false, [{ text: "Internet", cls: "title" }])}</g>`);
  if (S.traffic) parts.push(`<text class="rate d" id="wan-d" x="-12" y="-130"></text><text class="rate u" id="wan-u" x="14" y="-130"></text>`);
  const rlines = [];
  if (S.labels) rlines.push({ text: routerDev ? routerDev.name : "Router", cls: "title" });
  if (S.ips) rlines.push({ text: routerDev?.ip || st.router.url.replace(/^https?:\/\//, "").replace(/:\d+$/, ""), cls: "ip" });
  parts.push(`<g class="core ${routerDev ? "node" : ""}" ${routerDev ? `data-mac="${routerDev.mac}"` : ""}>
    <circle class="halo" r="46"/><circle class="bg" r="38"/>${iconPath("router", 0, 0, 1.25, "core-ic")}
    ${label(0, 62, true, rlines)}</g>`);

  const svg = $("#map");
  svg.innerHTML = parts.join("");
  // the WAN text labels need explicit anchors (CSS sets middle)
  if (S.traffic) { $("#wan-d").style.textAnchor = "end"; $("#wan-u").style.textAnchor = "start"; }
  const key = L.hubs.map((h) => h.key + h.items.length).join("|") + labelLines();
  if (S.fitNext || key !== mapKey) { fit(L.box); S.fitNext = false; }
  mapKey = key;
  setVB();
  sizeLabels();
  applyLive();
  renderMapKey(L);
  highlight(S.sel && !$("#sheet").hidden ? S.sel : S.hover);
  const dt = S.live?.device_traffic;
  $("#map-note").textContent = dt === "unavailable"
    ? "Per-device traffic isn't available: turn on Traffic Analyzer (or Adaptive QoS) in the router to see each device's throughput. Interface totals are shown."
    : dt === "off" ? "Per-device traffic is off (DEVICE_TRAFFIC=off). Interface totals are shown." : "";
}

const trunc = (s, n) => ((s || "").length > n ? s.slice(0, n - 1) + "…" : s || "");

// Fade everything except the path from the router to one device (or one hub).
function highlight(target) {
  const svg = $("#map");
  if (!target) { svg.classList.remove("focus"); return; }
  const isDev = !target.startsWith("hub:");
  const hubKey = isDev ? $(`#map .node[data-dev="${CSS.escape(target)}"]`)?.dataset.hub : target.slice(4);
  if (isDev && hubKey == null) { svg.classList.remove("focus"); return; }
  svg.classList.add("focus");
  for (const el of $$("#map [data-hub]")) {
    const lit = isDev ? (el.dataset.dev ? el.dataset.dev === target : el.dataset.hub === hubKey) : el.dataset.hub === hubKey;
    el.classList.toggle("lit", lit);
  }
}
$("#map").addEventListener("pointerover", (e) => {
  if (e.pointerType !== "mouse") return;
  const n = e.target.closest(".node[data-dev], .hub[data-hub]");
  const t = n ? (n.dataset.dev || `hub:${n.dataset.hub}`) : null;
  if (t === S.hover) return;
  S.hover = t;
  if (!(S.sel && !$("#sheet").hidden)) highlight(t);
});
$("#map").addEventListener("pointerleave", () => { S.hover = null; if (!(S.sel && !$("#sheet").hidden)) highlight(null); });

function renderToggles() {
  for (const b of $$("#map-toggles .tg")) {
    const on = !!S[b.dataset.k];
    b.classList.toggle("on", on);
    b.setAttribute("aria-pressed", on);
  }
}
$("#map-toggles").addEventListener("click", (e) => {
  const b = e.target.closest(".tg");
  if (!b) return;
  S[b.dataset.k] = !S[b.dataset.k];
  saveMapPrefs();
  renderMap();
});

function renderMapKey(L) {
  const seen = new Set(L.hubs.map((h) => bandOf(h.key).cls));
  for (const h of L.hubs) if (h.dev) for (const d of h.items) seen.add(bandOf(d.conn).cls);
  const st = S.state;
  const items = BANDS.filter((b) => seen.has(b.cls)).map((b) =>
    `<span class="k"><svg viewBox="0 0 22 8"><line class="link ${b.cls} ${b.cls === "b-wired" || b.cls === "b-mesh" ? "" : "wifi"}" x1="1" y1="4" x2="21" y2="4" stroke-width="2"/></svg>${esc(b.label)}</span>`);
  if (st.devices.some((d) => !d.approved)) items.push(`<span class="k"><i class="unrev-k"></i>Needs review</span>`);
  if (S.showOffline && st.devices.some((d) => !d.online)) items.push(`<span class="k"><i class="off-k"></i>Offline</span>`);
  items.push(`<span class="k hint-k">Point at a device to trace its path</span>`);
  $("#map-key").innerHTML = items.join("");
}

function renderLegend() {
  const st = S.state;
  const counts = {};
  for (const d of st.devices) if (S.showOffline || d.online) counts[d.group] = (counts[d.group] || 0) + 1;
  $("#map-legend").innerHTML = st.groups.filter((g) => counts[g.id]).map((g) =>
    `<span class="chip ${S.hidden.has(g.id) ? "off" : ""}" data-g="${g.id}"><i data-c="${g.color}"></i>${esc(g.label)} ${counts[g.id]}</span>`).join("");
  $$("#map-legend .chip i").forEach((i) => (i.style.background = i.dataset.c));
}
$("#map-legend").addEventListener("click", (e) => {
  const c = e.target.closest(".chip");
  if (!c) return;
  S.hidden.has(c.dataset.g) ? S.hidden.delete(c.dataset.g) : S.hidden.add(c.dataset.g);
  renderMap();
});

function styleFlow(el, bps, maxW) {
  if (!el) return;
  const m = mbps(bps);
  if (!S.traffic || m < 0.02) { el.style.display = "none"; return; }
  el.style.display = "";
  el.style.strokeWidth = (1 + Math.min(maxW, Math.log2(1 + m) * 1.25)).toFixed(2);
  el.style.animationDuration = Math.max(0.3, 2.4 - Math.log10(1 + m) * 0.85).toFixed(2) + "s";
}

// last ~2 minutes of each interface, for the small graphs in the live strip
const HIST_LEN = 40;
const HIST = {};
function recordHistory(ifs) {
  if (!ifs) return;
  for (const [k, r] of Object.entries(ifs)) {
    const h = (HIST[k] ||= []);
    h.push(mbps(r.down));
    if (h.length > HIST_LEN) h.shift();
  }
}

function applyLive() {
  const lv = S.live;
  if (!lv || !S.layout) return;
  const ifs = lv.ifaces || {}, dv = lv.devices || {};
  const wan = ifs.wan;
  $("#wan-d") && ($("#wan-d").textContent = wan ? `↓ ${fmtRate(wan.down)}` : "");
  $("#wan-u") && ($("#wan-u").textContent = wan ? `↑ ${fmtRate(wan.up)} Mbps` : "");
  styleFlow($("#fl-wan-d"), wan?.down, 8);
  styleFlow($("#fl-wan-u"), wan?.up, 6);
  const macs = byMac();
  for (const h of S.layout.hubs) {
    let r = ifs[h.key];
    if (!r && h.key.startsWith("mesh:")) {
      r = { down: 0, up: 0 };
      for (const d of h.items) { r.down += dv[d.mac]?.down || 0; r.up += dv[d.mac]?.up || 0; }
      if (!Object.keys(dv).length) r = null;
    }
    styleFlow($(`[data-flow="hub:${CSS.escape(h.key)}:d"]`), r?.down, 7);
    styleFlow($(`[data-flow="hub:${CSS.escape(h.key)}:u"]`), r?.up, 5);
    const t = $(`[data-hubrate="${CSS.escape(h.key)}:d"]`);
    if (t) t.textContent = r ? `↓${fmtRate(r.down)} ↑${fmtRate(r.up)}` : "";
  }
  for (const mac of Object.keys(macs)) {
    const r = dv[mac];
    styleFlow($(`[data-flow="dev:${mac}:d"]`), r ? r.down + r.up : 0, 5);
    const t = $(`[data-rate="${mac}"]`);
    if (t) t.textContent = r && mbps(r.down + r.up) >= 0.05 ? `${fmtRate(r.down + r.up)} Mbps` : "";
  }
  sizeLabels();
  renderLiveStrip();
}

function spark(k) {
  const h = HIST[k] || [];
  if (h.length < 2) return `<svg class="spark" viewBox="0 0 100 22" preserveAspectRatio="none"></svg>`;
  const max = Math.max(...h, 0.1);
  // newest reading on the right edge; the line grows leftwards until it has HIST_LEN readings
  const xs = h.map((v, i) => 100 - ((h.length - 1 - i) / (HIST_LEN - 1)) * 100);
  const pts = h.map((v, i) => `${xs[i].toFixed(1)},${(20 - (v / max) * 18).toFixed(1)}`);
  const x0 = xs[0].toFixed(1), xe = "100";
  const c = SPARK[k] || "#94a3b8";
  return `<svg class="spark" viewBox="0 0 100 22" preserveAspectRatio="none">
    <polygon points="${x0},22 ${pts.join(" ")} ${xe},22" fill="${c}" fill-opacity=".14"/>
    <polyline points="${pts.join(" ")}" fill="none" stroke="${c}" stroke-width="1.6" vector-effect="non-scaling-stroke" stroke-linejoin="round"/></svg>`;
}

function renderLiveStrip() {
  const ifs = S.live?.ifaces || {};
  const cells = [];
  const cell = (key, label, r) => `<div class="live"><div class="label">${esc(label)}</div>
    <div class="v"><span class="arrow-d">↓</span> ${fmtRate(r?.down)}<small>Mbps</small></div>
    <div class="u"><span class="arrow-u">↑</span> ${fmtRate(r?.up)} Mbps</div>${spark(key)}</div>`;
  cells.push(cell("wan", "Internet", ifs.wan));
  for (const k of HUB_ORDER) if (ifs[k]) cells.push(cell(k, k === "wired" ? "Wired LAN" : `${k} Wi-Fi`, ifs[k]));
  if (!Object.keys(ifs).length) {
    $("#live-strip").innerHTML = `<div class="live"><div class="label">Live traffic</div><div class="u">${S.state?.router?.ok === false ? "Waiting for the router…" : "Measuring…"}</div></div>`;
    return;
  }
  $("#live-strip").innerHTML = cells.join("");
}

// pan & zoom
function fit(box) {
  const wrap = $("#map-wrap").getBoundingClientRect();
  const aspect = wrap.width / Math.max(wrap.height, 1) || 1;
  const b = box || { x0: -400, x1: 400, y0: -400, y1: 400 };
  let w = b.x1 - b.x0, h = b.y1 - b.y0;
  const cx = (b.x0 + b.x1) / 2, cy = (b.y0 + b.y1) / 2;
  if (w / h < aspect) w = h * aspect; else h = w / aspect;
  Object.assign(VB, { x: cx - w / 2, y: cy - h / 2, w, h });
}
const setVB = () => $("#map").setAttribute("viewBox", `${VB.x.toFixed(1)} ${VB.y.toFixed(1)} ${VB.w.toFixed(1)} ${VB.h.toFixed(1)}`);
function zoom(f, cx, cy) {
  const rect = $("#map").getBoundingClientRect();
  const px = cx == null ? 0.5 : (cx - rect.left) / rect.width, py = cy == null ? 0.5 : (cy - rect.top) / rect.height;
  const nw = Math.min(Math.max(VB.w * f, 250), 6000), nh = VB.h * (nw / VB.w);
  VB.x += (VB.w - nw) * px; VB.y += (VB.h - nh) * py; VB.w = nw; VB.h = nh;
  setVB();
}
$("#zoom-in").onclick = () => zoom(0.8);
$("#zoom-out").onclick = () => zoom(1.25);
$("#zoom-reset").onclick = () => { fit(S.layout?.box); setVB(); };
(() => {
  const wrap = $("#map-wrap");
  const pts = new Map();
  let moved = 0, pinch = null;
  wrap.addEventListener("wheel", (e) => { e.preventDefault(); zoom(e.deltaY > 0 ? 1.12 : 0.89, e.clientX, e.clientY); }, { passive: false });
  wrap.addEventListener("pointerdown", (e) => {
    pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
    moved = 0;
    if (pts.size === 2) { const [a, b] = [...pts.values()]; pinch = Math.hypot(a.x - b.x, a.y - b.y); }
  });
  wrap.addEventListener("pointermove", (e) => {
    const p = pts.get(e.pointerId);
    if (!p) return;
    const rect = $("#map").getBoundingClientRect();
    if (pts.size === 1) {
      const dx = e.clientX - p.x, dy = e.clientY - p.y;
      moved += Math.abs(dx) + Math.abs(dy);
      if (moved > 4) {
        wrap.classList.add("dragging");
        try { wrap.setPointerCapture(e.pointerId); } catch (err) { /* ignore */ }
      }
      VB.x -= (dx * VB.w) / rect.width; VB.y -= (dy * VB.h) / rect.height;
      setVB();
    } else if (pts.size === 2 && pinch) {
      pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
      const [a, b] = [...pts.values()];
      const d = Math.hypot(a.x - b.x, a.y - b.y);
      zoom(pinch / d, (a.x + b.x) / 2, (a.y + b.y) / 2);
      pinch = d; moved = 99;
      return;
    }
    pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
  });
  const up = (e) => { pts.delete(e.pointerId); if (pts.size < 2) pinch = null; wrap.classList.remove("dragging"); };
  wrap.addEventListener("pointerup", up);
  wrap.addEventListener("pointercancel", up);
  $("#map").addEventListener("click", (e) => {
    if (moved > 6) return;
    const n = e.target.closest("[data-mac]");
    if (n) openSheet(n.dataset.mac);
  });
})();
window.addEventListener("resize", () => { if (S.view === "map" && S.layout) { fit(S.layout.box); setVB(); } });

// ------------------------------------------------------------------ DEVICES
function devRow(d, extra = "") {
  const g = groupInfo(d.group);
  const kind = d.auto?.kind || "";
  const bits = [kind && esc(kind), d.ip && esc(d.ip), esc(connLabel(d.conn))].filter(Boolean).join(" · ");
  const r = S.live?.devices?.[d.mac];
  const rate = r && mbps(r.down + r.up) >= 0.05 ? `${fmtRate(r.down + r.up)} Mbps<br>` : "";
  return `<div class="dev" data-open="${d.mac}">
    <span class="ico" data-c="${g.color}">${svgIcon(iconFor(d), g.color)}</span>
    <div class="main"><div class="n">${esc(d.name)}${d.approved ? "" : '<span class="tag warn">new</span>'}${d.random_mac ? '<span class="tag">private MAC</span>' : ""}${extra}</div>
    <div class="d">${bits}</div></div>
    <div class="r">${rate}<span class="dot ${d.online ? "on" : ""}"></span> ${d.online ? "online" : esc(ago(d.last_seen))}</div></div>`;
}

function matches(d, q) {
  if (!q) return true;
  const hay = [d.name, d.ip, d.mac, d.vendor, d.model, d.auto?.kind, d.label, d.notes, groupInfo(d.group).label].join(" ").toLowerCase();
  return q.toLowerCase().split(/\s+/).every((w) => hay.includes(w));
}

function renderDevices() {
  const st = S.state, q = $("#search").value.trim();
  let devs = st.devices.filter((d) => matches(d, q));
  if (S.devFilter === "online") devs = devs.filter((d) => d.online);
  if (S.devFilter === "new") devs = devs.filter((d) => !d.approved);
  $("#dev-count").textContent = `${devs.length} device${devs.length === 1 ? "" : "s"}`;
  const html = st.groups.map((g) => {
    const list = devs.filter((d) => d.group === g.id).sort((a, b) => (b.online - a.online) || (a.name || "").localeCompare(b.name || ""));
    if (!list.length) return "";
    return `<div class="card group"><div class="group-h"><i data-c="${g.color}"></i><b>${esc(g.label)}</b><span>${list.length}</span></div>
      ${list.map((d) => devRow(d)).join("")}</div>`;
  }).join("");
  $("#device-groups").innerHTML = html || `<div class="card empty">No devices match.</div>`;
  paintVars($("#device-groups"));
}
function paintVars(root) {
  $$(".group-h i", root).forEach((i) => (i.style.background = i.dataset.c));
  $$(".ico", root).forEach((i) => (i.style.background = i.dataset.c + "22"));
}
$("#search").addEventListener("input", renderDevices);
$("#dev-filter").addEventListener("click", (e) => {
  const b = e.target.closest("button"); if (!b) return;
  S.devFilter = b.dataset.f;
  $$("#dev-filter button").forEach((x) => x.classList.toggle("on", x === b));
  renderDevices();
});
document.addEventListener("click", (e) => {
  const r = e.target.closest("[data-open]");
  if (r && !e.target.closest("[data-act]")) openSheet(r.dataset.open);
});

// ------------------------------------------------------------------ REVIEW
function renderReview() {
  const devs = S.state.devices.filter((d) => !d.approved).sort((a, b) => b.first_seen - a.first_seen);
  const macs = byMac();
  $("#approve-all").hidden = devs.length < 2;
  $("#approve-all").dataset.act = "approve-all";
  $("#review-list").innerHTML = devs.length ? devs.map((d) => {
    const g = groupInfo(d.group);
    const same = d.maybe_same && macs[d.maybe_same] ? `<div class="d">Possibly the same device as <b>${esc(macs[d.maybe_same].name)}</b> with a new private MAC</div>` : "";
    return `<div class="rev"><span class="ico" data-c="${g.color}">${svgIcon(iconFor(d), g.color)}</span>
      <div class="main" data-open="${d.mac}"><div class="n"><b>${esc(d.name)}</b> <span class="tag">${esc(g.label)}</span> <span class="tag ${d.auto?.confidence === "high" ? "good" : d.auto?.confidence === "low" ? "warn" : ""}">${esc(d.auto?.confidence || "")}</span></div>
      <div class="hint">${esc([d.vendor || (d.random_mac ? "Private (random) MAC" : "Unknown vendor"), d.ip, d.mac].filter(Boolean).join(" · "))}</div>
      <div class="hint">First seen ${esc(when(d.first_seen))} · ${d.online ? "online now" : "last seen " + esc(ago(d.last_seen))}</div>${same}</div>
      <button class="btn small" data-act="approve" data-mac="${d.mac}">Approve</button></div>`;
  }).join("") : `<div class="empty">Nothing to review. Every device on the network has been approved.</div>`;
  paintVars($("#review-list"));
}

// ------------------------------------------------------------------ ACTIVITY
const IMPORTANT = new Set(["new", "ip", "cert", "approved", "forgot", "baseline"]);
function renderEvents() {
  const macs = byMac();
  const evs = S.state.events.filter((e) => S.evFilter === "all" || IMPORTANT.has(e.kind));
  $("#events").innerHTML = evs.length ? evs.map((e) => `<div class="ev"><time>${esc(when(e.ts))}</time><span class="k ${esc(e.kind)}"></span>
    <span class="t ${e.mac && macs[e.mac] ? "click" : ""}" ${e.mac && macs[e.mac] ? `data-open="${e.mac}"` : ""}>${esc(e.text)}</span></div>`).join("")
    : `<div class="empty">Nothing yet.</div>`;
}
$("#ev-filter").addEventListener("click", (e) => {
  const b = e.target.closest("button"); if (!b) return;
  S.evFilter = b.dataset.f;
  $$("#ev-filter button").forEach((x) => x.classList.toggle("on", x === b));
  renderEvents();
});

// ------------------------------------------------------------------ ROUTER
function renderRouter() {
  const st = S.state, r = st.router, sc = st.scan, se = st.settings;
  $("#router-card").innerHTML = `<div class="row between"><h2>Router</h2>
    ${r.paused ? '<button class="btn small" data-act="resume">Resume</button>' : '<button class="btn small" data-act="pause">Pause 15 min</button>'}</div>
    <div class="hint">Pause frees the router's single admin session so you can log in to its web page.</div>
    <dl class="kv">
      <dt>Model</dt><dd>${esc(r.model ? "ASUS " + r.model : "–")}</dd>
      <dt>Firmware</dt><dd>${esc(r.firmware || "–")}</dd>
      <dt>Address</dt><dd>${esc(r.url)}</dd>
      <dt>Status</dt><dd>${r.paused ? "Paused" : r.ok ? '<span class="tag good">connected</span>' : r.ok === false ? `<span class="tag bad">error</span> ${esc(r.error || "")}` : "connecting"}</dd>
      <dt>Client list</dt><dd>${esc(ago(r.last_clients))}</dd>
      <dt>Certificate</dt><dd class="mono">${esc(r.cert || "plain HTTP")}<br><span class="hint">${r.cert ? (r.cert_fixed ? "Pinned in .env (ROUTER_CERT_SHA256)" : "Pinned on first connection") : ""}</span></dd>
      <dt>Per-device traffic</dt><dd>${esc({ on: "On (Traffic Analyzer)", unavailable: "Not available. Turn on Traffic Analyzer", off: "Off", auto: "Checking…" }[S.live?.device_traffic || se.device_traffic] || "–")}</dd>
    </dl>`;
  $("#scan-card").innerHTML = `<div class="row between"><h2>Network scan</h2>
    <button class="btn small" data-act="scan" ${!sc.enabled || sc.running ? "disabled" : ""}>${sc.running ? "Scanning…" : "Scan now"}</button></div>
    <dl class="kv">
      <dt>Status</dt><dd>${sc.enabled ? '<span class="tag good">on</span>' : '<span class="tag warn">off</span>'} ${esc(sc.error || "")}</dd>
      <dt>Subnet</dt><dd>${esc(sc.subnet || "–")}</dd>
      <dt>Last scan</dt><dd>${esc(ago(sc.last))}${sc.last ? ` · ${sc.found} answered` : ""}</dd>
      <dt>Every</dt><dd>${se.scan_seconds}s (router list every ${se.clients_seconds}s)</dd>
      <dt>Offline after</dt><dd>${Math.round(se.offline_after / 60)} min unseen</dd>
    </dl>`;
  const yn = (v) => (v ? "on" : "off");
  $("#settings-card").innerHTML = `<h2>Discovery & alerts</h2><dl class="kv">
      <dt>Bonjour / mDNS</dt><dd>${yn(se.mdns)}</dd><dt>UPnP / SSDP</dt><dd>${yn(se.ssdp)}</dd>
      <dt>NetBIOS names</dt><dd>${yn(se.netbios)}</dd><dt>Port check</dt><dd>${se.port_probe ? "on (new devices)" : "off (manual only)"}</dd>
      <dt>New-device alerts</dt><dd>${se.alerts ? "webhook set" : "in the app only (set ALERT_WEBHOOK_URL)"}</dd>
    </dl><div class="hint">Change these in .env on the NAS and restart the container.</div>
    <div class="row exports"><a class="link" href="/api/export.csv">Export CSV</a><a class="link" href="/api/export.json">Export JSON</a></div>`;
}

// ------------------------------------------------------------------ DEVICE SHEET
async function openSheet(mac) {
  S.sel = mac;
  $("#sheet").hidden = $("#sheet-bg").hidden = false;
  refreshSheetHeader();
  $("#sh-body").innerHTML = `<div class="empty">Loading…</div>`;
  $$("#map .node").forEach((n) => n.classList.toggle("sel", n.dataset.mac === mac));
  highlight(mac);
  try {
    const d = await api(`/api/device/${mac}`);
    renderSheet(d);
  } catch (e) { $("#sh-body").innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
}
function refreshSheetHeader() {
  const d = byMac()[S.sel];
  if (!d) return;
  const g = groupInfo(d.group);
  $("#sh-icon").innerHTML = svgIcon(iconFor(d), g.color);
  $("#sh-icon").style.background = g.color + "22";
  $("#sh-name").textContent = d.name;
  $("#sh-sub").textContent = [d.auto?.kind || g.label, d.online ? "online" : `last seen ${ago(d.last_seen)}`].join(" · ");
}
function closeSheet() {
  $("#sheet").hidden = $("#sheet-bg").hidden = true;
  S.sel = null;
  $$("#map .node.sel").forEach((n) => n.classList.remove("sel"));
  highlight(S.hover);
}
$("#sh-close").onclick = closeSheet;
$("#sheet-bg").onclick = closeSheet;
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeSheet(); });

function renderSheet(d) {
  const st = S.state, sig = d.signals || {}, md = sig.mdns || {}, sd = sig.ssdp || {};
  const auto = d.auto || {};
  const opts = [`<option value="auto">Automatic: ${esc(groupInfo(auto.group).label)}</option>`]
    .concat(st.groups.map((g) => `<option value="${g.id}" ${d.group_manual === g.id ? "selected" : ""}>${esc(g.label)}</option>`));
  const live = S.live?.devices?.[d.mac];
  const kv = (k, v) => (v ? `<dt>${esc(k)}</dt><dd>${v}</dd>` : "");
  const names = [["Router", sig.router?.name], ["DNS", sig.ptr], ["Bonjour", md.hostname], ["NetBIOS", sig.netbios], ["UPnP", sd.friendlyName]]
    .filter(([, v]) => v).map(([k, v]) => `${esc(v)} <span class="tag">${k}</span>`).join("<br>");
  $("#sh-body").innerHTML = `
    <div class="form-row"><label for="f-label">Name</label><input type="text" id="f-label" value="${esc(d.label || "")}" placeholder="${esc(d.name)}" maxlength="80"></div>
    <div class="form-row"><label for="f-group">Group</label><select id="f-group">${opts.join("")}</select></div>
    <div class="form-row"><label for="f-notes">Notes</label><textarea id="f-notes" placeholder="Owner, location, asset tag…">${esc(d.notes || "")}</textarea></div>
    <div class="form-row"><label class="toggle"><input type="checkbox" id="f-approved" ${d.approved ? "checked" : ""}> Approved (I know this device)</label></div>
    <div class="actions"><button class="btn primary" id="f-save">Save</button><span class="hint" id="f-msg"></span></div>

    <h3>Details</h3><dl class="kv">
      ${kv("Status", d.online ? '<span class="tag good">online</span>' : `offline · last seen ${esc(when(d.last_seen))}`)}
      ${kv("IP address", esc(d.ip || "–"))}
      ${kv("MAC", `<span class="mono">${esc(d.mac)}</span>${d.random_mac ? ' <span class="tag">private / random</span>' : ""}`)}
      ${kv("Vendor", esc(d.vendor || (d.random_mac ? "Hidden by a private MAC" : "Unknown")))}
      ${kv("Model", esc(d.model || ""))}
      ${kv("Connection", esc(connLabel(d.conn)) + (d.mesh_parent ? ` via ${esc(byMac()[d.mesh_parent]?.name || d.mesh_parent)}` : ""))}
      ${kv("Signal", d.rssi ? `${d.rssi} dBm` : "")}
      ${kv("Link rate", d.link_tx ? `${d.link_tx} / ${d.link_rx ?? "–"} Mbps` : "")}
      ${kv("Traffic now", live ? `↓ ${fmtRate(live.down)} · ↑ ${fmtRate(live.up)} Mbps` : "")}
      ${kv("First seen", esc(when(d.first_seen)))}
      ${kv("Seen by", Object.entries(d.seen || {}).map(([k, v]) => `${esc(k)} ${esc(ago(v))}`).join(", "))}
      ${kv("Names", names)}
    </dl>

    <h3>Why “${esc(groupInfo(auto.group).label)}”</h3>
    <ul class="why">${(auto.why || []).map((w) => `<li>${esc(w)}</li>`).join("")}</ul>
    <div class="hint">Confidence: ${esc(auto.confidence || "–")}${d.group_manual ? " · overridden by you" : ""}</div>

    ${md.services?.length || sd.server || sd.types?.length ? `<h3>Discovered services</h3><dl class="kv">
      ${kv("Bonjour", (md.services || []).map(esc).join(", "))}
      ${kv("Bonjour names", (md.instances || []).map(esc).join(", "))}
      ${kv("Bonjour info", Object.entries(md.txt || {}).map(([k, v]) => `${esc(k)}=${esc(v)}`).join(", "))}
      ${kv("UPnP", esc([sd.manufacturer, sd.modelName, sd.modelDescription].filter(Boolean).join(" ")))}
      ${kv("UPnP server", esc(sd.server || ""))}</dl>` : ""}

    <h3>Open ports</h3>
    <div>${sig.ports ? (sig.ports.length ? sig.ports.map((p) => `<span class="tag">${p}</span>`).join(" ") : "None of the common ports are open") : "Not checked"}</div>
    <div class="actions"><button class="btn small" id="f-probe" ${d.online && d.ip ? "" : "disabled"}>Check common ports</button></div>

    <h3>Addresses used</h3>
    <dl class="kv">${(d.ips || []).map((i) => `<dt class="mono">${esc(i.ip)}</dt><dd>${esc(when(i.first_seen))} → ${esc(when(i.last_seen))}</dd>`).join("") || "<dd>–</dd>"}</dl>

    <h3>History</h3>
    ${(d.events || []).map((e) => `<div class="ev"><time>${esc(when(e.ts))}</time><span class="k ${esc(e.kind)}"></span><span class="t">${esc(e.text)}</span></div>`).join("") || '<div class="hint">–</div>'}

    ${d.is_router ? "" : `<div class="actions"><button class="btn danger small" id="f-forget">Remove from inventory</button></div>`}`;

  $("#f-save").onclick = async () => {
    const g = $("#f-group").value;
    try {
      const nd = await api(`/api/device/${d.mac}`, {
        label: $("#f-label").value, group: g === "auto" ? null : g,
        notes: $("#f-notes").value, approved: $("#f-approved").checked,
      });
      $("#f-msg").textContent = "Saved";
      await loadState(true);
      renderSheet(nd);
      refreshSheetHeader();
    } catch (e) { $("#f-msg").textContent = e.message; }
  };
  $("#f-probe").onclick = async (e) => {
    e.target.disabled = true; e.target.textContent = "Checking…";
    try { await api(`/api/device/${d.mac}/probe`, {}); renderSheet(await api(`/api/device/${d.mac}`)); }
    catch (err) { alert(err.message); }
  };
  const f = $("#f-forget");
  if (f) f.onclick = async () => {
    if (!confirm(`Remove ${d.name} from the inventory? If it is still on the network it will come back as a new device.`)) return;
    await api(`/api/device/${d.mac}/forget`, {});
    closeSheet();
    loadState(true);
  };
}

// ------------------------------------------------------------------ start
let liveTimer = null;
function startLive() {
  clearInterval(liveTimer);
  const ms = Math.max(2, S.state?.settings?.live_seconds || 3) * 1000;
  liveTimer = setInterval(loadLive, ms);
}
(async () => {
  let v = "map";
  try { v = localStorage.getItem("view") || "map"; } catch (e) { /* ignore */ }
  await loadState(true);
  showView(["map", "devices", "review", "activity", "router"].includes(v) ? v : "map");
  startLive();
  setInterval(() => loadState(false), 15000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) { loadState(false); loadLive(); } });
})();
