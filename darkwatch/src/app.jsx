const { useState, useEffect, useRef, useCallback } = React;

// ─── API helpers ─────────────────────────────────────────────────────────────

function computeSecure(health) {
    if (!health) return false;
    return !!(health.tor?.ok && health.vpn?.ok && health.ip_leak?.ok && health.dns?.ok);
}

function onionUrlError(url) {
    try {
        const host = new URL(url).hostname.toLowerCase();
        if (!host.endsWith(".onion")) return null;
        const label = host.slice(0, -6);
        if (/^[a-z2-7]{56}$/.test(label)) return null;
        if (/^[a-z2-7]{16}$/.test(label)) {
            return "v2 .onion deprecated — use a v3 address (56-character hostname)";
        }
        return `invalid .onion hostname (${host}) — need 56 base32 chars before .onion`;
    } catch {
        return "malformed URL";
    }
}

function externalLink(sample, host) {
    if (sample && /^https?:\/\//i.test(sample)) return sample;
    if (sample && /\.onion/i.test(sample)) return sample.startsWith("http") ? sample : `http://${sample}`;
    if (sample && /\./.test(sample)) {
        return sample.startsWith("//") ? `https:${sample}` : `https://${sample}`;
    }
    return host ? `https://${host}` : "#";
}

async function api(path, opts = {}) {
    const r = await fetch(path, {
        headers: { "Content-Type": "application/json" },
        ...opts,
    });
    const body = await r.json().catch(() => ({}));
    return { ok: r.ok, status: r.status, body };
}

const SEV_CLASSES = {
    critical: "text-red-400 bg-red-400/10 border-red-400/30",
    high:     "text-orange-400 bg-orange-400/10 border-orange-400/30",
    medium:   "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
    low:      "text-blue-400 bg-blue-400/10 border-blue-400/30",
};

// ─── Icon registry ───────────────────────────────────────────────────────────
// Single-color outline icons, 24×24 viewBox, stroke=currentColor so they
// inherit text-* colors. Use <Icon name="..." size={...} className="..." />.

const ICON_PATHS = {
    shield:    <path d="M12 2l8 4v6c0 5-3.5 9-8 10-4.5-1-8-5-8-10V6l8-4z" />,
    alert:     <g><path d="M10.3 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/></g>,
    clock:     <g><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></g>,
    close:     <g><path d="M6 6l12 12"/><path d="M6 18L18 6"/></g>,
    check:     <path d="M5 13l4 4L19 7"/>,
    refresh:   <g><path d="M21 12a9 9 0 11-3-6.7"/><path d="M21 4v5h-5"/></g>,
    trash:     <g><path d="M3 6h18"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6"/><path d="M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2"/><path d="M10 11v6"/><path d="M14 11v6"/></g>,
    play:      <path d="M5 3l14 9-14 9V3z"/>,
    stop:      <rect x="5" y="5" width="14" height="14"/>,
    plus:      <g><path d="M12 5v14"/><path d="M5 12h14"/></g>,
    copy:      <g><rect x="9" y="9" width="11" height="11" rx="1"/><path d="M5 15V5a2 2 0 012-2h10"/></g>,
    download:  <g><path d="M12 3v13"/><path d="M7 11l5 5 5-5"/><path d="M4 21h16"/></g>,
    eye:       <g><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></g>,
    keyboard:  <g><rect x="2" y="5" width="20" height="14" rx="2"/><path d="M6 10h.01"/><path d="M10 10h.01"/><path d="M14 10h.01"/><path d="M18 10h.01"/><path d="M6 14h12"/></g>,
    login:     <g><path d="M15 3h4a2 2 0 012 2v14a2 2 0 01-2 2h-4"/><path d="M10 17l5-5-5-5"/><path d="M15 12H3"/></g>,
    logout:    <g><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/></g>,
    users:     <g><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></g>,
    link:      <g><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></g>,
    scan:      <g><path d="M3 7V5a2 2 0 012-2h2"/><path d="M17 3h2a2 2 0 012 2v2"/><path d="M21 17v2a2 2 0 01-2 2h-2"/><path d="M7 21H5a2 2 0 01-2-2v-2"/><path d="M7 12h10"/></g>,
    file:      <g><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6"/></g>,
    archive:   <g><rect x="2" y="3" width="20" height="5" rx="1"/><path d="M4 8v12a1 1 0 001 1h14a1 1 0 001-1V8"/><path d="M10 12h4"/></g>,
};

function Icon({ name, size = 16, className = "" }) {
    const node = ICON_PATHS[name];
    if (!node) return null;
    return (
        <svg className={className} width={size} height={size}
             viewBox="0 0 24 24" fill="none" stroke="currentColor"
             strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"
             aria-hidden="true">
            {node}
        </svg>
    );
}

// ─── Logo (onion-rings + watchful eye + cardinal crosshair) ─────────────────
// Compact 32×32 version of the brand mark in /assets/logo.svg.
// The detailed three-ring + crosshair-tick version of this mark is in the
// README. At 32 px the middle ring and outer ticks lose to anti-aliasing,
// so this variant drops to two rings and skips the ticks. Color is the
// brand blue (#4A9EFF via tailwind `brand-400`), matching the README/
// external mark. Dashboard status colors stay emerald/red/amber — those
// carry semantic meaning and shouldn't collapse into the brand color.
function Logo() {
    return (
        <div className="flex items-center gap-2.5">
            <svg width="32" height="32" viewBox="0 0 32 32" fill="none"
                 className="text-brand-400"
                 stroke="currentColor"
                 strokeLinecap="round" strokeLinejoin="round"
                 aria-hidden="true">
                {/* outer dashed onion-routing ring */}
                <circle cx="16" cy="16" r="13" strokeWidth="1.25"
                        strokeDasharray="18 5" opacity="0.6" />
                {/* inner solid ring */}
                <circle cx="16" cy="16" r="8" strokeWidth="1.5" opacity="0.95" />
                {/* almond eye */}
                <path d="M 11 16 Q 16 12 21 16 Q 16 20 11 16 Z" strokeWidth="1.4" />
                {/* pupil (filled) */}
                <circle cx="16" cy="16" r="1.6" fill="currentColor" stroke="none" />
                {/* catchlight on pupil */}
                <circle cx="15.5" cy="15.5" r="0.45" fill="#FFFFFF" stroke="none" />
            </svg>
            <span className="text-xl font-bold tracking-tight text-gray-100">
                Dark<span className="text-brand-400">Watch</span>
            </span>
        </div>
    );
}

// ─── Small components ────────────────────────────────────────────────────────

function Dot({ ok, label }) {
    return (
        <span className="inline-flex items-center gap-1.5">
            <span className={
                "inline-block w-2.5 h-2.5 rounded-full " +
                (ok ? "bg-emerald-400" : "bg-red-400 pulse-red")
            } aria-hidden="true" />
            <span className="sr-only">{label}: {ok ? "ok" : "failed"}</span>
        </span>
    );
}

function SevBadge({ sev }) {
    const cls = SEV_CLASSES[sev] || "text-gray-400 bg-gray-400/10 border-gray-400/30";
    return (
        <span className={
            "inline-block px-2 py-0.5 rounded text-xs font-semibold uppercase " +
            "border " + cls
        }>{sev || "?"}</span>
    );
}

// Small pill rendered next to page URLs to show what kind of page it is.
// Mostly used to visually distinguish findings on login/register forms
// (which the crawler detects automatically) from findings on real leak
// content. `other` never renders.
// Small pill showing where a finding came from: onion (tor) vs telegram.
// `manual` / `web-ui` / `file` all fall under "tor" — they're .onion URLs
// added by different means but scanned via the same Tor path.
function SourceBadge({ source }) {
    if (!source) return null;
    const cfg = source === "telegram"
        ? { label: "tg",  cls: "text-cyan-300 border-cyan-500/40 bg-cyan-500/10" }
        : { label: "tor", cls: "text-emerald-300 border-emerald-500/40 bg-emerald-500/10" };
    return (
        <span className={
            "inline-block px-1.5 py-0.5 text-[10px] mono rounded border ml-1 " +
            "align-middle " + cfg.cls}
              title={`Source: ${source}`}>
            {cfg.label}
        </span>
    );
}

function PageTypeBadge({ type }) {
    if (!type || type === "other") return null;
    const label = {
        login:          "login page",
        register:       "register page",
        login_register: "login + register",
    }[type] || type;
    return (
        <span className="inline-block px-1.5 py-0.5 text-[10px] rounded
                         bg-gray-700/60 text-gray-300 border border-gray-600
                         mono ml-1 align-middle"
              title="Classified by form structure — not necessarily an indicator of credential leak content">
            {label}
        </span>
    );
}

function CopyButton({ text, label = "copy" }) {
    const [copied, setCopied] = useState(false);
    const [failed, setFailed] = useState(false);
    return (
        <button
            onClick={async () => {
                try {
                    await navigator.clipboard.writeText(text);
                    setCopied(true);
                    setFailed(false);
                    setTimeout(() => setCopied(false), 1200);
                } catch {
                    setFailed(true);
                    setTimeout(() => setFailed(false), 2000);
                }
            }}
            title={text}
            aria-label={label === "copy" ? "Copy to clipboard" : `Copy ${label}`}
            className="inline-flex items-center gap-1 text-xs text-gray-400
                       hover:text-brand-400 mono"
        >
            {copied
                ? <Icon name="check" size={12} className="text-brand-400" />
                : <Icon name="copy" size={12} />}
            {failed ? <span className="text-red-400">failed</span>
                : label === "copy" ? null : label}
        </button>
    );
}

function Toast({ message, onClose }) {
    useEffect(() => {
        if (!message) return;
        const t = setTimeout(onClose, 3500);
        return () => clearTimeout(t);
    }, [message, onClose]);
    if (!message) return null;
    return (
        <div role="status" aria-live="polite"
             className="fixed bottom-6 right-6 z-50 bg-gray-800 border border-gray-700
                        text-gray-100 px-4 py-3 rounded shadow-xl max-w-sm">
            {message}
        </div>
    );
}

// ─── Header + Security ───────────────────────────────────────────────────────

function Header({ health, healthReady, scanning, scanTimer, onOpenSecurity,
                  onRecheck, rechecking, version }) {
    const secure = computeSecure(health);
    const checking = !healthReady || rechecking;
    return (
        <header className="border-b border-gray-800 bg-gray-900/60 backdrop-blur">
            <div className="max-w-7xl mx-auto px-3 sm:px-6 py-3 sm:py-4
                            flex flex-wrap items-center gap-3 sm:gap-6">
                <div className="flex items-center gap-2">
                    <Logo />
                    {version && (
                        <span className="text-xs text-gray-500 mono ml-1">v{version}</span>
                    )}
                </div>

                <button
                    onClick={onOpenSecurity}
                    disabled={checking}
                    className={
                        "flex items-center gap-2 px-3 py-1.5 rounded border text-sm font-medium " +
                        (checking
                            ? "border-gray-700 bg-gray-800/40 text-gray-500 cursor-wait"
                            : secure
                            ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                            : "border-red-500/40 bg-red-500/10 text-red-300 pulse-red")
                    }
                    title={checking ? "Running security checks…" : "Click for security details"}
                >
                    <Icon name={checking ? "shield" : secure ? "shield" : "alert"} size={14} />
                    <span>{checking ? "CHECKING…" : secure ? "SECURE" : "NOT SECURE"}</span>
                </button>

                <button
                    onClick={onRecheck}
                    disabled={rechecking}
                    title="Run full security checks (Tor, VPN, IP leak, .onion)"
                    className="px-3 py-1.5 rounded border border-gray-700 bg-gray-800/60
                               text-gray-300 text-sm hover:bg-gray-700 disabled:opacity-50
                               flex items-center gap-1.5"
                >
                    <Icon name="refresh" size={14}
                          className={rechecking ? "animate-spin" : ""} />
                    {rechecking ? "Checking…" : "Re-check"}
                </button>

                <div className="flex items-center gap-3 text-xs text-gray-400">
                    <span className="flex items-center gap-1.5">
                        <Dot ok={health?.tor?.ok} label="Tor" /> Tor
                    </span>
                    <span className="flex items-center gap-1.5">
                        <Dot ok={health?.vpn?.ok} label="VPN" /> VPN
                    </span>
                </div>

                <div className="ml-auto flex items-center gap-4">
                    {scanning && (
                        <span className="mono text-sm text-emerald-400 flex items-center gap-1.5">
                            <Icon name="clock" size={14} />
                            {Math.floor(scanTimer / 60)}:{String(scanTimer % 60).padStart(2, "0")}
                        </span>
                    )}
                    <span className={
                        "px-2 py-1 rounded text-xs font-semibold " +
                        (scanning
                            ? "bg-emerald-500/20 text-emerald-300"
                            : "bg-gray-700 text-gray-400")
                    }>
                        {scanning ? "● SCANNING" : "IDLE"}
                    </span>
                </div>
            </div>
        </header>
    );
}

function ShortcutsModal({ onClose }) {
    const rows = [
        ["?",       "Show this help"],
        ["/",       "Focus search / filter"],
        ["Esc",     "Close modal / lightbox"],
        ["g s",     "Go to Scan"],
        ["g f",     "Go to Findings"],
        ["g u",     "Go to URLs"],
        ["g t",     "Go to Telegram"],
        ["g k",     "Go to Keywords"],
        ["g r",     "Go to Rules"],
    ];
    return (
        <div onClick={onClose}
             className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
            <div onClick={e => e.stopPropagation()}
                 className="bg-gray-900 border border-gray-700 rounded max-w-md w-full p-5">
                <div className="flex items-center justify-between mb-4">
                    <h2 className="text-lg font-semibold text-gray-100">Keyboard shortcuts</h2>
                    <button onClick={onClose} aria-label="Close"
                            className="text-gray-500 hover:text-gray-200">
                        <Icon name="close" />
                    </button>
                </div>
                <table className="w-full text-sm">
                    <tbody>
                        {rows.map(([k, label]) => (
                            <tr key={k} className="border-b border-gray-800 last:border-0">
                                <td className="py-1.5 pr-3">
                                    <kbd className="bg-gray-800 border border-gray-700
                                                    rounded px-2 py-0.5 text-xs mono text-gray-200">
                                        {k}
                                    </kbd>
                                </td>
                                <td className="py-1.5 text-gray-400">{label}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

function SecurityModal({ health, onClose, onRecheck, rechecking }) {
    if (!health) {
        return (
            <div className="fixed inset-0 z-40 bg-black/70 flex items-center justify-center p-6"
                 onClick={onClose}>
                <div onClick={e => e.stopPropagation()}
                     className="bg-gray-900 border border-gray-700 rounded-lg max-w-lg w-full p-6">
                    <p className="text-sm text-gray-400">Running security checks…</p>
                </div>
            </div>
        );
    }
    const items = [
        ["tor", "Tor exit confirmed"],
        ["vpn", "VPN tunnel (Tor-side)"],
        ["ip_leak", "No IP leak"],
        ["dns", "DNS over Tor"],
        ["tg_vpn", "VPN tunnel (Telegram-side)"],
        ["playwright", "Playwright (screenshots)"],
    ];
    return (
        <div className="fixed inset-0 z-40 bg-black/70 flex items-center justify-center p-6"
             onClick={onClose}>
            <div onClick={e => e.stopPropagation()}
                 className="bg-gray-900 border border-gray-700 rounded-lg max-w-lg w-full p-6">
                <div className="flex items-center justify-between mb-4">
                    <h2 className="text-lg font-semibold">Security posture</h2>
                    <button onClick={onClose} aria-label="Close"
                            className="text-gray-500 hover:text-gray-200">
                        <Icon name="close" size={18} />
                    </button>
                </div>
                <ul className="space-y-3 mb-5">
                    {items.map(([key, label]) => {
                        const check = health[key];
                        if (!check) return null;
                        return (
                            <li key={key} className="flex items-start gap-3">
                                <span className="mt-0.5">{check.ok ? "✅" : "❌"}</span>
                                <div className="flex-1 min-w-0">
                                    <div className="text-sm">{label}</div>
                                    <div className="text-xs text-gray-500 mono break-all">
                                        {check.detail}
                                    </div>
                                </div>
                            </li>
                        );
                    })}
                </ul>
                <div className="flex items-center justify-between text-xs text-gray-500">
                    <span className="mono">{health.checked_at}</span>
                    <button
                        onClick={onRecheck}
                        disabled={rechecking}
                        className="px-3 py-1.5 rounded bg-gray-800 hover:bg-gray-700
                                   text-gray-200 disabled:opacity-50"
                    >{rechecking ? "Checking…" : "Re-check"}</button>
                </div>
            </div>
        </div>
    );
}

// ─── Stats / tabs ────────────────────────────────────────────────────────────

function StatsBar({ stats }) {
    const cards = [
        { label: "URLs tracked",  value: stats?.total_urls ?? 0,         tone: "text-gray-100" },
        { label: "Monitored",     value: stats?.monitored_urls ?? 0,     tone: "text-cyan-400" },
        { label: "Pages scanned", value: stats?.total_pages ?? 0,        tone: "text-gray-100" },
        { label: "Findings",      value: stats?.total_findings ?? 0,     tone: "text-emerald-400" },
        { label: "Critical",      value: stats?.critical_findings ?? 0,  tone: "text-red-400" },
    ];
    return (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
            {cards.map(c => (
                <div key={c.label}
                     className="bg-gray-800/50 border border-gray-700 rounded p-4">
                    <div className="text-xs text-gray-500 uppercase tracking-wide">{c.label}</div>
                    <div className={"text-2xl font-bold mt-1 " + c.tone}>{c.value}</div>
                </div>
            ))}
        </div>
    );
}

function TabNav({ activeTab, onChange, findingsCount, urlsCount,
                  rulesCount, keywordsCount, telegramCount, setupUrl }) {
    const tabs = [
        { id: "scan",     label: "Scan" },
        { id: "findings", label: "Findings", count: findingsCount },
        { id: "urls",     label: "URLs",     count: urlsCount },
        { id: "telegram", label: "Telegram", count: telegramCount },
        { id: "keywords", label: "Keywords", count: keywordsCount },
        { id: "rules",    label: "Rules",    count: rulesCount },
    ];
    const settingsHref = setupUrl || `${window.location.protocol}//${window.location.hostname}:8082/`;
    return (
        <nav className="flex gap-1 border-b border-gray-800 mb-6
                        overflow-x-auto whitespace-nowrap -mx-3 sm:mx-0 px-3 sm:px-0"
             role="tablist" aria-label="Dashboard sections">
            {tabs.map(t => (
                <button
                    key={t.id}
                    role="tab"
                    aria-selected={activeTab === t.id}
                    onClick={() => onChange(t.id)}
                    className={
                        "px-3 sm:px-4 py-2 text-xs sm:text-sm border-b-2 transition-colors " +
                        (activeTab === t.id
                            ? "border-brand-400 text-brand-300"
                            : "border-transparent text-gray-400 hover:text-gray-200")
                    }
                >
                    {t.label}
                    {typeof t.count === "number" && (
                        <span className="ml-2 text-xs text-gray-500">({t.count})</span>
                    )}
                </button>
            ))}
            <a
                href={settingsHref}
                target="_blank"
                rel="noopener noreferrer"
                title="Open Setup UI. Sign in once with your token; session lasts 7 days."
                className="ml-auto px-3 sm:px-4 py-2 text-xs sm:text-sm
                           border-b-2 border-transparent text-gray-400
                           hover:text-brand-300 hover:border-brand-400/40
                           transition-colors"
            >
                Settings <span aria-hidden="true">↗</span>
            </a>
        </nav>
    );
}

// ─── Scan panel ──────────────────────────────────────────────────────────────

// `tor`, `vpn`, `ip_leak`, `dns` are REQUIRED to scan. The rest are advisory.
const SECURITY_REQUIRED = new Set(["tor", "vpn", "ip_leak", "dns"]);

function SecurityChecklist({ health }) {
    if (!health) return <div className="text-xs text-gray-500">Checking security…</div>;
    const rows = [
        ["tor",     "Tor exit (IsTor)"],
        ["vpn",     "VPN / SOCKS path"],
        ["ip_leak", "No IP leak"],
        ["dns",     ".onion reachability"],
        ["tg_vpn",     "Telegram VPN (optional)"],
        ["playwright", "Playwright (optional)"],
    ];
    return (
        <div className="text-xs bg-gray-900/60 border border-gray-800 rounded p-3 mono space-y-1">
            {rows.map(([key, label]) => {
                const c = health[key];
                if (!c) return null;
                const required = SECURITY_REQUIRED.has(key);
                const iconName = c.ok ? "check"
                    : required ? "close" : "alert";
                const iconColor = c.ok ? "text-emerald-400"
                    : required ? "text-red-400" : "text-yellow-400";
                return (
                    <div key={key} className="flex items-start gap-2">
                        <Icon name={iconName} size={14}
                              className={iconColor + " flex-shrink-0 mt-0.5"} />
                        <span className="text-gray-300 w-44 flex-shrink-0">{label}</span>
                        <span className="text-gray-500 truncate">{c.detail}</span>
                    </div>
                );
            })}
        </div>
    );
}

function LogViewer({ logs, truncated, paused, onClear, onTogglePause }) {
    const ref = useRef(null);
    // Auto-scroll to bottom on every new log UNLESS the operator paused —
    // then the viewport stays put so they can read earlier lines.
    useEffect(() => {
        if (paused) return;
        const el = ref.current;
        if (el) el.scrollTop = el.scrollHeight;
    }, [logs, paused]);
    return (
        <div className="bg-gray-950 border border-gray-800 rounded">
            <div className="flex items-center justify-between px-3 py-2 border-b border-gray-800 gap-2">
                <span className="text-xs text-gray-500 uppercase">Live log</span>
                {truncated && (
                    <span className="text-[10px] text-yellow-400 mono">
                        … oldest lines discarded (capped at 500)
                    </span>
                )}
                <span className="ml-auto flex items-center gap-2">
                    <button onClick={onTogglePause}
                            title={paused ? "Resume auto-scroll" : "Pause auto-scroll"}
                            className={"text-xs " + (paused
                                ? "text-yellow-400 hover:text-yellow-300"
                                : "text-gray-500 hover:text-gray-200")}>
                        {paused ? "paused" : "pause"}
                    </button>
                    <button onClick={onClear}
                            className="text-xs text-gray-500 hover:text-gray-200">clear</button>
                </span>
            </div>
            <div ref={ref}
                 className="h-80 overflow-y-auto p-3 text-xs mono space-y-0.5">
                {logs.length === 0 && (
                    <div className="text-gray-600">Waiting for scan output…</div>
                )}
                {logs.map((line, i) => {
                    let cls = "text-gray-300";
                    if (/ERROR|FAIL|ALERT CRITICAL/.test(line)) cls = "text-red-400";
                    else if (/WARNING|ALERT HIGH/.test(line)) cls = "text-orange-400";
                    else if (/MATCH|Scanning:/.test(line)) cls = "text-emerald-300";
                    return <div key={i} className={"log-line " + cls}>{line}</div>;
                })}
            </div>
        </div>
    );
}

function ScanPanel({ scanning, submitting, progress, health, onStart, onStop,
                     onRecheckHealth, rechecking, onImportTargets,
                     logs, logsTruncated, paused, onClearLogs, onTogglePause }) {
    const [targets, setTargets] = useState("");
    const [depth, setDepth] = useState(2);
    const [importing, setImporting] = useState(false);
    const secure = computeSecure(health);
    const busy = scanning || submitting;

    // Parse + validate the textarea content: every non-blank line must be
    // a http(s) URL. Show counts; disable Start if any line is invalid.
    const lines = targets.split("\n").map(s => s.trim()).filter(Boolean);
    const validUrls = lines.filter(l => /^https?:\/\//i.test(l));
    const invalidCount = lines.length - validUrls.length;
    const badOnions = validUrls
        .map(u => ({ url: u, error: onionUrlError(u) }))
        .filter(x => x.error);

    const canStart = !busy && secure && lines.length > 0
        && invalidCount === 0 && badOnions.length === 0;

    const submit = () => {
        if (validUrls.length === 0 || invalidCount > 0 || badOnions.length > 0) return;
        onStart(validUrls, depth);
    };

    const doImport = async () => {
        setImporting(true);
        try {
            const urls = await onImportTargets();
            if (Array.isArray(urls) && urls.length > 0) {
                setTargets(prev => {
                    const existing = new Set(prev.split("\n").map(s => s.trim()).filter(Boolean));
                    const merged = [...existing];
                    for (const u of urls) if (!existing.has(u)) merged.push(u);
                    return merged.join("\n");
                });
            }
        } finally {
            setImporting(false);
        }
    };

    return (
        <div className="grid lg:grid-cols-2 gap-6">
            <div className="space-y-4">
                <SecurityChecklist health={health} />

                <div>
                    <div className="flex items-center justify-between mb-1">
                        <label className="text-xs text-gray-400 uppercase tracking-wide">
                            Targets (one per line)
                        </label>
                        <button type="button"
                                onClick={doImport}
                                disabled={busy || importing}
                                className="text-xs text-gray-400 hover:text-brand-400
                                           disabled:opacity-50 flex items-center gap-1">
                            {importing ? <Spinner /> : null}
                            Import from targets.txt
                        </button>
                    </div>
                    <textarea
                        value={targets}
                        onChange={e => setTargets(e.target.value)}
                        disabled={busy}
                        rows={8}
                        placeholder="http://xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion"
                        className="w-full bg-gray-900 border border-gray-700 rounded
                                   p-3 text-sm mono text-gray-100
                                   focus:outline-none focus:border-brand-500"
                    />
                    {lines.length > 0 && (
                        <div className="text-[11px] mt-1 flex flex-col gap-0.5">
                            <div className="flex gap-3">
                                <span className={validUrls.length > 0 ? "text-emerald-400" : "text-gray-500"}>
                                    {validUrls.length} valid URL{validUrls.length !== 1 ? "s" : ""}
                                </span>
                                {invalidCount > 0 && (
                                    <span className="text-red-400">
                                        {invalidCount} invalid (must start with http:// or https://)
                                    </span>
                                )}
                            </div>
                            {badOnions.length > 0 && (
                                <span className="text-red-400">
                                    {badOnions.length} invalid .onion — v2 addresses no longer work in Tor
                                </span>
                            )}
                        </div>
                    )}
                </div>

                <div className="flex items-end gap-3">
                    <div>
                        <label className="text-xs text-gray-400 uppercase tracking-wide">
                            Depth
                        </label>
                        <select
                            value={depth}
                            onChange={e => setDepth(parseInt(e.target.value, 10))}
                            disabled={busy}
                            className="mt-1 bg-gray-900 border border-gray-700 rounded
                                       px-3 py-2 text-sm"
                        >
                            {[1, 2, 3, 4, 5].map(d => <option key={d} value={d}>{d}</option>)}
                        </select>
                    </div>

                    {!scanning ? (
                        <button
                            onClick={submit}
                            disabled={!canStart}
                            title={submitting ? "Verifying security…" :
                                   !secure ? "Security gate not green — fix before scanning" : ""}
                            className="px-5 py-2 rounded bg-brand-500 text-gray-50
                                       font-semibold hover:bg-brand-400
                                       disabled:bg-gray-700 disabled:text-gray-500
                                       disabled:cursor-not-allowed
                                       flex items-center gap-2 min-w-[150px] justify-center"
                        >
                            {submitting
                                ? (<><Spinner /> Starting…</>)
                                : (<><Icon name="play" /> Start scan</>)}
                        </button>
                    ) : (
                        <button
                            onClick={onStop}
                            className="px-5 py-2 rounded bg-red-500 text-gray-950 font-semibold
                                       hover:bg-red-400 flex items-center gap-2"
                        >
                            <Icon name="stop" /> Stop
                        </button>
                    )}

                    <button
                        onClick={onRecheckHealth}
                        disabled={rechecking}
                        className="px-3 py-2 rounded bg-gray-800 text-gray-300 text-sm
                                   hover:bg-gray-700 disabled:opacity-50"
                    >{rechecking ? "Checking…" : "Re-check"}</button>
                </div>

                {busy && progress.total > 0 && (
                    <div>
                        <div className="text-xs text-gray-500 mb-1">
                            {progress.completed} / {progress.total}
                        </div>
                        <div className="h-1.5 bg-gray-800 rounded overflow-hidden">
                            <div
                                className="h-full bg-brand-400 transition-all"
                                style={{ width: `${(progress.completed / progress.total) * 100}%` }}
                            />
                        </div>
                    </div>
                )}
            </div>

            <LogViewer
                logs={logs}
                truncated={logsTruncated}
                paused={paused}
                onClear={onClearLogs}
                onTogglePause={onTogglePause}
            />
        </div>
    );
}

// ─── Findings ────────────────────────────────────────────────────────────────

function Thumbnail({ url, fallback, onClick }) {
    const [broken, setBroken] = useState(false);
    const src = url || fallback;
    if (!src || broken) {
        return (
            <div className="w-16 h-10 bg-gray-800 rounded flex items-center justify-center
                            text-gray-600 text-xs border border-gray-700">—</div>
        );
    }
    return (
        <img
            src={src}
            onClick={onClick}
            onError={() => setBroken(true)}
            className="w-16 h-10 object-cover rounded border border-gray-700
                       cursor-zoom-in hover:border-brand-500"
            alt="Page thumbnail"
        />
    );
}

function Lightbox({ lightbox, onClose, onIndex }) {
    // lightbox = { items: [ {page_url, page_title, screenshot_url, severity} ],
    //              index: number } or null.
    // Passing onIndex allows callers to persist the new index.
    const items = lightbox?.items;
    const index = lightbox?.index ?? 0;
    const page = items ? items[index] : null;
    const many = items && items.length > 1;
    const [imgBroken, setImgBroken] = useState(false);

    useEffect(() => { setImgBroken(false); }, [page?.screenshot_url, index]);

    const go = (delta) => {
        if (!many) return;
        const next = (index + delta + items.length) % items.length;
        onIndex(next);
    };

    useEffect(() => {
        if (!page) return;
        const h = e => {
            if (e.key === "Escape") onClose();
            else if (e.key === "ArrowRight") go(1);
            else if (e.key === "ArrowLeft")  go(-1);
        };
        window.addEventListener("keydown", h);
        return () => window.removeEventListener("keydown", h);
    }, [page, index, items, onClose]);

    if (!page) return null;
    return (
        <div
            className="fixed inset-0 z-40 bg-black/90 flex items-center justify-center p-6"
            onClick={onClose}
        >
            <div onClick={e => e.stopPropagation()}
                 className="max-w-6xl w-full bg-gray-900 border border-gray-700
                            rounded-lg overflow-hidden">
                <div className="px-4 py-2 flex items-center justify-between border-b border-gray-800 gap-3">
                    <div className="flex-1 min-w-0">
                        {page.page_title && (
                            <div className="text-sm text-gray-100 font-medium truncate">{page.page_title}</div>
                        )}
                        <div className="mono text-xs text-gray-500 truncate">{page.page_url}</div>
                    </div>
                    {many && (
                        <span className="text-xs text-gray-500 mono flex-shrink-0">
                            {index + 1} / {items.length}
                        </span>
                    )}
                    {page.severity && <SevBadge sev={page.severity} />}
                    {page.screenshot_url && (
                        <a href={page.screenshot_url}
                           download
                           onClick={e => e.stopPropagation()}
                           title="Download screenshot"
                           aria-label="Download screenshot"
                           className="text-gray-500 hover:text-gray-200">
                            <Icon name="download" size={18} />
                        </a>
                    )}
                    <button onClick={onClose} aria-label="Close"
                            className="text-gray-500 hover:text-gray-200">
                        <Icon name="close" size={18} />
                    </button>
                </div>
                <div className="relative">
                    {page.screenshot_url && !imgBroken ? (
                        <img src={page.screenshot_url}
                             onError={() => setImgBroken(true)}
                             className="w-full max-h-[80vh] object-contain bg-gray-950"
                             alt="Full page screenshot" />
                    ) : (
                        <div className="w-full min-h-[240px] flex items-center justify-center
                                        bg-gray-950 text-gray-500 text-sm">
                            Screenshot unavailable
                        </div>
                    )}
                    {many && (
                        <>
                            <button onClick={() => go(-1)}
                                    aria-label="Previous"
                                    className="absolute left-2 top-1/2 -translate-y-1/2
                                               bg-black/60 hover:bg-black/80 text-white
                                               rounded-full w-10 h-10 flex items-center justify-center">
                                ‹
                            </button>
                            <button onClick={() => go(1)}
                                    aria-label="Next"
                                    className="absolute right-2 top-1/2 -translate-y-1/2
                                               bg-black/60 hover:bg-black/80 text-white
                                               rounded-full w-10 h-10 flex items-center justify-center">
                                ›
                            </button>
                        </>
                    )}
                </div>
            </div>
        </div>
    );
}

// Severity rank for ordering (higher = scarier).
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

function FindingsPanel({ findings, sevFilter, onFilter, onRefresh, onGenerateReport,
                         onDeleteOne, onDeleteMany, onLightbox,
                         hasMore, onLoadMore, loading, hasReport }) {
    const [expanded, setExpanded] = useState(null);
    const [sortKey, setSortKey] = useState("score");
    const [sortDir, setSortDir] = useState("desc");      // "asc" | "desc"
    const [query, setQuery] = useState("");
    const [sourceFilter, setSourceFilter] = useState("all");  // all | tor | telegram

    // Severity filter → source filter → text search → sort.
    const bySev = sevFilter === "all"
        ? findings
        : findings.filter(f => f.severity === sevFilter);

    const bySource = sourceFilter === "all" ? bySev
        : sourceFilter === "telegram" ? bySev.filter(f => f.source === "telegram")
        : bySev.filter(f => f.source !== "telegram");   // "tor" = anything not TG

    const q = query.trim().toLowerCase();
    const bySearch = q ? bySource.filter(f => {
        const hay = (f.page_url || "") + " " + (f.page_title || "") + " " +
                    (f.matched_strings || "") + " " + (f.rule_name || "");
        return hay.toLowerCase().includes(q);
    }) : bySource;

    const compare = (a, b) => {
        let va, vb;
        switch (sortKey) {
            case "severity":  va = SEV_RANK[a.severity] || 0; vb = SEV_RANK[b.severity] || 0; break;
            case "rule":      va = a.rule_name || ""; vb = b.rule_name || ""; break;
            case "score":     va = a.score || 0; vb = b.score || 0; break;
            case "found_at":
            default:          va = a.found_at || ""; vb = b.found_at || ""; break;
        }
        const cmp = va < vb ? -1 : va > vb ? 1 : 0;
        return sortDir === "asc" ? cmp : -cmp;
    };
    const filtered = [...bySearch].sort(compare);

    const clickHeader = (key) => {
        if (sortKey === key) setSortDir(d => d === "asc" ? "desc" : "asc");
        else { setSortKey(key); setSortDir("desc"); }
    };
    const headerArrow = (key) => sortKey !== key ? "" : (sortDir === "asc" ? " ↑" : " ↓");

    const bulkLabel = `Delete ${filtered.length} visible`;

    const doBulkDelete = () => {
        if (filtered.length === 0) return;
        if (!window.confirm(`Delete ${filtered.length} visible finding(s)? This cannot be undone.`)) return;
        onDeleteMany(filtered.map(f => f.id));
    };

    return (
        <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-3">
                <select value={sevFilter}
                        onChange={e => onFilter(e.target.value)}
                        className="bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm">
                    <option value="all">All severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
                <select value={sourceFilter}
                        onChange={e => setSourceFilter(e.target.value)}
                        className="bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm">
                    <option value="all">All sources</option>
                    <option value="tor">Tor (.onion)</option>
                    <option value="telegram">Telegram</option>
                </select>
                <button onClick={onRefresh}
                        className="px-3 py-2 rounded bg-gray-800 text-sm
                                   hover:bg-gray-700 flex items-center gap-1.5">
                    <Icon name="refresh" size={14} /> Refresh
                </button>
                <button onClick={onGenerateReport}
                        className="px-3 py-2 rounded bg-gray-800 text-sm hover:bg-gray-700">
                    Generate report
                </button>
                {hasReport ? (
                    <a href="/api/report/download"
                       className="px-3 py-2 rounded bg-gray-800 text-sm hover:bg-gray-700">
                        Download JSON
                    </a>
                ) : (
                    <span className="px-3 py-2 rounded bg-gray-900 text-sm text-gray-600"
                          title="Generate a report first">
                        Download JSON
                    </span>
                )}
                <a href="/api/findings.csv"
                   className="px-3 py-2 rounded bg-gray-800 text-sm hover:bg-gray-700">
                    Export CSV
                </a>
                <button onClick={doBulkDelete}
                        disabled={filtered.length === 0}
                        className="px-3 py-2 rounded bg-red-900/60 border border-red-800
                                   text-red-200 text-sm hover:bg-red-800/60
                                   disabled:opacity-40 disabled:cursor-not-allowed
                                   flex items-center gap-1.5">
                    <Icon name="trash" size={14} /> {bulkLabel}
                </button>
                <input
                    value={query}
                    onChange={e => setQuery(e.target.value)}
                    placeholder="Search URL, title, rule, match…"
                    className="flex-1 min-w-[200px] bg-gray-900 border border-gray-700
                               rounded px-3 py-2 text-sm
                               focus:outline-none focus:border-brand-500"
                />
                <span className="text-xs text-gray-500">
                    {filtered.length} of {findings.length} findings
                </span>
            </div>

            <div className="overflow-x-auto border border-gray-800 rounded">
                <table className="w-full text-sm">
                    <thead className="bg-gray-900 text-gray-400 text-xs uppercase">
                        <tr>
                            <th className="p-2 text-left"></th>
                            <th className="p-2 text-left cursor-pointer select-none
                                           hover:text-brand-300"
                                onClick={() => clickHeader("severity")}>
                                Severity{headerArrow("severity")}
                            </th>
                            <th className="p-2 text-left cursor-pointer select-none
                                           hover:text-brand-300"
                                onClick={() => clickHeader("rule")}>
                                Rule{headerArrow("rule")}
                            </th>
                            <th className="p-2 text-right cursor-pointer select-none
                                           hover:text-brand-300"
                                onClick={() => clickHeader("score")}>
                                Score{headerArrow("score")}
                            </th>
                            <th className="p-2 text-left">URL</th>
                            <th className="p-2 text-left cursor-pointer select-none
                                           hover:text-brand-300"
                                onClick={() => clickHeader("found_at")}>
                                Found{headerArrow("found_at")}
                            </th>
                            <th className="p-2"></th>
                        </tr>
                    </thead>
                    <tbody>
                        {filtered.length === 0 && (
                            <tr><td colSpan={7} className="p-6 text-center text-gray-500">
                                No findings match the current filter.
                            </td></tr>
                        )}
                        {filtered.map(f => (
                            <React.Fragment key={f.id}>
                                <tr className="border-t border-gray-800 hover:bg-gray-900/50">
                                    <td className="p-2">
                                        <Thumbnail
                                            url={f.thumbnail_url}
                                            fallback={f.screenshot_url}
                                            onClick={() => {
                                                // Build the full set of filtered findings
                                                // that HAVE screenshots, so arrow-key nav
                                                // walks through real shots only.
                                                const items = filtered
                                                    .filter(x => x.screenshot_url)
                                                    .map(x => ({
                                                        page_url: x.page_url,
                                                        page_title: x.page_title,
                                                        screenshot_url: x.screenshot_url,
                                                        severity: x.severity,
                                                    }));
                                                const idx = items.findIndex(
                                                    x => x.page_url === f.page_url
                                                       && x.screenshot_url === f.screenshot_url);
                                                onLightbox({ items, index: Math.max(0, idx) });
                                            }}
                                        />
                                    </td>
                                    <td className="p-2"><SevBadge sev={f.severity} /></td>
                                    <td className="p-2 mono text-xs">{f.rule_name}
                                        <div className="text-gray-500">{f.rule_type}</div>
                                    </td>
                                    <td className="p-2 text-right mono">{f.score}</td>
                                    <td className="p-2 text-xs max-w-md">
                                        <div className="text-gray-100 font-medium truncate mb-0.5"
                                             title={f.page_title || ""}>
                                            {f.page_title || <span className="text-gray-500">(no title)</span>}
                                            <SourceBadge source={f.source} />
                                            <PageTypeBadge type={f.page_type} />
                                        </div>
                                        <button
                                            onClick={() => setExpanded(expanded === f.id ? null : f.id)}
                                            className="truncate text-left text-gray-500 hover:text-brand-400 block max-w-full mono">
                                            {f.page_url}
                                        </button>
                                        <KeywordTags
                                            raw={f.matched_strings}
                                            onClick={() => setExpanded(expanded === f.id ? null : f.id)}
                                        />
                                        <CopyButton text={f.page_url} />
                                    </td>
                                    <td className="p-2 text-xs text-gray-500 mono whitespace-nowrap">
                                        {f.found_at}
                                    </td>
                                    <td className="p-2 text-right">
                                        <button
                                            onClick={() => {
                                                if (window.confirm(`Delete finding "${f.rule_name}"?`)) {
                                                    onDeleteOne(f.id);
                                                }
                                            }}
                                            title="Delete this finding"
                                            className="text-gray-500 hover:text-red-400">
                                            <Icon name="trash" size={14} />
                                        </button>
                                    </td>
                                </tr>
                                {expanded === f.id && (
                                    <tr className="bg-gray-900/70">
                                        <td colSpan={7} className="p-4 text-xs">
                                            <div className="text-gray-400 mb-1">Matched:</div>
                                            <div className="mono text-gray-300 mb-2 break-all">{f.matched_strings}</div>
                                            {f.snippet && (<>
                                                <div className="text-gray-400 mb-1">Snippet:</div>
                                                <div className="mono text-gray-300 bg-gray-950 p-2 rounded whitespace-pre-wrap break-words">
                                                    <HighlightedSnippet
                                                        text={f.snippet}
                                                        matches={f.matched_strings}
                                                    />
                                                </div>
                                            </>)}
                                        </td>
                                    </tr>
                                )}
                            </React.Fragment>
                        ))}
                    </tbody>
                </table>
            </div>
            {hasMore && (
                <div className="flex justify-center py-3">
                    <button onClick={onLoadMore}
                            disabled={loading}
                            className="px-4 py-2 rounded bg-gray-800 text-sm
                                       hover:bg-gray-700 text-gray-200
                                       disabled:opacity-50 flex items-center gap-2">
                        {loading && <Spinner />}
                        Load more findings
                    </button>
                </div>
            )}
        </div>
    );
}

// ─── URLs ────────────────────────────────────────────────────────────────────

// ─── Timeline (per-URL monitor history) ─────────────────────────────────────

function Timeline({ urlId, onLightbox }) {
    const [events, setEvents] = useState(null);
    const [error, setError] = useState("");
    useEffect(() => {
        let cancelled = false;
        setEvents(null);
        setError("");
        api(`/api/urls/${urlId}/timeline`).then(({ ok, body }) => {
            if (cancelled) return;
            if (!ok) {
                setError(body?.error || "Failed to load timeline");
                setEvents([]);
                return;
            }
            setEvents(Array.isArray(body) ? body : []);
        }).catch(() => {
            if (!cancelled) {
                setError("Failed to load timeline");
                setEvents([]);
            }
        });
        return () => { cancelled = true; };
    }, [urlId]);

    if (events === null) return <div className="p-3 text-xs text-gray-500">Loading…</div>;
    if (error) return <div className="p-3 text-xs text-red-400">{error}</div>;
    if (events.length === 0) {
        return <div className="p-3 text-xs text-gray-500 italic">
            No monitor events yet. Will appear after the next scheduled check.
        </div>;
    }
    return (
        <div className="p-3">
            <div className="text-xs text-gray-500 uppercase mb-2">
                Monitor timeline ({events.length} events, newest first)
            </div>
            <div className="space-y-1.5">
                {events.map(e => {
                    const ok = e.status === 200;
                    return (
                        <div key={e.id} className="flex items-center gap-3
                                                   bg-gray-950 border border-gray-800
                                                   rounded px-2 py-1.5 text-xs">
                            <span className={"inline-block w-2 h-2 rounded-full flex-shrink-0 " +
                                (ok ? "bg-emerald-400" : "bg-red-400")} />
                            <span className="mono text-gray-400 w-44 flex-shrink-0">{e.checked_at}</span>
                            <span className={"mono w-12 " + (ok ? "text-emerald-400" : "text-red-400")}>
                                {e.status || "fail"}
                            </span>
                            <span className="text-gray-500 w-32">
                                {e.pages} page · {e.findings} finding
                            </span>
                            {e.thumbnail_url ? (
                                <img src={e.thumbnail_url}
                                     onClick={() => {
                                         if (!e.screenshot_url) return;
                                         const items = events
                                             .filter(x => x.screenshot_url)
                                             .map(x => ({
                                                 page_url: `Event ${x.id} — ${x.checked_at}`,
                                                 screenshot_url: x.screenshot_url,
                                             }));
                                         const idx = items.findIndex(x => x.screenshot_url === e.screenshot_url);
                                         onLightbox({ items, index: Math.max(0, idx) });
                                     }}
                                     className="w-12 h-8 object-cover rounded
                                                border border-gray-700 cursor-zoom-in
                                                hover:border-brand-500"
                                     alt="event" />
                            ) : (
                                <span className="text-gray-700 mono text-[10px]">no shot</span>
                            )}
                            {e.note && (
                                <span className="text-gray-500 truncate text-[11px]" title={e.note}>
                                    {e.note}
                                </span>
                            )}
                        </div>
                    );
                })}
            </div>
        </div>
    );
}

function URLsPanel({ urls, onRefresh, onLightbox, onSetMonitor, onBulkMonitor,
                     monitorPending, onDelete, onBulkDelete, total, hasMore, onLoadMore }) {
    // Fall back to an empty Set so child rows never crash when the prop
    // is missing (e.g. during initial render before state is hydrated).
    const pending = monitorPending || new Set();
    const [expanded, setExpanded] = useState(null);
    const [selected, setSelected] = useState(new Set());
    const monitoredCount = urls.filter(u => u.monitored).length;
    const allIds = urls.map(u => u.id);
    const allSelected = selected.size > 0 && allIds.every(id => selected.has(id));
    const someSelected = selected.size > 0 && !allSelected;

    const toggleAll = () => {
        if (allSelected || someSelected) setSelected(new Set());
        else setSelected(new Set(allIds));
    };
    const toggleOne = (id) => {
        setSelected(prev => {
            const next = new Set(prev);
            if (next.has(id)) next.delete(id);
            else next.add(id);
            return next;
        });
    };

    const bulkApply = (enabled) => {
        if (selected.size === 0) return;
        const verb = enabled ? "Enable" : "Disable";
        if (!window.confirm(
            `${verb} monitoring on ${selected.size} selected URL(s)?`)) return;
        onBulkMonitor(Array.from(selected), enabled, 60);
        setSelected(new Set());
    };

    const bulkDelete = () => {
        if (selected.size === 0) return;
        if (!window.confirm(
            `Delete ${selected.size} selected URL(s) and all their scans, findings, and events?`)) return;
        onBulkDelete(Array.from(selected));
        setSelected(new Set());
    };

    return (
        <div className="space-y-4">
            <div className="flex items-center gap-3 flex-wrap">
                <button onClick={onRefresh}
                        className="px-3 py-2 rounded bg-gray-800 text-sm
                                   hover:bg-gray-700 flex items-center gap-1.5">
                    <Icon name="refresh" size={14} /> Refresh
                </button>
                {selected.size > 0 && (
                    <>
                        <span className="text-xs text-gray-400">{selected.size} selected:</span>
                        <button onClick={() => bulkApply(true)}
                                className="px-3 py-2 rounded bg-cyan-900/60 border border-cyan-800
                                           text-cyan-200 text-sm hover:bg-cyan-800/60">
                            Enable monitoring (1h)
                        </button>
                        <button onClick={() => bulkApply(false)}
                                className="px-3 py-2 rounded bg-gray-800 text-sm hover:bg-gray-700">
                            Disable monitoring
                        </button>
                        <button onClick={bulkDelete}
                                className="px-3 py-2 rounded bg-red-900/60 border border-red-800
                                           text-red-200 text-sm hover:bg-red-800/60 flex items-center gap-1.5">
                            <Icon name="trash" size={14} /> Delete selected
                        </button>
                        <button onClick={() => setSelected(new Set())}
                                className="text-xs text-gray-500 hover:text-gray-200">
                            clear selection
                        </button>
                    </>
                )}
                <span className="ml-auto text-xs text-gray-500">
                    {monitoredCount} monitored / {urls.length} total
                </span>
            </div>
            <div className="overflow-x-auto border border-gray-800 rounded">
                <table className="w-full text-sm">
                    <thead className="bg-gray-900 text-gray-400 text-xs uppercase">
                        <tr>
                            <th className="p-2 w-10 text-center">
                                <input type="checkbox"
                                       checked={allSelected}
                                       ref={el => { if (el) el.indeterminate = someSelected; }}
                                       onChange={toggleAll}
                                       disabled={urls.length === 0}
                                       className="w-4 h-4 accent-brand-500" />
                            </th>
                            <th className="p-2"></th>
                            <th className="p-2 text-left">Site</th>
                            <th className="p-2 text-center">Status</th>
                            <th className="p-2 text-center">Monitor</th>
                            <th className="p-2 text-left">Last / Next check</th>
                            <th className="p-2"></th>
                        </tr>
                    </thead>
                    <tbody>
                        {urls.length === 0 && (
                            <tr><td colSpan={7} className="p-6 text-center text-gray-500">
                                No URLs tracked yet. Run a scan to populate.
                            </td></tr>
                        )}
                        {urls.map(u => (
                            <React.Fragment key={u.id}>
                                <tr className="border-t border-gray-800 hover:bg-gray-900/50">
                                    <td className="p-2 text-center">
                                        <input type="checkbox"
                                               checked={selected.has(u.id)}
                                               onChange={() => toggleOne(u.id)}
                                               className="w-4 h-4 accent-brand-500" />
                                    </td>
                                    <td className="p-2">
                                        {u.latest_page_id ? (
                                            <img src={`/api/thumbnail/${u.latest_page_id}`}
                                                 onClick={() => {
                                                     const items = urls
                                                         .filter(x => x.latest_page_id)
                                                         .map(x => ({
                                                             page_url: x.url,
                                                             page_title: x.title,
                                                             screenshot_url: `/api/screenshot/${x.latest_page_id}`,
                                                         }));
                                                     const idx = items.findIndex(x => x.page_url === u.url);
                                                     onLightbox({ items, index: Math.max(0, idx) });
                                                 }}
                                                 onError={e => { e.currentTarget.style.display = "none"; }}
                                                 className="w-16 h-10 object-cover rounded
                                                            border border-gray-700 cursor-zoom-in
                                                            hover:border-brand-500"
                                                 alt="page" />
                                        ) : (
                                            <div className="w-16 h-10 bg-gray-800 rounded
                                                            flex items-center justify-center
                                                            text-gray-600 text-xs">—</div>
                                        )}
                                    </td>
                                    <td className="p-2 text-xs max-w-md">
                                        {u.title && (
                                            <div className="text-gray-100 font-medium truncate mb-0.5"
                                                 title={u.title}>
                                                {u.title}
                                                <PageTypeBadge type={u.page_type} />
                                            </div>
                                        )}
                                        <button
                                            onClick={() => setExpanded(expanded === u.id ? null : u.id)}
                                            className="truncate text-left text-gray-500 hover:text-brand-400 block max-w-full mono">
                                            {u.url}
                                        </button>
                                        <CopyButton text={u.url} />
                                    </td>
                                    <td className="p-2 text-center mono text-xs">
                                        <span className={
                                            u.status === 200 ? "text-emerald-400" :
                                            u.status === 0 ? "text-gray-500" : "text-red-400"
                                        }>{u.status || "—"}</span>
                                        <div className="text-gray-600 text-[10px] mt-0.5">
                                            {u.scan_count} scans
                                            {u.fail_count > 0 && <span className="text-red-400"> · {u.fail_count} fail</span>}
                                        </div>
                                    </td>
                                    <td className={"p-2 text-center " +
                                            (pending.has(u.id)
                                                ? "ring-1 ring-cyan-500/50 "
                                                  + "bg-cyan-500/10 rounded"
                                                : "")}>
                                        <label className={"inline-flex items-center gap-2 "
                                            + (pending.has(u.id)
                                                ? "cursor-wait" : "cursor-pointer")}>
                                            <span className="relative inline-flex items-center justify-center w-4 h-4">
                                                <input type="checkbox"
                                                       checked={!!u.monitored}
                                                       disabled={pending.has(u.id)}
                                                       onChange={e => onSetMonitor(
                                                           u.id, e.target.checked,
                                                           u.monitor_interval_min || 60)}
                                                       className={"w-4 h-4 accent-cyan-500 "
                                                           + (pending.has(u.id) ? "opacity-40" : "")} />
                                                {pending.has(u.id) && (
                                                    <span className="absolute inset-0 flex items-center justify-center
                                                                     text-cyan-400 pointer-events-none">
                                                        <Spinner size={14} />
                                                    </span>
                                                )}
                                            </span>
                                            <select
                                                value={u.monitor_interval_min || 60}
                                                disabled={!u.monitored || pending.has(u.id)}
                                                onChange={e => onSetMonitor(
                                                    u.id, true, parseInt(e.target.value, 10))}
                                                className="bg-gray-900 border border-gray-700 rounded
                                                           px-1 py-0.5 text-xs disabled:opacity-50">
                                                <option value="15">15m</option>
                                                <option value="30">30m</option>
                                                <option value="60">1h</option>
                                                <option value="120">2h</option>
                                                <option value="360">6h</option>
                                            </select>
                                            {pending.has(u.id) && (
                                                <span className="text-[10px] text-cyan-400 uppercase
                                                                 tracking-wide animate-pulse">
                                                    saving…
                                                </span>
                                            )}
                                        </label>
                                    </td>
                                    <td className="p-2 text-xs text-gray-500 mono">
                                        <div title="Last scan">{u.last_scan || "never"}</div>
                                        {u.monitored && u.next_check_at && (
                                            <div className="text-cyan-400/70 text-[10px] mt-0.5"
                                                 title="Next monitor check">
                                                next ≈ {u.next_check_at.split(".")[0].replace("T", " ")}
                                            </div>
                                        )}
                                    </td>
                                    <td className="p-2 text-right">
                                        <button
                                            onClick={() => {
                                                if (window.confirm(
                                                    `Delete "${u.url}" and all its scans / findings / events?`)) {
                                                    onDelete(u.id);
                                                }
                                            }}
                                            title="Delete URL and cascade"
                                            className="text-gray-500 hover:text-red-400">
                                            <Icon name="trash" size={14} />
                                        </button>
                                    </td>
                                </tr>
                                {expanded === u.id && (
                                    <tr className="bg-gray-900/70">
                                        <td colSpan={7}>
                                            <Timeline urlId={u.id} onLightbox={onLightbox} />
                                        </td>
                                    </tr>
                                )}
                            </React.Fragment>
                        ))}
                    </tbody>
                </table>
            </div>
            {(hasMore || (total != null && urls.length < total)) && (
                <div className="flex justify-between items-center py-3 px-2">
                    <span className="text-xs text-gray-500">
                        Showing {urls.length}{total != null && ` of ${total}`}
                    </span>
                    {hasMore && (
                        <button onClick={onLoadMore}
                                className="px-4 py-2 rounded bg-gray-800 text-sm
                                           hover:bg-gray-700 text-gray-200">
                            Load more URLs
                        </button>
                    )}
                </div>
            )}
        </div>
    );
}

// ─── Matched-keyword helpers ────────────────────────────────────────────────

// matched_strings is stored from yara-python as "offset:$var: match_bytes".
// Split on commas that precede the next "N:$var:" token to tolerate commas
// inside the match text itself.
function parseMatches(raw) {
    if (!raw) return [];
    // New format from the scanner: "match1, match2, match3" — plain text
    // substrings separated by comma+space. Legacy format looked like
    // "0:$var: match1, 1:$var: match2"; strip the prefix when seen so
    // findings from before the scanner fix still render readable tokens.
    const parts = raw.split(/,\s*(?=\d+:\$|[^,]*$)/);
    const out = [];
    const seen = new Set();
    for (const p of parts) {
        const m = p.match(/^\d+:\$\w+:\s*(.+)$/);
        let token = (m ? m[1] : p).trim();
        // A bare "$email" (very old broken rows) is not useful — hide it.
        if (/^\$\w+$/.test(token)) continue;
        if (token && !seen.has(token)) { seen.add(token); out.push(token); }
    }
    return out;
}

// Renders a snippet with the matched YARA tokens visually highlighted.
// `matches` is the raw matched_strings field from the finding; we reuse
// parseMatches() so legacy `N:$var: content` rows and new plain-comma rows
// both light up correctly. Case-insensitive (YARA rules use `nocase`).
function HighlightedSnippet({ text, matches }) {
    if (!text) return null;
    const tokens = parseMatches(matches).filter(t => t && t.length >= 2);
    if (tokens.length === 0) return <>{text}</>;
    // Escape regex metachars + sort longest-first so overlapping tokens
    // (e.g. "admin@x.com" and "admin") prefer the longer match.
    const escaped = tokens
        .map(t => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
        .sort((a, b) => b.length - a.length);
    const re = new RegExp("(" + escaped.join("|") + ")", "gi");
    const parts = text.split(re);
    // String.split with a capture group alternates: even indices are
    // plain text, odd indices are captured matches.
    return (
        <>
            {parts.map((p, i) => i % 2 === 1 ? (
                <mark key={i}
                      className="bg-emerald-500/25 text-emerald-200
                                 rounded px-0.5 font-semibold">
                    {p}
                </mark>
            ) : (
                <React.Fragment key={i}>{p}</React.Fragment>
            ))}
        </>
    );
}

function KeywordTags({ raw, onClick, limit = 6 }) {
    const tags = parseMatches(raw);
    if (tags.length === 0) return null;
    const shown = tags.slice(0, limit);
    const extra = tags.length - shown.length;
    return (
        <div className="flex flex-wrap gap-1 mt-1">
            {shown.map((t, i) => (
                <button
                    key={i}
                    onClick={onClick}
                    title="Click to view details + screenshot"
                    className="px-1.5 py-0.5 text-[10px] mono rounded
                               bg-emerald-500/10 text-emerald-300
                               border border-emerald-500/30
                               hover:bg-emerald-500/20"
                >{t}</button>
            ))}
            {extra > 0 && (
                <span className="px-1.5 py-0.5 text-[10px] mono text-gray-500">+{extra}</span>
            )}
        </div>
    );
}

// ─── Rules panel ─────────────────────────────────────────────────────────────

// ─── Telegram tab ────────────────────────────────────────────────────────────

function TelegramAuthModal({ open, onClose, onSubmit, busy }) {
    const [mode, setMode] = useState("sms");            // "sms" | "qr"
    const [phone, setPhone] = useState("");
    const [code, setCode] = useState("");
    const [password, setPassword] = useState("");
    const [phoneCodeHash, setPhoneCodeHash] = useState(null);
    const [error, setError] = useState("");
    const [qrSvg, setQrSvg] = useState(null);
    const [qrToken, setQrToken] = useState(null);
    const [qrNeedsPw, setQrNeedsPw] = useState(false);

    useEffect(() => {
        if (open) { setPhone(""); setCode(""); setPassword("");
                    setPhoneCodeHash(null); setError("");
                    setQrSvg(null); setQrToken(null); setQrNeedsPw(false);
                    setMode("sms"); }
    }, [open]);

    // QR polling — once a token is in hand, poll every 2s for status.
    useEffect(() => {
        if (!qrToken) return;
        const iv = setInterval(async () => {
            const { body } = await api(
                `/api/telegram/auth/qr/status?token=${qrToken}`);
            if (body?.authenticated) { clearInterval(iv); onClose(); }
            else if (body?.needs_password) { setQrNeedsPw(true); }
            else if (body?.error === "qr_expired") {
                clearInterval(iv);
                setError("QR expired — click again to get a new code");
                setQrToken(null); setQrSvg(null);
            }
        }, 2000);
        return () => clearInterval(iv);
    }, [qrToken, onClose]);

    const startQr = async () => {
        setError(""); setQrSvg(null); setQrToken(null); setQrNeedsPw(false);
        const { ok, body } = await api(
            "/api/telegram/auth/qr/start", { method: "POST" });
        if (!ok || body?.error) {
            setError(body?.error || "couldn't start QR login"); return;
        }
        setQrSvg(body.qr_svg);
        setQrToken(body.token);
    };

    const submitQrPw = async () => {
        setError("");
        const { ok, body } = await api(
            "/api/telegram/auth/qr/password", {
                method: "POST",
                body: JSON.stringify({ token: qrToken, password }),
            });
        if (ok && body?.ok) onClose();
        else setError(body?.error || "2FA failed");
    };

    const sendCode = async () => {
        setError("");
        const r = await onSubmit("start", { phone });
        if (r.ok) setPhoneCodeHash(r.body.phone_code_hash);
        else setError(r.body?.error || "couldn't send code");
    };
    const confirm = async () => {
        setError("");
        const r = await onSubmit("confirm", {
            phone, code, password: password || undefined,
            phone_code_hash: phoneCodeHash,
        });
        if (r.ok) onClose();
        else {
            if (r.body?.error === "2fa_password_required") {
                setError("2FA enabled — enter your cloud password below.");
            } else {
                setError(r.body?.error || "auth failed");
            }
        }
    };

    if (!open) return null;
    return (
        <div className="fixed inset-0 z-40 bg-black/70 flex items-center justify-center p-6"
             onClick={onClose}>
            <div onClick={e => e.stopPropagation()}
                 className="bg-gray-900 border border-gray-700 rounded-lg max-w-md w-full p-6">
                <div className="flex items-center justify-between mb-4">
                    <h2 className="text-lg font-semibold">Connect Telegram</h2>
                    <button onClick={onClose} aria-label="Close"
                            className="text-gray-500 hover:text-gray-200">
                        <Icon name="close" size={18} />
                    </button>
                </div>
                <p className="text-xs text-gray-400 mb-3">
                    The app logs in as your Telegram account to read public
                    channel content. All traffic is routed through the
                    dedicated Telegram VPN (not Tor).
                </p>

                <div className="flex gap-1 mb-4 border-b border-gray-800">
                    <button onClick={() => setMode("sms")}
                            className={"px-3 py-1.5 text-xs border-b-2 " +
                                (mode === "sms" ? "border-brand-400 text-brand-300"
                                : "border-transparent text-gray-500")}>
                        SMS code
                    </button>
                    <button onClick={() => setMode("qr")}
                            className={"px-3 py-1.5 text-xs border-b-2 " +
                                (mode === "qr" ? "border-brand-400 text-brand-300"
                                : "border-transparent text-gray-500")}>
                        QR code
                    </button>
                </div>

                {mode === "qr" ? (
                    <div className="text-center">
                        {!qrSvg && !qrToken && (
                            <button onClick={startQr}
                                    className="px-4 py-2 rounded bg-brand-500 text-gray-50
                                               font-semibold hover:bg-brand-400">
                                Generate QR code
                            </button>
                        )}
                        {qrSvg && !qrNeedsPw && (
                            <div>
                                <div className="bg-white p-3 inline-block rounded mb-3"
                                     dangerouslySetInnerHTML={{ __html: qrSvg }} />
                                <p className="text-xs text-gray-400">
                                    Open Telegram on your phone → Settings →
                                    Devices → Link Desktop Device → scan this code.
                                </p>
                            </div>
                        )}
                        {qrNeedsPw && (
                            <div className="text-left">
                                <p className="text-xs text-yellow-300 mb-2">
                                    2FA enabled. Enter your Telegram cloud password.
                                </p>
                                <input
                                    type="password"
                                    value={password}
                                    onChange={e => setPassword(e.target.value)}
                                    className="w-full mt-1 mb-3 bg-gray-950 border border-gray-700
                                               rounded px-3 py-2 text-sm mono
                                               focus:outline-none focus:border-brand-500"
                                />
                                <div className="flex justify-end">
                                    <button onClick={submitQrPw}
                                            disabled={!password}
                                            className="px-4 py-2 rounded bg-brand-500 text-gray-50
                                                       font-semibold hover:bg-brand-400
                                                       disabled:bg-gray-700 disabled:text-gray-500">
                                        Confirm
                                    </button>
                                </div>
                            </div>
                        )}
                        {error && (
                            <div className="text-xs text-red-400 mt-3 mono">{error}</div>
                        )}
                    </div>
                ) : (<>
                <label className="text-xs text-gray-400 uppercase">Phone number</label>
                <input
                    value={phone}
                    onChange={e => setPhone(e.target.value)}
                    disabled={!!phoneCodeHash || busy}
                    placeholder="+1234567890"
                    className="w-full mt-1 mb-3 bg-gray-950 border border-gray-700
                               rounded px-3 py-2 text-sm mono
                               focus:outline-none focus:border-brand-500
                               disabled:opacity-60"
                />
                {phoneCodeHash && (<>
                    <label className="text-xs text-gray-400 uppercase">Code from Telegram</label>
                    <input
                        value={code}
                        onChange={e => setCode(e.target.value)}
                        placeholder="12345"
                        className="w-full mt-1 mb-3 bg-gray-950 border border-gray-700
                                   rounded px-3 py-2 text-sm mono
                                   focus:outline-none focus:border-brand-500"
                    />
                    <label className="text-xs text-gray-400 uppercase">
                        2FA password (only if enabled)
                    </label>
                    <input
                        type="password"
                        value={password}
                        onChange={e => setPassword(e.target.value)}
                        placeholder="optional"
                        className="w-full mt-1 mb-3 bg-gray-950 border border-gray-700
                                   rounded px-3 py-2 text-sm mono
                                   focus:outline-none focus:border-brand-500"
                    />
                </>)}
                {error && (
                    <div className="text-xs text-red-400 mb-3 mono break-all">
                        {error}
                    </div>
                )}
                <div className="flex justify-end gap-2">
                    {!phoneCodeHash ? (
                        <button onClick={sendCode}
                                disabled={busy || !phone.trim()}
                                className="px-4 py-2 rounded bg-brand-500 text-gray-50
                                           font-semibold hover:bg-brand-400
                                           disabled:bg-gray-700 disabled:text-gray-500">
                            {busy ? <Spinner /> : "Send code"}
                        </button>
                    ) : (
                        <button onClick={confirm}
                                disabled={busy || !code.trim()}
                                className="px-4 py-2 rounded bg-brand-500 text-gray-50
                                           font-semibold hover:bg-brand-400
                                           disabled:bg-gray-700 disabled:text-gray-500">
                            {busy ? <Spinner /> : "Sign in"}
                        </button>
                    )}
                </div>
                </>)}
            </div>
        </div>
    );
}

// Tiny pill used by the TelegramPanel for channel / message metadata.
// Activity freshness tag for a channel — color-coded by how recently
// the channel posted (real message date, not scrape time). Gives the
// operator an at-a-glance signal of which tracked channels are worth
// attention vs. which have gone quiet / dead.
function ActivityPill({ lastMsgDate, msgCount }) {
    // Four buckets:
    //   active  — posted in the last 7d   (emerald)
    //   quiet   — posted 7-30d ago         (yellow)
    //   dormant — posted 30-180d ago       (gray)
    //   dead    — no post in 180d+         (red)
    //   unscanned — we've never scraped it (blue)
    if (!lastMsgDate) {
        return <Pill tone="blue"
                     title={msgCount ? `${msgCount} message(s) — no date` : "Not scraped yet"}>
            unscanned
        </Pill>;
    }
    const ageMs = Date.now() - new Date(lastMsgDate).getTime();
    const days = ageMs / 86400000;
    let tone, label, when;
    if      (days < 1)   { tone = "emerald"; label = "active";  when = "today"; }
    else if (days < 7)   { tone = "emerald"; label = "active";  when = `${Math.round(days)}d ago`; }
    else if (days < 30)  { tone = "yellow";  label = "quiet";   when = `${Math.round(days)}d ago`; }
    else if (days < 180) { tone = "gray";    label = "dormant"; when = `${Math.round(days)}d ago`; }
    else                 { tone = "red";     label = "dead";    when = `${Math.round(days/30)}mo ago`; }
    return <Pill tone={tone}
                 title={`Last post ${when} — ${new Date(lastMsgDate).toISOString().slice(0,16)}`}>
        {label} · {when}
    </Pill>;
}


function Pill({ children, tone = "gray", title }) {
    const tones = {
        gray:    "bg-gray-700/60 text-gray-300 border-gray-600",
        cyan:    "bg-cyan-500/10 text-cyan-300 border-cyan-500/30",
        emerald: "bg-emerald-500/10 text-emerald-300 border-emerald-500/30",
        red:     "bg-red-500/10 text-red-300 border-red-500/30",
        yellow:  "bg-yellow-500/10 text-yellow-300 border-yellow-500/30",
        blue:    "bg-blue-500/10 text-blue-300 border-blue-500/30",
    };
    return (
        <span title={title}
              className={"inline-block px-1.5 py-0.5 text-[10px] rounded border " +
                         "mono align-middle " + (tones[tone] || tones.gray)}>
            {children}
        </span>
    );
}

// Format large numbers as 1.2k / 34k / 1.1M for compact display.
function compact(n) {
    if (n == null) return null;
    const a = Math.abs(n);
    if (a >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, "") + "M";
    if (a >= 1e3) return (n / 1e3).toFixed(1).replace(/\.0$/, "") + "k";
    return String(n);
}

// Small icon button used throughout the channel action row. Consistent
// styling + tooltip + optional color tone. Works as both <button> and
// <a> (for download links) via the `href` prop.
function IconBtn({ icon, label, tone = "gray", href, onClick, disabled,
                   busy, download, children }) {
    const toneCls = {
        gray:    "text-gray-400 hover:text-gray-100 hover:bg-gray-800",
        emerald: "text-gray-400 hover:text-brand-300 hover:bg-emerald-500/10",
        cyan:    "text-gray-400 hover:text-cyan-300 hover:bg-cyan-500/10",
        red:     "text-gray-400 hover:text-red-300 hover:bg-red-500/10",
        yellow:  "text-gray-400 hover:text-yellow-300 hover:bg-yellow-500/10",
    }[tone] || "text-gray-400";
    const base = ("inline-flex items-center gap-1 px-2 py-1 rounded "
                 + "text-[11px] border border-transparent hover:border-gray-700 "
                 + "transition-colors disabled:opacity-40 disabled:pointer-events-none "
                 + toneCls);
    const content = (<>
        {busy ? <Spinner /> : <Icon name={icon} size={13} />}
        {label && <span>{label}</span>}
        {children}
    </>);
    if (href) {
        return <a href={href} download={download} title={label}
                  className={base}>{content}</a>;
    }
    return <button onClick={onClick} disabled={disabled} title={label}
                   className={base}>{content}</button>;
}


// Per-channel scrape controls — size selector, deep toggle, rescan. Replaces
// the old single "Scrape 100" button. Deep mode chunks through history in
// 500-message batches under the rate limiter AND re-runs YARA over stored
// messages afterward so newly-added keywords catch up on past messages.
function ScrapeControls({ channel, authed, onScrape, onRescan }) {
    const [size, setSize] = useState("100");
    const [deep, setDeep] = useState(false);
    const [busy, setBusy] = useState(false);

    const go = async () => {
        if (!authed || busy) return;
        setBusy(true);
        try { await onScrape(channel.id, size, deep); } finally { setBusy(false); }
    };

    const rescan = async () => {
        if (!authed || busy) return;
        setBusy(true);
        try { await onRescan(channel.id); } finally { setBusy(false); }
    };

    return (
        <span className="inline-flex items-center gap-1">
            <select value={size} onChange={e => setSize(e.target.value)}
                    disabled={!authed || busy}
                    title="Scrape batch size"
                    className="bg-gray-900 border border-gray-700 rounded
                               px-1.5 py-1 text-[11px] mono text-gray-300
                               disabled:opacity-50">
                <option value="100">100</option>
                <option value="500">500</option>
                <option value="1000">1000</option>
                <option value="all">all</option>
            </select>
            <label className="flex items-center gap-1 text-[11px] text-gray-500 cursor-pointer px-1"
                   title="Deep: chunked fetch + re-run YARA on stored messages">
                <input type="checkbox" checked={deep}
                       onChange={e => setDeep(e.target.checked)}
                       className="accent-brand-500" />
                deep
            </label>
            <IconBtn icon="scan" label="Scrape" tone="emerald"
                     busy={busy} disabled={!authed || busy}
                     onClick={go} />
            <IconBtn icon="refresh" label="Rescan" tone="cyan"
                     disabled={!authed || busy}
                     onClick={rescan} />
        </span>
    );
}


// Channel-details card (lazy-loaded on expand). Shows enriched metadata
// that came from GetFullChannelRequest + admin-list creator lookup:
// creation date, admin/online counts, slowmode, pinned msg, linked
// discussion group, antispam flag, and the channel creator's identity
// (including phone if they've chosen to expose it).
function TgChannelDetails({ urlId }) {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);
    const [err, setErr] = useState(null);

    const fetchDetails = async (refresh=false) => {
        setLoading(!data);
        if (refresh) setRefreshing(true);
        try {
            const { ok, body } = await api(
                `/api/telegram/channels/${urlId}/details${refresh ? "?refresh=1" : ""}`);
            if (ok) { setData(body); setErr(body?.error || null); }
            else    { setErr(body?.error || "lookup failed"); }
        } catch { setErr("network error"); }
        finally  { setLoading(false); setRefreshing(false); }
    };
    useEffect(() => { fetchDetails(false); }, [urlId]);

    if (loading && !data) return (
        <div className="p-4 text-xs text-gray-500">Loading channel details…</div>
    );
    if (!data) return (
        <div className="p-4 text-xs text-red-400 mono">
            {err || "no details available"}
        </div>
    );

    const fmtDate = (iso) => iso ? iso.slice(0, 19).replace("T", " ") + " UTC" : "—";
    const fmtSecs = (s) => {
        if (!s) return null;
        if (s < 60)   return `${s}s`;
        if (s < 3600) return `${Math.round(s/60)}m`;
        return `${Math.round(s/3600)}h`;
    };
    const row = (label, value, title) => value != null && value !== "" && (
        <div className="flex gap-2 py-0.5" title={title}>
            <span className="text-gray-500 min-w-[140px]">{label}</span>
            <span className="text-gray-200 break-all">{value}</span>
        </div>
    );

    const creator = data.creator;

    // Channel avatar fallback: first letter of title/handle on a
    // tinted circle. Keeps the UI visually stable when no photo
    // available (private account privacy, or photo fetch failed).
    const avatarFallback = ((data.title || data.username || "?")
        .trim()[0] || "?").toUpperCase();

    return (
        <div className="p-3 border-b border-gray-800 bg-gray-950/60 space-y-3">
            {/* Hero header: avatar + title + description */}
            <div className="flex gap-3 items-start">
                {data.photo_url ? (
                    <img src={data.photo_url} alt=""
                         className="w-16 h-16 rounded-full object-cover
                                    border border-gray-700 flex-shrink-0" />
                ) : (
                    <div className="w-16 h-16 rounded-full flex items-center
                                    justify-center bg-gray-800 border border-gray-700
                                    text-2xl font-bold text-gray-400 flex-shrink-0">
                        {avatarFallback}
                    </div>
                )}
                <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                        <h3 className="text-base font-semibold text-gray-100 truncate">
                            {data.title || data.username || "(untitled)"}
                        </h3>
                        {data.username && (
                            <a href={`https://t.me/${data.username}`}
                               target="_blank" rel="noreferrer"
                               className="text-emerald-400 hover:underline mono text-xs">
                                @{data.username}
                            </a>
                        )}
                        {data.verified && <Pill tone="emerald">✓ verified</Pill>}
                        {data.scam     && <Pill tone="red">scam</Pill>}
                    </div>
                    {data.about && (
                        <div className="mt-1.5 text-xs text-gray-300 whitespace-pre-wrap">
                            {data.about}
                        </div>
                    )}
                </div>
                <button onClick={() => fetchDetails(true)}
                        disabled={refreshing}
                        title="Re-fetch live metadata from Telegram"
                        className="text-[11px] text-gray-500 hover:text-brand-400
                                   flex items-center gap-1 disabled:opacity-50
                                   flex-shrink-0 self-start">
                    {refreshing ? <Spinner /> : <Icon name="refresh" size={12} />}
                    Refresh
                </button>
            </div>

            <div className="flex items-center justify-between text-xs text-gray-500">
                <span className="uppercase">Channel profile</span>
                <span className="text-[10px] normal-case">
                    {data.source === "cache" && `cached${data.fetched_at
                        ? " " + data.fetched_at.slice(0,16) : ""}`}
                    {data.stale && <span className="text-yellow-400 ml-2">⚠ stale</span>}
                </span>
            </div>
            {err && (
                <div className="text-xs text-yellow-400 mono">
                    {err} — showing cached data
                </div>
            )}
            <div className="grid md:grid-cols-2 gap-x-6 gap-y-1 text-xs mono">
                {row("Created",        fmtDate(data.created),
                     "When the channel was created on Telegram")}
                {row("Subscribers",    data.subscribers?.toLocaleString?.())}
                {row("Admins",         data.admins_count)}
                {row("Online now",     data.online_count)}
                {row("Kind",           data.kind)}
                {row("Privacy",
                     data.is_private ? "private (invite-only)" : "public (@handle)")}
                {row("Slowmode",       fmtSecs(data.slowmode_seconds))}
                {row("Auto-delete TTL", fmtSecs(data.ttl_period))}
                {row("Pinned message", data.pinned_msg_id && `#${data.pinned_msg_id}`)}
                {row("Linked discussion", data.linked_chat_id)}
                {row("Migrated from",  data.migrated_from)}
                {row("Participants hidden", data.participants_hidden ? "yes" : null)}
                {row("Antispam",       data.antispam ? "on" : null)}
                {row("Restricted",     data.restricted_reason)}
            </div>

            <div className="mt-3 pt-3 border-t border-gray-800/60">
                <div className="text-xs text-gray-500 uppercase mb-1">
                    Owner / creator
                </div>
                {!creator ? (
                    <div className="text-[11px] text-gray-500 italic">
                        {data.participants_hidden
                            ? "Owner is hidden — channel has participants_hidden=on."
                            : "Owner could not be resolved (admin list not enumerable)."}
                    </div>
                ) : (
                    <div className="grid md:grid-cols-2 gap-x-6 gap-y-1 text-xs mono">
                        {row("Display name", creator.name)}
                        {creator.username
                            ? row("Handle",
                                  <a href={`https://t.me/${creator.username}`}
                                     target="_blank" rel="noreferrer"
                                     className="text-emerald-400 hover:underline">
                                      @{creator.username}
                                  </a>)
                            : row("Handle", "— (none set)")}
                        {row("User ID",      creator.user_id)}
                        {row("Phone",
                             creator.phone
                                 ? `+${creator.phone}`
                                 : "— (hidden by privacy settings)",
                             "Telegram only exposes the phone if the user has opted in OR is in your contacts")}
                        {creator.bot     && row("Flags", "bot")}
                        {creator.verified && row("Flags", "verified")}
                        {creator.premium && row("Premium", "yes")}
                        {creator.scam    && row("Flags", "scam")}
                    </div>
                )}
            </div>

            <TgChannelLinks urlId={urlId} />
        </div>
    );
}


// Aggregates every link found in the channel's stored messages into three
// buckets (forwards / other telegram refs / external URLs). Pure CTI
// pivot panel — tells you who this channel quotes and where else it
// points.
function TgChannelLinks({ urlId }) {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError("");
        api(`/api/telegram/channels/${urlId}/links`).then(({ ok, body }) => {
            if (cancelled) return;
            if (!ok) {
                setError(body?.error || "Failed to load links");
                setData({});
            } else {
                setData(body || {});
            }
            setLoading(false);
        }).catch(() => {
            if (!cancelled) {
                setError("Failed to load links");
                setData({});
                setLoading(false);
            }
        });
        return () => { cancelled = true; };
    }, [urlId]);

    if (loading) return (
        <div className="mt-3 pt-3 border-t border-gray-800/60
                        text-xs text-gray-500">Loading links…</div>
    );
    if (error) return (
        <div className="mt-3 pt-3 border-t border-gray-800/60
                        text-xs text-red-400">{error}</div>
    );
    const fwds = data?.forwards || [];
    const tg   = data?.telegram || [];
    const ext  = data?.external || [];
    const total = fwds.length + tg.length + ext.length;

    return (
        <div className="mt-3 pt-3 border-t border-gray-800/60">
            <div className="text-xs text-gray-500 uppercase mb-2 flex items-center gap-2">
                <span>Links box</span>
                {data?.scanned_messages != null && (
                    <span className="text-[10px] text-gray-600 normal-case">
                        scanned {data.scanned_messages} message{data.scanned_messages !== 1 ? "s" : ""} —
                        {` ${total} unique link${total !== 1 ? "s" : ""}`}
                    </span>
                )}
            </div>

            {total === 0 && (
                <div className="text-[11px] text-gray-500 italic">
                    No links found yet. Scrape more messages to populate.
                </div>
            )}

            <div className="grid md:grid-cols-3 gap-3 text-xs">
                {/* Forwards — direct fwd_from_username signal (strongest) */}
                <LinksColumn title="Forwards from"
                    tone="yellow" emptyMsg="No forwards yet."
                    items={fwds.map(f => ({
                        key: f.handle,
                        label: <a href={f.url} target="_blank" rel="noreferrer"
                                  className="text-yellow-300 hover:underline mono">
                                @{f.handle}
                              </a>,
                        count: f.count,
                    }))} />

                {/* Other Telegram refs (mentions in body text) */}
                <LinksColumn title="Other Telegram refs"
                    tone="cyan" emptyMsg="No t.me links or @mentions."
                    items={tg.map(t => ({
                        key: `${t.handle}-${t.msg_id}`,
                        label: <a href={t.url} target="_blank" rel="noreferrer"
                                  className="text-cyan-300 hover:underline mono truncate">
                                @{t.handle}{t.msg_id ? `/${t.msg_id}` : ""}
                              </a>,
                        count: t.count,
                    }))} />

                {/* External non-Telegram hosts */}
                <LinksColumn title="External links"
                    tone="emerald" emptyMsg="No external URLs."
                    items={ext.map(e => ({
                        key: e.host,
                        label: <span>
                                <a href={externalLink(e.samples?.[0], e.host)}
                                   target="_blank" rel="noreferrer"
                                   className="text-emerald-300 hover:underline mono truncate">
                                    {e.host}
                                </a>
                                {e.samples && e.samples.length > 0 && (
                                    <div className="text-[10px] text-gray-500 truncate mono"
                                         title={e.samples.join("\n")}>
                                        {e.samples[0]}
                                    </div>
                                )}
                              </span>,
                        count: e.count,
                    }))} />
            </div>
        </div>
    );
}


function LinksColumn({ title, tone, items, emptyMsg }) {
    const toneCls = {
        yellow: "border-yellow-800/50",
        cyan: "border-cyan-800/50",
        emerald: "border-emerald-800/50",
    }[tone] || "border-gray-800";
    return (
        <div className={`bg-gray-900/50 border rounded p-2 ${toneCls}`}>
            <div className="text-[10px] text-gray-400 uppercase mb-1 flex justify-between">
                <span>{title}</span>
                <span>{items.length}</span>
            </div>
            {items.length === 0 && (
                <div className="text-[11px] text-gray-600 italic">{emptyMsg}</div>
            )}
            <ul className="space-y-1 max-h-48 overflow-y-auto">
                {items.map(it => (
                    <li key={it.key} className="flex justify-between gap-2 items-start">
                        <span className="min-w-0 flex-1">{it.label}</span>
                        <span className="text-[10px] text-gray-500 mono shrink-0">
                            ×{it.count}
                        </span>
                    </li>
                ))}
            </ul>
        </div>
    );
}


// Per-channel message list (lazy-loaded on expand). Shows each recent
// message with its metadata pills + YARA highlights when the message
// matched any rule.
function TgMessageList({ urlId, onToast }) {
    const [msgs, setMsgs] = useState(null);
    const [error, setError] = useState("");
    const [downloading, setDownloading] = useState(null);   // msg row id
    useEffect(() => {
        let cancelled = false;
        setMsgs(null);
        setError("");
        api(`/api/telegram/channels/${urlId}/messages?limit=50`)
            .then(({ ok, body }) => {
                if (cancelled) return;
                if (!ok) {
                    setError(body?.error || "Failed to load messages");
                    setMsgs([]);
                    return;
                }
                setMsgs(Array.isArray(body) ? body : []);
            })
            .catch(() => {
                if (!cancelled) {
                    setError("Failed to load messages");
                    setMsgs([]);
                }
            });
        return () => { cancelled = true; };
    }, [urlId]);

    const downloadMedia = async (msgRowId) => {
        setDownloading(msgRowId);
        try {
            const { ok, body } = await api(
                `/api/telegram/messages/${msgRowId}/media`, { method: "POST" });
            if (ok) {
                setMsgs(prev => (prev || []).map(mm =>
                    mm.id === msgRowId
                        ? { ...mm, media_path: body.path, media_bytes: body.bytes }
                        : mm));
            } else {
                onToast?.(`Download failed: ${body?.error || "unknown"}`);
            }
        } finally { setDownloading(null); }
    };

    if (msgs === null) return (
        <div className="p-4 text-xs text-gray-500">Loading…</div>
    );
    if (error) return (
        <div className="p-4 text-xs text-red-400">{error}</div>
    );
    if (msgs.length === 0) return (
        <div className="p-4 text-xs text-gray-500 italic">
            No messages scraped yet. Use Scrape above to pull recent history.
        </div>
    );

    return (
        <div className="p-3 space-y-2">
            <div className="text-xs text-gray-500 uppercase mb-1">
                Recent messages ({msgs.length})
            </div>
            {msgs.map(m => (
                <div key={m.id}
                     className="bg-gray-950 border border-gray-800 rounded p-2 text-xs">
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                        <span className="mono text-gray-500">#{m.msg_id}</span>
                        <span className="mono text-gray-500">{m.date_iso}</span>
                        {m.sender_username && (
                            <Pill tone="blue" title="Signed sender">
                                @{m.sender_username}
                            </Pill>
                        )}
                        {m.fwd_from_username && (
                            <Pill tone="yellow" title="Forwarded from">
                                ↱ {m.fwd_from_username}
                            </Pill>
                        )}
                        {m.reply_to_msg_id && (
                            <Pill tone="gray" title="In reply to">
                                ↩ #{m.reply_to_msg_id}
                            </Pill>
                        )}
                        {m.has_media && !m.media_path && (
                            <button onClick={() => downloadMedia(m.id)}
                                    disabled={downloading === m.id}
                                    title={`Download ${m.media_type || "media"} attachment`}
                                    className="inline-flex items-center gap-1 px-1.5 py-0.5
                                               text-[10px] mono rounded border
                                               bg-gray-700/60 text-gray-300 border-gray-600
                                               hover:bg-gray-600 disabled:opacity-50">
                                {downloading === m.id
                                    ? <Spinner />
                                    : <span>📎 {m.media_type || "media"} ↓</span>}
                            </button>
                        )}
                        {m.has_media && m.media_path && (
                            <Pill tone="gray" title="Media already stored">
                                📎 {m.media_type || "media"}
                            </Pill>
                        )}
                        {m.views != null && (
                            <Pill tone="gray" title={`${m.views} views`}>
                                👁 {compact(m.views)}
                            </Pill>
                        )}
                        {m.forwards != null && m.forwards > 0 && (
                            <Pill tone="gray" title={`Forwarded ${m.forwards} times`}>
                                ↳ {compact(m.forwards)}
                            </Pill>
                        )}
                        {m.reactions_total != null && m.reactions_total > 0 && (
                            Array.isArray(m.reactions_detail) && m.reactions_detail.length > 0
                                ? m.reactions_detail.slice(0, 6).map((r, i) => (
                                    <Pill key={`rx-${i}`} tone="gray" title={`${r.count}× ${r.emoji}`}>
                                        <span>{r.emoji.startsWith("custom:") ? "⭐" : r.emoji}</span>
                                        {" "}{compact(r.count)}
                                    </Pill>
                                  ))
                                : (
                                    <Pill tone="gray" title={`${m.reactions_total} reactions`}>
                                        ♥ {compact(m.reactions_total)}
                                    </Pill>
                                  )
                        )}
                        {m.topic_title && (
                            <Pill tone="blue" title={`Forum topic: ${m.topic_title}`}>
                                # {m.topic_title}
                            </Pill>
                        )}
                        {m.media_path && (
                            <a href={`/loot/tg-media/${m.media_path}`}
                               target="_blank" rel="noreferrer">
                                <Pill tone="cyan" title={`Downloaded media: ${compact(m.media_bytes || 0)} bytes`}>
                                    ⬇ media
                                </Pill>
                            </a>
                        )}
                        {m.finding_count > 0 && (
                            <Pill tone="red" title={`${m.finding_count} YARA finding(s)`}>
                                ⚑ {m.finding_count} finding{m.finding_count !== 1 ? "s" : ""}
                            </Pill>
                        )}
                    </div>
                    <div className="text-gray-300 whitespace-pre-wrap break-words">
                        <HighlightedSnippet
                            text={(m.text || "").slice(0, 800)
                                 + ((m.text || "").length > 800 ? "…" : "")}
                            matches={m.finding_matches}
                        />
                    </div>
                </div>
            ))}
        </div>
    );
}

// ─── Channel finder (discover channels by keyword + click-to-add) ─────────
// Unified search panel — three modes (Discover / Messages / User) via a
// single tab strip instead of three always-visible panels. Keeps the
// existing component bodies unchanged; only the wrapper is new.
function TgSearchPanel({ disabled, channels, onOpenChannel, onAddChannel,
                         onFollowChain }) {
    const [tab, setTab] = useState("discover");   // discover | messages | user
    const tabs = [
        { id: "discover", label: "Discover channels",
          hint: "Find new Telegram channels by keyword (global directory)" },
        { id: "messages", label: "Search messages",
          hint: "Keyword hunt across tracked channels + live search" },
        { id: "user",     label: "Look up user",
          hint: "Profile card + photo history by @handle or phone" },
    ];
    const current = tabs.find(t => t.id === tab);

    return (
        <div className="bg-gray-900/40 border border-gray-800 rounded">
            <div className="flex border-b border-gray-800">
                {tabs.map(t => (
                    <button key={t.id} onClick={() => setTab(t.id)}
                            className={"px-4 py-2 text-xs border-b-2 transition-colors " +
                                (tab === t.id
                                    ? "border-brand-400 text-brand-300 bg-gray-900/60"
                                    : "border-transparent text-gray-400 hover:text-gray-200")}>
                        {t.label}
                    </button>
                ))}
                <div className="ml-auto flex items-center px-3 text-[11px] text-gray-500">
                    {current?.hint}
                </div>
            </div>
            <div className="p-3">
                {tab === "discover" && (
                    <TgChannelFinder
                        disabled={disabled}
                        knownUsernames={new Set(
                            channels.map(c => (c.tg_username || "").toLowerCase())
                                    .filter(Boolean))}
                        onAddChannel={onAddChannel} />
                )}
                {tab === "messages" && (
                    <TgSmartSearch
                        disabled={disabled}
                        channels={channels}
                        onOpenChannel={onOpenChannel}
                        onAddChannel={onAddChannel}
                        onFollowChain={onFollowChain} />
                )}
                {tab === "user" && (
                    <TgUserLookup disabled={disabled} />
                )}
            </div>
        </div>
    );
}


function TgChannelFinder({ disabled, knownUsernames, onAddChannel }) {
    const [q, setQ] = useState("");
    const [busy, setBusy] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState("");
    const [addingId, setAddingId] = useState(null);    // channel id being added
    const [smart, setSmart] = useState(true);          // clever expansion on by default
    const [mode, setMode] = useState("safe");          // safe | thorough
    const [mineForwards, setMineForwards] = useState(true);

    const find = async () => {
        const query = q.trim();
        if (query.length < 3) {
            setError("query must be at least 3 characters"); return;
        }
        setBusy(true); setError(""); setResult(null);
        try {
            const url = smart
                ? `/api/telegram/discover/smart?q=${encodeURIComponent(query)}`
                  + `&limit=30&mode=${mode}&mine_forwards=${mineForwards ? 1 : 0}`
                : `/api/telegram/discover?q=${encodeURIComponent(query)}&limit=30`;
            const { ok, body } = await api(url);
            if (ok) setResult(body);
            else setError(body?.error || "discovery failed");
        } catch (e) {
            setError("network error");
        } finally { setBusy(false); }
    };

    const add = async (ch) => {
        if (!ch.username) return;
        setAddingId(ch.id);
        try {
            const ok = await onAddChannel(ch.username);
            // If successfully added, mark locally so the UI shows "added"
            // without needing to refetch the discover result.
            if (ok) {
                setResult(prev => prev ? {
                    ...prev,
                    channels: prev.channels.map(c =>
                        c.id === ch.id ? { ...c, _added: true } : c),
                } : prev);
            }
        } finally { setAddingId(null); }
    };

    const channels = result?.channels || [];
    const users = result?.users || [];

    return (
        <div className="bg-gray-900/60 border border-gray-800 rounded p-3 space-y-3">
            <div className="flex items-center justify-between gap-2">
                <div className="text-xs text-gray-500 uppercase flex items-center gap-2">
                    Find channels (global directory)
                    <span className="text-gray-600 text-[10px] normal-case">
                        — {smart
                            ? "smart search: expands synonyms + mines tracked forwards"
                            : "basic search by name/handle"}
                    </span>
                </div>
                <label className="flex items-center gap-1.5 text-[11px] text-gray-400 cursor-pointer">
                    <input type="checkbox" checked={smart}
                           onChange={e => setSmart(e.target.checked)}
                           className="accent-brand-500" />
                    <span>Smart</span>
                </label>
            </div>
            <div className="flex gap-2 items-center">
                <input
                    value={q}
                    onChange={e => setQ(e.target.value)}
                    onKeyDown={e => e.key === "Enter" && !busy && find()}
                    disabled={disabled || busy}
                    placeholder="e.g. ransomware, breach forums, leaks… (min 3 chars)"
                    className="flex-1 bg-gray-950 border border-gray-700 rounded
                               px-3 py-2 text-sm mono
                               focus:outline-none focus:border-brand-500
                               disabled:opacity-60" />
                {smart && (
                    <select value={mode} onChange={e => setMode(e.target.value)}
                            disabled={disabled || busy}
                            className="bg-gray-950 border border-gray-700 rounded
                                       px-2 py-2 text-xs mono text-gray-300"
                            title="Safe: ~1 call per 3s, no bursts, 20-call budget. Thorough: ~1 per 1.5s, 40-call budget. Neither uses bursts.">
                        <option value="safe">safe</option>
                        <option value="thorough">thorough</option>
                    </select>
                )}
                <button onClick={find}
                        disabled={disabled || busy || q.trim().length < 3}
                        className="px-4 py-2 rounded bg-brand-500 text-gray-50
                                   font-semibold hover:bg-brand-400
                                   disabled:bg-gray-700 disabled:text-gray-500
                                   flex items-center gap-1.5">
                    {busy ? <Spinner /> : <Icon name="eye" size={14} />}
                    Discover
                </button>
            </div>
            {smart && (
                <div className="flex items-center gap-3 text-[11px] text-gray-500">
                    <label className="flex items-center gap-1 cursor-pointer">
                        <input type="checkbox" checked={mineForwards}
                               onChange={e => setMineForwards(e.target.checked)}
                               className="accent-brand-500" />
                        <span>mine forwards from tracked channels</span>
                    </label>
                    {result?.variants && (
                        <span className="mono text-gray-600">
                            variants tried: {result.variants.join(", ")}
                        </span>
                    )}
                </div>
            )}

            {error && (
                <div className="text-xs text-red-400 mono">{error}</div>
            )}

            {result && channels.length === 0 && users.length === 0 && (
                <div className="text-xs text-gray-500 italic p-3">
                    No channels or users matched "{q}".
                </div>
            )}

            {channels.length > 0 && (
                <div>
                    <div className="text-xs text-gray-400 uppercase mb-2">
                        Channels ({channels.length})
                    </div>
                    <div className="grid md:grid-cols-2 gap-2">
                        {channels.map(c => {
                            const known = c.username
                                && knownUsernames.has(c.username.toLowerCase());
                            const added = c._added || known || c.already_tracked;
                            const fwdSignals = (c.signals || [])
                                .filter(s => s && s.startsWith("forward_from:"));
                            return (
                                <div key={`c-${c.id}`}
                                     className="bg-gray-950 border border-gray-800 rounded p-2 text-xs">
                                    <div className="flex items-start gap-2">
                                        <div className="flex-1 min-w-0">
                                            <div className="text-gray-100 font-medium truncate">
                                                {c.title || c.username || "(no title)"}
                                                {c.verified && <Pill tone="emerald"> ✓ </Pill>}
                                                {c.scam && <Pill tone="red"> scam </Pill>}
                                                {c.fake && <Pill tone="red"> fake </Pill>}
                                                {c.restricted && <Pill tone="yellow"> restricted </Pill>}
                                            </div>
                                            <div className="flex items-center gap-2 mt-0.5 mono text-gray-500 flex-wrap">
                                                {c.username && (
                                                    <a href={`https://t.me/${c.username}`}
                                                       target="_blank" rel="noreferrer"
                                                       className="hover:text-brand-400">
                                                        @{c.username}
                                                    </a>
                                                )}
                                                <Pill tone="gray">{c.kind}</Pill>
                                                {c.subscribers != null && (
                                                    <span className="text-[10px]">
                                                        {compact(c.subscribers)} subs
                                                    </span>
                                                )}
                                                {c.score != null && (
                                                    <span className="text-[10px] text-cyan-400"
                                                          title="Ranking score: popularity × trust × variant breadth">
                                                        score {c.score}
                                                    </span>
                                                )}
                                                {Array.isArray(c.variant_hits) && c.variant_hits.length > 1 && (
                                                    <Pill tone="cyan">×{c.variant_hits.length} variants</Pill>
                                                )}
                                                {fwdSignals.length > 0 && (
                                                    <Pill tone="yellow"
                                                          title={fwdSignals.join(", ")}>
                                                        fwd {fwdSignals.length}
                                                    </Pill>
                                                )}
                                            </div>
                                        </div>
                                        <button
                                            onClick={() => !added && add(c)}
                                            disabled={!c.username || added || addingId === c.id}
                                            title={added ? "Already tracked"
                                                   : !c.username ? "Private — no @handle"
                                                   : "Add to tracked channels"}
                                            className={"px-2 py-1 rounded text-xs font-semibold " +
                                                (added ? "bg-gray-800 text-gray-500 cursor-default"
                                                 : "bg-cyan-500 text-gray-950 hover:bg-cyan-400 " +
                                                   "disabled:bg-gray-700 disabled:text-gray-500")}>
                                            {addingId === c.id ? <Spinner />
                                             : added ? "added"
                                             : "+ Add"}
                                        </button>
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </div>
            )}

            {users.length > 0 && (
                <div>
                    <div className="text-xs text-gray-400 uppercase mb-2">
                        Users ({users.length})
                        <span className="text-gray-600 ml-1 normal-case text-[10px]">
                            — not tracked; shown for context
                        </span>
                    </div>
                    <div className="flex flex-wrap gap-2">
                        {users.slice(0, 20).map(u => (
                            <a key={`u-${u.id}`}
                               href={`https://t.me/${u.username}`}
                               target="_blank" rel="noreferrer"
                               className="bg-gray-950 border border-gray-800 rounded
                                          px-2 py-1 mono text-xs text-gray-300
                                          hover:text-brand-400">
                                @{u.username}
                                {u.bot && <span className="text-blue-400"> · bot</span>}
                                {u.verified && <span className="text-emerald-400"> ✓</span>}
                                {u.scam && <span className="text-red-400"> scam</span>}
                            </a>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}

// ─── User lookup (OSINT card for a @handle / phone) ──────────────────────
function TgUserLookup({ disabled }) {
    const [handle, setHandle] = useState("");
    const [busy, setBusy] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState("");
    const [dlPhotos, setDlPhotos] = useState(false);

    const lookup = async () => {
        if (!handle.trim()) return;
        setBusy(true); setError(""); setResult(null);
        try {
            const { ok, body } = await api(
                `/api/telegram/user/${encodeURIComponent(handle.trim())}`
                + `?photos=1&download=${dlPhotos ? 1 : 0}&photo_limit=10`);
            if (ok) setResult(body);
            else setError(body?.error || "lookup failed");
        } catch (e) {
            setError("network error");
        } finally { setBusy(false); }
    };

    const flags = result ? [
        result.verified && ["emerald", "verified"],
        result.scam     && ["red", "scam"],
        result.fake     && ["red", "fake"],
        result.bot      && ["blue", "bot"],
        result.premium  && ["yellow", "premium"],
        result.restricted && ["red", "restricted"],
    ].filter(Boolean) : [];

    return (
        <div className="bg-gray-900/60 border border-gray-800 rounded p-3">
            <div className="text-xs text-gray-500 uppercase mb-2">
                User lookup (OSINT)
            </div>
            <div className="flex gap-2 items-center">
                <input
                    value={handle}
                    onChange={e => setHandle(e.target.value)}
                    onKeyDown={e => e.key === "Enter" && lookup()}
                    disabled={disabled || busy}
                    placeholder="@username / phone / t.me/username"
                    className="flex-1 bg-gray-950 border border-gray-700 rounded
                               px-3 py-2 text-sm mono
                               focus:outline-none focus:border-brand-500
                               disabled:opacity-60"
                />
                <button onClick={lookup}
                        disabled={disabled || busy || !handle.trim()}
                        className="px-4 py-2 rounded bg-brand-500 text-gray-50
                                   font-semibold hover:bg-brand-400
                                   disabled:bg-gray-700 disabled:text-gray-500
                                   flex items-center gap-1.5">
                    {busy ? <Spinner /> : <Icon name="eye" size={14} />}
                    Lookup
                </button>
            </div>
            {error && (
                <div className="mt-3 text-xs text-red-400 mono">{error}</div>
            )}
            {result && (
                <div className="mt-3 bg-gray-950 border border-gray-800 rounded p-3 text-xs">
                    <div className="flex items-center gap-2 flex-wrap mb-2">
                        <span className="text-gray-100 font-medium text-base">
                            {[result.first_name, result.last_name].filter(Boolean).join(" ")
                             || result.username || "(no name)"}
                        </span>
                        {result.username && (
                            <a href={`https://t.me/${result.username}`}
                               target="_blank" rel="noreferrer"
                               className="text-emerald-400 hover:underline mono">
                                @{result.username}
                            </a>
                        )}
                        {flags.map(([tone, label], i) => (
                            <Pill key={i} tone={tone}>{label}</Pill>
                        ))}
                    </div>
                    <div className="grid grid-cols-2 gap-x-4 gap-y-1 mono text-gray-400">
                        <div>user_id: <span className="text-gray-200">{result.user_id}</span></div>
                        {result.phone != null && (
                            <div>phone: <span className="text-gray-200">+{result.phone}</span></div>
                        )}
                        {result.lang_code && (
                            <div>lang: <span className="text-gray-200">{result.lang_code}</span></div>
                        )}
                        {result.common_chats_count != null && (
                            <div>common chats: <span className="text-gray-200">{result.common_chats_count}</span></div>
                        )}
                        <div>profile photo: <span className="text-gray-200">{result.has_photo ? "yes" : "no"}</span></div>
                    </div>
                    {result.bio && (
                        <div className="mt-2 text-gray-300 whitespace-pre-wrap">
                            <span className="text-gray-500">bio: </span>
                            {result.bio}
                        </div>
                    )}
                    {Array.isArray(result.photos) && result.photos.length > 0 && (
                        <div className="mt-3">
                            <div className="text-gray-500 uppercase text-[10px] mb-1">
                                Profile photo history ({result.photos.length})
                            </div>
                            <div className="flex gap-2 flex-wrap">
                                {result.photos.map(p => (
                                    <div key={p.id}
                                         className="bg-gray-900 border border-gray-800 rounded p-1
                                                    flex flex-col items-center">
                                        {p.url ? (
                                            <a href={p.url} target="_blank" rel="noreferrer">
                                                <img src={p.url} alt=""
                                                     className="w-16 h-16 object-cover rounded" />
                                            </a>
                                        ) : (
                                            <div className="w-16 h-16 flex items-center justify-center
                                                            bg-gray-800 rounded text-gray-500 text-[10px]">
                                                id {String(p.id).slice(-4)}
                                            </div>
                                        )}
                                        <span className="text-[9px] text-gray-500 mt-1 mono">
                                            {p.date?.slice(0, 10)}
                                        </span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            )}
            <label className="mt-2 flex items-center gap-1.5 text-[11px] text-gray-500 cursor-pointer">
                <input type="checkbox" checked={dlPhotos}
                       onChange={e => setDlPhotos(e.target.checked)}
                       className="accent-brand-500" />
                <span>download photo history to loot (so you can see them)</span>
            </label>
        </div>
    );
}

// ─── Smart search (OSINT keyword hunt across TG channels) ─────────────────
// ─── Smart search with multi-stage deep mode + discovery tree ───────────
const DEEP_STAGES = [
    { n: 1, name: "Local DB",          hint: "instant" },
    { n: 2, name: "Known channels",    hint: "live" },
    { n: 3, name: "Forward expand",    hint: "discover channels via forwards" },
    { n: 4, name: "Mention expand",    hint: "discover channels via @handles in text" },
    { n: 5, name: "Successor chain",   hint: "follow dead channels to their backups" },
];

// Centralized "how was this channel discovered" pill — used in smart
// search, chain viewer, channel finder. Keeps tone/label mapping in
// one place so we don't drift.
function DiscoveryViaPill({ via }) {
    if (!via) return null;
    const tone = via.startsWith("forward") ? "yellow"
               : via.startsWith("mention") ? "blue"
               : via.startsWith("successor") ? "red"
               : via === "local hit" || via === "known channel" ? "gray"
               : "gray";
    return <Pill tone={tone}>{via}</Pill>;
}

function DeepSearchStages({ current, stats, budgetExhausted }) {
    return (
        <div className="space-y-1.5">
            {DEEP_STAGES.map(s => {
                const st = stats[s.n] || {};
                const isDone = st.done;
                const isActive = current === s.n;
                const isBlocked = budgetExhausted && !isDone && !isActive;
                return (
                    <div key={s.n}
                         className={"flex items-center gap-2 text-xs " +
                                    ((!isActive && !isDone) ? "opacity-40" : "")}>
                        <span className={
                            "inline-flex items-center justify-center w-5 h-5 " +
                            "rounded-full border text-[10px] mono flex-shrink-0 " +
                            (isDone ? "bg-emerald-500/20 border-emerald-500/40 text-emerald-300"
                             : isActive ? "bg-cyan-500/20 border-cyan-500/40 text-cyan-300 animate-pulse"
                             : isBlocked ? "bg-yellow-500/20 border-yellow-500/40 text-yellow-300"
                             : "bg-gray-900 border-gray-700 text-gray-500")
                        }>{isDone ? "✓" : isBlocked ? "!" : s.n}</span>
                        <span className="text-gray-200 w-36">{s.name}</span>
                        <span className="text-[10px] text-gray-500 mono">
                            {isDone && st.hits != null && `${st.hits} hits`}
                            {isDone && st.expanded != null && ` · ${st.expanded} discovered`}
                            {isDone && st.chains != null && ` · ${st.chains.length} chain(s)`}
                            {isActive && (st.searched != null
                                ? `searching ${st.searched}…`
                                : "starting…")}
                            {isActive && st.budget_remaining != null
                                && ` · budget ${st.budget_remaining}`}
                            {isBlocked && "skipped — budget exhausted"}
                            {!isDone && !isActive && !isBlocked && `(${s.hint})`}
                        </span>
                    </div>
                );
            })}
        </div>
    );
}

function DiscoveryList({ discovered }) {
    if (!discovered.length) return null;
    return (
        <div className="bg-gray-950 border border-gray-800 rounded p-3 text-xs">
            <div className="text-gray-400 uppercase text-[10px] mb-2">
                Discovered channels ({discovered.length})
            </div>
            <div className="space-y-1">
                {discovered.map((d, i) => {
                    const alive = (d.status || "").startsWith("searched")
                                  || d.status === "alive" || d.status === "known";
                    return (
                        <div key={i} className="flex items-center gap-2 mono">
                            <span className={alive ? "text-emerald-400" : "text-gray-600"}>
                                {alive ? "●" : "○"}
                            </span>
                            <span className="text-gray-200">@{d.handle}</span>
                            <DiscoveryViaPill via={d.via} />
                            {d.hits > 0 && <Pill tone="emerald">{d.hits} hits</Pill>}
                            {!alive && d.status && (
                                <span className="text-red-400 text-[10px]">{d.status}</span>
                            )}
                        </div>
                    );
                })}
            </div>
        </div>
    );
}

function SuccessorChainList({ chains }) {
    if (!chains?.length) return null;
    return (
        <div className="bg-gray-950 border border-gray-800 rounded p-3 text-xs">
            <div className="text-gray-400 uppercase text-[10px] mb-2">
                Successor chains
            </div>
            <div className="space-y-2">
                {chains.map((c, i) => (
                    <div key={i}>
                        <div className="text-gray-400 mb-1">Chasing @{c.from}:</div>
                        <div className="flex flex-wrap items-center gap-1">
                            {c.chain.map((node, j) => (
                                <React.Fragment key={j}>
                                    {j > 0 && <span className="text-gray-600">→</span>}
                                    <span className={
                                        "px-1.5 py-0.5 rounded border mono " +
                                        (node.status === "alive"
                                            ? "bg-emerald-500/10 border-emerald-500/40 text-emerald-300"
                                         : node.status === "dead"
                                            ? "bg-red-500/10 border-red-500/40 text-red-300"
                                            : "bg-gray-700/40 border-gray-600 text-gray-300")
                                    } title={node.reason}>
                                        @{node.handle}
                                    </span>
                                </React.Fragment>
                            ))}
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}

function SmartSearchResultRow({ m, q, onOpenChannel }) {
    const username = m.channel_username;
    const deep = username ? `https://t.me/${username}/${m.msg_id}` : null;
    return (
        <div className="bg-gray-950 border border-gray-800 rounded p-2 text-xs">
            <div className="flex gap-2 flex-wrap items-center mb-1">
                {username && (
                    <button
                        onClick={() => m.url_id && onOpenChannel?.(m.url_id)}
                        className="mono text-emerald-400 hover:underline">
                        @{username}
                    </button>
                )}
                <span className="mono text-gray-500">#{m.msg_id}</span>
                <span className="mono text-gray-500">{m.date_iso}</span>
                {m._stage && <Pill tone="gray">stage {m._stage}</Pill>}
                {m.finding_count > 0 && (
                    <Pill tone="red">⚑ {m.finding_count} finding</Pill>
                )}
                {m.views != null && <Pill tone="gray">👁 {compact(m.views)}</Pill>}
                {deep && (
                    <a href={deep} target="_blank" rel="noreferrer"
                       className="ml-auto text-xs text-gray-500 hover:text-brand-400">
                        open ↗
                    </a>
                )}
            </div>
            <div className="text-gray-300 whitespace-pre-wrap break-words">
                <HighlightedSnippet
                    text={(m.text || "").slice(0, 600)
                         + ((m.text || "").length > 600 ? "…" : "")}
                    matches={q} />
            </div>
        </div>
    );
}

function SmartSearchResults({ results, q, onOpenChannel }) {
    if (!results) return null;
    if (results.length === 0) {
        return <div className="text-xs text-gray-500 italic p-3">No results.</div>;
    }
    // Dedupe — deep mode returns duplicates across stages when the same
    // message surfaces through multiple discovery paths.
    const seen = new Set();
    const unique = results.filter(m => {
        const k = `${m.channel_username || m.url_id || ""}-${m.msg_id}`;
        if (seen.has(k)) return false;
        seen.add(k); return true;
    });
    return (
        <div className="space-y-2 max-h-[60vh] overflow-y-auto">
            <div className="text-[10px] text-gray-500 mono">
                {unique.length} unique message{unique.length !== 1 ? "s" : ""}
            </div>
            {unique.map((m, i) => (
                <SmartSearchResultRow
                    key={`${m.channel_username || m.url_id || ""}-${m.msg_id}-${i}`}
                    m={m} q={q} onOpenChannel={onOpenChannel} />
            ))}
        </div>
    );
}

// ─── Discovery map (isometric SVG graph) ────────────────────────────────
// Renders the `discovered` + `chains` output from deep-search as a radial
// BFS graph, then skews it with a CSS 3D transform so the whole thing
// reads as an isometric map — root centered, discovered channels arc
// outward on concentric rings, edges color-coded by discovery method.

// Convert the flat `discovered` list + `chains` list into {nodes, edges}
// suitable for layout. Derives parent-of from the `via` string:
//   "local hit"             → parent = root
//   "known channel"         → parent = root
//   "forward from @xyz"     → parent = xyz   (edge kind: forward)
//   "mention in text"       → parent = root  (no clear source; attach to root)
//   "successor of @xyz"     → parent = xyz   (edge kind: successor)
function buildDiscoveryGraph(discovered, chains) {
    const nodes = new Map();           // id → node
    const edges = [];
    const ROOT = "__root__";
    nodes.set(ROOT, {
        id: ROOT, title: "search root", kind: "root",
        status: "alive", via: "seed", hits: 0,
    });

    const upsert = (handle, patch) => {
        const id = (handle || "").toLowerCase();
        if (!id) return null;
        const existing = nodes.get(id) || {
            id, kind: "channel", status: "unknown",
        };
        nodes.set(id, { ...existing, ...patch, id });
        return id;
    };

    const parseVia = via => {
        if (!via) return null;
        const m1 = via.match(/^forward from @?([A-Za-z0-9_]+)/i);
        if (m1) return { kind: "forward", parent: m1[1].toLowerCase() };
        const m2 = via.match(/^successor of @?([A-Za-z0-9_]+)/i);
        if (m2) return { kind: "successor", parent: m2[1].toLowerCase() };
        if (via.startsWith("mention")) return { kind: "mention", parent: ROOT };
        // "local hit" / "known channel" / anything else — attach to root.
        return { kind: "mention", parent: ROOT };
    };

    for (const d of discovered) {
        const status = (d.status || "").startsWith("searched")
                       || d.status === "alive" ? "alive"
                       : d.status === "known"   ? "alive"
                       : (d.status || "").startsWith("unresolvable") ? "dead"
                       : "unknown";
        const id = upsert(d.handle, {
            title: d.handle, via: d.via, hits: d.hits || 0,
            status,
        });
        if (!id) continue;
        const v = parseVia(d.via);
        if (!v) continue;
        // Only create parent node if it's the root (otherwise it'll already
        // exist in `discovered` as the forwarding channel).
        if (v.parent === ROOT || !nodes.has(v.parent)) {
            // For forward/successor parents we don't yet have, create a
            // placeholder so edges resolve.
            if (v.parent !== ROOT && !nodes.has(v.parent)) {
                nodes.set(v.parent, {
                    id: v.parent, kind: "channel", status: "unknown",
                    via: "intermediate",
                });
            }
        }
        edges.push({ from: v.parent, to: id, kind: v.kind });
    }

    // Chains: each chain is a linear path; edges between consecutive nodes.
    for (const c of (chains || [])) {
        if (!c.chain?.length) continue;
        let prev = null;
        for (const node of c.chain) {
            const status = node.status === "alive" ? "alive"
                         : node.status === "dead"  ? "dead"
                         : node.status === "stale" ? "stale" : "unknown";
            upsert(node.handle, {
                title: node.handle, status, via: "successor",
            });
            if (prev) edges.push({
                from: prev, to: (node.handle || "").toLowerCase(),
                kind: "successor",
            });
            prev = (node.handle || "").toLowerCase();
        }
        // Connect the chain's starting point to root.
        const first = (c.chain[0].handle || "").toLowerCase();
        if (first) edges.push({ from: ROOT, to: first, kind: "successor" });
    }

    return { nodes: Array.from(nodes.values()), edges };
}

// Radial BFS layout — returns positions keyed by node id.
function layoutRadial(nodes, edges, rootId = "__root__") {
    const adj = new Map();
    for (const e of edges) {
        if (!adj.has(e.from)) adj.set(e.from, []);
        adj.get(e.from).push(e.to);
    }
    const layer = new Map();     // id → layer number
    const parent = new Map();    // id → parent id (first discovered)
    layer.set(rootId, 0);
    const queue = [rootId];
    while (queue.length) {
        const id = queue.shift();
        for (const child of (adj.get(id) || [])) {
            if (!layer.has(child)) {
                layer.set(child, layer.get(id) + 1);
                parent.set(child, id);
                queue.push(child);
            }
        }
    }
    // Nodes not reached by BFS (disconnected) — pin them in an outer ring.
    const maxReachedLayer = Math.max(0, ...Array.from(layer.values()));
    for (const n of nodes) {
        if (!layer.has(n.id)) {
            layer.set(n.id, maxReachedLayer + 1);
        }
    }
    // Group by layer for angle allocation.
    const byLayer = new Map();
    for (const [id, L] of layer.entries()) {
        if (!byLayer.has(L)) byLayer.set(L, []);
        byLayer.get(L).push(id);
    }
    const pos = new Map();
    pos.set(rootId, { x: 0, y: 0 });
    const RING = 140;
    for (const [L, ids] of byLayer.entries()) {
        if (L === 0) continue;
        const r = RING * L;
        // For each node, inherit a phase from its parent so children fan
        // outward from where the parent sits.
        ids.forEach((id, i) => {
            const p = parent.get(id);
            const pPos = p && pos.get(p);
            const basePhase = pPos
                ? Math.atan2(pPos.y, pPos.x) || 0
                : 0;
            const count = ids.length;
            const spread = Math.min(2 * Math.PI, Math.PI * 0.9);
            const angle = basePhase + (i - (count - 1) / 2) * (spread / Math.max(1, count));
            pos.set(id, { x: Math.cos(angle) * r, y: Math.sin(angle) * r });
        });
    }
    return pos;
}

const MAP_VIA_STROKE = {
    forward:   "#facc15",   // yellow
    mention:   "#60a5fa",   // blue
    successor: "#f87171",   // red
};

function TgDiscoveryMap({ discovered, chains, onAddChannel, knownUsernames,
                          onFollowChain, rootQuery }) {
    const { nodes, edges } = React.useMemo(
        () => buildDiscoveryGraph(discovered, chains),
        [discovered, chains]);

    if (nodes.length === 0) {
        return (
            <div className="bg-gray-900/60 border border-gray-800 rounded p-10
                            text-center text-xs text-gray-500">
                <div className="mb-2 text-gray-400">
                    Discovery map is empty.
                </div>
                <div>
                    Run a <span className="text-emerald-400">Deep search</span> above
                    {rootQuery && <> for "<span className="mono">{rootQuery}</span>"</>}.
                    Stages 3-5 will discover channels via forwards, mentions, and
                    successor chains — they'll render here as a web emanating from
                    the root query.
                </div>
            </div>
        );
    }
    const positions = React.useMemo(
        () => layoutRadial(nodes, edges),
        [nodes, edges]);

    const [hover, setHover] = useState(null);       // node id
    const [viewBox, setViewBox] = useState({ x: -400, y: -400, w: 800, h: 800 });
    const [panning, setPanning] = useState(null);    // {startX, startY, vbX, vbY}
    const [adding, setAdding] = useState(null);      // node id currently being added

    // Fit-to-content: compute bounding box of all nodes + 100px padding.
    const fit = React.useCallback(() => {
        if (nodes.length === 0) return;
        const xs = nodes.map(n => positions.get(n.id)?.x || 0);
        const ys = nodes.map(n => positions.get(n.id)?.y || 0);
        const minX = Math.min(...xs) - 120;
        const maxX = Math.max(...xs) + 120;
        const minY = Math.min(...ys) - 80;
        const maxY = Math.max(...ys) + 80;
        const w = Math.max(400, maxX - minX);
        const h = Math.max(400, maxY - minY);
        setViewBox({ x: minX, y: minY, w, h });
    }, [nodes, positions]);

    useEffect(() => { fit(); }, [fit]);

    const onWheel = (e) => {
        e.preventDefault();
        const factor = e.deltaY > 0 ? 1.15 : 1 / 1.15;
        setViewBox(vb => ({
            x: vb.x, y: vb.y,
            w: Math.max(200, Math.min(5000, vb.w * factor)),
            h: Math.max(200, Math.min(5000, vb.h * factor)),
        }));
    };
    const onPointerDown = (e) => {
        if (e.button !== 0) return;
        setPanning({ startX: e.clientX, startY: e.clientY,
                     vbX: viewBox.x, vbY: viewBox.y });
    };
    const onPointerMove = (e) => {
        if (!panning) return;
        const dx = (e.clientX - panning.startX) * (viewBox.w / 800);
        const dy = (e.clientY - panning.startY) * (viewBox.h / 800);
        setViewBox(vb => ({ ...vb, x: panning.vbX - dx, y: panning.vbY - dy }));
    };
    const onPointerUp = () => setPanning(null);

    const handleNodeClick = async (node, ev) => {
        if (node.id === "__root__") return;
        if (ev.shiftKey) {
            onFollowChain?.(node.id);
            return;
        }
        const known = knownUsernames?.has(node.id);
        if (known || node.added) return;
        setAdding(node.id);
        try { await onAddChannel?.(node.id); }
        finally { setAdding(null); }
    };

    if (nodes.length <= 1) {
        return (
            <div className="text-xs text-gray-500 italic p-6 text-center
                            bg-gray-950 border border-gray-800 rounded">
                Run a Deep search to populate the map.
            </div>
        );
    }

    const hoverNode = hover && nodes.find(n => n.id === hover);
    const hoverPos = hoverNode ? positions.get(hoverNode.id) : null;

    // Ground-plane grid lines (static, faint)
    const gridLines = [];
    const gridStep = 140;
    for (let g = -4; g <= 4; g++) {
        gridLines.push({ x1: g * gridStep, y1: -560, x2: g * gridStep, y2: 560 });
        gridLines.push({ x1: -560, y1: g * gridStep, x2: 560, y2: g * gridStep });
    }

    return (
        <div className="relative bg-gray-950 border border-gray-800 rounded p-3">
            <div className="flex items-center gap-2 mb-2 text-xs">
                <span className="text-gray-400 uppercase text-[10px]">
                    Discovery map
                </span>
                <span className="text-gray-500 mono text-[10px]">
                    {nodes.length - 1} nodes · {edges.length} edges
                </span>
                <span className="ml-auto flex items-center gap-1 text-[10px] text-gray-500">
                    <span className="inline-block w-2 h-2 rounded-full bg-yellow-400" /> forward
                    <span className="inline-block w-2 h-2 rounded-full bg-blue-400 ml-2" /> mention
                    <span className="inline-block w-2 h-2 rounded-full bg-red-400 ml-2" /> successor
                </span>
                <button onClick={fit}
                        className="px-2 py-1 rounded bg-gray-800 text-xs
                                   hover:bg-gray-700 text-gray-300">
                    Fit
                </button>
            </div>
            <div
                className="relative select-none overflow-hidden rounded
                           bg-gradient-to-b from-gray-950 to-gray-900"
                style={{ height: 520, perspective: 1200 }}
                onWheel={onWheel}
                onPointerDown={onPointerDown}
                onPointerMove={onPointerMove}
                onPointerUp={onPointerUp}
                onPointerLeave={onPointerUp}
            >
                {/* Isometric skew applied to the SVG container */}
                <svg
                    viewBox={`${viewBox.x} ${viewBox.y} ${viewBox.w} ${viewBox.h}`}
                    className="w-full h-full"
                    style={{
                        transform: "rotateX(55deg) rotateZ(-35deg) scale(0.95)",
                        transformStyle: "preserve-3d",
                        cursor: panning ? "grabbing" : "grab",
                    }}
                >
                    {/* Ground grid */}
                    <g opacity="0.18">
                        {gridLines.map((l, i) => (
                            <line key={i} x1={l.x1} y1={l.y1} x2={l.x2} y2={l.y2}
                                  stroke="#334155" strokeWidth="1" />
                        ))}
                    </g>
                    {/* Ring outlines to hint at BFS layers */}
                    {[1, 2, 3, 4].map(L => (
                        <circle key={L} cx="0" cy="0" r={140 * L}
                                fill="none" stroke="#1e293b"
                                strokeWidth="1" strokeDasharray="4 6"
                                opacity="0.35" />
                    ))}
                    {/* Edges */}
                    <g>
                        {edges.map((e, i) => {
                            const a = positions.get(e.from);
                            const b = positions.get(e.to);
                            if (!a || !b) return null;
                            const color = MAP_VIA_STROKE[e.kind] || "#475569";
                            const midX = (a.x + b.x) / 2;
                            const midY = (a.y + b.y) / 2 - 18;  // slight arc
                            return (
                                <path key={i}
                                      d={`M ${a.x} ${a.y} Q ${midX} ${midY}, ${b.x} ${b.y}`}
                                      stroke={color}
                                      strokeWidth={e.kind === "successor" ? 2 : 1.5}
                                      strokeDasharray={e.kind === "successor" ? "6 4" : ""}
                                      fill="none"
                                      opacity="0.6" />
                            );
                        })}
                    </g>
                    {/* Nodes (upright via counter-rotation) */}
                    <g>
                        {nodes.map(n => {
                            const p = positions.get(n.id);
                            if (!p) return null;
                            const isRoot = n.kind === "root";
                            const size = isRoot ? 28
                                : Math.max(18, Math.min(36,
                                    14 + Math.log10((n.subscribers || 10)) * 4));
                            const statusFill = {
                                alive: "#10b981", dead: "#ef4444",
                                stale: "#facc15", unknown: "#64748b",
                            }[n.status] || "#64748b";
                            const known = knownUsernames?.has(n.id);
                            return (
                                <g key={n.id}
                                   transform={`translate(${p.x}, ${p.y}) rotate(35) rotateX(-55)`}
                                   onMouseEnter={() => setHover(n.id)}
                                   onMouseLeave={() => setHover(h => h === n.id ? null : h)}
                                   onClick={(e) => handleNodeClick(n, e)}
                                   style={{ cursor: isRoot ? "default" : "pointer",
                                            transformBox: "fill-box",
                                            transformOrigin: "center" }}>
                                    <circle r={size} fill={statusFill}
                                            fillOpacity={isRoot ? 0.25 : 0.15}
                                            stroke={statusFill}
                                            strokeWidth={isRoot ? 3 : known ? 2 : 1.5}
                                            strokeDasharray={known || isRoot ? "" : "4 3"} />
                                    {adding === n.id && (
                                        <circle r={size + 4} fill="none"
                                                stroke="#22d3ee" strokeWidth="2"
                                                opacity="0.7">
                                            <animate attributeName="r"
                                                     values={`${size};${size + 8};${size}`}
                                                     dur="0.8s" repeatCount="indefinite" />
                                        </circle>
                                    )}
                                    <text y={size + 14}
                                          textAnchor="middle"
                                          fontSize="11"
                                          fontFamily="ui-monospace,monospace"
                                          fill={known ? "#d1d5db" : "#94a3b8"}>
                                        {isRoot ? "root" : "@" + n.id}
                                    </text>
                                    {n.hits > 0 && (
                                        <text y={-size - 6}
                                              textAnchor="middle" fontSize="10"
                                              fontFamily="ui-monospace,monospace"
                                              fill="#10b981">
                                            {n.hits} hits
                                        </text>
                                    )}
                                </g>
                            );
                        })}
                    </g>
                </svg>
                {/* Hover tooltip (not inside the skewed SVG so text is flat) */}
                {hoverNode && hoverPos && (
                    <div className="absolute bottom-3 left-3 right-3
                                    bg-gray-900/95 border border-gray-700 rounded
                                    p-2 text-xs mono pointer-events-none
                                    max-w-md">
                        <div className="text-gray-100 font-medium">
                            @{hoverNode.id}
                            {hoverNode.hits > 0 && (
                                <span className="text-emerald-400 ml-2">
                                    {hoverNode.hits} hits
                                </span>
                            )}
                        </div>
                        <div className="text-gray-500">
                            status: <span className={
                                hoverNode.status === "alive" ? "text-emerald-400"
                                : hoverNode.status === "dead" ? "text-red-400"
                                : hoverNode.status === "stale" ? "text-yellow-400"
                                : "text-gray-400"}>{hoverNode.status}</span>
                            {hoverNode.via && (
                                <span className="ml-2">via: {hoverNode.via}</span>
                            )}
                            {knownUsernames?.has(hoverNode.id) && (
                                <span className="ml-2 text-cyan-400">· already tracked</span>
                            )}
                        </div>
                        <div className="text-gray-600 text-[10px] mt-1">
                            click to add · shift+click to follow chain · drag to pan · scroll to zoom
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}

function TgSmartSearch({ disabled, channels, onOpenChannel,
                          onAddChannel, onFollowChain }) {
    const [q, setQ] = useState("");
    const [mode, setMode] = useState("simple");    // simple | deep
    const [scanMode, setScanMode] = useState("safe");  // safe | thorough (deep only)
    const [viewMode, setViewMode] = useState("list");  // list | map (deep only)
    const [scope, setScope] = useState("local");   // simple only
    const [sinceDays, setSinceDays] = useState("0");
    const [channelId, setChannelId] = useState("");
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState("");

    // Simple-mode state
    const [result, setResult] = useState(null);

    // Deep-mode state
    const [currentStage, setCurrentStage] = useState(0);   // 0 = none, 1-5
    const [stageStats, setStageStats] = useState({});       // {1: {hits, ...}}
    const [deepResults, setDeepResults] = useState([]);
    const [discovered, setDiscovered] = useState([]);
    const [chains, setChains] = useState([]);               // stage 5 output
    const [deepDone, setDeepDone] = useState(false);
    const [budget, setBudget] = useState(null);             // {total, remaining}
    const [budgetExhausted, setBudgetExhausted] = useState(false);

    const esRef = useRef(null);

    const simpleSearch = async () => {
        setBusy(true); setError(""); setResult(null);
        try {
            const params = new URLSearchParams({ q: q.trim(), scope, limit: "50" });
            if (scope === "channel" && channelId) params.set("channel_id", channelId);
            if (sinceDays !== "0") {
                const d = new Date(Date.now() - parseInt(sinceDays, 10) * 86400000);
                params.set("since", d.toISOString());
            }
            const { ok, body } = await api(`/api/telegram/search?${params}`);
            if (ok) setResult(body);
            else setError(body?.error || "search failed");
        } catch (e) { setError("network error"); }
        finally { setBusy(false); }
    };

    const deepSearch = () => {
        if (esRef.current) esRef.current.close();
        setBusy(true); setError("");
        setCurrentStage(0); setStageStats({});
        setDeepResults([]); setDiscovered([]); setChains([]);
        setDeepDone(false); setBudget(null); setBudgetExhausted(false);

        const params = new URLSearchParams({
            q: q.trim(), max_hops: "2", mode: scanMode,
        });
        if (sinceDays !== "0") {
            const d = new Date(Date.now() - parseInt(sinceDays, 10) * 86400000);
            params.set("since", d.toISOString());
        }

        const es = new EventSource(`/api/telegram/search/deep?${params}`);
        esRef.current = es;

        es.addEventListener("start", (ev) => {
            const d = JSON.parse(ev.data);
            setBudget({ total: d.budget, remaining: d.budget });
        });
        es.addEventListener("stage", (ev) => {
            const d = JSON.parse(ev.data);
            setCurrentStage(d.n);
        });
        es.addEventListener("progress", (ev) => {
            const d = JSON.parse(ev.data);
            setStageStats(prev => ({ ...prev, [d.stage]: { ...(prev[d.stage] || {}), ...d } }));
            if (d.budget_remaining != null) {
                setBudget(b => b ? { ...b, remaining: d.budget_remaining } : b);
            }
            if (d.results?.length) {
                setDeepResults(prev => [...prev, ...d.results]);
            }
        });
        es.addEventListener("stage_done", (ev) => {
            const d = JSON.parse(ev.data);
            setStageStats(prev => ({ ...prev, [d.stage]: { ...(prev[d.stage] || {}), ...d, done: true } }));
            if (d.chains) setChains(d.chains);
        });
        es.addEventListener("budget_exhausted", (ev) => {
            setBudgetExhausted(true);
        });
        es.addEventListener("done", (ev) => {
            const d = JSON.parse(ev.data);
            setDiscovered(d.discovered || []);
            if (d.results) setDeepResults(d.results);
            if (d.budget_remaining != null) {
                setBudget(b => b ? { ...b, remaining: d.budget_remaining } : b);
            }
            setDeepDone(true); setBusy(false); setCurrentStage(0);
            es.close(); esRef.current = null;
        });
        es.onerror = () => {
            setError("stream interrupted");
            setBusy(false); setCurrentStage(0);
            es.close(); esRef.current = null;
        };
    };

    useEffect(() => () => {
        if (esRef.current) esRef.current.close();
    }, []);

    const doSearch = () => {
        if (!q.trim()) return;
        mode === "deep" ? deepSearch() : simpleSearch();
    };

    const cancel = () => {
        if (esRef.current) esRef.current.close();
        esRef.current = null;
        setBusy(false); setCurrentStage(0);
    };

    return (
        <div className="bg-gray-900/60 border border-gray-800 rounded p-3 space-y-3">
            <div className="text-xs text-gray-500 uppercase flex items-center gap-2">
                Smart search
                {mode === "deep" && (
                    <span className="text-cyan-400 normal-case">
                        — deep (multi-stage OSINT)
                    </span>
                )}
                {mode === "simple" && scope !== "local" && (
                    <span className="text-yellow-400 normal-case">
                        (live — will call Telegram API)
                    </span>
                )}
            </div>
            <div className="flex gap-2 flex-wrap items-center">
                <input
                    value={q}
                    onChange={e => setQ(e.target.value)}
                    onKeyDown={e => e.key === "Enter" && !busy && doSearch()}
                    disabled={busy}
                    placeholder="keyword or phrase"
                    className="flex-1 min-w-[200px] bg-gray-950 border border-gray-700 rounded
                               px-3 py-2 text-sm mono
                               focus:outline-none focus:border-brand-500" />
                <select value={mode} onChange={e => setMode(e.target.value)}
                        disabled={busy}
                        className="bg-gray-950 border border-gray-700 rounded
                                   px-3 py-2 text-sm">
                    <option value="simple">Simple</option>
                    <option value="deep" disabled={disabled}>Deep (5 stages)</option>
                </select>
                {mode === "deep" && (
                    <select value={scanMode}
                            onChange={e => setScanMode(e.target.value)}
                            disabled={busy}
                            title={scanMode === "safe"
                                ? "Rate-limited, ~25 API calls max. Recommended."
                                : "Faster, larger budget, higher chance of FloodWait."}
                            className="bg-gray-950 border border-gray-700 rounded
                                       px-3 py-2 text-sm">
                        <option value="safe">Safe (rate-limited)</option>
                        <option value="thorough">Thorough (aggressive)</option>
                    </select>
                )}
                {mode === "simple" && (
                    <select value={scope} onChange={e => setScope(e.target.value)}
                            disabled={busy}
                            className="bg-gray-950 border border-gray-700 rounded
                                       px-3 py-2 text-sm">
                        <option value="local">Local</option>
                        <option value="channel" disabled={disabled}>One channel</option>
                        <option value="all" disabled={disabled}>All channels</option>
                    </select>
                )}
                {mode === "simple" && scope === "channel" && (
                    <select value={channelId}
                            onChange={e => setChannelId(e.target.value)}
                            disabled={busy}
                            className="bg-gray-950 border border-gray-700 rounded
                                       px-3 py-2 text-sm">
                        <option value="">(select channel)</option>
                        {channels.map(c => (
                            <option key={c.id} value={c.id}>@{c.tg_username}</option>
                        ))}
                    </select>
                )}
                <select value={sinceDays}
                        onChange={e => setSinceDays(e.target.value)}
                        disabled={busy}
                        className="bg-gray-950 border border-gray-700 rounded
                                   px-3 py-2 text-sm">
                    <option value="0">all time</option>
                    <option value="1">last 24h</option>
                    <option value="7">last 7d</option>
                    <option value="30">last 30d</option>
                    <option value="90">last 90d</option>
                </select>
                {!busy ? (
                    <button onClick={doSearch}
                            disabled={!q.trim() ||
                                      (mode === "simple" && scope === "channel" && !channelId)}
                            className="px-4 py-2 rounded bg-brand-500 text-gray-50
                                       font-semibold hover:bg-brand-400
                                       disabled:bg-gray-700 disabled:text-gray-500
                                       flex items-center gap-1.5">
                        <Icon name="eye" size={14} /> Search
                    </button>
                ) : (
                    <button onClick={cancel}
                            className="px-4 py-2 rounded bg-red-500 text-gray-950
                                       font-semibold hover:bg-red-400 flex items-center gap-1.5">
                        <Icon name="stop" size={14} /> Cancel
                    </button>
                )}
            </div>

            {error && (
                <div className="text-xs text-red-400 mono">{error}</div>
            )}

            {/* Deep-mode stage progress + budget chip */}
            {mode === "deep" && (busy || deepDone || Object.keys(stageStats).length > 0) && (
                <div className="bg-gray-950 border border-gray-800 rounded p-3 space-y-2">
                    <DeepSearchStages current={currentStage}
                                      stats={stageStats}
                                      budgetExhausted={budgetExhausted} />
                    {budget && (
                        <div className="text-[10px] text-gray-500 mono flex items-center gap-2">
                            <span>API budget:</span>
                            <span className={budgetExhausted
                                ? "text-yellow-400"
                                : budget.remaining <= budget.total * 0.25
                                  ? "text-yellow-400"
                                  : "text-emerald-400"}>
                                {budget.remaining} / {budget.total}
                            </span>
                            {budgetExhausted && (
                                <span className="text-yellow-400">
                                    — exhausted, later stages skipped
                                </span>
                            )}
                        </div>
                    )}
                </div>
            )}

            {/* Simple-mode result summary */}
            {mode === "simple" && result && (
                <div className="text-xs text-gray-400">
                    {result.hits} match{result.hits !== 1 ? "es" : ""}
                    {result.channels_searched != null &&
                        ` across ${result.channels_searched} channel${result.channels_searched !== 1 ? "s" : ""}`}
                </div>
            )}

            {/* View toggle (deep only) — always shown in deep mode so the
                 map feature is discoverable BEFORE results exist. */}
            {mode === "deep" && (
                <div className="flex items-center gap-2 text-xs">
                    <span className="text-gray-500">View:</span>
                    <button onClick={() => setViewMode("list")}
                            className={"px-2 py-1 rounded " +
                                (viewMode === "list"
                                    ? "bg-emerald-500/20 border border-emerald-500/40 text-emerald-300"
                                    : "bg-gray-800 border border-gray-700 text-gray-400 hover:text-gray-200")}>
                        List
                    </button>
                    <button onClick={() => setViewMode("map")}
                            className={"px-2 py-1 rounded " +
                                (viewMode === "map"
                                    ? "bg-cyan-500/20 border border-cyan-500/40 text-cyan-300"
                                    : "bg-gray-800 border border-gray-700 text-gray-400 hover:text-gray-200")}>
                        Map (isometric)
                    </button>
                    {viewMode === "map" && discovered.length === 0 && chains.length === 0 && (
                        <span className="text-gray-600">
                            — run a deep search first; discovered channels appear here as a web
                        </span>
                    )}
                </div>
            )}

            {/* Discovery visualisation — list OR map */}
            {mode === "deep" && viewMode === "list" && (
                <>
                    <DiscoveryList discovered={discovered} />
                    <SuccessorChainList chains={chains} />
                </>
            )}
            {mode === "deep" && viewMode === "map" && (
                <TgDiscoveryMap
                    discovered={discovered}
                    chains={chains}
                    rootQuery={q}
                    onAddChannel={onAddChannel}
                    onFollowChain={onFollowChain}
                    knownUsernames={new Set(
                        channels.map(c => (c.tg_username || "").toLowerCase())
                                .filter(Boolean))}
                />
            )}

            {/* Results list (always — both views share it) */}
            <SmartSearchResults
                results={mode === "deep" ? deepResults : result?.results}
                q={q}
                onOpenChannel={onOpenChannel} />
        </div>
    );
}

function TelegramPanel({ status, channels, onReloadStatus, onAuth, onLogout,
                        onAddChannel, onScrape, onRescan, onJoin, onLeave,
                        onSetMonitor, monitorPending, onDelete, onLightbox,
                        tgVpnOk, onToast }) {
    const pending = monitorPending || new Set();
    const [authOpen, setAuthOpen] = useState(false);
    const [authBusy, setAuthBusy] = useState(false);
    const [newChannel, setNewChannel] = useState("");
    const [chainResult, setChainResult] = useState(null);  // {starting, chain[]}
    const [chainBusy, setChainBusy] = useState(false);
    const [adding, setAdding] = useState(false);
    const [expanded, setExpanded] = useState(null);
    const [membersFor, setMembersFor] = useState(null);    // { urlId, title }
    const [membersData, setMembersData] = useState(null);  // server response
    const [membersBusy, setMembersBusy] = useState(false);

    const openMembers = async (c) => {
        setMembersFor({ urlId: c.id, title: c.tg_username || c.title });
        setMembersData(null);
        setMembersBusy(true);
        try {
            const { ok, body } = await api(
                `/api/telegram/channels/${c.id}/members?limit=200`);
            setMembersData(ok ? body : { error: body?.error || "failed" });
        } finally { setMembersBusy(false); }
    };

    const configured = status?.configured;
    const authed = status?.authenticated;

    const authHandler = async (step, body) => {
        setAuthBusy(true);
        try {
            const r = await onAuth(step, body);
            return r;
        } finally {
            setAuthBusy(false);
            if (step === "confirm") onReloadStatus();
        }
    };

    const followChain = async (handle) => {
        setChainBusy(true); setChainResult(null);
        try {
            const { ok, body } = await api(
                `/api/telegram/chain/${encodeURIComponent(handle)}`);
            if (ok) setChainResult(body);
            else setChainResult({ error: body?.error || "chain follow failed",
                                   starting: handle });
        } catch (e) {
            setChainResult({ error: "network error", starting: handle });
        } finally { setChainBusy(false); }
    };

    const addChannel = async () => {
        if (!newChannel.trim()) return;
        setAdding(true);
        try {
            const ok = await onAddChannel(newChannel.trim());
            if (ok) setNewChannel("");
        } finally { setAdding(false); }
    };

    return (
        <div className="space-y-4">
            {/* Auth banner */}
            <div className="bg-gray-900/60 border border-gray-800 rounded p-3
                            flex items-center gap-3">
                {!configured ? (
                    <>
                        <span className="text-red-400">
                            <Icon name="alert" size={16} />
                        </span>
                        <div className="flex-1 text-sm">
                            <div className="text-gray-200">Telegram not configured</div>
                            <div className="text-xs text-gray-500">
                                Save <code className="mono">api_id</code> and{" "}
                                <code className="mono">api_hash</code> in the{" "}
                                Setup UI (Settings ↗), then open the Telegram tab
                                and click Connect. Get credentials at{" "}
                                <a href="https://my.telegram.org" target="_blank"
                                      rel="noreferrer"
                                      className="underline text-emerald-400">my.telegram.org</a>.
                            </div>
                        </div>
                    </>
                ) : !authed ? (
                    <>
                        <span className="text-yellow-400">
                            <Icon name="alert" size={16} />
                        </span>
                        <div className="flex-1 text-sm">
                            <div className="text-gray-200">Not signed in</div>
                            <div className="text-xs text-gray-500">
                                Session file missing or expired.
                            </div>
                        </div>
                        <button onClick={() => setAuthOpen(true)}
                                disabled={!tgVpnOk}
                                title={tgVpnOk ? "" : "Telegram VPN is not reachable — check protonvpn-tg"}
                                className="px-3 py-1.5 rounded bg-brand-500 text-gray-50
                                           font-semibold hover:bg-brand-400 text-sm
                                           disabled:bg-gray-700 disabled:text-gray-500">
                            Connect Telegram
                        </button>
                    </>
                ) : (
                    <>
                        <span className="text-emerald-400">
                            <Icon name="check" size={16} />
                        </span>
                        <div className="flex-1 text-sm text-gray-200">
                            Connected
                            {status.use_tor && (
                                <span className="text-[10px] ml-2 mono text-yellow-400">
                                    via Tor (slow)
                                </span>
                            )}
                        </div>
                        <button onClick={onLogout}
                                className="text-xs text-gray-500 hover:text-red-400">
                            Disconnect
                        </button>
                    </>
                )}
                <button onClick={onReloadStatus}
                        className="text-xs text-gray-500 hover:text-gray-200 ml-2">
                    <Icon name="refresh" size={14} />
                </button>
            </div>

            {/* Add channel (requires auth) */}
            {configured && authed && (
                <div className="flex gap-2 items-center bg-gray-900/60
                                border border-gray-800 rounded p-3">
                    <input
                        value={newChannel}
                        onChange={e => setNewChannel(e.target.value)}
                        placeholder="@channel_name, t.me/channel_name, or https://t.me/channel_name"
                        className="flex-1 bg-gray-950 border border-gray-700 rounded
                                   px-3 py-2 text-sm mono
                                   focus:outline-none focus:border-brand-500"
                    />
                    <button onClick={addChannel}
                            disabled={adding || !newChannel.trim()}
                            className="px-4 py-2 rounded bg-brand-500 text-gray-50
                                       font-semibold hover:bg-brand-400 flex items-center gap-1.5
                                       disabled:bg-gray-700 disabled:text-gray-500">
                        {adding ? <Spinner /> : <Icon name="plus" size={14} />}
                        Add channel
                    </button>
                </div>
            )}

            {/* Unified Search panel — one tab strip instead of three stacked
                 panels. Clearer labels, only one box visible at a time. */}
            {configured && authed && (
                <TgSearchPanel
                    disabled={!tgVpnOk}
                    channels={channels}
                    onOpenChannel={urlId => setExpanded(urlId)}
                    onAddChannel={onAddChannel}
                    onFollowChain={followChain}
                />
            )}

            {/* Chain-follow result */}
            {(chainBusy || chainResult) && (
                <div className="bg-gray-950 border border-gray-800 rounded p-3 text-xs">
                    <div className="flex items-center gap-2 mb-2">
                        <span className="text-gray-400 uppercase text-[10px]">
                            Successor chain {chainBusy ? "(following…)" : ""}
                        </span>
                        {chainResult && (
                            <button onClick={() => setChainResult(null)}
                                    className="ml-auto text-gray-500 hover:text-gray-200">
                                <Icon name="close" size={12} />
                            </button>
                        )}
                    </div>
                    {chainBusy && <div className="flex items-center gap-2 text-gray-400">
                        <Spinner /> following @{chainResult?.starting || "…"}
                    </div>}
                    {chainResult?.error && (
                        <div className="text-red-400">{chainResult.error}</div>
                    )}
                    {chainResult?.chain && chainResult.chain.length > 0 && (
                        <div className="space-y-2">
                            <div className="flex flex-wrap items-center gap-1">
                                {chainResult.chain.map((node, j) => (
                                    <React.Fragment key={j}>
                                        {j > 0 && <span className="text-gray-600">→</span>}
                                        <span className={
                                            "px-1.5 py-0.5 rounded border mono text-[11px] " +
                                            (node.status === "alive"
                                                ? "bg-emerald-500/10 border-emerald-500/40 text-emerald-300"
                                             : node.status === "dead"
                                                ? "bg-red-500/10 border-red-500/40 text-red-300"
                                                : "bg-gray-700/40 border-gray-600 text-gray-300")
                                        } title={node.reason}>
                                            @{node.handle}
                                        </span>
                                    </React.Fragment>
                                ))}
                            </div>
                            <div className="text-[10px] text-gray-500 space-y-0.5">
                                {chainResult.chain.map((node, j) => (
                                    <div key={j}>
                                        <span className="mono text-gray-400">@{node.handle}</span>
                                        <span className="text-gray-600"> · {node.status}</span>
                                        {node.reason && <span className="text-gray-500"> — {node.reason}</span>}
                                        {node.chose && <span className="text-gray-400"> · {node.chose}</span>}
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* Channels list */}
            <div className="overflow-x-auto border border-gray-800 rounded">
                <table className="w-full text-sm">
                    <thead className="bg-gray-900 text-gray-400 text-xs uppercase">
                        <tr>
                            <th className="p-2 text-left">Channel</th>
                            <th className="p-2 text-right">Subscribers</th>
                            <th className="p-2 text-left">Last scan</th>
                            <th className="p-2 text-center">Monitor</th>
                            <th className="p-2 text-right"></th>
                        </tr>
                    </thead>
                    <tbody>
                        {channels.length === 0 && (
                            <tr><td colSpan={5} className="p-6 text-center text-gray-500">
                                No Telegram channels tracked yet.
                                {authed && " Add one above to start."}
                            </td></tr>
                        )}
                        {channels.map(c => (
                            <React.Fragment key={c.id}>
                            <tr className="border-t border-gray-800 hover:bg-gray-900/50">
                                <td className="p-2 text-xs max-w-md">
                                    <button
                                        onClick={() => setExpanded(expanded === c.id ? null : c.id)}
                                        title="Click to expand / collapse messages"
                                        className="text-gray-100 font-medium truncate mb-0.5
                                                   text-left block w-full hover:text-brand-400
                                                   flex items-center gap-1.5">
                                        <span className={
                                            "inline-block transition-transform text-gray-500 " +
                                            (expanded === c.id ? "rotate-90" : "")}>
                                            ▸
                                        </span>
                                        <span className="truncate">
                                            {c.tg_title || c.title || c.tg_username}
                                        </span>
                                        {c.tg_is_private ? (
                                            <Pill tone="yellow"
                                                  title="Private — no public @handle; only members can access">
                                                private
                                            </Pill>
                                        ) : (
                                            <Pill tone="emerald"
                                                  title="Public — anyone can resolve by @handle">
                                                public
                                            </Pill>
                                        )}
                                        <ActivityPill
                                            lastMsgDate={c.tg_last_msg_date}
                                            msgCount={c.tg_msg_count} />
                                        {c.tg_verified ? (
                                            <Pill tone="emerald" title="Verified by Telegram"> ✓ </Pill>
                                        ) : null}
                                        {c.tg_scam ? (
                                            <Pill tone="red" title="Flagged as scam by Telegram"> scam </Pill>
                                        ) : null}
                                        {c.tg_kind && c.tg_kind !== "channel" && (
                                            <Pill tone="gray"> {c.tg_kind} </Pill>
                                        )}
                                    </button>
                                    <div className="flex gap-2 items-center text-gray-500 mono">
                                        {c.tg_username ? (
                                            <a href={`https://t.me/${c.tg_username}`}
                                               target="_blank" rel="noreferrer"
                                               className="truncate hover:text-brand-400">
                                                @{c.tg_username}
                                            </a>
                                        ) : (
                                            <span className="text-gray-600 italic">private channel</span>
                                        )}
                                    </div>
                                    {c.tg_about && (
                                        <div className="text-[11px] text-gray-500 mt-1 line-clamp-2"
                                             title={c.tg_about}>
                                            {c.tg_about.slice(0, 140)}
                                            {c.tg_about.length > 140 ? "…" : ""}
                                        </div>
                                    )}
                                </td>
                                <td className="p-2 text-right mono text-xs text-gray-400">
                                    {c.tg_subscribers != null
                                        ? c.tg_subscribers.toLocaleString()
                                        : "—"}
                                </td>
                                <td className="p-2 text-xs text-gray-500 mono">
                                    {c.last_scan || "never"}
                                </td>
                                <td className={"p-2 text-center " +
                                        (pending.has(c.id)
                                            ? "ring-1 ring-cyan-500/50 "
                                              + "bg-cyan-500/10 rounded"
                                            : "")}>
                                    <label className={"inline-flex items-center gap-2 "
                                        + (pending.has(c.id)
                                            ? "cursor-wait" : "cursor-pointer")}>
                                        <span className="relative inline-flex items-center justify-center w-4 h-4">
                                            <input type="checkbox"
                                                   checked={!!c.monitored}
                                                   disabled={pending.has(c.id)}
                                                   onChange={e => onSetMonitor(
                                                       c.id, e.target.checked,
                                                       c.monitor_interval_min || 60)}
                                                   className={"w-4 h-4 accent-cyan-500 "
                                                       + (pending.has(c.id) ? "opacity-40" : "")} />
                                            {pending.has(c.id) && (
                                                <span className="absolute inset-0 flex items-center justify-center
                                                                 text-cyan-400 pointer-events-none">
                                                    <Spinner size={14} />
                                                </span>
                                            )}
                                        </span>
                                        <select
                                            value={c.monitor_interval_min || 60}
                                            disabled={!c.monitored || pending.has(c.id)}
                                            onChange={e => onSetMonitor(
                                                c.id, true, parseInt(e.target.value, 10))}
                                            className="bg-gray-900 border border-gray-700 rounded
                                                       px-1 py-0.5 text-xs disabled:opacity-50">
                                            <option value="15">15m</option>
                                            <option value="30">30m</option>
                                            <option value="60">1h</option>
                                            <option value="120">2h</option>
                                            <option value="360">6h</option>
                                        </select>
                                        {pending.has(c.id) && (
                                            <span className="text-[10px] text-cyan-400 uppercase
                                                             tracking-wide animate-pulse">
                                                saving…
                                            </span>
                                        )}
                                    </label>
                                </td>
                                <td className="p-2 text-right whitespace-nowrap">
                                    <div className="inline-flex items-center gap-0.5 flex-wrap justify-end">
                                        <ScrapeControls
                                            channel={c}
                                            authed={authed}
                                            onScrape={onScrape}
                                            onRescan={onRescan} />
                                        <span className="w-px h-4 bg-gray-800 mx-1" />
                                        {c.tg_is_member === 1 ? (
                                            <IconBtn icon="logout" label="Leave" tone="yellow"
                                                     disabled={!authed}
                                                     onClick={() => onLeave?.(c)} />
                                        ) : (
                                            <IconBtn icon="login" label="Join" tone="emerald"
                                                     disabled={!authed}
                                                     onClick={() => onJoin?.(c)} />
                                        )}
                                        <IconBtn icon="link" label="Chain" tone="cyan"
                                                 disabled={!authed || chainBusy || !c.tg_username}
                                                 onClick={() => followChain(c.tg_username)} />
                                        {(c.tg_kind === "megagroup" || c.tg_kind === "group") && (
                                            <IconBtn icon="users" label="Members" tone="cyan"
                                                     disabled={!authed}
                                                     onClick={() => openMembers(c)} />
                                        )}
                                        <span className="w-px h-4 bg-gray-800 mx-1" />
                                        <IconBtn icon="file" label="CSV"
                                                 href={`/api/telegram/channels/${c.id}/export.csv`} />
                                        <IconBtn icon="file" label="JSON"
                                                 href={`/api/telegram/channels/${c.id}/export.json`} />
                                        <IconBtn icon="archive" label="ZIP" tone="cyan"
                                                 href={`/api/telegram/channels/${c.id}/export.zip`} />
                                        <span className="w-px h-4 bg-gray-800 mx-1" />
                                        <IconBtn icon="trash" tone="red"
                                                 onClick={() => {
                                                     if (window.confirm(
                                                         `Delete @${c.tg_username} and all its messages / findings?`)) {
                                                         onDelete(c.id);
                                                     }
                                                 }} label="Delete" />
                                    </div>
                                </td>
                            </tr>
                            {expanded === c.id && (
                                <tr className="bg-gray-900/70">
                                    <td colSpan={5}>
                                        <TgChannelDetails urlId={c.id} />
                                        <TgMessageList urlId={c.id} onToast={onToast} />
                                    </td>
                                </tr>
                            )}
                            </React.Fragment>
                        ))}
                    </tbody>
                </table>
            </div>

            <TelegramAuthModal
                open={authOpen}
                onClose={() => setAuthOpen(false)}
                onSubmit={authHandler}
                busy={authBusy}
            />
            {membersFor && (
                <div onClick={() => setMembersFor(null)}
                     className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
                    <div onClick={e => e.stopPropagation()}
                         className="bg-gray-900 border border-gray-700 rounded
                                    max-w-3xl w-full max-h-[85vh] flex flex-col">
                        <div className="flex items-center justify-between p-3 border-b border-gray-800">
                            <h3 className="text-sm font-semibold text-gray-100">
                                Members — @{membersFor.title}
                                {membersData?.count != null && (
                                    <span className="ml-2 text-xs text-gray-500">
                                        ({membersData.count} shown)
                                    </span>
                                )}
                            </h3>
                            <button onClick={() => setMembersFor(null)}
                                    className="text-gray-500 hover:text-gray-200">
                                <Icon name="close" />
                            </button>
                        </div>
                        <div className="overflow-auto flex-1 p-3 text-xs">
                            {membersBusy && <div className="text-gray-500">Loading…</div>}
                            {membersData?.error && (
                                <div className="text-red-400 mono">{membersData.error}</div>
                            )}
                            {membersData?.members?.length === 0 && !membersBusy && (
                                <div className="text-gray-500 italic">No visible members.</div>
                            )}
                            {Array.isArray(membersData?.members) && membersData.members.length > 0 && (
                                <table className="w-full">
                                    <thead>
                                        <tr className="text-left text-gray-500 uppercase text-[10px] border-b border-gray-800">
                                            <th className="p-1.5">Name</th>
                                            <th className="p-1.5">Handle</th>
                                            <th className="p-1.5">Status</th>
                                            <th className="p-1.5">Flags</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {membersData.members.map(m => (
                                            <tr key={m.user_id}
                                                className="border-b border-gray-800/50">
                                                <td className="p-1.5 text-gray-200">
                                                    {[m.first_name, m.last_name].filter(Boolean).join(" ")
                                                     || <span className="text-gray-600 italic">—</span>}
                                                </td>
                                                <td className="p-1.5 mono">
                                                    {m.username
                                                        ? <a href={`https://t.me/${m.username}`}
                                                             target="_blank" rel="noreferrer"
                                                             className="text-emerald-400 hover:underline">
                                                              @{m.username}
                                                          </a>
                                                        : <span className="text-gray-600">—</span>}
                                                </td>
                                                <td className="p-1.5 text-gray-400">{m.status || "—"}</td>
                                                <td className="p-1.5 flex gap-1 flex-wrap">
                                                    {m.bot && <Pill tone="blue">bot</Pill>}
                                                    {m.verified && <Pill tone="emerald">✓</Pill>}
                                                    {m.scam && <Pill tone="red">scam</Pill>}
                                                    {m.premium && <Pill tone="yellow">prem</Pill>}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            )}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

function RulesPanel({ rules, onRefresh, onDeleteMany, onAddCustom, addingCustom }) {
    const [q, setQ] = useState("");
    const [selected, setSelected] = useState(new Set());
    const [customOpen, setCustomOpen] = useState(true);
    const [customName, setCustomName] = useState("");
    const [customBody, setCustomBody] = useState("");
    const filtered = !q ? rules : rules.filter(r => {
        const hay = (r.name + " " + r.description + " "
                     + r.strings.map(s => s.value).join(" ")).toLowerCase();
        return hay.includes(q.toLowerCase());
    });
    const deletable = filtered.filter(r => r.deletable);
    const deletableNames = deletable.map(r => r.name);
    const allSelected = deletableNames.length > 0
        && deletableNames.every(n => selected.has(n));
    const someSelected = selected.size > 0 && !allSelected;

    const toggleAll = () => {
        if (allSelected || someSelected) setSelected(new Set());
        else setSelected(new Set(deletableNames));
    };
    const toggleOne = (name, canDelete) => {
        if (!canDelete) return;
        setSelected(prev => {
            const next = new Set(prev);
            if (next.has(name)) next.delete(name);
            else next.add(name);
            return next;
        });
    };
    const bulkDelete = () => {
        if (selected.size === 0) return;
        if (!window.confirm(
            `Delete ${selected.size} selected rule(s)? `
            + "Keyword rules remove their keywords; custom YARA files are deleted.")) return;
        onDeleteMany(Array.from(selected));
        setSelected(new Set());
    };

    const submitCustom = async (e) => {
        e.preventDefault();
        if (!customName.trim() || !customBody.trim()) return;
        const ok = await onAddCustom(customName.trim(), customBody);
        if (ok) {
            setCustomName("");
            setCustomBody("");
            setCustomOpen(false);
        }
    };

    const scoreTone = s =>
        s >= 100 ? "text-red-400" : s >= 60 ? "text-orange-400" :
        s >= 30 ? "text-yellow-400" : "text-blue-400";
    return (
        <div className="space-y-4">
            <p className="text-xs text-gray-500 leading-relaxed">
                <span className="text-gray-400">Keywords tab</span> adds simple
                strings (auto-generated into <code className="mono">user.yar</code>).
                Use <span className="text-gray-400">Add custom YARA</span> below for
                full rules with conditions, regex, and meta scores. Shipped rules in{" "}
                <code className="mono">keywords.yar</code> /{" "}
                <code className="mono">categories.yar</code> are read-only.
            </p>

            <div className="bg-gray-900/60 border border-brand-500/20 rounded-lg p-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="text-sm font-medium text-gray-100 flex items-center gap-2">
                        <Icon name="plus" size={14} className="text-brand-300" />
                        Add custom YARA rule
                    </h3>
                    <button type="button"
                            onClick={() => setCustomOpen(v => !v)}
                            className="text-xs text-gray-500 hover:text-gray-300">
                        {customOpen ? "Collapse" : "Expand"}
                    </button>
                </div>
                <p className="text-xs text-gray-500">
                    Paste a full <code className="mono">.yar</code> rule — saved to{" "}
                    <code className="mono">yara-private/</code> after YARA compile validation
                    (including your other custom rules). Duplicate filenames or rule names
                    are rejected.
                </p>
                {customOpen && (
                    <form onSubmit={submitCustom} className="space-y-3 border-t border-gray-800 pt-3">
                        <label className="block text-xs text-gray-400">
                            Filename (without path)
                            <input value={customName}
                                   onChange={e => setCustomName(e.target.value)}
                                   placeholder="acme_corp_leaks"
                                   pattern="[A-Za-z0-9][A-Za-z0-9_-]*"
                                   required
                                   className="mt-1 w-full bg-gray-950 border border-gray-700
                                              rounded px-3 py-2 text-sm mono" />
                        </label>
                        <label className="block text-xs text-gray-400">
                            YARA source
                            <textarea value={customBody}
                                      onChange={e => setCustomBody(e.target.value)}
                                      required rows={12}
                                      placeholder={`rule acme_leak
{
    meta:
        description = "Acme Corp mentions"
        score = 80
    strings:
        $a = "acme corp" nocase
        $b = "acme.internal" nocase
    condition:
        any of them
}`}
                                      className="mt-1 w-full bg-gray-950 border border-gray-700
                                                 rounded px-3 py-2 text-sm mono resize-y" />
                        </label>
                        <button type="submit"
                                disabled={addingCustom || !customName.trim() || !customBody.trim()}
                                className="px-4 py-2 rounded bg-brand-500 text-gray-50 font-semibold
                                           hover:bg-brand-400 disabled:bg-gray-700 disabled:text-gray-500
                                           disabled:cursor-not-allowed
                                           flex items-center gap-2">
                            {addingCustom ? <Spinner /> : <Icon name="plus" />}
                            Save rule
                        </button>
                    </form>
                )}
            </div>

            <div className="flex flex-wrap items-center gap-3">
                <input
                    value={q}
                    onChange={e => setQ(e.target.value)}
                    placeholder="Filter by rule name, description, or keyword…"
                    className="flex-1 bg-gray-900 border border-gray-700 rounded
                               px-3 py-2 text-sm mono focus:outline-none focus:border-brand-500"
                />
                <button onClick={onRefresh}
                        className="px-3 py-2 rounded bg-gray-800 text-sm
                                   hover:bg-gray-700 flex items-center gap-1.5">
                    <Icon name="refresh" size={14} /> Reload
                </button>
                {selected.size > 0 && (
                    <>
                        <span className="text-xs text-gray-400">{selected.size} selected</span>
                        <button onClick={bulkDelete}
                                className="px-3 py-2 rounded bg-red-900/60 border border-red-800
                                           text-red-200 text-sm hover:bg-red-800/60 flex items-center gap-1.5">
                            <Icon name="trash" size={14} /> Delete selected
                        </button>
                        <button onClick={() => setSelected(new Set())}
                                className="text-xs text-gray-500 hover:text-gray-200">
                            clear
                        </button>
                    </>
                )}
                <span className="text-xs text-gray-500 ml-auto">
                    {filtered.length} of {rules.length} rules
                    {deletable.length < filtered.length && (
                        <span className="text-gray-600"> · curated rules cannot be deleted here</span>
                    )}
                </span>
            </div>

            {deletable.length > 0 && (
                <label className="flex items-center gap-2 text-xs text-gray-400 px-1">
                    <input type="checkbox"
                           checked={allSelected}
                           ref={el => { if (el) el.indeterminate = someSelected; }}
                           onChange={toggleAll}
                           className="w-4 h-4 accent-brand-500" />
                    Select all deletable rules ({deletable.length})
                </label>
            )}

            <div className="grid md:grid-cols-2 gap-3">
                {filtered.length === 0 && (
                    <div className="col-span-2 p-8 text-center text-gray-500">
                        No rules loaded. Check {"/app/yara/"} in the container.
                    </div>
                )}
                {filtered.map(r => (
                    <div key={r.name}
                         className={"bg-gray-800/50 border rounded p-4 "
                             + (selected.has(r.name)
                                 ? "border-brand-500/60 ring-1 ring-brand-500/30"
                                 : "border-gray-700")}>
                        <div className="flex items-start justify-between gap-2 mb-2">
                            <div className="flex items-start gap-2 min-w-0">
                                {r.deletable ? (
                                    <input type="checkbox"
                                           checked={selected.has(r.name)}
                                           onChange={() => toggleOne(r.name, true)}
                                           className="mt-1 w-4 h-4 accent-brand-500 flex-shrink-0" />
                                ) : (
                                    <span className="mt-1 w-4 flex-shrink-0" title="Shipped rule — not deletable from UI" />
                                )}
                                <div className="min-w-0">
                                <div className="font-semibold mono text-sm truncate">{r.name}</div>
                                <div className="text-xs text-gray-400">{r.description}</div>
                                </div>
                            </div>
                            <div className="text-right flex-shrink-0">
                                <div className={"text-lg font-bold mono " + scoreTone(r.score)}>
                                    {r.score}
                                </div>
                                <div className="text-[10px] text-gray-500 uppercase">score</div>
                            </div>
                        </div>
                        <div className="text-[10px] text-gray-500 mono mb-2">
                            {r.file}
                            {r.custom && (
                                <span className="ml-2 text-brand-400">custom</span>
                            )}
                        </div>
                        <div className="flex flex-wrap gap-1">
                            {r.strings.map((s, i) => (
                                <span key={i}
                                      title={"$" + s.name}
                                      className="px-1.5 py-0.5 text-[11px] mono rounded
                                                 bg-gray-900 border border-gray-700
                                                 text-gray-300">
                                    {s.value}
                                </span>
                            ))}
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}

// ─── Spinner ─────────────────────────────────────────────────────────────────

function Spinner({ size = 16 }) {
    // size is in pixels via inline style — dynamic values would otherwise
    // not survive Tailwind's class-name purge.
    return (
        <svg className="animate-spin" width={size} height={size}
             viewBox="0 0 24 24" fill="none">
            <circle cx="12" cy="12" r="10" stroke="currentColor"
                    strokeWidth="3" className="opacity-25" />
            <path d="M22 12a10 10 0 0 1-10 10" stroke="currentColor"
                  strokeWidth="3" strokeLinecap="round" />
        </svg>
    );
}

// ─── Keywords panel ─────────────────────────────────────────────────────────

function KeywordsPanel({ keywords, onAdd, onAddBulk, onDelete, onRefresh, onGoRules, adding }) {
    const [kw, setKw] = useState("");
    const [sev, setSev] = useState("high");

    // Parse the input as one-or-many keywords. Split on newline, tab,
    // comma, semicolon, or pipe. Non-ASCII letters inside tokens are kept.
    const tokens = kw
        .split(/[\n\r\t,;|]+/)
        .map(s => s.trim())
        .filter(Boolean);
    const isBulk = tokens.length > 1;

    const submit = e => {
        e.preventDefault();
        if (tokens.length === 0) return;
        if (isBulk) {
            onAddBulk(tokens, sev);
        } else {
            onAdd(tokens[0], sev);
        }
        setKw("");
    };

    const grouped = { critical: [], high: [], medium: [], low: [] };
    for (const k of keywords) {
        (grouped[k.severity] || grouped.medium).push(k);
    }

    return (
        <div className="space-y-4">
            <div className="text-xs text-gray-500 leading-relaxed border border-gray-800
                            bg-gray-900/40 rounded px-3 py-2">
                Add simple search strings here — they become auto-generated rules in{" "}
                <code className="mono text-gray-400">user.yar</code>.
                {onGoRules && (
                    <>
                        {" "}For full YARA (regex, conditions, custom scores), use the{" "}
                        <button type="button" onClick={onGoRules}
                                className="text-brand-300 hover:text-brand-200 underline-offset-2 hover:underline">
                            Rules tab
                        </button>.
                    </>
                )}
            </div>

            <form onSubmit={submit}
                  className="bg-gray-900/60 border border-gray-800 rounded-lg p-4 space-y-3">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                    <label className="text-xs text-gray-400 uppercase tracking-wide">
                        Keywords
                    </label>
                    <span className="text-xs text-gray-500">
                        {keywords.length} saved · active on next scan
                    </span>
                </div>

                <textarea
                    value={kw}
                    onChange={e => setKw(e.target.value)}
                    placeholder={"Add one keyword — or paste many at once.\n"
                        + "e.g. ransomware, combo list, leak, breach\n"
                        + "     or one per line."}
                    rows={kw.includes("\n") ? 5 : 3}
                    className="w-full bg-gray-950 border border-gray-700
                               rounded px-3 py-2 text-sm mono resize-y min-h-[4.5rem]
                               focus:outline-none focus:border-brand-500"
                />

                <div className="text-[11px] text-gray-500 leading-relaxed">
                    <span className="text-gray-400">Tip:</span> paste one per line{" "}
                    <span className="text-gray-600">or</span> separate with{" "}
                    <span className="mono text-gray-300">, ; | tab</span>. Case-insensitive
                    where applicable.
                </div>

                {isBulk && (
                    <div className="text-[11px] text-emerald-400">
                        {tokens.length} keywords will be added at severity {sev}
                    </div>
                )}

                <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-gray-800">
                    <select value={sev}
                            onChange={e => setSev(e.target.value)}
                            aria-label="Severity"
                            className="bg-gray-950 border border-gray-700 rounded
                                       px-3 py-2 text-sm">
                        <option value="critical">Critical (100)</option>
                        <option value="high">High (70)</option>
                        <option value="medium">Medium (40)</option>
                        <option value="low">Low (15)</option>
                    </select>
                    <button type="submit"
                            disabled={adding || !kw.trim()}
                            className="px-4 py-2 rounded bg-brand-500 text-gray-50
                                       font-semibold hover:bg-brand-400
                                       disabled:bg-gray-700 disabled:text-gray-500
                                       disabled:cursor-not-allowed
                                       flex items-center gap-2">
                        {adding ? <Spinner /> : <Icon name="plus" />}
                        {isBulk ? `Add ${tokens.length}` : "Add keyword"}
                    </button>
                    <button type="button" onClick={onRefresh}
                            title="Reload keyword list"
                            className="px-3 py-2 rounded bg-gray-800 text-sm text-gray-300
                                       hover:bg-gray-700 flex items-center gap-1.5">
                        <Icon name="refresh" size={14} /> Reload
                    </button>
                    <div className="flex items-center gap-2 sm:ml-auto">
                        <a href="/api/keywords/export.json" download
                           title="Export keywords as JSON"
                           className="px-3 py-2 rounded bg-gray-800 text-sm
                                      hover:bg-gray-700 flex items-center gap-1 text-gray-300">
                            <Icon name="download" size={14} /> JSON
                        </a>
                        <a href="/api/keywords/export.csv" download
                           title="Export keywords as CSV"
                           className="px-3 py-2 rounded bg-gray-800 text-sm
                                      hover:bg-gray-700 flex items-center gap-1 text-gray-300">
                            <Icon name="download" size={14} /> CSV
                        </a>
                    </div>
                </div>
            </form>

            <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
                {["critical", "high", "medium", "low"].map(sv => (
                    <div key={sv}
                         className="bg-gray-800/50 border border-gray-700 rounded p-3">
                        <div className="flex items-baseline justify-between mb-2">
                            <SevBadge sev={sv} />
                            <span className="text-xs text-gray-500">
                                {grouped[sv].length}
                            </span>
                        </div>
                        <div className="flex flex-wrap gap-1 min-h-[2rem]">
                            {grouped[sv].length === 0 && (
                                <span className="text-xs text-gray-600 italic">
                                    none
                                </span>
                            )}
                            {grouped[sv].map(k => (
                                <span key={k.id}
                                      className="group flex items-center gap-1
                                                 px-2 py-0.5 text-xs mono rounded
                                                 bg-gray-900 border border-gray-700
                                                 text-gray-200">
                                    {k.keyword}
                                    <button
                                        onClick={() => {
                                            if (window.confirm(`Delete "${k.keyword}"?`)) {
                                                onDelete(k.id);
                                            }
                                        }}
                                        title="Remove keyword"
                                        className="text-gray-500 hover:text-red-400">
                                        <Icon name="close" size={12} />
                                    </button>
                                </span>
                            ))}
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}

// ─── App (root) ──────────────────────────────────────────────────────────────

function App() {
    const [activeTab, setActiveTab] = useState("scan");
    const [scanning, setScanning] = useState(false);
    const [submitting, setSubmitting] = useState(false);
    const [stats, setStats] = useState({});
    const [logs, setLogs] = useState([]);
    const [logsTruncated, setLogsTruncated] = useState(false);
    const [logsPaused, setLogsPaused] = useState(false);
    const [findings, setFindings] = useState([]);
    const [urls, setUrls] = useState([]);
    const [rules, setRules] = useState([]);
    const [keywords, setKeywords] = useState([]);
    const [addingKeyword, setAddingKeyword] = useState(false);
    const [addingCustomRule, setAddingCustomRule] = useState(false);
    // Telegram tab state — channels are a subset of /api/urls filtered on source.
    const [tgStatus, setTgStatus] = useState(null);
    const [tgChannels, setTgChannels] = useState([]);
    // Set of url_ids currently mid-flight through a monitor toggle. UI uses
    // this to show a spinner + disable the controls so the operator gets
    // immediate feedback on click instead of waiting the full API
    // round-trip before anything visible changes.
    const [monitorPending, setMonitorPending] = useState(new Set());
    const [sevFilter, setSevFilter] = useState("all");
    const [progress, setProgress] = useState({ completed: 0, total: 0 });
    const [scanTimer, setScanTimer] = useState(0);
    const [health, setHealth] = useState(null);
    const [healthReady, setHealthReady] = useState(false);
    const [rechecking, setRechecking] = useState(false);
    const [securityModalOpen, setSecurityModalOpen] = useState(false);
    const [lightbox, setLightbox] = useState(null);
    const [toast, setToast] = useState("");
    const [uiConfig, setUiConfig] = useState(null);
    const [findingsLoading, setFindingsLoading] = useState(false);
    const [hasReport, setHasReport] = useState(false);

    const statusTimer = useRef(null);
    const healthTimer = useRef(null);
    const tickTimer = useRef(null);

    // ─── Data fetches ────────────────────────────────────────────────────────

    const fetchStatus = useCallback(async () => {
        try {
            const { ok, body } = await api("/api/status");
            if (!ok) return false;
            setStats(body.stats || {});
            setProgress(body.progress || { completed: 0, total: 0 });
            if (body.new_logs?.length) {
                setLogs(prev => {
                    const merged = [...prev, ...body.new_logs];
                    if (merged.length > 500) {
                        setLogsTruncated(true);
                        return merged.slice(-500);
                    }
                    return merged;
                });
            }
            if (body.elapsed_seconds != null) setScanTimer(body.elapsed_seconds);
            return body.running;
        } catch {
            return false;
        }
    }, []);

    const [findingsPageSize, setFindingsPageSize] = useState(100);
    const [findingsHasMore, setFindingsHasMore] = useState(false);
    const [findingsCursor, setFindingsCursor] = useState(null);

    const fetchFindings = useCallback(async (opts = {}) => {
        setFindingsLoading(true);
        try {
            const limit = findingsPageSize;
            const cursor = opts.append ? findingsCursor : null;
            const params = new URLSearchParams({ limit: String(limit) });
            if (cursor) params.set("before_id", String(cursor));
            const { body } = await api(`/api/findings?${params}`);
            const list = Array.isArray(body?.findings) ? body.findings
                       : Array.isArray(body) ? body : [];
            setFindings(prev => opts.append ? [...prev, ...list] : list);
            setFindingsHasMore(!!body?.has_more);
            setFindingsCursor(body?.next_cursor ?? null);
        } finally {
            setFindingsLoading(false);
        }
    }, [findingsPageSize, findingsCursor]);

    const [urlsTotal, setUrlsTotal] = useState(0);
    const [urlsHasMore, setUrlsHasMore] = useState(false);
    const [urlsOffset, setUrlsOffset] = useState(0);
    const URLS_PAGE = 200;

    const fetchUrls = useCallback(async (opts = {}) => {
        const offset = opts.append ? urlsOffset + URLS_PAGE : 0;
        const { body } = await api(`/api/urls?limit=${URLS_PAGE}&offset=${offset}`);
        // Back-compat: older server returned a plain array.
        const list = Array.isArray(body) ? body
                   : Array.isArray(body?.urls) ? body.urls : [];
        setUrls(prev => opts.append ? [...prev, ...list] : list);
        setUrlsTotal(body?.total ?? list.length);
        setUrlsHasMore(!!body?.has_more);
        setUrlsOffset(offset);
    }, [urlsOffset]);

    const fetchRules = useCallback(async () => {
        const { body } = await api("/api/rules");
        if (Array.isArray(body)) setRules(body);
    }, []);

    const handleDeleteManyRules = async (names) => {
        if (!Array.isArray(names) || names.length === 0) return;
        const { ok, body } = await api("/api/rules/delete", {
            method: "POST",
            body: JSON.stringify({ names }),
        });
        if (ok) {
            await fetchRules();
            await fetchKeywords();
            const parts = [];
            if (body.removed_keywords) parts.push(`${body.removed_keywords} keyword(s)`);
            if (body.removed_custom_files) parts.push(`${body.removed_custom_files} file(s)`);
            setToast(parts.length ? `Deleted ${parts.join(", ")}` : "Rules deleted");
        } else {
            setToast(body.error || "Delete failed");
        }
    };

    const handleAddCustomRule = async (filename, content) => {
        setAddingCustomRule(true);
        try {
            const { ok, body } = await api("/api/yara/custom", {
                method: "POST",
                body: JSON.stringify({ filename, content }),
            });
            if (ok) {
                await fetchRules();
                setToast(`Custom rule saved: ${body.filename}`);
                return true;
            }
            setToast(body.error || "YARA validation/save failed");
            return false;
        } finally {
            setAddingCustomRule(false);
        }
    };

    const fetchKeywords = useCallback(async () => {
        const { body } = await api("/api/keywords");
        if (Array.isArray(body)) setKeywords(body);
    }, []);

    const fetchTgStatus = useCallback(async () => {
        const { body } = await api("/api/telegram/status");
        setTgStatus(body);
    }, []);

    const fetchTgChannels = useCallback(async () => {
        // Reuse /api/urls with the source filter on the server side.
        const { body } = await api("/api/urls?source=telegram&limit=500");
        const list = Array.isArray(body) ? body
                   : Array.isArray(body?.urls) ? body.urls : [];
        setTgChannels(list);
    }, []);

    const fetchHealth = useCallback(async (fresh = false) => {
        try {
            const { ok, body } = await api("/api/health" + (fresh ? "?fresh=1" : ""));
            if (ok) {
                const merged = { ...body, secure: computeSecure(body) };
                setHealth(merged);
                setHealthReady(true);
                return merged;
            }
        } catch { /* ignore */ }
        return null;
    }, []);

    const fetchQuickHealth = useCallback(async () => {
        try {
            const { ok, body } = await api("/api/health/quick");
            if (!ok) return null;
            let merged;
            setHealth(prev => {
                // Quick poll only refreshes liveness; need a full check first.
                if (!prev?.ip_leak || !prev?.dns) return prev;
                const keepTor = prev?.tor?.detail?.includes?.("IsTor");
                merged = {
                    ...prev,
                    tor: keepTor ? prev.tor : body.tor,
                    vpn: body.vpn,
                    checked_at: body.checked_at,
                };
                merged.secure = computeSecure(merged);
                return merged;
            });
            return merged || body;
        } catch {
            return null;
        }
    }, []);

    const fetchUiConfig = useCallback(async () => {
        try {
            const { ok, body } = await api("/api/ui-config");
            if (ok) {
                setUiConfig(body);
                setHasReport(!!body.has_report);
            }
        } catch { /* ignore */ }
    }, []);

    // ─── Mount: initial load + health poll ───────────────────────────────────

    useEffect(() => {
        fetchStatus();
        fetchHealth();
        fetchUiConfig();
        fetchTgStatus();
        healthTimer.current = setInterval(() => fetchQuickHealth(), 30000);
        const fullHealthTimer = setInterval(() => fetchHealth(true), 90000);
        const tgTimer = setInterval(() => fetchTgStatus(), 15000);
        return () => {
            clearInterval(healthTimer.current);
            clearInterval(fullHealthTimer);
            clearInterval(tgTimer);
        };
    }, [fetchStatus, fetchHealth, fetchQuickHealth, fetchUiConfig, fetchTgStatus]);

    // ─── Tab-change side effects ─────────────────────────────────────────────

    useEffect(() => {
        if (activeTab === "findings") fetchFindings();
        else if (activeTab === "urls") fetchUrls();
        else if (activeTab === "rules") fetchRules();
        else if (activeTab === "keywords") fetchKeywords();
        else if (activeTab === "telegram") {
            fetchTgStatus();
            fetchTgChannels();
        }
    }, [activeTab, fetchFindings, fetchUrls, fetchRules, fetchKeywords,
        fetchTgStatus, fetchTgChannels]);

    // ─── Scan polling lifecycle ──────────────────────────────────────────────

    const stopPolling = () => {
        if (statusTimer.current) { clearInterval(statusTimer.current); statusTimer.current = null; }
        if (tickTimer.current) { clearInterval(tickTimer.current); tickTimer.current = null; }
    };

    const startPolling = () => {
        stopPolling();
        statusTimer.current = setInterval(async () => {
            const running = await fetchStatus();
            if (!running) {
                stopPolling();
                setScanning(false);
                setToast("Scan complete");
                fetchFindings();
                fetchUrls();
            }
            // Mid-scan watchdog
            const h = await fetchQuickHealth();
            if (h && (!h.tor?.ok || !h.vpn?.ok)) {
                setToast("Security lost — scan aborted");
                api("/api/stop", { method: "POST" });
            }
        }, 2000);
        tickTimer.current = setInterval(() => setScanTimer(t => t + 1), 1000);
    };

    useEffect(() => () => stopPolling(), []);

    // ─── Keyboard shortcuts ─────────────────────────────────────────────────
    const [shortcutsOpen, setShortcutsOpen] = useState(false);
    // `g` pending — track the timestamp of the last 'g' press; any key within
    // 1.2s that matches a tab alias switches tabs. Classic Gmail pattern.
    const gPendingRef = useRef(0);
    useEffect(() => {
        const handler = (e) => {
            // Ignore when typing into inputs/textareas/contenteditable.
            const tgt = e.target;
            const tag = (tgt?.tagName || "").toLowerCase();
            const editable = tag === "input" || tag === "textarea"
                            || tgt?.isContentEditable;
            if (e.key === "Escape") {
                if (lightbox) setLightbox(null);
                else if (shortcutsOpen) setShortcutsOpen(false);
                else if (securityModalOpen) setSecurityModalOpen(false);
                return;
            }
            if (editable) return;

            // "?" opens help, "/" focuses the first search input on the page.
            if (e.key === "?" && !e.ctrlKey && !e.metaKey) {
                e.preventDefault(); setShortcutsOpen(true); return;
            }
            if (e.key === "/" && !e.ctrlKey && !e.metaKey) {
                e.preventDefault();
                // Focus whatever input looks like "search" — heuristic is
                // enough for a single-page app.
                const el = document.querySelector(
                    "input[placeholder*='search' i], input[placeholder*='filter' i]");
                if (el) el.focus();
                return;
            }

            // g-prefixed tab jumps.
            const now = Date.now();
            if (e.key === "g" && !e.ctrlKey && !e.metaKey && !e.altKey) {
                gPendingRef.current = now; return;
            }
            if (now - gPendingRef.current < 1200) {
                const jumps = { s: "scan", f: "findings", u: "urls",
                                t: "telegram", k: "keywords", r: "rules" };
                const tab = jumps[e.key];
                if (tab) {
                    e.preventDefault();
                    setActiveTab(tab);
                    gPendingRef.current = 0;
                }
            }
        };
        window.addEventListener("keydown", handler);
        return () => window.removeEventListener("keydown", handler);
    }, [lightbox, shortcutsOpen, securityModalOpen]);

    // ─── Actions ─────────────────────────────────────────────────────────────

    const handleStart = async (targets, depth) => {
        // Instant feedback: flip submitting immediately so the button
        // shows a spinner while the server does its (slow) fresh health
        // check + spawns the scan thread.
        setSubmitting(true);
        setLogs([]);
        setProgress({ completed: 0, total: targets.length });
        setScanTimer(0);

        try {
            const { ok, status, body } = await api("/api/scan", {
                method: "POST",
                body: JSON.stringify({ urls: targets, depth }),
            });
            if (!ok) {
                if (status === 403 && body.detail) {
                    setHealth(body.detail);
                    setSecurityModalOpen(true);
                }
                if (status === 400 && body.details) {
                    const msg = body.details.map(d => d.error).join("; ");
                    setToast(`${body.error}: ${msg}`);
                    return;
                }
                setToast(body.error || `Scan failed (${status})`);
                return;
            }
            setScanning(true);
            startPolling();
        } catch (err) {
            // Network error / fetch threw — show a toast, leave scanning false.
            setToast("Network error: could not start scan");
        } finally {
            // Always clear the spinner so the button never wedges, even if
            // the fetch itself threw mid-flight.
            setSubmitting(false);
        }
    };

    const handleStop = async () => {
        await api("/api/stop", { method: "POST" });
        setToast("Stop signal sent");
    };

    const handleRecheckHealth = async () => {
        setRechecking(true);
        await fetchHealth(true);
        setRechecking(false);
    };

    const handleGenerateReport = async () => {
        const { ok, body } = await api("/api/report", { method: "POST" });
        if (ok && body.report) {
            setHasReport(true);
            setToast("Report generated: " + body.report.split("/").pop());
        } else {
            setToast(body?.error || "Report generation failed");
        }
    };

    const handleDeleteFinding = async (id) => {
        const { ok } = await api(`/api/findings/${id}`, { method: "DELETE" });
        if (ok) {
            setFindings(prev => prev.filter(f => f.id !== id));
            setToast("Finding deleted");
        } else {
            setToast("Delete failed");
        }
    };

    const handleDeleteManyFindings = async (ids) => {
        if (!Array.isArray(ids) || ids.length === 0) return;
        let deleted = 0;
        for (const id of ids) {
            const { ok } = await api(`/api/findings/${id}`, { method: "DELETE" });
            if (ok) deleted += 1;
        }
        await fetchFindings();
        setToast(`Deleted ${deleted} finding(s)`);
    };

    const handleAddKeyword = async (keyword, severity) => {
        setAddingKeyword(true);
        try {
            const { ok, status, body } = await api("/api/keywords", {
                method: "POST",
                body: JSON.stringify({ keyword, severity }),
            });
            if (ok) {
                await fetchKeywords();
                setToast(`Added "${keyword}" (${severity})`);
            } else if (status === 409) {
                setToast("Keyword already exists");
            } else {
                setToast(body.error || "Failed to add keyword");
            }
        } catch (err) {
            setToast("Network error: could not add keyword");
        } finally {
            // Always clear the busy flag so the Add button doesn't wedge
            // if the fetch itself throws.
            setAddingKeyword(false);
        }
    };

    const handleAddKeywordsBulk = async (keywords, severity) => {
        setAddingKeyword(true);
        try {
            const { ok, body } = await api("/api/keywords", {
                method: "POST",
                body: JSON.stringify({ keywords, severity }),
            });
            if (ok) {
                await fetchKeywords();
                const parts = [`${body.added} added`];
                if (body.skipped) parts.push(`${body.skipped} skipped`);
                if (body.errors) parts.push(`${body.errors} invalid`);
                setToast(parts.join(", "));
            } else {
                setToast(body.error || "Bulk add failed");
            }
        } catch (err) {
            setToast("Network error: bulk add");
        } finally {
            setAddingKeyword(false);
        }
    };

    const handleDeleteKeyword = async (id) => {
        const { ok } = await api(`/api/keywords/${id}`, { method: "DELETE" });
        if (ok) {
            setKeywords(prev => prev.filter(k => k.id !== id));
            setToast("Keyword removed");
        } else {
            setToast("Delete failed");
        }
    };

    const handleSetMonitor = async (urlId, enabled, intervalMin) => {
        // Optimistic UI: flip the checkbox + interval locally the instant
        // the operator clicks, so the change is visible during the API
        // round-trip. On failure we revert and surface a toast — this is
        // safer than leaving the UI in a "what just happened?" limbo, and
        // cheap because the server is authoritative on the next fetch.
        const patch = (u) => u.id === urlId
            ? { ...u, monitored: enabled ? 1 : 0,
                monitor_interval_min: intervalMin }
            : u;
        const prevUrls = urls;
        const prevTg = tgChannels;
        setUrls(prev => prev.map(patch));
        setTgChannels(prev => prev.map(patch));
        setMonitorPending(prev => {
            const next = new Set(prev); next.add(urlId); return next;
        });
        try {
            const { ok } = await api(`/api/urls/${urlId}/monitor`, {
                method: "PATCH",
                body: JSON.stringify({ enabled, interval_min: intervalMin }),
            });
            if (ok) {
                // Refetch to pick up server-computed `next_check_at`, which
                // the optimistic patch can't know.
                await fetchUrls();
                setToast(enabled
                    ? `Monitoring on (every ${intervalMin}m, randomized)`
                    : "Monitoring off");
            } else {
                setUrls(prevUrls);
                setTgChannels(prevTg);
                setToast("Failed to update monitor");
            }
        } finally {
            setMonitorPending(prev => {
                const next = new Set(prev); next.delete(urlId); return next;
            });
        }
    };

    const handleImportTargets = async () => {
        const { ok, body, status } = await api("/api/targets-file");
        if (ok && Array.isArray(body.urls)) {
            setToast(body.urls.length > 0
                ? `Imported ${body.urls.length} URL(s) from targets.txt`
                : "targets.txt is empty");
            return body.urls;
        }
        setToast(status === 404 ? "targets.txt not found" : "Import failed");
        return [];
    };

    const handleBulkMonitor = async (ids, enabled, intervalMin) => {
        // Same optimistic pattern as single-URL toggle — mark every
        // affected id pending so each row shows its own spinner, then
        // apply the optimistic checkbox state in one pass.
        const idSet = new Set(ids);
        const patch = (u) => idSet.has(u.id)
            ? { ...u, monitored: enabled ? 1 : 0,
                monitor_interval_min: intervalMin }
            : u;
        const prevUrls = urls;
        const prevTg = tgChannels;
        setUrls(prev => prev.map(patch));
        setTgChannels(prev => prev.map(patch));
        setMonitorPending(prev => {
            const next = new Set(prev);
            for (const id of ids) next.add(id);
            return next;
        });
        try {
            const { ok, body } = await api("/api/urls/monitor", {
                method: "PATCH",
                body: JSON.stringify({
                    ids, enabled, interval_min: intervalMin,
                }),
            });
            if (ok) {
                await fetchUrls();
                setToast(`${body.updated} URL(s) ${enabled ? "monitored" : "unmonitored"}`);
            } else {
                setUrls(prevUrls);
                setTgChannels(prevTg);
                setToast("Bulk monitor failed");
            }
        } finally {
            setMonitorPending(prev => {
                const next = new Set(prev);
                for (const id of ids) next.delete(id);
                return next;
            });
        }
    };

    const handleDeleteUrl = async (urlId) => {
        const { ok } = await api(`/api/urls/${urlId}`, { method: "DELETE" });
        if (ok) {
            setUrls(prev => prev.filter(u => u.id !== urlId));
            setTgChannels(prev => prev.filter(u => u.id !== urlId));
            setToast("URL deleted (cascade)");
        } else {
            setToast("Delete failed");
        }
    };

    const handleDeleteManyUrls = async (ids) => {
        if (!Array.isArray(ids) || ids.length === 0) return;
        const idSet = new Set(ids);
        let deleted = 0;
        for (const id of ids) {
            const { ok } = await api(`/api/urls/${id}`, { method: "DELETE" });
            if (ok) deleted += 1;
        }
        setUrls(prev => prev.filter(u => !idSet.has(u.id)));
        setTgChannels(prev => prev.filter(u => !idSet.has(u.id)));
        setToast(`Deleted ${deleted} URL(s)`);
    };

    // ── Telegram handlers ─────────────────────────────────────────────────
    const handleTgAuth = async (step, body) => {
        const path = step === "start"
            ? "/api/telegram/auth/start"
            : "/api/telegram/auth/confirm";
        return await api(path, {
            method: "POST",
            body: JSON.stringify(body),
        });
    };

    const handleTgLogout = async () => {
        if (!window.confirm("Disconnect Telegram? You'll need to re-auth to resume scraping.")) return;
        await api("/api/telegram/auth/logout", { method: "POST" });
        setToast("Telegram session removed");
        fetchTgStatus();
    };

    const handleTgAddChannel = async (identifier) => {
        const { ok, body } = await api("/api/telegram/channels", {
            method: "POST",
            body: JSON.stringify({ identifier }),
        });
        if (ok) {
            setToast(`Added @${body.username} (${body.subscribers || "?"} subs)`);
            fetchTgChannels();
            return true;
        }
        setToast(body.error || "Add channel failed");
        return false;
    };

    const handleTgScrape = async (urlId, size, deep) => {
        const sizeLabel = size === "all" ? "all" : `up to ${size}`;
        setToast(deep
            ? `Deep scrape (${sizeLabel}) + rescan… this takes a while`
            : `Scraping ${sizeLabel} messages…`);
        const { ok, body } = await api(
            `/api/telegram/channels/${urlId}/scrape`,
            { method: "POST",
              body: JSON.stringify({ limit: size, deep: !!deep }) });
        if (ok) {
            if (body.warning) {
                setToast(`⚠ ${body.warning}`);
            } else {
                const extra = body.rescan_findings != null
                    ? ` (rescan: +${body.rescan_findings})` : "";
                setToast(`Fetched ${body.fetched} msg, ${body.findings} finding(s)${extra}`);
            }
            fetchTgChannels();
            fetchFindings();
        } else {
            setToast(body.error || "Scrape failed");
        }
    };

    const handleTgJoin = async (channel) => {
        const name = channel.tg_username || channel.title || `#${channel.id}`;
        if (!window.confirm(
            `Join @${name} with your Telegram account?\n\n`
            + `This persists on your account — the channel will appear in your `
            + `chat list and other admins can see you as a member.`)) return;
        setToast(`Joining @${name}…`);
        const { ok, body } = await api(
            `/api/telegram/channels/${channel.id}/join`, { method: "POST" });
        if (ok && body.ok) {
            const suffix = body.pending_approval ? " (approval requested)"
                         : body.joined_via === "already_member" ? " (already member)"
                         : "";
            setToast(`Joined @${name}${suffix}`);
            fetchTgChannels();
        } else {
            setToast(`Join failed: ${body?.error || "unknown"}`);
        }
    };

    const handleTgLeave = async (channel) => {
        const name = channel.tg_username || channel.title || `#${channel.id}`;
        if (!window.confirm(`Leave @${name}?`)) return;
        setToast(`Leaving @${name}…`);
        const { ok, body } = await api(
            `/api/telegram/channels/${channel.id}/leave`, { method: "POST" });
        if (ok && body.ok) {
            setToast(`Left @${name}`);
            fetchTgChannels();
        } else {
            setToast(`Leave failed: ${body?.error || "unknown"}`);
        }
    };

    const handleTgRescan = async (urlId) => {
        setToast("Re-running YARA rules over stored messages…");
        const { ok, body } = await api(
            `/api/telegram/channels/${urlId}/rescan`, { method: "POST" });
        if (ok) {
            setToast(`Rescanned ${body.scanned} msg, ${body.findings} finding(s)`);
            fetchFindings();
        } else {
            setToast(body.error || "Rescan failed");
        }
    };

    return (
        <div className="min-h-screen flex flex-col">
            <Header
                health={health}
                healthReady={healthReady}
                scanning={scanning}
                scanTimer={scanTimer}
                onOpenSecurity={() => setSecurityModalOpen(true)}
                onRecheck={handleRecheckHealth}
                rechecking={rechecking}
                version={uiConfig?.version}
            />

            <main className="max-w-7xl w-full mx-auto px-3 sm:px-6 py-4 sm:py-6 flex-1">
                <StatsBar stats={stats} />
                <TabNav
                    activeTab={activeTab}
                    onChange={setActiveTab}
                    findingsCount={stats.total_findings ?? findings.length}
                    urlsCount={urlsTotal || urls.length}
                    rulesCount={rules.length}
                    keywordsCount={keywords.length}
                    telegramCount={tgChannels.length}
                    setupUrl={uiConfig?.setup_url}
                />

                {activeTab === "scan" && (
                    <ScanPanel
                        scanning={scanning}
                        submitting={submitting}
                        progress={progress}
                        health={health}
                        onStart={handleStart}
                        onStop={handleStop}
                        onRecheckHealth={handleRecheckHealth}
                        rechecking={rechecking}
                        onImportTargets={handleImportTargets}
                        logs={logs}
                        logsTruncated={logsTruncated}
                        paused={logsPaused}
                        onClearLogs={() => { setLogs([]); setLogsTruncated(false); }}
                        onTogglePause={() => setLogsPaused(p => !p)}
                    />
                )}

                {activeTab === "findings" && (
                    <FindingsPanel
                        findings={findings}
                        sevFilter={sevFilter}
                        onFilter={setSevFilter}
                        onRefresh={fetchFindings}
                        onGenerateReport={handleGenerateReport}
                        onDeleteOne={handleDeleteFinding}
                        onDeleteMany={handleDeleteManyFindings}
                        onLightbox={setLightbox}
                        hasMore={findingsHasMore}
                        onLoadMore={() => fetchFindings({ append: true })}
                        loading={findingsLoading}
                        hasReport={hasReport}
                    />
                )}

                {activeTab === "urls" && (
                    <URLsPanel
                        urls={urls}
                        onRefresh={fetchUrls}
                        onLightbox={setLightbox}
                        onSetMonitor={handleSetMonitor}
                        onBulkMonitor={handleBulkMonitor}
                        monitorPending={monitorPending}
                        onDelete={handleDeleteUrl}
                        onBulkDelete={handleDeleteManyUrls}
                        total={urlsTotal}
                        hasMore={urlsHasMore}
                        onLoadMore={() => fetchUrls({ append: true })}
                    />
                )}

                {activeTab === "telegram" && (
                    <TelegramPanel
                        status={tgStatus}
                        channels={tgChannels}
                        tgVpnOk={!!health?.tg_vpn?.ok}
                        onReloadStatus={fetchTgStatus}
                        onAuth={handleTgAuth}
                        onLogout={handleTgLogout}
                        onAddChannel={handleTgAddChannel}
                        onScrape={handleTgScrape}
                        onRescan={handleTgRescan}
                        onJoin={handleTgJoin}
                        onLeave={handleTgLeave}
                        onSetMonitor={handleSetMonitor}
                        monitorPending={monitorPending}
                        onDelete={handleDeleteUrl}
                        onLightbox={setLightbox}
                        onToast={setToast}
                    />
                )}

                {activeTab === "keywords" && (
                    <KeywordsPanel
                        keywords={keywords}
                        onAdd={handleAddKeyword}
                        onAddBulk={handleAddKeywordsBulk}
                        onDelete={handleDeleteKeyword}
                        onRefresh={fetchKeywords}
                        onGoRules={() => setActiveTab("rules")}
                        adding={addingKeyword}
                    />
                )}

                {activeTab === "rules" && (
                    <RulesPanel rules={rules} onRefresh={fetchRules}
                                onDeleteMany={handleDeleteManyRules}
                                onAddCustom={handleAddCustomRule}
                                addingCustom={addingCustomRule} />
                )}
            </main>

            <footer className="border-t border-gray-800 py-3 text-center text-xs text-gray-600">
                DarkWatch{uiConfig?.version ? ` v${uiConfig.version}` : ""} — scan through Tor only. Never run without VPN.
            </footer>

            {securityModalOpen && (
                <SecurityModal
                    health={health}
                    onClose={() => setSecurityModalOpen(false)}
                    onRecheck={handleRecheckHealth}
                    rechecking={rechecking}
                />
            )}

            {shortcutsOpen && (
                <ShortcutsModal onClose={() => setShortcutsOpen(false)} />
            )}

            <Lightbox
                lightbox={lightbox}
                onClose={() => setLightbox(null)}
                onIndex={i => setLightbox(l => l ? { ...l, index: i } : l)}
            />

            <Toast message={toast} onClose={() => setToast("")} />
        </div>
    );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
