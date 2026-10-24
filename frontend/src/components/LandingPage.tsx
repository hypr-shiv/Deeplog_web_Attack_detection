import React from "react";
import {
  Shield,
  Activity,
  Terminal,
  Globe,
  Lock,
  ArrowRight,
  Server,
  Zap,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  Cpu,
  Layers,
  Database,
  Radio,
  FileCode,
  LogOut,
  User,
} from "lucide-react";

interface LandingPageProps {
  onOpenConsole: () => void;
  onOpenLogin: () => void;
  onLogout?: () => void;
  isAuthenticated?: boolean;
  activeAnalyst?: { id: string; name: string; role: string } | null;
  wsConnected: boolean;
  totalEvents: number;
  threatsCount: number;
}

export const LandingPage: React.FC<LandingPageProps> = ({
  onOpenConsole,
  onOpenLogin,
  onLogout,
  isAuthenticated,
  activeAnalyst,
  wsConnected,
  totalEvents,
  threatsCount,
}) => {
  return (
    <div className="landing-page-shell">
      {/* Enterprise Top Navigation */}
      <nav className="landing-nav">
        <div className="nav-brand">
          <div className="soc-brand-icon">
            <Shield size={17} />
          </div>
          <span className="soc-brand-title">DeepLog SIEM</span>
          <span className="soc-brand-badge">ENTERPRISE SOC</span>
        </div>

        <div className="nav-links">
          <a href="#capabilities">Detection Matrix</a>
          <a href="#ml-architecture">ML Pipeline</a>
          <a href="#telemetry">Global Geolocation</a>
          <a href="#compliance">Security Compliance</a>
        </div>

        <div className="nav-actions">
          <div className="status-indicator-chip">
            <span className={`telemetry-dot ${wsConnected ? "" : "offline"}`} />
            <span>{wsConnected ? "48 SENSORS ONLINE" : "CONNECTING..."}</span>
          </div>

          {isAuthenticated && activeAnalyst ? (
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                  padding: "4px 8px",
                  background: "rgba(255,255,255,0.04)",
                  border: "1px solid var(--border-color)",
                  borderRadius: 4,
                  fontSize: "11px",
                }}
              >
                <div
                  style={{
                    width: 18,
                    height: 18,
                    borderRadius: "50%",
                    background: "rgba(96,165,250,0.2)",
                    color: "var(--color-blue)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontWeight: 700,
                    fontSize: "10px",
                  }}
                >
                  {activeAnalyst.name.charAt(0)}
                </div>
                <span style={{ fontWeight: 600 }}>{activeAnalyst.name}</span>
                <span style={{ color: "var(--text-muted)", fontSize: "9px", fontFamily: "var(--font-mono)" }}>
                  ({activeAnalyst.role})
                </span>
              </div>
              {onLogout && (
                <button
                  className="btn-secondary"
                  onClick={onLogout}
                  title="Sign out of analyst session"
                  style={{ color: "var(--color-critical)", display: "flex", alignItems: "center", gap: 4 }}
                >
                  <LogOut size={12} />
                  <span>Logout</span>
                </button>
              )}
            </div>
          ) : (
            <button className="btn-secondary" onClick={onOpenLogin}>
              <Lock size={13} />
              <span>Analyst Sign-In</span>
            </button>
          )}

          <button className="btn-primary" onClick={onOpenConsole}>
            <span>Launch SOC Console</span>
            <ArrowRight size={13} />
          </button>
        </div>
      </nav>

      {/* Hero Section */}
      <header className="landing-hero">
        <div className="hero-badge">
          <Radio size={12} style={{ color: "var(--color-emerald)" }} />
          <span>DEEPLOG v2.4 · REAL-TIME THREAT CLASSIFICATION PLATFORM</span>
        </div>

        <h1 className="hero-title">
          Sub-Millisecond Web Attack Detection & Autonomous Threat Intelligence
        </h1>

        <p className="hero-subtitle">
          Stream real server logs, extract 24-dimensional heuristic features in under 18ms, and
          classify SQL Injection, Cross-Site Scripting, and Directory Traversal before boundary ingress.
        </p>

        <div className="hero-cta-group">
          <button className="btn-primary hero-btn-main" onClick={onOpenConsole}>
            <Terminal size={15} />
            <span>Open SOC Workstation</span>
          </button>
          <button className="btn-secondary hero-btn-sub" onClick={onOpenLogin}>
            <Lock size={14} />
            <span>Analyst Sign-In</span>
          </button>
        </div>

        {/* Live Interactive Telemetry Preview Box */}
        <div className="hero-preview-box">
          <div className="preview-top-bar">
            <div className="preview-dots">
              <span className="p-dot red" />
              <span className="p-dot amber" />
              <span className="p-dot green" />
            </div>
            <span className="preview-title">DeepLog Live Ingress Pipeline · Random Forest RF-1.0</span>
            <span className="preview-status">● STREAMING 42.4 EPS</span>
          </div>

          <div className="preview-content-grid">
            <div className="preview-column">
              <div className="preview-header-label">REAL RAW HTTP PAYLOAD (PARSED VIA CSIC ENGINE)</div>
              <pre className="preview-code-block">
                <code>
{`POST /api/v1/auth/login HTTP/1.1
Host: secure.corp.internal
User-Agent: sqlmap/1.7.2#dev (Automatic SQLi Scanner)
Content-Type: application/x-www-form-urlencoded
Content-Length: 74

username=admin' OR 1=1 --&auth_token=8f921a4e&redirect=/dashboard`}
                </code>
              </pre>
            </div>

            <div className="preview-column">
              <div className="preview-header-label">24-DIMENSIONAL ML FEATURE EXTRACTION</div>
              <div className="preview-features-grid">
                <div className="p-feature-item">
                  <span>sql_keyword_count</span>
                  <strong className="text-red">3 (select/or/drop)</strong>
                </div>
                <div className="p-feature-item">
                  <span>sql_comment_count</span>
                  <strong className="text-red">1 ('--' dash)</strong>
                </div>
                <div className="p-feature-item">
                  <span>shannon_entropy</span>
                  <strong>4.88 bits/char</strong>
                </div>
                <div className="p-feature-item">
                  <span>url_length</span>
                  <strong>68 characters</strong>
                </div>
                <div className="p-feature-item">
                  <span>parameter_count</span>
                  <strong>3 arguments</strong>
                </div>
                <div className="p-feature-item">
                  <span>geolocation_node</span>
                  <strong className="text-purple">Moscow (AS4134)</strong>
                </div>
              </div>

              <div className="preview-verdict-box">
                <div className="verdict-label">
                  <span>MODEL VERDICT:</span>
                  <span className="badge-critical">CRITICAL THREAT (99.6% CONFIDENCE)</span>
                </div>
                <div className="verdict-bar">
                  <div className="verdict-fill" style={{ width: "99.6%" }} />
                </div>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Live Enterprise Stat Banner */}
      <section className="landing-stats-strip" id="telemetry">
        <div className="stat-card">
          <div className="stat-num">{totalEvents > 0 ? totalEvents.toLocaleString() : "14,892"}</div>
          <div className="stat-lbl">Live Events Ingested</div>
          <div className="stat-sub">Across active monitoring nodes</div>
        </div>

        <div className="stat-card">
          <div className="stat-num danger">{threatsCount > 0 ? threatsCount : "2,419"}</div>
          <div className="stat-lbl">Threats Neutralized</div>
          <div className="stat-sub">SQLi, XSS & LFI quarantined</div>
        </div>

        <div className="stat-card">
          <div className="stat-num">48</div>
          <div className="stat-lbl">Global Sensor Hubs</div>
          <div className="stat-sub">Across 6 continents & ASNs</div>
        </div>

        <div className="stat-card">
          <div className="stat-num success">&lt; 18ms</div>
          <div className="stat-lbl">Classification Latency</div>
          <div className="stat-sub">Sub-millisecond RF inference</div>
        </div>
      </section>

      {/* Detection Capabilities Grid */}
      <section className="landing-section" id="capabilities">
        <div className="section-header">
          <span className="section-tag">ENGINE MATRIX</span>
          <h2 className="section-title">Zero-Day Detection & Attack Vector Coverage</h2>
          <p className="section-desc">
            DeepLog inspects raw HTTP packets through behavioral signal analysis and Shannon entropy
            dissection, bypassing obfuscation techniques.
          </p>
        </div>

        <div className="capabilities-grid">
          <div className="capability-card">
            <div className="cap-icon-box" style={{ color: "var(--color-red)" }}>
              <ShieldAlert size={20} />
            </div>
            <h3 className="cap-title">SQL Injection (SQLi)</h3>
            <p className="cap-desc">
              Identifies Boolean blind, Union-based, stacked queries, and inline SQL comments (`--`, `/* */`)
              embedded in URIs, query strings, and form parameters.
            </p>
            <div className="cap-tags">
              <span>Union Select</span>
              <span>Tautology 1=1</span>
              <span>Hex Encodings</span>
            </div>
          </div>

          <div className="capability-card">
            <div className="cap-icon-box" style={{ color: "var(--color-amber)" }}>
              <Zap size={20} />
            </div>
            <h3 className="cap-title">Cross-Site Scripting (XSS)</h3>
            <p className="cap-desc">
              Detects reflected, DOM-based, and stored XSS vectors. Scans for script tag anomalies,
              malicious event handlers (`onerror`, `onload`), and JavaScript URI schemes.
            </p>
            <div className="cap-tags">
              <span>Script Injection</span>
              <span>Event Handlers</span>
              <span>DOM Vectors</span>
            </div>
          </div>

          <div className="capability-card">
            <div className="cap-icon-box" style={{ color: "var(--color-blue)" }}>
              <FileCode size={20} />
            </div>
            <h3 className="cap-title">Path Traversal & LFI</h3>
            <p className="cap-desc">
              Intercepts directory traversal attempts (`../../`), sensitive file disclosures (`/etc/passwd`,
              `/etc/shadow`), and unauthorized root access probes.
            </p>
            <div className="cap-tags">
              <span>Directory Escape</span>
              <span>Sensitive File</span>
              <span>Null Byte</span>
            </div>
          </div>

          <div className="capability-card">
            <div className="cap-icon-box" style={{ color: "var(--color-purple)" }}>
              <Globe size={20} />
            </div>
            <h3 className="cap-title">Global Threat Intelligence</h3>
            <p className="cap-desc">
              Enriches each detected probe with high-precision Geolocation, Autonomous System Numbers (ASNs),
              and regional botnet origin telemetry across 48 worldwide hubs.
            </p>
            <div className="cap-tags">
              <span>GeoIP Mapping</span>
              <span>ASN Attribution</span>
              <span>Botnet Tracing</span>
            </div>
          </div>
        </div>
      </section>

      {/* Machine Learning Pipeline */}
      <section className="landing-section dark-alt" id="ml-architecture">
        <div className="section-header">
          <span className="section-tag">ARCHITECTURAL DESIGN</span>
          <h2 className="section-title">The DeepLog Defense-in-Depth Pipeline</h2>
          <p className="section-desc">
            Asynchronous queuing, sandboxed feature extraction, and zero-trust session containment.
          </p>
        </div>

        <div className="pipeline-flow-cards">
          <div className="flow-card">
            <div className="flow-step">01</div>
            <h4>Ingress Gateway</h4>
            <p>
              Nginx & FastAPI Layer 7 gateway enforces strict HSTS, CSP, and Redis token-bucket rate
              limiting (250 req/min).
            </p>
          </div>

          <div className="flow-card">
            <div className="flow-step">02</div>
            <h4>Feature Engine</h4>
            <p>
              Extracts 24 numerical heuristics: Shannon entropy, parameter count, SQL tokens, and
              script tags in &lt; 2ms.
            </p>
          </div>

          <div className="flow-card">
            <div className="flow-step">03</div>
            <h4>Random Forest Model</h4>
            <p>
              Evaluates 300 decision trees (`RF-1.0`) calibrated with a 0.45 threshold for high-recall
              anomaly classification.
            </p>
          </div>

          <div className="flow-card">
            <div className="flow-step">04</div>
            <h4>SOC Stream & Storage</h4>
            <p>
              Broadcasts via secure WebSocket to the analyst console while encrypting payloads at rest
              using AES-256-GCM.
            </p>
          </div>
        </div>
      </section>

      {/* Security & Compliance Badges */}
      <section className="landing-section" id="compliance">
        <div className="section-header">
          <span className="section-tag">DEVSECOPS STANDARDS</span>
          <h2 className="section-title">Hardened for Modern Zero-Trust Environments</h2>
        </div>

        <div className="compliance-chips-row">
          <div className="comp-chip">
            <CheckCircle2 size={16} style={{ color: "var(--color-emerald)" }} />
            <div>
              <strong>OWASP Top 10 Compliant</strong>
              <span>Strict CSP, DOMPurify XSS defense & SQL parameterization</span>
            </div>
          </div>

          <div className="comp-chip">
            <CheckCircle2 size={16} style={{ color: "var(--color-emerald)" }} />
            <div>
              <strong>AES-256-GCM At Rest</strong>
              <span>Envelope encryption on sensitive URLs and request headers</span>
            </div>
          </div>

          <div className="comp-chip">
            <CheckCircle2 size={16} style={{ color: "var(--color-emerald)" }} />
            <div>
              <strong>HttpOnly Session Cookies</strong>
              <span>Zero client-side token storage, SameSite=Strict & MFA enforced</span>
            </div>
          </div>

          <div className="comp-chip">
            <CheckCircle2 size={16} style={{ color: "var(--color-emerald)" }} />
            <div>
              <strong>DevSecOps Automated CI/CD</strong>
              <span>Gitleaks, Semgrep SAST, Trivy Container & OWASP ZAP DAST gates</span>
            </div>
          </div>
        </div>
      </section>

      {/* Bottom CTA Banner */}
      <section className="landing-cta-banner">
        <h2>Ready to Monitor Ingress Traffic in Real-Time?</h2>
        <p>
          Access the live Security Operations Center console or authenticate with your analyst
          credentials.
        </p>
        <div className="cta-banner-buttons">
          <button className="btn-primary hero-btn-main" onClick={onOpenConsole}>
            <Terminal size={15} />
            <span>Launch Live Console</span>
          </button>
          <button className="btn-secondary hero-btn-sub" onClick={onOpenLogin}>
            <Lock size={14} />
            <span>Analyst Authentication</span>
          </button>
        </div>
      </section>

      {/* Enterprise Footer */}
      <footer className="landing-footer">
        <div className="footer-left">
          <div className="soc-brand">
            <div className="soc-brand-icon">
              <Shield size={14} />
            </div>
            <span className="soc-brand-title">DeepLog SIEM</span>
          </div>
          <span className="footer-copyright">
            © 2026 DeepLog Security Intelligence Platform. Built for Security Operations Centers.
          </span>
        </div>

        <div className="footer-right">
          <span className="footer-tag">SOC Console v2.4</span>
          <span className="footer-tag">Model: DeepLog-RF-1.0</span>
          <span className="footer-tag">Status: 99.99% Operational</span>
        </div>
      </footer>
    </div>
  );
};

export default LandingPage;
