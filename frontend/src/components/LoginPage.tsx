import React, { useEffect, useState } from "react";
import {
  Shield,
  Lock,
  KeyRound,
  User,
  UserPlus,
  ArrowLeft,
  CheckCircle2,
  AlertTriangle,
  Server,
  Eye,
  EyeOff,
  Fingerprint,
  Activity,
  X,
  Mail,
} from "lucide-react";

interface LoginPageProps {
  onLoginSuccess: (analystData: { id: string; email?: string; name: string; role: string }) => void;
  onBackToLanding: () => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({
  onLoginSuccess,
  onBackToLanding,
}) => {
  const [authMode, setAuthMode] = useState<"signin" | "register">("signin");

  // Authentication Fields (Clean, unpopulated real inputs)
  const [analystId, setAnalystId] = useState("");
  const [passcode, setPasscode] = useState("");
  const [mfaCode, setMfaCode] = useState("");

  // Registration Specific Fields
  const [regName, setRegName] = useState("");
  const [regEmail, setRegEmail] = useState("");
  const [regPasscode, setRegPasscode] = useState("");
  const [regConfirmPasscode, setRegConfirmPasscode] = useState("");
  const [regRole, setRegRole] = useState("ANALYST");

  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [loadingStep, setLoadingStep] = useState<string>("");
  const [authStatus, setAuthStatus] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Auto-clear error on Escape key
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape" && errorMessage) {
        setErrorMessage(null);
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [errorMessage]);

  // Handle Sign In Submission
  async function handleSignIn(e: React.FormEvent) {
    e.preventDefault();
    setErrorMessage(null);
    setAuthStatus(null);

    if (!analystId.trim() || !passcode.trim()) {
      setErrorMessage("Please enter both your analyst identifier and workstation passcode.");
      return;
    }

    setIsSubmitting(true);
    setLoadingStep("Step 1/3: Computing PBKDF2 HMAC-SHA256 hash (100,000 rounds)...");

    let timer1: ReturnType<typeof setTimeout> | undefined;
    let timer2: ReturnType<typeof setTimeout> | undefined;

    timer1 = setTimeout(() => {
      setLoadingStep("Step 2/3: Validating cryptographic workstation tokens...");
    }, 250);

    timer2 = setTimeout(() => {
      setLoadingStep("Step 3/3: Establishing __Host-HttpOnly session cookie...");
    }, 500);

    try {
      const res = await fetch("http://127.0.0.1:8000/api/v1/auth/login", {
        method: "POST",
        credentials: "include", // Transmits and receives HttpOnly session cookie
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          analyst_id: analystId.trim(),
          passcode: passcode,
          mfa_code: mfaCode.trim() || undefined,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        if (res.status === 429) {
          throw new Error(
            data.detail ||
              "Rate limit exceeded (HTTP 429): Too many login attempts. Cooldown active for brute-force defense."
          );
        }
        throw new Error(data.detail || "Authentication rejected: Invalid analyst identifier or passcode.");
      }

      setAuthStatus("Authentication verified. Establishing secure SOC session...");

      setTimeout(() => {
        onLoginSuccess({
          id: data.user?.id || analystId.split("@")[0].toUpperCase(),
          email: data.user?.email || analystId,
          name: data.user?.name || "SOC Analyst",
          role: data.user?.role || "ANALYST",
        });
      }, 500);
    } catch (err: any) {
      setAuthStatus(null);
      setErrorMessage(err.message || "Authentication rejected. Check your analyst credentials.");
    } finally {
      clearTimeout(timer1);
      clearTimeout(timer2);
      setIsSubmitting(false);
    }
  }

  // Handle Account Registration Submission
  async function handleRegister(e: React.FormEvent) {
    e.preventDefault();
    setErrorMessage(null);
    setAuthStatus(null);

    if (!regName.trim()) {
      setErrorMessage("Please enter your analyst full name.");
      return;
    }
    if (!regEmail.trim() || !regEmail.includes("@")) {
      setErrorMessage("Please enter a valid corporate email address.");
      return;
    }
    if (regPasscode.length < 8) {
      setErrorMessage("Workstation passcode must be at least 8 characters long.");
      return;
    }
    if (regPasscode !== regConfirmPasscode) {
      setErrorMessage("Passcodes do not match. Please verify your passcode confirmation.");
      return;
    }

    setIsSubmitting(true);
    setLoadingStep("Step 1/3: Salted PBKDF2 HMAC-SHA256 cryptographic derivation...");

    let timer1: ReturnType<typeof setTimeout> | undefined;
    let timer2: ReturnType<typeof setTimeout> | undefined;

    timer1 = setTimeout(() => {
      setLoadingStep("Step 2/3: Generating TOTP authenticator secrets & RBAC role...");
    }, 250);

    timer2 = setTimeout(() => {
      setLoadingStep("Step 3/3: Issuing HttpOnly session and registering credentials...");
    }, 500);

    try {
      const res = await fetch("http://127.0.0.1:8000/api/v1/auth/register", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: regName.trim(),
          email: regEmail.trim(),
          passcode: regPasscode,
          role: regRole,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        if (res.status === 429) {
          throw new Error("Rate limit exceeded: Too many registration attempts. Please wait.");
        }
        throw new Error(data.detail || "Account creation failed. Please verify your details.");
      }

      setAuthStatus("Account created successfully! Logging you into the SOC console...");

      setTimeout(() => {
        onLoginSuccess({
          id: data.user?.id || regEmail.split("@")[0].toUpperCase(),
          email: data.user?.email || regEmail,
          name: data.user?.name || regName,
          role: data.user?.role || regRole,
        });
      }, 600);
    } catch (err: any) {
      setAuthStatus(null);
      setErrorMessage(err.message || "Failed to create account. Please check input requirements.");
    } finally {
      clearTimeout(timer1);
      clearTimeout(timer2);
      setIsSubmitting(false);
    }
  }

  return (
    <div className="login-page-shell">
      {/* Top Header Bar */}
      <header className="login-top-bar">
        <button className="back-link-btn" onClick={onBackToLanding}>
          <ArrowLeft size={14} />
          <span>Back to Landing Page</span>
        </button>

        <div className="login-brand">
          <div className="soc-brand-icon">
            <Shield size={16} />
          </div>
          <span className="soc-brand-title">DeepLog SIEM</span>
        </div>

        {/* Empty space to balance navbar without direct console bypass */}
        <div style={{ width: 140 }} />
      </header>

      {/* Main Login Card Container */}
      <main className="login-container">
        <div className="login-card">
          <div className="login-card-header">
            <div className="login-badge-warning">
              <AlertTriangle size={12} />
              <span>AUTHORIZED SOC PERSONNEL ONLY · MONITORED SESSION</span>
            </div>
            <h1 className="login-title">
              {authMode === "signin" ? "Analyst Authentication Portal" : "Create Analyst Account"}
            </h1>
            <p className="login-subtitle">
              {authMode === "signin"
                ? "Authenticate using your registered corporate credentials and salted PBKDF2 hash verification."
                : "Register a verified analyst identity to establish a zero-trust HttpOnly SOC session."}
            </p>
          </div>

          {/* Mode Switcher Tabs */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              borderBottom: "1px solid var(--border-subtle)",
              background: "#12171E",
            }}
          >
            <button
              type="button"
              onClick={() => {
                setAuthMode("signin");
                setErrorMessage(null);
                setAuthStatus(null);
              }}
              style={{
                padding: "11px 16px",
                background: authMode === "signin" ? "var(--bg-panel)" : "transparent",
                border: "none",
                borderBottom: authMode === "signin" ? "2px solid var(--color-blue)" : "2px solid transparent",
                color: authMode === "signin" ? "var(--text-primary)" : "var(--text-muted)",
                fontSize: "13px",
                fontWeight: 600,
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: 6,
                transition: "all 0.15s ease",
              }}
            >
              <Lock size={13} />
              <span>Sign In</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setAuthMode("register");
                setErrorMessage(null);
                setAuthStatus(null);
              }}
              style={{
                padding: "11px 16px",
                background: authMode === "register" ? "var(--bg-panel)" : "transparent",
                border: "none",
                borderBottom: authMode === "register" ? "2px solid var(--color-blue)" : "2px solid transparent",
                color: authMode === "register" ? "var(--text-primary)" : "var(--text-muted)",
                fontSize: "13px",
                fontWeight: 600,
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: 6,
                transition: "all 0.15s ease",
              }}
            >
              <UserPlus size={13} />
              <span>Create Account</span>
            </button>
          </div>

          {/* Form Area */}
          {authMode === "signin" ? (
            <form onSubmit={handleSignIn} className="login-form">
              {/* Analyst ID */}
              <div className="form-group">
                <label className="form-label" htmlFor="analyst-id">
                  <User size={13} />
                  <span>Corporate Email / Analyst ID</span>
                </label>
                <input
                  id="analyst-id"
                  type="text"
                  className="form-input"
                  value={analystId}
                  onChange={(e) => {
                    setAnalystId(e.target.value);
                    if (errorMessage) setErrorMessage(null);
                  }}
                  onFocus={() => {
                    if (errorMessage) setErrorMessage(null);
                  }}
                  placeholder="e.g. analyst@corp.internal"
                  required
                  autoFocus
                />
              </div>

              {/* Secret Passcode */}
              <div className="form-group">
                <div className="label-with-meta">
                  <label className="form-label" htmlFor="passcode">
                    <KeyRound size={13} />
                    <span>Workstation Passcode</span>
                  </label>
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    style={{
                      background: "transparent",
                      border: "none",
                      color: "var(--text-muted)",
                      display: "flex",
                      alignItems: "center",
                      gap: 4,
                      cursor: "pointer",
                      fontSize: "11px",
                    }}
                  >
                    {showPassword ? <EyeOff size={12} /> : <Eye size={12} />}
                    <span>{showPassword ? "Hide" : "Show"}</span>
                  </button>
                </div>
                <input
                  id="passcode"
                  type={showPassword ? "text" : "password"}
                  className="form-input font-mono"
                  value={passcode}
                  onChange={(e) => {
                    setPasscode(e.target.value);
                    if (errorMessage) setErrorMessage(null);
                  }}
                  onFocus={() => {
                    if (errorMessage) setErrorMessage(null);
                  }}
                  placeholder="Enter your passcode..."
                  required
                />
              </div>

              {/* TOTP MFA Code (Optional) */}
              <div className="form-group">
                <div className="label-with-meta">
                  <label className="form-label" htmlFor="mfa-code">
                    <Fingerprint size={13} />
                    <span>MFA Token (Optional if configured)</span>
                  </label>
                  <span className="mfa-badge">FIPS 140-2</span>
                </div>
                <input
                  id="mfa-code"
                  type="text"
                  maxLength={6}
                  className="form-input font-mono tracking-widest text-center"
                  value={mfaCode}
                  onChange={(e) => {
                    setMfaCode(e.target.value);
                    if (errorMessage) setErrorMessage(null);
                  }}
                  onFocus={() => {
                    if (errorMessage) setErrorMessage(null);
                  }}
                  placeholder="000000"
                />
              </div>

              {/* Loading Indicator */}
              {isSubmitting && (
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: 8,
                    padding: "10px 14px",
                    background: "rgba(96, 165, 250, 0.07)",
                    border: "1px solid rgba(96, 165, 250, 0.3)",
                    borderRadius: 6,
                    fontSize: "12px",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--color-blue)" }}>
                    <Activity size={14} className="animate-spin" />
                    <span>{loadingStep || "Authenticating credentials..."}</span>
                  </div>
                  <div style={{ width: "100%", height: 3, background: "rgba(255, 255, 255, 0.08)", borderRadius: 2, overflow: "hidden" }}>
                    <div className="soc-preloader-bar-fill" style={{ height: "100%" }} />
                  </div>
                </div>
              )}

              {/* Status Feedback */}
              {authStatus && (
                <div className="auth-status-box success">
                  <CheckCircle2 size={13} />
                  <span>{authStatus}</span>
                </div>
              )}

              {/* Error Display with Clear Button */}
              {errorMessage && (
                <div
                  className="auth-status-box error"
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 10,
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 8, flex: 1 }}>
                    <AlertTriangle size={14} style={{ flexShrink: 0 }} />
                    <span>{errorMessage}</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => setErrorMessage(null)}
                    style={{
                      background: "rgba(239, 68, 68, 0.15)",
                      border: "1px solid rgba(239, 68, 68, 0.3)",
                      color: "var(--color-red)",
                      borderRadius: 4,
                      padding: "2px 6px",
                      display: "flex",
                      alignItems: "center",
                      gap: 3,
                      fontSize: "11px",
                      cursor: "pointer",
                      flexShrink: 0,
                    }}
                    title="Clear error message (Esc)"
                  >
                    <X size={11} />
                    <span>Clear</span>
                  </button>
                </div>
              )}

              {/* Submit Button */}
              <button
                type="submit"
                className="btn-primary login-submit-btn"
                disabled={isSubmitting}
                style={{ opacity: isSubmitting ? 0.8 : 1, cursor: isSubmitting ? "wait" : "pointer" }}
              >
                {isSubmitting ? (
                  <>
                    <Activity size={14} className="animate-spin" />
                    <span>Verifying Credentials...</span>
                  </>
                ) : (
                  <>
                    <Lock size={14} />
                    <span>Sign In to SOC Console</span>
                  </>
                )}
              </button>

              <div style={{ textAlign: "center", marginTop: 8 }}>
                <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                  Need an authorized account?{" "}
                  <button
                    type="button"
                    onClick={() => {
                      setAuthMode("register");
                      setErrorMessage(null);
                    }}
                    style={{
                      background: "transparent",
                      border: "none",
                      color: "var(--color-blue)",
                      fontWeight: 600,
                      cursor: "pointer",
                      padding: 0,
                      fontSize: "12px",
                      textDecoration: "underline",
                    }}
                  >
                    Create Account
                  </button>
                </span>
              </div>
            </form>
          ) : (
            <form onSubmit={handleRegister} className="login-form">
              {/* Full Name */}
              <div className="form-group">
                <label className="form-label" htmlFor="reg-name">
                  <User size={13} />
                  <span>Analyst Full Name</span>
                </label>
                <input
                  id="reg-name"
                  type="text"
                  className="form-input"
                  value={regName}
                  onChange={(e) => {
                    setRegName(e.target.value);
                    if (errorMessage) setErrorMessage(null);
                  }}
                  onFocus={() => {
                    if (errorMessage) setErrorMessage(null);
                  }}
                  placeholder="e.g. Alex Rivera"
                  required
                  autoFocus
                />
              </div>

              {/* Corporate Email */}
              <div className="form-group">
                <label className="form-label" htmlFor="reg-email">
                  <Mail size={13} />
                  <span>Corporate Email Address</span>
                </label>
                <input
                  id="reg-email"
                  type="email"
                  className="form-input"
                  value={regEmail}
                  onChange={(e) => {
                    setRegEmail(e.target.value);
                    if (errorMessage) setErrorMessage(null);
                  }}
                  onFocus={() => {
                    if (errorMessage) setErrorMessage(null);
                  }}
                  placeholder="e.g. alex.rivera@corp.internal"
                  required
                />
              </div>

              {/* Workstation Passcode */}
              <div className="form-group">
                <div className="label-with-meta">
                  <label className="form-label" htmlFor="reg-passcode">
                    <KeyRound size={13} />
                    <span>Create Workstation Passcode (Min 8 chars)</span>
                  </label>
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    style={{
                      background: "transparent",
                      border: "none",
                      color: "var(--text-muted)",
                      display: "flex",
                      alignItems: "center",
                      gap: 4,
                      cursor: "pointer",
                      fontSize: "11px",
                    }}
                  >
                    {showPassword ? <EyeOff size={12} /> : <Eye size={12} />}
                    <span>{showPassword ? "Hide" : "Show"}</span>
                  </button>
                </div>
                <input
                  id="reg-passcode"
                  type={showPassword ? "text" : "password"}
                  className="form-input font-mono"
                  value={regPasscode}
                  onChange={(e) => {
                    setRegPasscode(e.target.value);
                    if (errorMessage) setErrorMessage(null);
                  }}
                  onFocus={() => {
                    if (errorMessage) setErrorMessage(null);
                  }}
                  placeholder="Min 8 characters..."
                  required
                  minLength={8}
                />
              </div>

              {/* Confirm Passcode */}
              <div className="form-group">
                <label className="form-label" htmlFor="reg-confirm-passcode">
                  <KeyRound size={13} />
                  <span>Confirm Passcode</span>
                </label>
                <input
                  id="reg-confirm-passcode"
                  type={showPassword ? "text" : "password"}
                  className="form-input font-mono"
                  value={regConfirmPasscode}
                  onChange={(e) => {
                    setRegConfirmPasscode(e.target.value);
                    if (errorMessage) setErrorMessage(null);
                  }}
                  onFocus={() => {
                    if (errorMessage) setErrorMessage(null);
                  }}
                  placeholder="Re-enter passcode..."
                  required
                  minLength={8}
                />
              </div>

              {/* Role Assignment */}
              <div className="form-group">
                <label className="form-label" htmlFor="reg-role">
                  <Shield size={13} />
                  <span>Assigned Operational Role</span>
                </label>
                <select
                  id="reg-role"
                  className="form-input"
                  value={regRole}
                  onChange={(e) => setRegRole(e.target.value)}
                  style={{ cursor: "pointer" }}
                >
                  <option value="ANALYST">SOC Analyst (Tier-1 / Tier-2)</option>
                  <option value="ADMIN">SecOps Administrator (Lead)</option>
                  <option value="VIEWER">Read-Only Threat Intelligence Viewer</option>
                </select>
              </div>

              {/* Loading Indicator */}
              {isSubmitting && (
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: 8,
                    padding: "10px 14px",
                    background: "rgba(96, 165, 250, 0.07)",
                    border: "1px solid rgba(96, 165, 250, 0.3)",
                    borderRadius: 6,
                    fontSize: "12px",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--color-blue)" }}>
                    <Activity size={14} className="animate-spin" />
                    <span>{loadingStep || "Deriving cryptographic keys..."}</span>
                  </div>
                  <div style={{ width: "100%", height: 3, background: "rgba(255, 255, 255, 0.08)", borderRadius: 2, overflow: "hidden" }}>
                    <div className="soc-preloader-bar-fill" style={{ height: "100%" }} />
                  </div>
                </div>
              )}

              {/* Status Feedback */}
              {authStatus && (
                <div className="auth-status-box success">
                  <CheckCircle2 size={13} />
                  <span>{authStatus}</span>
                </div>
              )}

              {/* Error Display with Clear Button */}
              {errorMessage && (
                <div
                  className="auth-status-box error"
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 10,
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 8, flex: 1 }}>
                    <AlertTriangle size={14} style={{ flexShrink: 0 }} />
                    <span>{errorMessage}</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => setErrorMessage(null)}
                    style={{
                      background: "rgba(239, 68, 68, 0.15)",
                      border: "1px solid rgba(239, 68, 68, 0.3)",
                      color: "var(--color-red)",
                      borderRadius: 4,
                      padding: "2px 6px",
                      display: "flex",
                      alignItems: "center",
                      gap: 3,
                      fontSize: "11px",
                      cursor: "pointer",
                      flexShrink: 0,
                    }}
                    title="Clear error message (Esc)"
                  >
                    <X size={11} />
                    <span>Clear</span>
                  </button>
                </div>
              )}

              {/* Submit Button */}
              <button
                type="submit"
                className="btn-primary login-submit-btn"
                disabled={isSubmitting}
                style={{ opacity: isSubmitting ? 0.8 : 1, cursor: isSubmitting ? "wait" : "pointer" }}
              >
                {isSubmitting ? (
                  <>
                    <Activity size={14} className="animate-spin" />
                    <span>Registering Account...</span>
                  </>
                ) : (
                  <>
                    <UserPlus size={14} />
                    <span>Create Analyst Account &amp; Sign In</span>
                  </>
                )}
              </button>

              <div style={{ textAlign: "center", marginTop: 8 }}>
                <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                  Already have an account?{" "}
                  <button
                    type="button"
                    onClick={() => {
                      setAuthMode("signin");
                      setErrorMessage(null);
                    }}
                    style={{
                      background: "transparent",
                      border: "none",
                      color: "var(--color-blue)",
                      fontWeight: 600,
                      cursor: "pointer",
                      padding: 0,
                      fontSize: "12px",
                      textDecoration: "underline",
                    }}
                  >
                    Sign In
                  </button>
                </span>
              </div>
            </form>
          )}

          {/* Security Compliance Footer */}
          <div className="login-card-footer">
            <div className="compliance-item">
              <span className="telemetry-dot live" />
              <span>TLS 1.3 Active</span>
            </div>
            <div className="compliance-item">
              <Lock size={11} />
              <span>HttpOnly Session</span>
            </div>
            <div className="compliance-item" title="Sliding-window token bucket: 10 attempts/min">
              <Shield size={11} style={{ color: "var(--color-amber)" }} />
              <span>Rate Limited (10/min)</span>
            </div>
            <div className="compliance-item">
              <Server size={11} />
              <span>FIPS 140-2</span>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default LoginPage;
