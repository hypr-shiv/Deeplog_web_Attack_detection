/**
 * DeepLog SIEM Unified API Client
 * Provides robust endpoint resolution across:
 * - Same-origin Vite proxy (/api/v1/...) to prevent CORS/CSP blocks
 * - Direct backend connection on current host (:8000)
 * - Safe fallback with user-friendly diagnostics
 */

export function getWebSocketUrl(): string {
  if (typeof window === "undefined") return "ws://127.0.0.1:8000/api/v1/stream/ws";
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const hostname = window.location.hostname || "127.0.0.1";
  return `${protocol}//${hostname}:8000/api/v1/stream/ws`;
}

export async function apiRequest(path: string, options: RequestInit = {}): Promise<Response> {
  const cleanPath = path.startsWith("/") ? path : `/${path}`;
  const headers = new Headers(options.headers || {});
  if (!headers.has("Content-Type") && !(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }

  const fetchOptions: RequestInit = {
    ...options,
    headers,
    credentials: "include",
  };

  // Attempt 1: Same-origin relative request via Vite dev proxy (eliminates CORS and CSP origin mismatch)
  try {
    const res = await fetch(cleanPath, fetchOptions);
    return res;
  } catch (errFirst) {
    // Attempt 2: Direct request matching page hostname (e.g. localhost:8000 or 127.0.0.1:8000)
    try {
      const hostname = (typeof window !== "undefined" && window.location.hostname) || "127.0.0.1";
      const directUrl = `http://${hostname}:8000${cleanPath}`;
      const res = await fetch(directUrl, fetchOptions);
      return res;
    } catch (errSecond) {
      // Attempt 3: Direct request to 127.0.0.1:8000
      try {
        const loopbackUrl = `http://127.0.0.1:8000${cleanPath}`;
        const res = await fetch(loopbackUrl, fetchOptions);
        return res;
      } catch (errThird) {
        throw new Error(
          "Unable to connect to DeepLog backend server. Please verify FastAPI is running at http://127.0.0.1:8000."
        );
      }
    }
  }
}
