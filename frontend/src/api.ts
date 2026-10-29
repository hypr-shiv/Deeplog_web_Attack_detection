/**
 * DeepLog SIEM Unified API Client
 * Provides robust endpoint resolution across:
 * - Same-origin Vite proxy (/api/v1/...) to prevent CORS/CSP blocks
 * - Direct backend connection on current host (:8000)
 * - Automatic skipping of non-JSON / HTML 404 proxy misses
 * - Safe response JSON parser preventing SyntaxErrors
 */

export function getWebSocketUrl(): string {
  if (typeof window === "undefined") return "ws://127.0.0.1:8000/api/v1/stream/ws";
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const hostname = window.location.hostname || "127.0.0.1";
  return `${protocol}//${hostname}:8000/api/v1/stream/ws`;
}

/**
 * Safely parses response JSON, throwing user-friendly error messages if the response
 * is HTML (e.g. proxy 404 or web server error page) instead of cryptic SyntaxErrors.
 */
export async function parseResponseData<T = any>(res: Response): Promise<T> {
  const text = await res.text();
  if (!text || !text.trim()) {
    return {} as T;
  }
  try {
    return JSON.parse(text) as T;
  } catch {
    const preview = text.trim().slice(0, 80).replace(/\s+/g, " ");
    if (!res.ok) {
      throw new Error(
        `Backend service error (HTTP ${res.status}): Server returned non-JSON content: "${preview}". Please verify the FastAPI backend is running.`
      );
    }
    throw new Error(
      `Invalid server response format (HTTP ${res.status}): Expected JSON but received: "${preview}".`
    );
  }
}

/**
 * Makes an API request to the backend with intelligent URL candidate resolution.
 * If a relative proxy path returns an HTML 404/502 (e.g., when running on static preview),
 * it automatically falls back to direct http://127.0.0.1:8000 or http://localhost:8000.
 */
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

  const hostname = (typeof window !== "undefined" && window.location.hostname) || "127.0.0.1";

  // Build candidate targets in priority order
  const candidateUrls: string[] = [];

  // When running on Vite dev port 5173 or 3000, try relative proxy first
  if (typeof window !== "undefined" && (window.location.port === "5173" || window.location.port === "3000")) {
    candidateUrls.push(cleanPath);
  }

  // Direct backend on 127.0.0.1:8000
  candidateUrls.push(`http://127.0.0.1:8000${cleanPath}`);

  // Direct backend on current hostname if different
  if (hostname && hostname !== "127.0.0.1") {
    candidateUrls.push(`http://${hostname}:8000${cleanPath}`);
  }

  // Fallback relative if not yet included
  if (!candidateUrls.includes(cleanPath)) {
    candidateUrls.push(cleanPath);
  }

  let lastError: any = null;

  for (const url of candidateUrls) {
    try {
      const res = await fetch(url, fetchOptions);
      const contentType = (res.headers.get("content-type") || "").toLowerCase();

      // If a candidate returns an HTML 404/502/504 (e.g. static dev server without /api proxy),
      // continue to the next direct candidate instead of returning the HTML error page.
      if ((res.status === 404 || res.status === 502 || res.status === 504) && contentType.includes("text/html")) {
        continue;
      }

      return res;
    } catch (err) {
      lastError = err;
    }
  }

  throw (
    lastError ||
    new Error(
      "Unable to connect to DeepLog backend server. Please verify FastAPI is running at http://127.0.0.1:8000."
    )
  );
}
