import React, { useMemo } from "react";
import DOMPurify from "dompurify";

interface SafeLogViewerProps {
  content: string;
  className?: string;
  highlightThreat?: boolean;
}

/**
 * Enterprise-grade XSS-Safe Log Viewer.
 * Sanitizes untrusted log strings with DOMPurify and renders via text nodes to prevent Stored XSS.
 */
export const SafeLogViewer: React.FC<SafeLogViewerProps> = ({
  content,
  className = "",
  highlightThreat = false,
}) => {
  const sanitized = useMemo(() => {
    return DOMPurify.sanitize(content || "", {
      ALLOWED_TAGS: [],   // Disallow all HTML tags (<script>, <img>, <iframe>, etc.)
      ALLOWED_ATTR: [],   // Disallow all attributes (onerror, onload, onclick)
      KEEP_CONTENT: true, // Preserve text content
    });
  }, [content]);

  return (
    <span
      className={`select-all break-all ${
        highlightThreat ? "text-amber-400 font-bold" : ""
      } ${className}`}
    >
      {sanitized}
    </span>
  );
};

export default SafeLogViewer;
