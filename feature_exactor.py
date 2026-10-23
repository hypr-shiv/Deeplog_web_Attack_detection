import math
import re
from collections import Counter
from urllib.parse import parse_qsl, unquote, urlparse

# Expected feature schema - must match the trained model's feature list
EXPECTED_FEATURES = [
    "url_length",
    "parameter_count",
    "special_char_count",
    "encoding_count",
    "dot_count",
    "question_mark_count",
    "content_length",
    "content_encoded_count",
    "is_form_urlencoded",
    "sql_keyword_count",
    "sql_comment_count",
    "sql_logic_count",
    "query_sql_keyword_count",
    "xss_angle_bracket_count",
    "xss_parentheses_count",
    "javascript_keyword_count",
    "dot_dot_count",
    "etc_passwd_indicator",
    "ssi_exec_indicator",
    "method_post",
    "method_put",
    "suspicious_path_keyword_count",
    "sensitive_endpoint_indicator",
    "url_entropy",
]


def calculate_entropy(text):
    if not text:
        return 0.0

    counter = Counter(text)
    length = len(text)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )


def validate_features(features_dict):
    """
    Validate that the features dictionary matches the expected schema.

    Checks:
    - All required features exist
    - Feature names match the saved model feature list
    - No unexpected features are present
    - Feature count is correct

    Returns True if validation passes, raises ValueError otherwise.
    """
    feature_names = list(features_dict.keys())

    if feature_names != EXPECTED_FEATURES:
        missing = set(EXPECTED_FEATURES) - set(feature_names)
        extra = set(feature_names) - set(EXPECTED_FEATURES)
        raise ValueError(
            "Feature schema mismatch!\n"
            f"Expected features: {EXPECTED_FEATURES}\n"
            f"Missing features: {missing}\n"
            f"Extra features: {extra}\n"
            "Please ensure the feature extractor version matches the model version."
        )

    if len(features_dict) != len(EXPECTED_FEATURES):
        raise ValueError(
            f"Expected {len(EXPECTED_FEATURES)} features, got {len(features_dict)}"
        )

    # Validate numeric types for all features
    for name, value in features_dict.items():
        if not isinstance(value, (int, float)):
            raise ValueError(
                f"Feature '{name}' must be numeric (int or float), got {type(value).__name__}"
            )

    return True


def extract_features(url, method="GET", content="", content_type="", content_length=None):
    raw_url = "" if url is None else str(url)
    url = re.sub(r"\s+HTTP/\d(?:\.\d)?$", "", raw_url, flags=re.IGNORECASE)

    if isinstance(content, float) and math.isnan(content):
        content = ""
    else:
        content = "" if content is None else str(content)

    if isinstance(content_type, float) and math.isnan(content_type):
        content_type = ""
    else:
        content_type = "" if content_type is None else str(content_type)

    method = "" if method is None else str(method).upper()

    parsed = urlparse(url)
    decoded_url = unquote(url)
    query = parsed.query
    query_params = parse_qsl(query, keep_blank_values=True)
    lower_url = decoded_url.lower()

    features = {
        "url_length": len(url),
        "parameter_count": len(query_params),
        "special_char_count": len(re.findall(r"[<>'\";]", decoded_url)),
        "encoding_count": url.count("%"),
        "dot_count": url.count("."),
        "question_mark_count": url.count("?"),
        "content_length": (
            len(content)
            if content_length is None or content_length == "" or not str(content_length).isdigit()
            else int(content_length)
        ),
        "content_encoded_count": content.count("%"),
        "is_form_urlencoded": int(
            "application/x-www-form-urlencoded" in content_type.lower()
        ),
        "sql_keyword_count": sum(
            lower_url.count(keyword)
            for keyword in ["select", "union", "insert", "delete", "update", "drop"]
        ),
        "sql_comment_count": (
            decoded_url.count("--")
            + decoded_url.count("/*")
            + decoded_url.count("*/")
        ),
        "sql_logic_count": lower_url.count(" or ") + lower_url.count(" and "),
        "query_sql_keyword_count": sum(
            unquote(query).lower().count(keyword)
            for keyword in ["select", "union", "insert", "delete", "update", "drop"]
        ),
        "xss_angle_bracket_count": decoded_url.count("<") + decoded_url.count(">"),
        "xss_parentheses_count": decoded_url.count("(") + decoded_url.count(")"),
        "javascript_keyword_count": sum(
            lower_url.count(keyword)
            for keyword in ["javascript", "alert", "onerror", "onload", "script"]
        ),
        "dot_dot_count": decoded_url.count("../"),
        "etc_passwd_indicator": int("/etc/passwd" in lower_url),
        "ssi_exec_indicator": int("exec" in lower_url),
        "method_post": int(method == "POST"),
        "method_put": int(method == "PUT"),
        "suspicious_path_keyword_count": sum(
            unquote(parsed.path).lower().count(keyword)
            for keyword in ["admin", "login", "register", "edit", "upload", "config", "shell"]
        ),
        "sensitive_endpoint_indicator": int(
            any(
                keyword in unquote(parsed.path).lower()
                for keyword in ["admin", "administrator", "login", "wp-admin", "phpmyadmin"]
            )
        ),
        "url_entropy": calculate_entropy(unquote(url)),
    }

    # Validate features against the expected schema
    validate_features(features)

    return features
