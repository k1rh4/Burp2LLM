import json
import os
import sys
import glob
import re
import base64
import argparse

from openai import OpenAI

# --- Config ---
LITELLM_BASE_URL = os.environ.get("LITELLM_BASE_URL", "http://127.0.0.1:4000")
LITELLM_API_KEY = os.environ.get("LITELLM_API_KEY", "sk-1234")
LITELLM_MODEL = os.environ.get("LITELLM_MODEL", "gpt-4o")
PACKET_DIR = os.environ.get("PACKET_DIR", "../CollectServer/packets")
MAX_PACKETS_PER_CHUNK = int(os.environ.get("MAX_PACKETS_PER_CHUNK", "20"))
LARGE_VALUE_THRESHOLD = 500


def _detect_data_type(value):
    """Detect the type of large data."""
    if not isinstance(value, str):
        return "unknown"

    # base64 pattern
    if re.match(r'^[A-Za-z0-9+/=\s]{100,}$', value.strip()):
        try:
            base64.b64decode(value.strip()[:200])
            return "base64"
        except Exception:
            pass

    # binary-like (high ratio of non-printable or escape sequences)
    non_printable = sum(1 for c in value[:500] if ord(c) < 32 and c not in '\n\r\t')
    if len(value[:500]) > 0 and non_printable / len(value[:500]) > 0.1:
        return "binary"

    # HTML/JS
    if "<html" in value[:200].lower() or "<script" in value[:200].lower():
        return "html"

    # JSON
    stripped = value.strip()
    if (stripped.startswith("{") and stripped.endswith("}")) or \
       (stripped.startswith("[") and stripped.endswith("]")):
        return "json"

    return "text"


def _human_size(length):
    """Convert byte length to human readable."""
    if length < 1024:
        return "{}B".format(length)
    elif length < 1024 * 1024:
        return "{:.1f}KB".format(length / 1024)
    else:
        return "{:.1f}MB".format(length / (1024 * 1024))


def sanitize_large_value(value):
    """Replace large values with a descriptive placeholder."""
    if not isinstance(value, str) or len(value) < LARGE_VALUE_THRESHOLD:
        return value

    data_type = _detect_data_type(value)
    size = _human_size(len(value))
    return "[LARGE_DATA:{}, {}]".format(data_type, size)


def sanitize_body(body):
    """Sanitize request/response body, replacing large values with placeholders."""
    if not body or len(body) < LARGE_VALUE_THRESHOLD:
        return body

    # Try to parse as JSON and sanitize individual fields
    stripped = body.strip()
    if (stripped.startswith("{") or stripped.startswith("[")):
        try:
            parsed = json.loads(stripped)
            sanitized = _sanitize_json(parsed)
            return json.dumps(sanitized, ensure_ascii=False, indent=2)
        except (json.JSONDecodeError, ValueError):
            pass

    # Try to handle URL-encoded form data
    if "=" in body and "&" in body and "\n" not in body[:200]:
        try:
            pairs = body.split("&")
            sanitized_pairs = []
            for pair in pairs:
                if "=" in pair:
                    key, val = pair.split("=", 1)
                    val = sanitize_large_value(val)
                    sanitized_pairs.append("{}={}".format(key, val))
                else:
                    sanitized_pairs.append(pair)
            return "&".join(sanitized_pairs)
        except Exception:
            pass

    # Multipart form-data: sanitize each part's body
    if "Content-Disposition: form-data" in body:
        return _sanitize_multipart(body)

    # Fallback: treat whole body as a single value
    return sanitize_large_value(body)


def _sanitize_json(obj):
    """Recursively sanitize JSON values."""
    if isinstance(obj, dict):
        return {k: _sanitize_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_sanitize_json(item) for item in obj]
    elif isinstance(obj, str):
        return sanitize_large_value(obj)
    return obj


def _sanitize_multipart(body):
    """Sanitize multipart form-data, replacing file content with placeholders."""
    parts = re.split(r'(------\S+)', body)
    result = []
    for part in parts:
        if "Content-Disposition: form-data" in part and "filename=" in part:
            # File upload part — keep headers, replace content
            header_end = part.find("\r\n\r\n")
            if header_end == -1:
                header_end = part.find("\n\n")
            if header_end != -1:
                header = part[:header_end + 4]
                content = part[header_end + 4:]
                data_type = _detect_data_type(content)
                size = _human_size(len(content))
                part = header + "[LARGE_DATA:{}, {}]".format(data_type, size)
        elif len(part) > LARGE_VALUE_THRESHOLD and "Content-Disposition" not in part:
            part = sanitize_large_value(part)
        result.append(part)
    return "".join(result)


def _clean_surrogates(obj):
    """Recursively remove surrogate characters from strings."""
    if isinstance(obj, str):
        return obj.encode("utf-8", errors="replace").decode("utf-8")
    elif isinstance(obj, dict):
        return {k: _clean_surrogates(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_clean_surrogates(item) for item in obj]
    return obj


def load_packets(packet_dir):
    """Load all packet JSON files sorted by sequence number."""
    pattern = os.path.join(packet_dir, "*.json")
    files = sorted(glob.glob(pattern))

    packets = []
    for filepath in files:
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
                data = _clean_surrogates(data)
                data["_filename"] = os.path.basename(filepath)
                packets.append(data)
        except Exception as e:
            print("[!] Failed to load {}: {}".format(filepath, e))

    return packets


def format_packet_summary(packets):
    """Create a summary table of all loaded packets."""
    lines = ["Loaded {} packets:\n".format(len(packets))]
    lines.append("{:<6} {:<8} {:<50} {:<6}".format("#", "METHOD", "PATH", "STATUS"))
    lines.append("-" * 72)

    for i, pkt in enumerate(packets, 1):
        method = pkt.get("method", "?")
        path = pkt.get("path", "?")
        status = pkt.get("response", {}).get("status_code", "?")
        lines.append("{:<6} {:<8} {:<50} {:<6}".format(i, method, path[:50], status))

    return "\n".join(lines)


def format_packets_for_context(packets):
    """Format packets as structured text for LLM context."""
    parts = []
    for i, pkt in enumerate(packets, 1):
        method = pkt.get("method", "?")
        path = pkt.get("path", "?")
        host = pkt.get("host", "?")
        protocol = pkt.get("protocol", "http")
        port = pkt.get("port", 80)

        req = pkt.get("request", {})
        resp = pkt.get("response", {})

        req_headers = "\n".join(req.get("headers", []))
        req_body = sanitize_body(req.get("body", ""))
        resp_headers = "\n".join(resp.get("headers", []))
        resp_body = sanitize_body(resp.get("body", ""))

        part = (
            "=== Packet #{idx} ===\n"
            "URL: {proto}://{host}:{port}{path}\n"
            "Method: {method}\n\n"
            "-- Request Headers --\n{req_headers}\n\n"
            "-- Request Body --\n{req_body}\n\n"
            "-- Response Status: {status} --\n"
            "-- Response Headers --\n{resp_headers}\n\n"
            "-- Response Body --\n{resp_body}\n"
        ).format(
            idx=i,
            proto=protocol,
            host=host,
            port=port,
            path=path,
            method=method,
            req_headers=req_headers,
            req_body=req_body if req_body else "(empty)",
            status=resp.get("status_code", "?"),
            resp_headers=resp_headers,
            resp_body=resp_body if resp_body else "(empty)",
        )
        parts.append(part)

    return "\n\n".join(parts)


SYSTEM_PROMPT = """\
You are a security analysis assistant. You have access to HTTP request/response packets \
captured from a web application via Burp Suite.

Your job is to:
1. Analyze the packets when the user asks questions
2. Identify potential security vulnerabilities (OWASP Top 10, business logic flaws, etc.)
3. Explain API structure, authentication flow, and data flow
4. Highlight suspicious patterns, sensitive data exposure, or misconfigurations
5. Provide actionable insights for penetration testing

When analyzing, be specific — reference packet numbers, endpoints, headers, and parameters.
Answer in the user's language.
"""


def build_messages(packets, conversation, chunk_start, chunk_end):
    """Build the message list for the LLM API call."""
    chunk = packets[chunk_start:chunk_end]
    context = format_packets_for_context(chunk)

    system_content = SYSTEM_PROMPT + "\n\n" + \
        "The following HTTP packets (#{} ~ #{}) are loaded as context:\n\n{}".format(
            chunk_start + 1, chunk_end, context
        )

    messages = [
        {"role": "system", "content": system_content},
    ]
    messages.extend(conversation)
    return messages


def main():
    parser = argparse.ArgumentParser(description="Burp2LLM Packet Analysis Agent")
    parser.add_argument("--packet-dir", default=PACKET_DIR, help="Packet directory path")
    parser.add_argument("--model", default=LITELLM_MODEL, help="LiteLLM model name")
    parser.add_argument("--base-url", default=LITELLM_BASE_URL, help="LiteLLM base URL")
    parser.add_argument("--api-key", default=LITELLM_API_KEY, help="LiteLLM API key")
    parser.add_argument("--chunk-size", type=int, default=MAX_PACKETS_PER_CHUNK, help="Packets per chunk")
    args = parser.parse_args()

    client = OpenAI(base_url=args.base_url, api_key=args.api_key)

    # Load packets
    print("[*] Loading packets from: {}".format(args.packet_dir))
    packets = load_packets(args.packet_dir)

    if not packets:
        print("[!] No packets found. Make sure CollectServer has captured packets.")
        sys.exit(1)

    print(format_packet_summary(packets))

    # Chunk management
    total = len(packets)
    chunk_size = args.chunk_size
    chunk_start = 0
    chunk_end = min(chunk_size, total)

    print("\n[*] Viewing packets #{} ~ #{} (total: {})".format(chunk_start + 1, chunk_end, total))
    print("[*] Model: {} @ {}".format(args.model, args.base_url))
    print()
    print("Commands:")
    print("  /next        - Load next chunk of packets")
    print("  /prev        - Load previous chunk of packets")
    print("  /jump <n>    - Jump to packet #n")
    print("  /list        - Show packet summary")
    print("  /reload      - Reload packets from disk")
    print("  /reset       - Clear conversation history")
    print("  /quit        - Exit")
    print()

    conversation = []

    while True:
        try:
            user_input = input("You> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Bye!")
            break

        if not user_input:
            continue

        # --- Commands ---
        if user_input == "/quit":
            print("[*] Bye!")
            break

        elif user_input == "/next":
            if chunk_end >= total:
                print("[!] Already at the last chunk.")
            else:
                chunk_start = chunk_end
                chunk_end = min(chunk_start + chunk_size, total)
                print("[*] Now viewing packets #{} ~ #{}".format(chunk_start + 1, chunk_end))
            continue

        elif user_input == "/prev":
            if chunk_start <= 0:
                print("[!] Already at the first chunk.")
            else:
                chunk_end = chunk_start
                chunk_start = max(chunk_end - chunk_size, 0)
                print("[*] Now viewing packets #{} ~ #{}".format(chunk_start + 1, chunk_end))
            continue

        elif user_input.startswith("/jump"):
            parts = user_input.split()
            if len(parts) == 2 and parts[1].isdigit():
                n = int(parts[1])
                if 1 <= n <= total:
                    chunk_start = n - 1
                    chunk_end = min(chunk_start + chunk_size, total)
                    print("[*] Now viewing packets #{} ~ #{}".format(chunk_start + 1, chunk_end))
                else:
                    print("[!] Invalid packet number. Range: 1-{}".format(total))
            else:
                print("Usage: /jump <packet_number>")
            continue

        elif user_input == "/list":
            print(format_packet_summary(packets))
            continue

        elif user_input == "/reload":
            packets = load_packets(args.packet_dir)
            total = len(packets)
            chunk_start = 0
            chunk_end = min(chunk_size, total)
            conversation = []
            print("[*] Reloaded {} packets. Conversation cleared.".format(total))
            continue

        elif user_input == "/reset":
            conversation = []
            print("[*] Conversation history cleared.")
            continue

        # --- LLM Query ---
        conversation.append({"role": "user", "content": user_input})

        messages = build_messages(packets, conversation, chunk_start, chunk_end)

        try:
            print("\nAssistant> ", end="", flush=True)
            response = client.chat.completions.create(
                model=args.model,
                messages=messages,
                stream=True,
            )

            full_response = []
            for chunk in response:
                delta = chunk.choices[0].delta
                if delta.content:
                    print(delta.content, end="", flush=True)
                    full_response.append(delta.content)

            print("\n")
            assistant_msg = "".join(full_response)
            conversation.append({"role": "assistant", "content": assistant_msg})

        except Exception as e:
            print("\n[!] LLM request failed: {}".format(e))
            conversation.pop()  # Remove failed user message


if __name__ == "__main__":
    main()
