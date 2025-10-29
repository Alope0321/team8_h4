#!/usr/bin/env python3
import argparse
import os
import socket
import sys
import threading
from datetime import datetime, timezone

SERVER_NAME = "CSCI4406-HTTP-Server/1.0"
RECV_BUF = 65536

MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".htm":  "text/html; charset=utf-8",
    ".txt":  "text/plain; charset=utf-8",
    ".css":  "text/css",
    ".js":   "application/javascript",
    ".json": "application/json",
    ".png":  "image/png",
    ".jpg":  "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif":  "image/gif",
    ".svg":  "image/svg+xml",
    ".ico":  "image/x-icon",
    ".tif":  "image/tiff",
    ".tiff": "image/tiff",
    ".pdf":  "application/pdf",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".csv":  "text/csv; charset=utf-8",
    ".xml":  "application/xml",
    ".zip":  "application/zip",
    ".gz":   "application/gzip",
    ".tar":  "application/x-tar",
    ".mp3":  "audio/mpeg",
    ".wav":  "audio/wav",
    ".mp4":  "video/mp4",
    ".o":    "application/octet-stream",
}

# --- concurrency accounting ---
total_open_conns = 0
open_conns_by_client = {}   # dict[str, int]
acct_lock = threading.Lock()

def http_date():
    now = datetime.now(timezone.utc)
    return now.strftime("%a, %d %b %Y %H:%M:%S GMT")

def status_line(code):
    phrases = {
        200: "OK",
        400: "Bad Request",
        404: "Not Found",
        405: "Method Not Allowed",
        429: "Too Many Requests",
        500: "Internal Server Error",
        503: "Service Unavailable",
    }
    return f"HTTP/1.0 {code} {phrases.get(code, 'Unknown')}\r\n"

def guess_mime(path):
    _, ext = os.path.splitext(path.lower())
    return MIME_TYPES.get(ext, "application/octet-stream")

def safe_path(root, url_path):
    url_path = url_path.split("?")[0].split("#")[0]
    if url_path.endswith("/"):
        url_path += "index.html"
    if url_path == "/":
        url_path = "/index.html"
    normalized = os.path.normpath(url_path.lstrip("/"))
    full_path = os.path.join(root, normalized)
    real_root = os.path.realpath(root)
    real_path = os.path.realpath(full_path)
    if not real_path.startswith(real_root):
        return None
    return real_path

def send_response(conn, code, headers, body_bytes):
    headers_base = {
        "Date": http_date(),
        "Server": SERVER_NAME,
        "Content-Length": str(len(body_bytes)),
        "Connection": "close",
    }
    headers_base.update(headers)
    resp = status_line(code)
    for k, v in headers_base.items():
        resp += f"{k}: {v}\r\n"
    resp += "\r\n"
    try:
        conn.sendall(resp.encode("utf-8") + body_bytes)
    except Exception:
        pass  # best-effort write for error paths

def parse_headers(raw_request_bytes):
    """
    Returns (request_line:str, headers:dict[str,str]).
    Only parses up to the first blank line.
    """
    try:
        raw = raw_request_bytes.decode("utf-8", errors="ignore")
        head = raw.split("\r\n\r\n", 1)[0]
        lines = head.split("\r\n")
        if not lines:
            return "", {}
        req_line = lines[0]
        headers = {}
        for line in lines[1:]:
            if not line:
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return req_line, headers
    except Exception:
        return "", {}

def compute_client_id(addr, headers):
    """
    Client application identity:
    1) Prefer X-Client-App header (exact string)
    2) Else fallback to (User-Agent, source IP, Host)
    """
    x_client = headers.get("x-client-app")
    if x_client:
        return f"xhdr:{x_client}"
    ua = headers.get("user-agent", "UA-unknown")
    host = headers.get("host", "host-unknown")
    ip = addr[0] if isinstance(addr, tuple) and len(addr) >= 1 else "ip-unknown"
    return f"heur:{ua}|{ip}|{host}"

def admit_connection(client_id, maxtotal, maxclient):
    """
    Try to reserve a slot globally and in the client's bucket.
    Returns: (ok:bool, over_which:str|None) where over_which in {"global","client",None}
    """
    global total_open_conns, open_conns_by_client
    with acct_lock:
        if total_open_conns >= maxtotal:
            return False, "global"
        current = open_conns_by_client.get(client_id, 0)
        if current >= maxclient:
            return False, "client"
        # admit
        total_open_conns += 1
        open_conns_by_client[client_id] = current + 1
        return True, None

def release_connection(client_id):
    global total_open_conns, open_conns_by_client
    with acct_lock:
        total_open_conns = max(0, total_open_conns - 1)
        if client_id in open_conns_by_client:
            newv = max(0, open_conns_by_client[client_id] - 1)
            if newv == 0:
                del open_conns_by_client[client_id]
            else:
                open_conns_by_client[client_id] = newv

def handle_client(conn, addr, root, first_chunk):
    client_id = None
    try:
        # We already have some bytes in first_chunk; parse request line & headers
        req_line, headers = parse_headers(first_chunk)
        if not req_line:
            send_response(conn, 400, {"Content-Type": "text/plain"}, b"Bad Request\n")
            return

        # Identify client app
        client_id = compute_client_id(addr, headers)

        # At this point we were already admitted (counters incremented) in accept loop

        # Parse method and path
        try:
            method, path, _ = req_line.split()
        except ValueError:
            send_response(conn, 400, {"Content-Type": "text/plain"}, b"Bad Request\n")
            return

        if method != "GET":
            send_response(conn, 405, {"Content-Type": "text/plain"}, b"Method Not Allowed\n")
            return

        safe_file = safe_path(root, path)
        if not safe_file or not os.path.exists(safe_file):
            send_response(conn, 404, {"Content-Type": "text/plain"}, b"Not Found\n")
            return

        with open(safe_file, "rb") as f:
            body = f.read()
        mime = guess_mime(safe_file)
        send_response(conn, 200, {"Content-Type": mime}, body)

    except Exception as e:
        msg = f"Internal Server Error: {e}\n".encode()
        send_response(conn, 500, {"Content-Type": "text/plain"}, msg)
    finally:
        try:
            conn.close()
        finally:
            if client_id is not None:
                release_connection(client_id)

def run_server(port, root, maxclient, maxtotal):
    # listener
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen(128)
        print(f"Concurrent server on http://localhost:{port}/  (root: {os.path.abspath(root)})")
        print(f"Limits: per-client={maxclient}, total={maxtotal}")

        while True:
            conn, addr = s.accept()
            # Read just enough to identify the client (headers). Set a tiny timeout.
            conn.settimeout(0.5)
            try:
                # Read up to first CRLF CRLF (or a cap) to parse headers
                chunks = []
                total = 0
                while total < 4096:  # 4KB is plenty for start line + headers
                    b = conn.recv(min(4096 - total, RECV_BUF))
                    if not b:
                        break
                    chunks.append(b)
                    total += len(b)
                    joined = b"".join(chunks)
                    if b"\r\n\r\n" in joined:
                        break
                first_chunk = b"".join(chunks)

                # Minimal parse to compute client_id for admission check
                req_line, headers = parse_headers(first_chunk)
                if not req_line:
                    # malformed → just respond and close without admitting
                    send_response(conn, 400, {"Content-Type": "text/plain"}, b"Bad Request\n")
                    conn.close()
                    continue
                client_id = compute_client_id(addr, headers)

                ok, over = admit_connection(client_id, maxtotal, maxclient)
                if not ok:
                    if over == "global":
                        send_response(conn, 503,
                                      {"Content-Type": "text/plain", "Retry-After": "5"},
                                      b"Service Unavailable: server connection limit reached\n")
                    else:
                        send_response(conn, 429,
                                      {"Content-Type": "text/plain", "Retry-After": "5"},
                                      b"Too Many Requests: per-client connection limit reached\n")
                    conn.close()
                    continue

                # admitted → hand off to a worker thread
                t = threading.Thread(target=handle_client, args=(conn, addr, root, first_chunk), daemon=True)
                t.start()

            except Exception:
                # If anything blew up before admit, just close.
                try:
                    conn.close()
                except Exception:
                    pass
                # If we admitted already, handle_client will release in finally.

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CSCI4406 Concurrent HTTP Server")
    parser.add_argument("-p", "--port", type=int, required=True, help="Port to listen on (e.g., 20001)")
    parser.add_argument("--root", default=os.getcwd(), help="Document root (default: current directory)")
    parser.add_argument("-maxclient", type=int, required=True, help="Max concurrent connections per client")
    parser.add_argument("-maxtotal", type=int, required=True, help="Max total concurrent connections")
    args = parser.parse_args()

    if args.maxclient <= 0 or args.maxtotal <= 0:
        print("maxclient and maxtotal must be > 0", file=sys.stderr)
        sys.exit(2)

    try:
        run_server(args.port, args.root, args.maxclient, args.maxtotal)
    except KeyboardInterrupt:
        print("\nServer stopped.")
        sys.exit(0)
