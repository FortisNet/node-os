"""A release store for the host tests: static files over HTTPS on loopback,
with range requests, the way an object store serves them."""
import http.server
from pathlib import Path
import re
import ssl
import threading


class Store:
    """Serve `folder`. `requests` records (path, Range header) of every GET."""

    def __init__(self, folder: Path, certificate: Path, key: Path):
        self.folder, self.requests = folder, []
        self.truncate = {}   # path -> number of bytes to cut from the end of each answer
        store = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_):
                pass

            def do_GET(self):
                store.requests.append((self.path, self.headers.get('Range')))
                target = (store.folder / self.path.lstrip('/')).resolve()
                if store.folder.resolve() not in target.parents or not target.is_file():
                    self.send_response(404)
                    self.send_header('Content-Length', '0')
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    return
                data, status = target.read_bytes(), 200
                requested = re.fullmatch(r'bytes=(\d+)-(\d+)', self.headers.get('Range') or '')
                if requested:
                    first, last = int(requested[1]), min(int(requested[2]), len(data) - 1)
                    total, data, status = len(data), data[first:last + 1], 206
                cut = store.truncate.get(self.path, 0)
                if cut:
                    data = data[:-cut]
                self.send_response(status)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Length', str(len(data)))
                if status == 206:
                    self.send_header('Content-Range', f'bytes {first}-{first + len(data) - 1}/{total}')
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(data)

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.url = f'https://127.0.0.1:{self.server.server_address[1]}'
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
