"""Run the extracted Linux download against a disposable HTTPS receiver."""

import json
import os
from pathlib import Path
from queue import Empty, Queue
import secrets
import ssl
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Thread
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def smoke(collector):
    source = "collector-" + secrets.token_hex(10)
    key = secrets.token_hex(32)
    snapshots = Queue()

    class Receiver(BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.send_response(200 if self.path == "/api/cloud/health" else 404)
            self.end_headers()

        def do_POST(self):
            if self.path != "/api/cloud/snapshot":
                self.send_error(404)
                return
            if self.headers.get("Authorization") != f"Bearer {key}":
                self.send_error(401)
                return
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 700_000:
                self.send_error(400)
                return
            snapshots.put(json.loads(self.rfile.read(size)))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_args):
            pass

    with TemporaryDirectory() as folder:
        certificate = Path(folder) / "localhost.pem"
        private_key = Path(folder) / "localhost.key"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
            "-keyout", str(private_key), "-out", str(certificate),
        ], check=True, capture_output=True)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(certificate, private_key)

        with ThreadingHTTPServer(("127.0.0.1", 0), Receiver) as server:
            server.socket = tls.wrap_socket(server.socket, server_side=True)
            receiver = Thread(target=server.serve_forever, daemon=True)
            receiver.start()
            try:
                port = server.server_address[1]
                env = {**os.environ, "SSL_CERT_FILE": str(certificate), "NO_PROXY": "127.0.0.1"}
                with (Path(folder) / "collector.log").open("w+", encoding="utf-8") as log:
                    with subprocess.Popen([
                        "bash", str(collector / "tools/Start-NorthCollectorLinux.sh"),
                        source, f"https://127.0.0.1:{port}",
                    ], stdin=subprocess.PIPE, stdout=log, stderr=log, env=env) as process:
                        try:
                            process.stdin.write(key.encode() + b"\n")
                            process.stdin.close()
                            for _ in range(150):
                                if process.poll() is not None:
                                    raise RuntimeError(f"Collector exited with code {process.returncode}")
                                try:
                                    snapshot = snapshots.get(timeout=1)
                                    break
                                except Empty:
                                    continue
                            else:
                                raise TimeoutError("Collector did not send its first snapshot")
                            if snapshot["source"]["id"] != source or "linux_journal" not in snapshot["network"]:
                                raise RuntimeError("First snapshot did not identify the Linux collector")
                        except Exception:
                            log.seek(0)
                            print(log.read().replace(key, "[redacted]"), file=sys.stderr)
                            raise
                        finally:
                            if process.poll() is None:
                                process.terminate()
                                try:
                                    process.wait(timeout=5)
                                except subprocess.TimeoutExpired:
                                    process.kill()
                                    process.wait()
            finally:
                server.shutdown()
                receiver.join()

    print("Linux collector sent its first authenticated snapshot over HTTPS.")


if __name__ == "__main__":
    smoke(Path(sys.argv[1]).resolve())
