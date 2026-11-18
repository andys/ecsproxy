import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
PORT = sys.argv[1] if len(sys.argv) > 1 else "9000"
R = {
 "ListTasks": {"taskArns": ["arn:aws:ecs:us-east-1:1:task/bench/abc"]},
 "DescribeTasks": {"failures": [], "tasks": [{"taskArn": "arn:aws:ecs:us-east-1:1:task/bench/abc",
   "taskDefinitionArn": "arn:aws:ecs:us-east-1:1:task-definition/hello:1", "lastStatus": "RUNNING",
   "containers": [{"name": "app", "networkInterfaces": [{"privateIpv4Address": "127.0.0.1"}]}]}]},
 "DescribeTaskDefinition": {"taskDefinition": {"family": "hello", "containerDefinitions": [
   {"name": "app", "dockerLabels": {"proxy-hostname": "bench.local", "proxy-port": PORT}}]}},
}
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", 0)))
        op = self.headers.get("x-amz-target", "").split(".")[-1]
        body = json.dumps(R[op]).encode() if op in R else b"{}"
        self.send_response(200 if op in R else 500)
        self.send_header("content-type", "application/x-amz-json-1.1")
        self.send_header("content-length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    do_GET = do_PUT = do_HEAD = do_POST
ThreadingHTTPServer(("127.0.0.1", 4566), H).serve_forever()
