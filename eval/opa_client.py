import http.client, json
class OPA:
    def __init__(self, host="127.0.0.1", port=8181):
        self.conn = http.client.HTTPConnection(host, port)
    def violations(self, resource):
        body = json.dumps({"input": resource})
        self.conn.request("POST", "/v1/data/pac/normative/violations", body, {"Content-Type": "application/json"})
        return json.loads(self.conn.getresponse().read()).get("result", [])
