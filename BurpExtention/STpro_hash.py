from burp import IBurpExtender, IHttpListener
import json
import threading

try:
    from java.net import URL, HttpURLConnection
    from java.io import BufferedReader, InputStreamReader, DataOutputStream
except:
    pass


class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._cache = set()
        self._lock = threading.Lock()

        callbacks.setExtensionName("Request/Response Forwarder")
        callbacks.registerHttpListener(self)

        print("[*] Request/Response Forwarder loaded")
        print("[*] Forwarding to 127.0.0.1:8888")

    def _get_cache_key(self, method, path):
        return "{}:{}".format(method, path)

    def _is_cached(self, key):
        with self._lock:
            return key in self._cache

    def _add_cache(self, key):
        with self._lock:
            self._cache.add(key)

    def _send_to_server(self, data):
        try:
            url = URL("http://127.0.0.1:8888/forward")
            conn = url.openConnection()
            conn.setRequestMethod("POST")
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setDoOutput(True)

            body = json.dumps(data)
            out = DataOutputStream(conn.getOutputStream())
            out.writeBytes(body)
            out.flush()
            out.close()

            code = conn.getResponseCode()
            conn.disconnect()
            print("[*] Forwarded -> {} {} (HTTP {})".format(data.get("method"), data.get("path"), code))
        except Exception as e:
            print("[!] Forward failed: {}".format(str(e)))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Process on response so we have both request and response
        if messageIsRequest:
            return

        request = messageInfo.getRequest()
        response = messageInfo.getResponse()

        if not request or not response:
            return

        request_info = self._helpers.analyzeRequest(messageInfo)
        method = request_info.getMethod()
        url = request_info.getUrl()
        path = url.getPath()

        cache_key = self._get_cache_key(method, path)

        if self._is_cached(cache_key):
            return

        self._add_cache(cache_key)

        # Build request data
        request_headers = list(request_info.getHeaders())
        request_body_offset = request_info.getBodyOffset()
        request_body = self._helpers.bytesToString(request[request_body_offset:])

        # Build response data
        response_info = self._helpers.analyzeResponse(response)
        response_headers = list(response_info.getHeaders())
        response_body_offset = response_info.getBodyOffset()
        response_body = self._helpers.bytesToString(response[response_body_offset:])
        status_code = response_info.getStatusCode()

        data = {
            "method": method,
            "path": path,
            "host": str(url.getHost()),
            "port": url.getPort(),
            "protocol": str(url.getProtocol()),
            "request": {
                "headers": request_headers,
                "body": request_body
            },
            "response": {
                "status_code": status_code,
                "headers": response_headers,
                "body": response_body
            }
        }

        # Send in a separate thread to avoid blocking
        t = threading.Thread(target=self._send_to_server, args=(data,))
        t.start()
