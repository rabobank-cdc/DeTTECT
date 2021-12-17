import webbrowser
import os
import signal
import threading
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer


class QuietHTTPRequestHandler(SimpleHTTPRequestHandler):

    def log_message(self, format, *args):
        pass

    def log_request(self, code='-', size='-'):
        pass


class DeTTECTEditor:

    def __init__(self, port):
        """
        Constructor of the DeTTECTEditor class. Sets the SIGTERM (clean quit) en SIGINT (Ctrl+C) handlers and the default variables.
        :param port: The port for the webserver to listen on
        """
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        self.port = port
        self.httpd = None

    def _signal_handler(self, signal, frame):
        """
        Handles the termination of the application.
        :param signum: Indicator of the termination signal
        :param frame:
        """
        print("Shutting down webserver")
        self.httpd.server_close()
        self.httpd.shutdown()

    def _run_webserver(self):
        """
        Starts the webserver on the given port.
        """
        try:
            os.chdir('./editor/dist/dettect-editor')
            self.httpd = TCPServer(('', self.port), QuietHTTPRequestHandler)

            print("Editor started at port %d" % self.port)
            url = 'http://localhost:%d/' % self.port

            if not os.getenv('DeTTECT_DOCKER_CONTAINER'):
                print("Opening webbrowser: " + url)
                webbrowser.open_new_tab(url)
            else:
                print("You can open the Editor on: " + url)

            self.httpd.serve_forever()
        except Exception as e:
            print("Could not start webserver: " + str(e))

    def start(self):
        """
        Starts the Editor by starting a thread where the webserver runs in.
        """
        thread = threading.Thread(target=self._run_webserver)
        thread.start()


if __name__ == '__main__':
    print("Please use dettect.py for running the DeTT&CT Editor. Run 'python dettect.py e -h' for more information.")
