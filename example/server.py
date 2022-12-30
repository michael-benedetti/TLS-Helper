from flask import Flask, Response
import os

ASSETS_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)


@app.route('/')
def index():
    return Response("Flask is running with TLS!")


if __name__ == '__main__':
    context = ('server.pem', 'server.key')
    app.run(debug=True, ssl_context=context)
