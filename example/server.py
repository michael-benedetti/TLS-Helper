from flask import Flask, jsonify
import os

ASSETS_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)


@app.route('/')
def index():
    return 'Flask is running!'


@app.route('/data')
def names():
    data = {"names": ["John", "Jacob", "Julie", "Jennifer"]}
    return jsonify(data)


if __name__ == '__main__':
    context = ('server.pem', 'server.key')#certificate and key files
    app.run(debug=True, ssl_context=context)