"""
An example flask server that leverages a TLS certificate and private key generated by TLS Helper.

If the generated root CA certificate has been installed and trusted for web traffic on a target device, and the device
is resolving DNS queries to target domains to your server's IP, a valid TLS session will be established!
"""

from flask import Flask, Response, jsonify

app = Flask(__name__)

# Stub a 204 response from /generate_204
# This can be used to trick an Android phone into thinking it has internet connection!
# Android phones will reach out to http://www.gstatic.com/generate_204 and https://www.google.com/generate_204 to
# determine connectivity.
@app.route('/generate_204')
def generate_204():
    return Response(status=204)


# Stub a response from the /login endpoint
@app.route('/login')
def login():
    return jsonify(
        username="admin",
        displayName="Administrator",
        role="admin",
    )

if __name__ == '__main__':
    # Set the context to use the certificate and key generated by TLS Helper
    context = ('server.pem', 'server.key')
    # Run the server
    app.run(debug=True, ssl_context=context)
