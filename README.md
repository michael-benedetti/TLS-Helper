# TLS Helper

Generate a full TLS certificate chain and Coredns configuration without the headache!

## Why?
The original purpose of this project was to enable easy server communication stubbing for reverse engineering purposes.  

Imagine you are attempting to analyze how an Android application is communicating with a remote server.  Through your 
reverse engineering endeavors, you can see that the app is sending a `POST` request to `https://api.example.com/login` 
and expecting a `JSON` object to return that contains user details.  If we had our own server that could act as a 
stand-in for `api.example.com`, we could send whatever response we want back to the app.  This opens up some nice 
possibilities for conducting dynamic analysis without needing to hook a bunch of app functionality.

Since the app is communicating via `HTTPS`, to act as a stand-in server, we need to have valid `TLS` certificates from a
trusted certificate authority, and we need to own the domain `api.example.com` -- OR we can create our own certificate 
chain, make our target Android device trust our root CA, and use our own DNS server to direct traffic headed towards 
`api.example.com` to our own ip.  Setting all of that up seems like a lot of work, but that's where `TLS Helper` comes 
in.

## Requirements
`TLS Helper` requires `python3` and is operating system independent.  Other dependencies will be installed 
automatically.  See [setup.py](setup.py) for the full list of dependencies.

## Installation

Run `python3 -m pip install git+https://github.com/michael-benedetti/TLS-Helper`

OR

Clone this repository and run `python3 -m pip install .`

Following installation, you may need to add the location of the emitted command line utility to your `PATH`.  See the
output from the above command for instructions.

## Usage

```
$ tlshelper
Usage: tlshelper [OPTIONS]

  Generate a full TLS certificate chain and Coredns configuration without the
  headache!

Options:
  Domain Extraction: [mutually_exclusive, required]
    -f, --file PATH               Path to a file containing domain entries -
                                  one per line.
    -p, --pcap PATH               Extract DNS queries from a single PCAP.
    -d, --pcap-diff               Perform a diff of two PCAP files - a
                                  baseline and a target PCAP.  Produces
                                  domains that only exist in the target PCAP
                                  and do not exist in the baseline PCAP.
  PCAP Diff Options:
    -b, --baseline-pcap PATH      Path to the baseline PCAP when performing
                                  PCAP diff.
    -t, --target-pcap PATH        Path to the target PCAP when performing PCAP
                                  diff.
  Coredns Generation:
    -c, --coredns                 Generate Coredns config.  Requires an IP
                                  address - see --ip-address.
    -i, --ip-address TEXT         IP address to route traffic to when
                                  generating Coredns config files.
  Certificate Authority Settings:
    --ca-country, --ca-c TEXT     Country Name field for the CA certificate
                                  subject.  [default: US]
    --ca-state, --ca-s TEXT       State or Province field for the CA
                                  certificate subject.  [default: State]
    --ca-locality, --ca-l TEXT    Locality Name field for the CA certificate
                                  subject.  [default: Locality]
    --ca-organization, --ca-o TEXT
                                  Organization Name field for the CA
                                  certificate subject.  [default:
                                  Organization]
    --ca-common-name, --ca-cn TEXT
                                  Common Name field for the CA certificate
                                  subject.  [default: example.ca]
    --ca-expire-days, --ca-e INTEGER
                                  Number of days until CA certificate expires.
                                  [default: 365]
  Server Certificate Settings:
    --server-country, --s-c TEXT  Country Name field for the server
                                  certificate subject.  [default: US]
    --server-state, --s-s TEXT    State or Province field for the server
                                  certificate subject.  [default: State]
    --server-locality, --s-l TEXT
                                  Locality Name field for the server
                                  certificate subject.  [default: Locality]
    --server-organization, --s-o TEXT
                                  Organization Name field for the server
                                  certificate subject.  [default:
                                  Organization]
    --server-common-name, --s-cn TEXT
                                  Common Name field for the server certificate
                                  subject.  [default: example.com]
    --server-expire-days, --s-e INTEGER
                                  Number of days until server certificate
                                  expires.  [default: 365]
  -h, --help                      Show this message and exit.
```