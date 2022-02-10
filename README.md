# Bot Filter

A workspace for my ideas around bot filtration. I hope to culminate
this project into my final project for [Machine Learning and Computational Modeling](http://jorr.cs.georgefox.edu/courses/csis441-machine-learning).

## Run
1. Generate a self-signed cert for local development:
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365
```
2. Test
```bash
go mod download
go run main.go /path/to/cert.pem /path/to/key.pem
```


## Thanks/licenses
* Original modifications found in [CapacitorSet's ja3-server](https://github.com/CapacitorSet/ja3-server)
* Original algorithm: [Salesforce](https://github.com/salesforce/ja3)
* Golang implementation: [Remco Verhoef](https://github.com/honeytrap/honeytrap/commit/192795147948103a24d34dc06dba74eecdeb086b), copyright DutchSec, AGPL 3.
* Golang stdlib (`crypto/tls`, `net/http`): copyright the Go authors, BSD.