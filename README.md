# An SNMP v2c/v3 client library written in Rust

The workspace has two crates:

- [`snmprs_lib`](src/snmprs_lib): the library
- [`snmprs_client`](src/snmprs_client): `snmprs`, a sample command-line client

## Status

Early development; the API will change.

| Feature                                        | Status      |
| ---------------------------------------------- | ----------- |
| OID parsing and validation                     | Done        |
| v2c message encoding (Get, GetNext, GetBulk, Set) | Done     |
| UDP send and receive                           | Done        |
| Message decoding                               | Not started |
| Request retries and request-id matching        | Not started |
| v3 message format, USM auth and privacy        | Not started |

Until decoding exists, the client prints responses as hex:

```sh
cargo run -p snmprs_client -- -i 127.0.0.1 v2 -c public get 1.3.6.1.2.1.1.1.0
```
