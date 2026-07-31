# onc-rpcbind

Portmapper v2 ([RFC 1057] appendix A) and rpcbind v3/v4 ([RFC 1833]) clients for ONC RPC service discovery.

Given a host running NFS, this crate talks to its portmapper or rpcbind daemon to find out which RPC programs are registered, what ports they listen on, and (via rpcbind v3/v4) the server's clock and per-version call statistics. The portmapper runs on the well-known port 111 and answers before any NFS call is made, so it is the first service a scanner touches.

Generic over `onc_rpc_client::RpcTransport`, so it carries no connection policy of its own.

## Pre-1.0

This crate is pre-1.0. The API may change between minor versions.

[RFC 1057]: https://www.rfc-editor.org/rfc/rfc1057
[RFC 1833]: https://www.rfc-editor.org/rfc/rfc1833
