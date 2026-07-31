# nfs-v2

NFS version 2 ([RFC 1094]): all 18 procedures and the fixed-width wire format.

The version is long obsolete and still enabled on plenty of servers, which is exactly why it matters. It is the weakest of the three by a wide margin:

- **No security negotiation at all** ([RFC 2623] sec. 2.7). The server cannot advertise, and the client cannot request, anything beyond AUTH_SYS.
- **No `ACCESS` procedure.** NFSv3 added it so a client could ask what it would be permitted to do; under v2 a client simply tries the operation and finds out.
- **Fixed 32-byte file handles** with no length prefix (`FHSIZE = 32`, RFC 1094 sec. 2.3.3), unlike NFSv3's variable-length handle. That difference in XDR encoding is why these types cannot share NFSv3's.

Some servers apply `root_squash` on their v3 path but not their v2 path, so where both are offered, v2 is worth probing first.

Like the other protocol crates here, this one is generic over `onc_rpc_client::RpcTransport` and carries no connection policy of its own.

## Pre-1.0

This crate is pre-1.0. The API may change between minor versions.

[RFC 1094]: https://www.rfc-editor.org/rfc/rfc1094
[RFC 2623]: https://www.rfc-editor.org/rfc/rfc2623
