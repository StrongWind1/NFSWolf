# RFC Index

Comprehensive index of every NFS-related RFC. This page catalogs 59 documents spanning 38 years of NFS protocol development, from the original XDR encoding standard (RFC 1014, 1987) through the latest NFSv4.2 extensions (RFC 9766, 2025).

RFCs marked with :material-star: are **primary references** -- nfswolf's protocol crates implement them directly, or the analyzer/shell references specific sections in source comments. The rest provide context for the broader NFS ecosystem.

All listed RFCs are available locally in `ref/rfc/` (primary) and `ref/all_rfcs/` (complete corpus).

!!! info "How to read this page"
    Each table is sorted chronologically. The **Status** column reflects the current IETF status. The **nfswolf relevance** column tells you which crate implements the RFC, which findings reference it, or whether it is context-only. Use ++ctrl+f++ to search by RFC number.

---

## Core NFS protocols

The protocol specifications that define NFSv2, v3, v4.0, v4.1, and v4.2. These are the documents that describe the actual file operations -- LOOKUP, READ, WRITE, COMPOUND, and so on.

| RFC | Year | Title | Status | nfswolf relevance |
|-----|------|-------|--------|-------------------|
| :material-star: [1094](https://www.rfc-editor.org/rfc/rfc1094) | 1989 | NFS: Network File System Protocol Specification | Historic | Full implementation in `nfs-v2` crate: 18 procedures, fixed 32-byte handles, `Nfs2Client` domain API. Referenced 133 times in source. Also defines MOUNT v1 in Appendix A. |
| :material-star: [1813](https://www.rfc-editor.org/rfc/rfc1813) | 1995 | NFS Version 3 Protocol Specification | Informational | Full implementation in `nfs-v3` crate: 22 procedures, variable-length handles, `Nfs3Error` classification. Referenced 144 times in source. ACCESS advisory semantics (sec. 3.3.4) drive F-2.1. STALE vs BADHANDLE distinction (sec. 2.6) enables the handle oracle. Also defines MOUNT v3 in Appendix I. |
| [2624](https://www.rfc-editor.org/rfc/rfc2624) | 1999 | NFS Version 4 Design Considerations | Informational | Historical context for why NFSv4 merged MOUNT into the protocol, added COMPOUND batching, and introduced SECINFO security negotiation. |
| [3010](https://www.rfc-editor.org/rfc/rfc3010) | 2000 | NFS version 4 Protocol | Proposed Standard | Original NFSv4 specification. Obsoleted by RFC 3530, then RFC 7530. Historical reference only. |
| [3530](https://www.rfc-editor.org/rfc/rfc3530) | 2003 | Network File System (NFS) version 4 Protocol | Proposed Standard | Revised NFSv4.0 specification. Obsoleted by RFC 7530. Referenced in RFC 5661's backward-compatibility notes. |
| :material-star: [7530](https://www.rfc-editor.org/rfc/rfc7530) | 2015 | Network File System (NFS) Version 4 Protocol | Proposed Standard | Full implementation in `nfs-v4` crate: all 37 ops with typed args and response decoders, 66 named status codes, stateful infrastructure (SETCLIENTID lifecycle, OPEN/CLOSE/LOCK state), 47 public client methods. **Most-cited RFC in codebase** with 430+ references. Drives findings F-1.1 through F-5.15. |
| [7531](https://www.rfc-editor.org/rfc/rfc7531) | 2015 | NFS Version 4 External Data Representation Standard (XDR) Description | Proposed Standard | XDR companion to RFC 7530. Wire types cross-referenced during `nfs-v4` crate development for COMPOUND encoding verification. |
| [5661](https://www.rfc-editor.org/rfc/rfc5661) | 2010 | NFS Version 4 Minor Version 1 Protocol | Proposed Standard | Obsoleted by RFC 8881. Introduced sessions, directory delegations, and pNFS. Referenced 29 times in source for NFSv4.1 context. |
| [5662](https://www.rfc-editor.org/rfc/rfc5662) | 2010 | NFS Version 4 Minor Version 1 XDR Description | Proposed Standard | XDR companion to RFC 5661. Machine-readable type definitions for NFSv4.1. |
| :material-star: [8881](https://www.rfc-editor.org/rfc/rfc8881) | 2020 | NFS Version 4 Minor Version 1 Protocol | Proposed Standard | Current NFSv4.1 specification, obsoletes RFC 5661. Referenced 14 times in source for session semantics and multi-server namespace behavior. Substantially revises multi-server features. |
| [7862](https://www.rfc-editor.org/rfc/rfc7862) | 2016 | NFS Version 4 Minor Version 2 Protocol | Proposed Standard | Introduces Labeled NFS (sec. 9), server-side copy, sparse files, application I/O advise. Referenced 7 times in source; Labeled NFS is context for finding F-4.5. |
| [7863](https://www.rfc-editor.org/rfc/rfc7863) | 2016 | NFS Version 4 Minor Version 2 XDR Description | Proposed Standard | XDR companion to RFC 7862. Machine-readable type definitions for NFSv4.2. |

---

## RPC and XDR

The transport layer that every NFS version rides on. ONC RPC defines message framing and authentication; XDR defines how every field is encoded on the wire. Understanding these is essential because the authentication weaknesses (AUTH_SYS trust model, stamp replay) live at this layer, not in NFS itself.

| RFC | Year | Title | Status | nfswolf relevance |
|-----|------|-------|--------|-------------------|
| [1014](https://www.rfc-editor.org/rfc/rfc1014) | 1987 | XDR: External Data Representation Standard | Historic | Original XDR specification from Sun Microsystems. Superseded by RFC 1832, then RFC 4506. Historical reference only. |
| [1832](https://www.rfc-editor.org/rfc/rfc1832) | 1995 | XDR: External Data Representation Standard | Proposed Standard | Revised XDR, first IETF publication. Superseded by RFC 4506. Historical reference. |
| :material-star: [4506](https://www.rfc-editor.org/rfc/rfc4506) | 2006 | XDR: External Data Representation Standard | Internet Standard (STD 67) | **Current XDR standard.** Full implementation in `onc-xdr` crate: `Pack`, `Unpack`, `Opaque`, `List`, `BoundedList`, `Void`, padding, and length-hardened readers. Referenced 43 times in source. The `#[derive(XdrCodec)]` proc macro in `onc-xdr-derive` generates conforming encoders/decoders. |
| [1050](https://www.rfc-editor.org/rfc/rfc1050) | 1988 | RPC: Remote Procedure Call Protocol Specification | Historic | Original RPC v1 specification from Sun Microsystems. Superseded by RFC 1057. Historical reference only. |
| :material-star: [1057](https://www.rfc-editor.org/rfc/rfc1057) | 1988 | RPC: Remote Procedure Call Protocol Specification Version 2 | Historic | Portmapper v2 protocol (Appendix A) fully implemented in `onc-rpcbind` crate: `PortmapperClient` with DUMP, GETPORT. AUTH_SYS stamp field semantics (sec. 9.2) drive nfswolf's `AtomicU32` counter design. Referenced 59 times in source. |
| [1831](https://www.rfc-editor.org/rfc/rfc1831) | 1995 | RPC: Remote Procedure Call Protocol Specification Version 2 | Proposed Standard | IETF formalization of ONC RPC v2. Superseded by RFC 5531. Referenced 3 times for RPC message structure. |
| :material-star: [5531](https://www.rfc-editor.org/rfc/rfc5531) | 2009 | RPC: Remote Procedure Call Protocol Specification Version 2 | Draft Standard | **Current RPC v2 standard.** Full implementation in `onc-rpc-client` crate: `RpcClient`, `AuthSys`, credential swapping, record marking, `RpcTransport` seam. AUTH_SYS definition (sec. 14) is the foundation for all identity attacks. Referenced 71 times in source. Updated by RFC 9289 (TLS). |
| :material-star: [1833](https://www.rfc-editor.org/rfc/rfc1833) | 1995 | Binding Protocols for ONC RPC Version 2 | Proposed Standard | Defines rpcbind v3/v4 (portmapper replacement). Full implementation in `onc-rpcbind` crate: `RpcbindClient` with GETTIME (server clock retrieval) and GETSTAT (per-version call counts). Referenced 45 times in source. Updated by RFC 5665. |
| [5665](https://www.rfc-editor.org/rfc/rfc5665) | 2010 | IANA Considerations for RPC Network Identifiers and Universal Address Formats | Proposed Standard | IANA RPC program number registry. nfswolf includes the complete registry (1251 entries) for program identification in scanner and portmapper output. |

---

## MOUNT protocol

The sideband protocol that maps export paths to opaque file handles in NFSv2 and NFSv3. MOUNT is security-critical because it is the primary way an attacker obtains the initial root handle for an export, and because MOUNT access control is separate from NFS access control.

| RFC | Year | Title | Status | nfswolf relevance |
|-----|------|-------|--------|-------------------|
| :material-star: [1094 App. A](https://www.rfc-editor.org/rfc/rfc1094#appendix-A) | 1989 | MOUNT Protocol (v1) | Historic | `MountV1Client` in `nfs-mount` crate: MNT (returns 32-byte handle), EXPORT, UMNT. MOUNT v1 leaks handles without krb5 auth even when `sec=krb5` is set on the export (finding F-1.6). The escape pipeline gathers seed handles from MOUNT v1 as a fallback when v3 is unavailable. |
| :material-star: [1813 App. I](https://www.rfc-editor.org/rfc/rfc1813#appendix-I) | 1995 | MOUNT Protocol (v3) | Informational | `MountClient` in `nfs-mount` crate: NULL, MNT (returns variable-length handle + auth flavor list), UMNT, DUMP, UMNTALL, EXPORT. The auth flavor list returned by MNT is the primary input for the analyzer's authentication checks. |

!!! note
    MOUNT is defined in appendices of the NFS v2 and v3 RFCs, not in standalone documents. NFSv4 eliminates MOUNT entirely -- the pseudo-filesystem replaces it. nfswolf's escape pipeline still uses MOUNT v1 and v3 as seed handle sources even when targeting NFSv4, because many servers expose all three simultaneously.

---

## NFS security

RFCs addressing NFS authentication, authorization, and transport security. These documents describe both the intended security mechanisms (RPCSEC_GSS, Kerberos, TLS) and the acknowledged weaknesses (AUTH_SYS trust, handle bearer-token semantics) that nfswolf exploits.

| RFC | Year | Title | Status | nfswolf relevance |
|-----|------|-------|--------|-------------------|
| :material-star: [2623](https://www.rfc-editor.org/rfc/rfc2623) | 1999 | NFS Version 2 and Version 3 Security Issues and the NFS Protocol's Use of RPCSEC_GSS and Kerberos V5 | Proposed Standard | **Primary security reference for nfswolf.** AUTH_SYS weakness documented in sec. 2.2.1 (server trusts client-asserted UID/GID without verification). File handle security in sec. 2.6 (an attacker can circumvent MOUNT access control by stealing or guessing a file handle). NFSv2-specific weaknesses in sec. 2.7. Referenced 31 times in source across findings F-1.1, F-1.2, F-1.3, F-2.2, F-2.6, F-5.1. |
| :material-star: [2203](https://www.rfc-editor.org/rfc/rfc2203) | 1997 | RPCSEC_GSS Protocol Specification | Proposed Standard | GSS-API security flavor for RPC. nfswolf decodes GSS mechanism OIDs in SECINFO responses to identify Kerberos v5, SPKM-3, and LIPKEY. The analyzer checks for AUTH_TOOWEAK status as an oracle for security flavor requirements. Referenced 7 times in source. |
| :material-star: [5403](https://www.rfc-editor.org/rfc/rfc5403) | 2009 | RPCSEC_GSS Version 2 | Proposed Standard | Adds multi-principal authentication, channel bindings, and structured privilege assertions to RPCSEC_GSS. Referenced for understanding compound authentication contexts. Updated by RFC 7861. |
| :material-star: [7861](https://www.rfc-editor.org/rfc/rfc7861) | 2016 | Remote Procedure Call (RPC) Security Version 3 | Proposed Standard | RPCSEC_GSS v3. Adds security label assertions for multi-level security (MLS) and type enforcement. Referenced 4 times in source; context for finding F-4.5 (Labeled NFS security label bypass). |
| :material-star: [2695](https://www.rfc-editor.org/rfc/rfc2695) | 1999 | Authentication Mechanisms for ONC RPC | Informational | Defines AUTH_DH (Diffie-Hellman authentication, originally AUTH_DES). `AuthDhSession` in `onc-rpc-client` implements the full DH key exchange behind the `auth-dh` Cargo feature. CLI flags `--auth-dh-netname` and `--auth-dh-pubkey` expose it. Referenced 15 times in source. |
| :material-star: [9289](https://www.rfc-editor.org/rfc/rfc9289) | 2022 | Towards Remote Procedure Call Encryption by Default | Proposed Standard | Defines RPC-over-TLS (AUTH_TLS), enabling opportunistic encryption for NFS. The analyzer checks whether the server advertises TLS support. The opt-in nature of the mechanism (sec. 1: "A server is not required to support RPC-over-TLS") means cleartext is the default, driving finding F-3.4. Referenced 12 times in source. |
| [2755](https://www.rfc-editor.org/rfc/rfc2755) | 2000 | Security Negotiation for WebNFS | Informational | Defines a security negotiation mechanism for WebNFS using a pseudo-flavor handshake. Historical precursor to NFSv4's SECINFO operation; context for understanding how security flavor negotiation evolved. |
| [7204](https://www.rfc-editor.org/rfc/rfc7204) | 2014 | Requirements for Labeled NFS | Informational | Outlines requirements for integrating Mandatory Access Control (MAC) into NFSv4.2 using security labels. Context for understanding finding F-4.5 and why Labeled NFS adoption remains limited. |
| [8000](https://www.rfc-editor.org/rfc/rfc8000) | 2016 | Requirements for NFSv4 Multi-Domain Namespace Deployment | Proposed Standard | Specifies requirements for RPCSEC_GSS deployment in multi-domain NFSv4 environments with cross-realm identity mapping. Context for understanding why Kerberos deployment is difficult in practice. |
| [8275](https://www.rfc-editor.org/rfc/rfc8275) | 2017 | Allowing Inheritable NFSv4 Access Control Entries to Override the Umask | Proposed Standard | Addresses the interaction between NFSv4 ACE inheritance and the process umask. Relevant to access control bypass findings where inherited ACEs are silently masked. |

---

## NFSv4 extensions and updates

Errata, migration specification updates, trunking clarifications, and versioning governance rules for the NFSv4 protocol family. These documents update existing specifications rather than defining new ones.

| RFC | Year | Title | Status | nfswolf relevance |
|-----|------|-------|--------|-------------------|
| :material-star: [7931](https://www.rfc-editor.org/rfc/rfc7931) | 2016 | NFSv4.0 Migration: Specification Update | Proposed Standard | Updates RFC 7530 to fix problems in the migration feature discovered during implementation. Clarifies fs_locations behavior and transparent state migration semantics. |
| :material-star: [8587](https://www.rfc-editor.org/rfc/rfc8587) | 2019 | NFS Version 4.0 Trunking Update | Proposed Standard | Updates RFC 7530 to describe how fs_locations can be used for trunking (multiple network paths to the same server) in addition to migration and replication. |
| [8178](https://www.rfc-editor.org/rfc/rfc8178) | 2017 | Rules for NFSv4 Extensions and Minor Versions | Proposed Standard | Governance document defining how NFSv4 minor versions are created and how optional features are added to existing versions. Updates RFCs 5661 and 7862. |
| [8276](https://www.rfc-editor.org/rfc/rfc8276) | 2017 | File System Extended Attributes in NFSv4 | Proposed Standard | Adds xattr (extended attribute) support to NFSv4. Relevant to the information disclosure attack surface -- xattrs can leak security-sensitive metadata such as SELinux contexts. |
| [9754](https://www.rfc-editor.org/rfc/rfc9754) | 2025 | Extensions for Opening and Delegating Files in NFSv4.2 | Proposed Standard | Latest NFSv4.2 extensions for file open and delegation operations. Extends RFC 7863. |
| [9737](https://www.rfc-editor.org/rfc/rfc9737) | 2025 | Reporting Errors in NFSv4.2 via LAYOUTRETURN | Proposed Standard | Extends RFC 8435 to allow pNFS clients to report data file errors to the metadata server via LAYOUTRETURN, avoiding unnecessary resilvering after MDS restart. |
| [9766](https://www.rfc-editor.org/rfc/rfc9766) | 2025 | Extensions for Weak Cache Consistency in NFSv4.2's Flexible File Layout | Proposed Standard | Adds WCC (Weak Cache Consistency) mechanisms to the pNFS flexible file layout for coherent partial writes across multiple data servers. |

---

## Parallel NFS (pNFS)

Layout types and storage protocols for parallel data access in NFSv4.1 and later. pNFS allows clients to bypass the metadata server and read/write directly to storage devices. nfswolf does not implement pNFS layouts, but the scanner detects pNFS-capable servers and the RFCs provide context for understanding NFSv4.1+ deployments.

| RFC | Year | Title | Status | nfswolf relevance |
|-----|------|-------|--------|-------------------|
| [5663](https://www.rfc-editor.org/rfc/rfc5663) | 2010 | Parallel NFS (pNFS) Block/Volume Layout | Proposed Standard | Block storage layout type allowing direct SCSI/FC access to LUNs. Not directly implemented; context for pNFS architecture. |
| [5664](https://www.rfc-editor.org/rfc/rfc5664) | 2010 | Object-Based Parallel NFS (pNFS) Operations | Proposed Standard | Object storage layout type using OSD protocol. Not directly implemented; context for pNFS architecture. |
| [6688](https://www.rfc-editor.org/rfc/rfc6688) | 2012 | Parallel NFS (pNFS) Block Disk Protection | Proposed Standard | Updates RFC 5663 with block disk protection to prevent unauthorized access to data on shared block devices. Context for pNFS security. |
| [8154](https://www.rfc-editor.org/rfc/rfc8154) | 2017 | Parallel NFS (pNFS) SCSI Layout | Proposed Standard | SCSI layout type using persistent reservations for fencing. Replaces the block/volume layout in modern deployments. |
| [8434](https://www.rfc-editor.org/rfc/rfc8434) | 2018 | Requirements for Parallel NFS (pNFS) Layout Types | Proposed Standard | Clarifies the boundary between pNFS-generic and file-layout-specific requirements in RFC 5661. Governance document for new layout type specifications. |
| [8435](https://www.rfc-editor.org/rfc/rfc8435) | 2018 | Parallel NFS (pNFS) Flexible File Layout | Proposed Standard | File-based layout type supporting client-side mirroring and minimal MDS interaction. The most widely deployed pNFS layout in Linux. |
| [9561](https://www.rfc-editor.org/rfc/rfc9561) | 2024 | Using the pNFS SCSI Layout to Access NVMe Storage Devices | Proposed Standard | Extends the SCSI layout (RFC 8154) to cover NVMe storage over NVMe-oF fabrics. |

---

## RDMA transports

RPC-over-RDMA and NFS direct data placement for high-performance networks. These protocols allow NFS to operate over InfiniBand, RoCE, and iWARP without TCP overhead. nfswolf's scanner detects RDMA service advertisements but does not implement RDMA transports.

| RFC | Year | Title | Status | nfswolf relevance |
|-----|------|-------|--------|-------------------|
| [5532](https://www.rfc-editor.org/rfc/rfc5532) | 2009 | NFS Remote Direct Memory Access (RDMA) Problem Statement | Informational | Motivates NFS/RDMA: TCP/IP copy overhead limits throughput on high-bandwidth networks. Context for RDMA detection in scanner. |
| [5666](https://www.rfc-editor.org/rfc/rfc5666) | 2010 | Remote Direct Memory Access Transport for Remote Procedure Call | Proposed Standard | Original RPC-over-RDMA v1 specification. Obsoleted by RFC 8166. Historical reference. |
| [5667](https://www.rfc-editor.org/rfc/rfc5667) | 2010 | Network File System (NFS) Direct Data Placement | Proposed Standard | Original NFS upper-layer binding to RDMA for v2/v3/v4/v4.1. Obsoleted by RFC 8267. Historical reference. |
| [8166](https://www.rfc-editor.org/rfc/rfc8166) | 2017 | Remote Direct Memory Access Transport for Remote Procedure Call Version 1 | Proposed Standard | **Current RPC-over-RDMA v1 specification.** Defines credit-based flow control and chunk types for RDMA transport. Context for scanner RDMA detection. |
| [8167](https://www.rfc-editor.org/rfc/rfc8167) | 2017 | Bidirectional Remote Procedure Call on RPC-over-RDMA Transports | Proposed Standard | Enables NFSv4.1+ callback channels over RDMA, allowing the server to push delegations and layout recalls to the client. |
| [8267](https://www.rfc-editor.org/rfc/rfc8267) | 2017 | NFS Upper-Layer Binding to RPC-over-RDMA Version 1 | Proposed Standard | **Current NFS/RDMA binding.** Specifies how each NFS version maps operations onto RDMA chunks. Obsoletes RFC 5667. |

---

## WebNFS and related

WebNFS extensions and NFS URL schemes. These are largely historical but relevant for understanding the concept of public file handles and MOUNT-less access, which NFSv4 later adopted as the pseudo-filesystem.

| RFC | Year | Title | Status | nfswolf relevance |
|-----|------|-------|--------|-------------------|
| [2054](https://www.rfc-editor.org/rfc/rfc2054) | 1996 | WebNFS Client Specification | Informational | Introduced the public filehandle concept (a well-known handle that bypasses MOUNT). NFSv4's pseudo-FS root handle descends from this idea. |
| [2055](https://www.rfc-editor.org/rfc/rfc2055) | 1996 | WebNFS Server Specification | Informational | Server-side semantics for the public filehandle and multi-component LOOKUP. Context for MOUNT bypass techniques. |
| [2224](https://www.rfc-editor.org/rfc/rfc2224) | 1997 | NFS URL Scheme | Informational | Defines the `nfs://` URL scheme for referencing files on NFS servers. Historical; never widely adopted outside WebNFS. |
| [6641](https://www.rfc-editor.org/rfc/rfc6641) | 2012 | Using DNS SRV to Specify a Global File Namespace with NFS Version 4 | Proposed Standard | DNS SRV records for NFSv4 namespace discovery, enabling `_nfs4._tcp.example.com` lookups. Not directly implemented in nfswolf. |

---

## Other

RFCs present in the `ref/all_rfcs/` collection that are not directly related to NFS. Included for completeness.

| RFC | Year | Title | Status | nfswolf relevance |
|-----|------|-------|--------|-------------------|
| [3529](https://www.rfc-editor.org/rfc/rfc3529) | 2003 | Using XML-RPC in Blocks Extensible Exchange Protocol (BEEP) | Experimental | Not NFS-related. Present in collection only; uses "RPC" in the title but defines an unrelated XML-RPC/BEEP binding. |
| [5717](https://www.rfc-editor.org/rfc/rfc5717) | 2009 | Partial Lock Remote Procedure Call (RPC) for NETCONF | Proposed Standard | Not NFS-related. Defines partial configuration locking for NETCONF; uses "RPC" in the title but is a network management protocol. |

---

## Obsolescence chain

Several NFS RFCs obsolete or update earlier versions. This table tracks the supersession chain for each core specification so you can quickly find the current document.

| Current | Obsoletes | Updated by |
|---------|-----------|------------|
| RFC 4506 (XDR) | RFC 1832 :material-arrow-left: RFC 1014 | -- |
| RFC 5531 (RPC v2) | RFC 1831 :material-arrow-left: RFC 1057 :material-arrow-left: RFC 1050 | RFC 9289 (TLS) |
| RFC 7530 (NFSv4.0) | RFC 3530 :material-arrow-left: RFC 3010 | RFC 7931 (migration), RFC 8587 (trunking) |
| RFC 8881 (NFSv4.1) | RFC 5661 | -- |
| RFC 7862 (NFSv4.2) | -- | RFC 8178 (versioning rules), RFC 9737, RFC 9754, RFC 9766 |
| RFC 5403 (RPCSEC_GSS v2) | -- (updates RFC 2203) | RFC 7861 (v3) |
| RFC 8166 (RPC-over-RDMA v1) | RFC 5666 | -- |
| RFC 8267 (NFS/RDMA binding) | RFC 5667 | -- |

---

## Cross-reference: RFC to crate

Quick lookup from primary RFCs to the nfswolf crate that implements them.

| RFC | Crate | What is implemented |
|-----|-------|---------------------|
| 4506 | `onc-xdr` | XDR codec: `Pack`, `Unpack`, padding, bounded readers |
| 4506 | `onc-xdr-derive` | `#[derive(XdrCodec)]` proc macro |
| 1057, 5531 | `onc-rpc-client` | ONC RPC v2 message types, `RpcClient`, AUTH_SYS, `RpcTransport` |
| 1057, 1833 | `onc-rpcbind` | Portmapper v2 DUMP/GETPORT, rpcbind v3/v4 GETTIME/GETSTAT |
| 1094 App. A, 1813 App. I | `nfs-mount` | MOUNT v1/v3: NULL, MNT, UMNT, DUMP, UMNTALL, EXPORT |
| 1094 | `nfs-v2` | NFSv2: 18 procedures, fixed 32-byte handles, domain API |
| 1813 | `nfs-v3` | NFSv3: 22 procedures, domain types, `Nfs3Error` classification |
| 7530 | `nfs-v4` | NFSv4.0: 37 ops, COMPOUND, stateful infrastructure, 47 public methods |
| 2695 | `onc-rpc-client` | AUTH_DH cryptographic sessions (behind `auth-dh` feature) |

---

## Cross-reference: RFC to finding

Which findings cite which RFCs in their rationale.

| RFC | Findings | Topic |
|-----|----------|-------|
| 1094 | F-1.6, F-2.6 | NFSv2 protocol weaknesses, handle format predictability |
| 1813 | F-2.1, F-2.2, F-2.6, F-5.1 | ACCESS advisory semantics, handle oracle, READDIRPLUS info leak |
| 2623 | F-1.1, F-1.2, F-1.3, F-2.2, F-2.6, F-5.1 | AUTH_SYS trust model, handle bearer-token semantics |
| 5531 | F-1.1, F-1.2, F-1.3 | AUTH_SYS credential forgery |
| 7530 | F-1.1 through F-5.15 | NFSv4 COMPOUND, SECINFO, pseudo-FS traversal |
| 7861 | F-4.5 | RPCSEC_GSS v3 security labels |
| 7862 | F-4.5 | Labeled NFS in NFSv4.2 |
| 9289 | F-3.4 | RPC-over-TLS opt-in nature |
