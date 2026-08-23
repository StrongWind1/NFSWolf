*[ACL]: Access Control List
*[AUTH_DH]: Diffie-Hellman authentication (RPC flavor 3, deprecated)
*[AUTH_NONE]: No authentication (RPC flavor 0)
*[AUTH_SHORT]: Abbreviated credential token (RPC flavor 2)
*[AUTH_SYS]: Default NFS authentication where the client states its own user ID without proof (RPC flavor 1)
*[AUTH_TLS]: TLS upgrade negotiation (RPC flavor 7, RFC 9289)
*[AUTH_UNIX]: Same as AUTH_SYS (older name)
*[COMPOUND]: NFSv4 operation that batches multiple sub-operations into one RPC call
*[DAC]: Discretionary Access Control (standard UNIX permissions)
*[DRC]: Duplicate Request Cache (server-side dedup of retried RPCs)
*[FUSE]: Filesystem in Userspace
*[GID]: Group ID
*[GSS-API]: Generic Security Services Application Programming Interface
*[HMAC]: Hash-based Message Authentication Code
*[KDC]: Key Distribution Center (Kerberos server)
*[LOOKUPP]: NFS operation that navigates to the parent directory
*[MAC]: Mandatory Access Control (SELinux, AppArmor, SMACK)
*[MKNOD]: NFS operation to create a device node
*[MNT]: MOUNT procedure that returns a file handle for an export
*[NFS_ACL]: Sideband RPC program (100227) for POSIX ACL queries
*[NIS]: Network Information Service (legacy directory service)
*[NLM]: Network Lock Manager (separate RPC program for file locking)
*[NSM]: Network Status Monitor (tracks NLM lock state across reboots)
*[ONC RPC]: Open Network Computing Remote Procedure Call
*[POSIX]: Portable Operating System Interface (UNIX standards family)
*[READDIRPLUS]: NFSv3 operation that returns directory entries with handles and attributes
*[RQUOTA]: Remote Quota protocol (RPC program 100011)
*[RPCSEC_GSS]: Kerberos-based RPC authentication (RPC flavor 6)
*[SECINFO]: NFSv4 operation to query supported security flavors per export
*[SUID]: Set User ID on execution (a permission bit that runs the file as its owner)
*[UID]: User ID
*[UMNT]: MOUNT procedure to remove a client from the mount list
*[VFS]: Virtual File System (kernel abstraction layer over filesystems)
*[XDR]: External Data Representation (serialization format for RPC, RFC 4506)
*[XID]: Transaction Identifier (4-byte ID in every RPC message)
*[inode]: A file's unique number on disk
*[knfsd]: The Linux kernel NFS server daemon
*[mountd]: The MOUNT protocol daemon (rpc.mountd)
*[pNFS]: Parallel NFS (NFSv4.1 extension for distributed data access)
*[portmapper]: RPC service directory on port 111 that maps program numbers to ports
*[rpcbind]: Modern replacement for portmapper (same port 111, additional features)
*[writeverf3]: 8-byte verifier returned by COMMIT that changes on server reboot
