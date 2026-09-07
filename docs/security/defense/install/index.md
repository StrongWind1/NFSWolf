# Installing NFS

NFS requires software on both ends of the connection. The **server** exports directories from its local filesystem, and the **client** mounts those exports into its own directory tree. On Linux, both roles are provided by the same upstream package (`nfs-utils`), but distributions split them into separate packages with different service units.

A minimal NFS deployment involves two machines and three services:

```mermaid
graph LR
    subgraph Server
        RPCBIND_S["rpcbind<br>:111"]
        NFSD["nfs-server<br>:2049"]
        MOUNTD["rpc.mountd<br>:dynamic"]
    end

    subgraph Client
        RPCBIND_C["rpcbind<br>:111"]
        MOUNT_CMD["mount.nfs"]
    end

    MOUNT_CMD -- "1. GETPORT(mountd)" --> RPCBIND_S
    MOUNT_CMD -- "2. MNT(/export)" --> MOUNTD
    MOUNT_CMD -- "3. NFS ops" --> NFSD

    style NFSD fill:#1a1a2e,stroke:#e94560,color:#fff
    style MOUNTD fill:#1a1a2e,stroke:#0f3460,color:#fff
    style RPCBIND_S fill:#1a1a2e,stroke:#0f3460,color:#fff
    style RPCBIND_C fill:#1a1a2e,stroke:#533483,color:#fff
    style MOUNT_CMD fill:#1a1a2e,stroke:#533483,color:#fff
```

The server side is more involved: you install the NFS server packages, define exports in `/etc/exports`, enable the kernel NFS daemon, and open firewall ports. The client side is simpler: install the client utilities and run `mount -t nfs`.

!!! warning "Security context"
    These pages cover installation mechanics only. A working NFS server with default settings is an insecure NFS server. AUTH_SYS credentials are trivially forged, file handles are bearer tokens, and export boundaries can be escaped. After installation, proceed to [Configuring NFS](../configure/index.md) and [Hardening](../hardening/index.md) before exposing the server to any network you do not fully control.

## Sub-pages

- **[Server setup](server.md)**: Install and start the NFS server daemon, define exports, verify with `showmount`, and configure firewall rules.
- **[Client setup](client.md)**: Install client utilities, mount exports manually and via `/etc/fstab`, set up `autofs` for auto-mounting, and configure NFSv4 ID mapping.
