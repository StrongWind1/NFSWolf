//! Credential escalation ladder shared by every subcommand that performs
//! NFS operations.
//!
//! When the server returns NFS3ERR_ACCES, callers retry through a
//! consistent sequence of (uid, gid) pairs: the file owner first, then
//! root, then well-known service accounts. Centralising the order means
//! the shell, the FUSE adapter, and the offensive subcommands all walk
//! the same ladder, so behaviour is predictable across surfaces.

/// Build the credential escalation ladder for a failed NFS operation.
///
/// `caller` is the (uid, gid) that was rejected.
/// `owner` is the file/directory owner from GETATTR, if available.
///
/// Priority:
///   1. (owner_uid, owner_gid)  -- file owner; works on uid-protected files
///   2. (caller_uid, owner_gid) -- caller claiming the file group; works for
///      group-readable files when root is squashed (e.g. chrony gid=989)
///   3. (0, 0)                  -- root, works when export has no_root_squash
///   4. Common service UIDs (nobody, 1000, www-data, mysql, postgres)
///
/// Used by the shell (ls, cd, cat) and attack modules (read, lookup) so
/// every NFS operation gets the same automatic privilege escalation.
pub fn escalation_list(caller: (u32, u32), owner: Option<(u32, u32)>) -> Vec<(u32, u32)> {
    let (caller_uid, caller_gid) = caller;
    let mut list = Vec::with_capacity(14);
    if let Some((owner_uid, owner_gid)) = owner {
        list.push((owner_uid, owner_gid));
        if owner_gid != caller_gid {
            list.push((caller_uid, owner_gid));
        }
    }
    list.push((0, 0));
    list.push((65534, 65534));
    list.push((1000, 1000));
    list.push((33, 33)); // www-data
    list.push((27, 27)); // mysql
    list.push((26, 26)); // postgres
    list.push((1001, 1001));
    list.push((1002, 1002));
    list.dedup();
    list
}
