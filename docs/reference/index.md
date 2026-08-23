# Reference

Technical reference material for nfswolf: protocol specifications, kernel internals, compatibility matrices, and project history. Everything in this section is designed for quick lookup rather than sequential reading -- tables and matrices that answer specific questions in one scan.

## Contents

| Page | Description |
|------|-------------|
| [RFC Index](rfcs.md) | Every NFS-related RFC (55+ documents from 1987 to 2025), organized by category, with nfswolf relevance notes and obsolescence chains |
| [Kernel Source Map](kernel.md) | Function-level walkthrough of the Linux 7.1.8 knfsd server, with every security-relevant code path mapped to nfswolf findings |
| [Filesystem Escape Matrix](escape-matrix.md) | Per-filesystem escape support across 19 Linux filesystem types: which file handle layouts nfswolf can construct and which resist escape |
| [Spec Completeness](spec-completeness.md) | Protocol coverage tracking -- which RFC procedures and fields are implemented in each of the 8 workspace crates |
| [Comparison](comparison.md) | Feature comparison against other NFS security tools (showmount, nfs-ls, NFSpy, etc.) |
| [Changelog](changelog.md) | Release history and migration notes from v0.1.0 through the current release |

## How to use this section

The reference pages are lookup tables, not tutorials. They exist so you can quickly answer questions like:

- "Which RFC defines the ACCESS procedure's advisory semantics?" -- check the [RFC Index](rfcs.md)
- "Does the ext4 escape work on 64-bit inodes?" -- check the [Escape Matrix](escape-matrix.md)
- "What kernel function enforces `sec=krb5`?" -- check the [Kernel Source Map](kernel.md)
- "Does nfswolf implement NFSv4 SECINFO?" -- check [Spec Completeness](spec-completeness.md)
- "How does nfswolf compare to NFSpy for UID spoofing?" -- check the [Comparison](comparison.md)

For guided explanations of protocols and attacks, see the [NFS](../nfs/index.md), [Protocols](../protocols/index.md), and [Findings](../findings/index.md) tabs instead. For practical usage instructions, see the [Usage](../usage/index.md) tab.

## Local copies

nfswolf ships with local copies of all referenced RFCs in `ref/rfc/` (15 primary references cited in source code) and `ref/all_rfcs/` (complete NFS RFC corpus, 55+ documents). The Linux kernel NFS source breakdown is in `ref/linux-kernel/BREAKDOWN.md`, with copied kernel source files in `ref/linux-kernel/` for local reference.

These are checked into the repository so the documentation and offline development both work without network access.
