# Reference

Technical reference material for nfswolf: protocol specifications, kernel internals, compatibility matrices, and project history. Everything in this section is designed for quick lookup rather than sequential reading -- tables and matrices that answer specific questions in one scan.

## Contents

| Page | Description |
|------|-------------|
| [RFC Index](rfcs.md) | Every NFS-related RFC (55+ documents from 1987 to 2025), organized by category, with nfswolf relevance notes and obsolescence chains |
| [Kernel Source Map](kernel.md) | Function-level walkthrough of the Linux 7.1.8 knfsd server, with every security-relevant code path mapped to nfswolf findings |
| [Filesystem Escape Matrix](escape-matrix.md) | Per-filesystem escape support across 18 Linux filesystem types (22 tested configurations): which file handle layouts nfswolf can construct and which resist escape |
| [Spec Completeness](spec-completeness.md) | Protocol coverage tracking -- which RFC procedures and fields are implemented in each of the 8 workspace crates |
| [Changelog](changelog.md) | Release history and migration notes from v0.1.0 through the current release |

## How to use this section

The reference pages are lookup tables, not tutorials. They exist so you can quickly answer questions like:

- "Which RFC defines the ACCESS procedure's advisory semantics?" -- check the [RFC Index](rfcs.md)
- "Does the ext4 escape work on 64-bit inodes?" -- check the [Escape Matrix](escape-matrix.md)
- "What kernel function enforces `sec=krb5`?" -- check the [Kernel Source Map](kernel.md)
- "Does nfswolf implement NFSv4 SECINFO?" -- check [Spec Completeness](spec-completeness.md)
For guided explanations of protocols and attacks, see the [NFS](../nfs/index.md) and [Security](../security/index.md) tabs instead. For practical usage instructions, see the [NFSWolf](../index.md) tab.

## Local copies

The maintainers work against a local reference checkout under `ref/`: the RFCs cited in source code in `ref/rfc/`, the complete NFS RFC corpus in `ref/all_rfcs/`, and the Linux kernel NFS source breakdown in `ref/linux-kernel/BREAKDOWN.md` with copied kernel source files beside it. That directory is gitignored and not shipped in the repository. The [RFC Index](rfcs.md) links every RFC to its published text, and the [Kernel Source Map](kernel.md) summarizes the kernel breakdown.
