# Publication scope and review

The release unit is the reviewed Git commit or a source ZIP verified against it.
Do not upload a working-directory ZIP, the parent development project, `.git`,
local evidence, generated dependencies, build logs or binaries. Ignore rules do
not remove files from history or protect them from a manual folder upload.

## What this source contains

GPU/PCI model IDs, firmware and driver versions, broad OS information, monitor
model checks and rounded benchmark results are intentionally public. Protocol
GUIDs are public interface identifiers; fixture device paths and volume IDs are
synthetic. Upstream contributor names and copyright notices are attribution,
not experiment-operator metadata.

Private ROM-chain, PROM and decoded GOP code digests have been removed from the
public source and export history. The C checks require a local reviewed header;
the offline analyzer keeps an explicit blocker when no reviewed ROM identity is
provided. No mismatch check has been bypassed to make an unknown board pass.

At the repository owner's explicit request, release commits identify
Eungyu Park <ekpark97.dev@gmail.com>. This attribution is intentionally public.
The UTC release-date timestamp is not the original development/experiment time. The original local history stays
outside this repository. Future contributors must review their own commit/tag
identity, timestamps, messages and refs before publishing.

## Repeatable checks

```bash
python3 tools/test_public.py
python3 tools/audit_public.py --release
mkdir -p dist
git archive --format=zip --output=dist/rtx4080-tensor-unlock-source.zip HEAD
python3 tools/audit_public.py --release --archive dist/rtx4080-tensor-unlock-source.zip
```

After creating a new commit, recreate and check the ZIP. The auditor checks
tracked working files, index entries, all Git object contents (including
unreachable objects), commit/tag identities and messages, ref names and selected
local Git metadata. The ZIP must have exactly the committed file set and file
bytes. Known private strings/digests may be supplied with `--deny-file`; the
private marker file must stay outside the distribution.

The strict preparation review also checked the complete local file inventory,
manual source/URL/identifier inspection, vendored file hashes and license notices,
and the mutation/network entry points. No automatic boot, USB staging, Windows
privilege elevation or remote publication command is supplied. Explicit hardware
benchmark/display operations and UEFI transaction source remain potentially
harmful when deliberately invoked; CPU tests do not qualify them for hardware use.

## Limits that remain

A heuristic scan cannot discover every unknown secret, encoding or correlation.
A GPU/monitor/software combination and distinctive performance results can be
linked to information published elsewhere. Publishing through an identifiable
GitHub account links the repository to that account even with generic commit
metadata. This export excludes private machine identifiers; the explicitly
approved author name and email remain public. It **does not promise anonymity**.

The GPL and third-party notices are preserved. Fixed-revision LICENSE files from
JustAResearcher and WildFlash1st, plus TOTORONG's LICENSE and payload generator,
were directly checked; their hashes match the recorded source provenance. No
NVIDIA binary firmware, ROM, CUDA DLL or Windows boot file is included. Public
source licensing does not establish ownership of every historical input or grant
rights to redistribute those separate proprietary assets.

GitHub's [dual-use research policy](https://docs.github.com/en/site-policy/acceptable-use-policies/github-active-malware-or-exploits)
allows research content, subject to its restrictions. That is not a legal opinion
or a guarantee against a future copyright claim or platform moderation decision.
The research remains unqualified for general hardware use, and the display
handoff defect remains disclosed. See [results](RESULTS.md) and [reporting concerns](../SECURITY.md).
