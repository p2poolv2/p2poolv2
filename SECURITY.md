# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities privately. Do **not** open a
public GitHub issue.

**Primary channel:** Use GitHub's private vulnerability reporting at
https://github.com/p2poolv2/p2poolv2/security/advisories/new

**Fallback channel:** If you cannot use GitHub's reporting feature,
email the maintainer at kp@opdup.com.

Please include, where possible:

- A description of the vulnerability and its impact.
- Steps to reproduce, or a proof of concept.
- Affected versions or commit hashes.
- Any suggested mitigations or fixes.

## Scope

This policy covers the P2Poolv2 node software, including:

- The P2P share chain networking and consensus logic.
- The Stratum server handling miner submissions.
- Share validation and the PPLNS accounting pipeline.
- The REST API and WebSocket server, including the endpoints serving
  the web dashboard.
- The web dashboard and its static assets.
- The Prometheus metrics endpoint and the data exposed through it.
- Interactions with `bitcoind` (block templates, coinbase payouts).

P2Poolv2 has not yet shipped a mainnet release handling real payouts.
However, vulnerabilities should still be reported privately: users run
nodes on public networks today, and a premature public disclosure could
put their funds, hashrate, or infrastructure at risk.

The following are generally out of scope:

- Vulnerabilities in third-party dependencies (report these upstream;
  do let us know if a dependency issue materially affects P2Poolv2).
- Issues requiring physical access or root access to the host machine.
- Denial-of-service attacks that are generic to any P2P network and
  require resources disproportionate to the impact.

## Response Timeline

- We will acknowledge receipt of your report within **72 hours**.
- We will keep you informed of progress as we investigate and develop
  a fix.

Please note that P2Poolv2 is maintained by volunteers; while we treat
security reports as the highest priority, fix timelines depend on the
severity and complexity of the issue.

## Disclosure Policy

We follow coordinated disclosure:

- We will work with you to agree on a public disclosure date once a
  fix is ready.
- If we cannot reach agreement, we default to disclosing **90 days**
  after the initial report, in line with common industry practice.
- We will credit you in the disclosure unless you prefer to remain
  anonymous.

## Supported Versions

P2Poolv2 is pre-1.0 and under active development. Only the **latest
release** receives security fixes. Please ensure you are running the
most recent release before reporting an issue.

## Bug Bounty

We do not currently offer a bug bounty program. We are grateful for
responsible disclosures and will publicly credit reporters (with their
permission) in release notes and security advisories.
