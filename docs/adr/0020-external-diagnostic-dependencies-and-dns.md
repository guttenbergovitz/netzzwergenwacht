# 0020. External diagnostic dependencies and DNS acquisition

## Status

Accepted

## Context

CAA records are needed to explain certificate-authority restrictions, but the previous
implementation hard-coded a Cloudflare DNS-over-HTTPS endpoint and treated any response
without an `Answer` array as a failure. That silently transmits investigated hostnames to
a third party, ignores resolver configuration, and conflates NXDOMAIN, an empty answer
and a transport failure.

## Decision

1. **External DNS is opt-in.** Direct CAA acquisition stays disabled unless a resolver is
   configured. The default configuration performs no external DNS query, and the
   observation is reported as `skipped`, never as "no CAA policy".
2. **Resolver configuration is explicit.** The configuration may name a DNS-over-HTTPS
   endpoint, and the selected endpoint is recorded with the observation. There is no
   silent fallback to a hard-coded provider.
3. **Acquisition respects the execution budget.** The query uses the audit timeout and
   the remaining investigation deadline, a bounded response size, no redirects and no
   additional request after the deadline has expired.
4. **Private targets are protected.** IP literals and reserved fixture names are skipped,
   and the target policy gates the query exactly as it gates HTTP acquisition.
5. **DNS response codes are interpreted explicitly.** `NOERROR` with records, `NOERROR`
   without records, `NXDOMAIN`, `SERVFAIL`, `REFUSED`, timeout, invalid response and
   policy-blocked are distinct outcomes. A successful response without an `Answer` array
   is a successful observation of an empty answer, not a failure.
6. **Direct records are not effective policy.** The observation is named "direct CAA
   records observed for the queried hostname". CAA inheritance and alias handling are not
   inferred; the absence of a direct record does not imply that no effective policy
   exists.
7. **TLS provenance stays layered.** Certificate metadata, chain and hostname validation,
   negotiated protocol and cipher, browser security state and DNS observations remain
   distinguishable. Filling an empty CAA field never replaces previously observed TLS
   facts.

## Consequences

- Absent configuration means less evidence, which is preferred over an undocumented
  third-party dependency.
- Operators who want CAA evidence must configure a resolver explicitly, and the
  configuration becomes part of the audit provenance.
- The observation answers a narrower question than "is there a CAA policy", and the
  documentation says so.
