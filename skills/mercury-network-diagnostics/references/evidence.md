# Evidence interpretation

Mercury records observations with direction, timing, provenance, and confidence. Preserve these distinctions:

| Observation | Safe interpretation |
|---|---|
| Peer-correlated arrival/acknowledgement | The exact tested carrier crossed in that direction during the window. |
| TCP connected | A TCP handshake completed to the selected endpoint. |
| TCP refused/reset | The destination or path returned an explicit negative TCP response. |
| Native Nmap open/closed/filtered/open-or-filtered | Nmap reported that state for its fixed profile; retain native provenance. |
| ICMP reply/unreachable | An explicit ICMP response was observed. |
| Timeout or silent | No qualifying response was observed before the bound; inconclusive. |
| Unsupported/unavailable | The platform or dependency could not perform the profile. |
| Permission denied | The profile needed privileges that were not available. |
| Not applicable | The profile does not apply, such as ARP/ND across subnets. |
| Error | Execution or parsing failed; do not convert it to a network conclusion. |

A candidate carrier is not evidence that an unauthorized tunnel is currently deployed. It shows that the tested carrier could convey a correlated message. Conversely, zero observed candidates means only that none appeared in the completed finite matrix. Always enumerate unfinished, silent, unavailable, permission-denied, skipped, and non-applicable gaps.
