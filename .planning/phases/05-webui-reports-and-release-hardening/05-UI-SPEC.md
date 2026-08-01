---
phase: 05
status: approved
---

# Mercury WebUI Design Contract

## Users and Primary Flow

An operator opens the loopback dashboard, reads local network status, starts
one explicitly authorized diagnostic/discovery/trace request, sees admitted
and completed progress, inspects evidence and exports a redacted report.

## Information Hierarchy

1. Persistent safety state: bind, authorization reminder and supported
   platform/capability degradation.
2. Current task progress plus clear `positive`, `negative`, `inconclusive`,
   `unavailable` and `error` labels (never a color-only distinction).
3. Evidence table: direction, target, layer, timing, source and raw detail.
4. Historical comparison and export controls.

## Accessibility

- Semantic landmarks, explicit `label` elements, native buttons and form
  controls; no clickable generic containers.
- Keyboard focus remains visible; polling updates use a concise `aria-live`
  region and do not steal focus.
- Tables have headers and responsive overflow rather than hidden evidence.
- Color supports but never replaces textual status; contrast meets WCAG AA.
- Errors are associated with their fields and summarized before submission.

## Visual Direction

Compact diagnostic-console layout: high-contrast neutral surfaces, one
reserved accent for active work, status chips with labels, monospaced values
only for IDs/addresses, and mobile-safe stacked panels. No charts or external
fonts are required.

## Safety Copy

Discovery and trace forms visibly state the CIDR/target, authorization
attestation and immutable budget before submit. Topology text says that a
gateway, ARP/NDP entry or first route hop is not an observed switch.
