# Changelog

## Unreleased

- Add the experimental `sysbox-runc-inner` nested path: it skips unavailable
  special mounts, preserves the exec FIFO handshake without `/proc`, and uses
  a 65,535-ID mapping. This lets a Sysbox K3s Pod run a pause Pod through a
  second Sysbox runtime while preserving parent ID 0 as an isolation boundary.
