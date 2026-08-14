# Changelog

## Unreleased

- Add the experimental `nested-identity` path for `sysbox-runc-inner`. It
  always creates a child user namespace with `0:0:65536`, uses NoShift for
  rootfs and bind mounts, and migrates CRI CNI links into a child-owned netns.
  The migrated namespace restores addresses and routes, enables loopback, and
  rebinds the persistent CNI handle so sandbox and workload containers share
  the same child userns and netns.
