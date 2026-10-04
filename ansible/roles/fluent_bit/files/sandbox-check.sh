#!/bin/sh
# Fluent Bit's start check (ExecStartPre, siem contract P2 MJ8). It runs inside the unit's own
# sandbox - same user, same capability, same InaccessiblePaths - and refuses the start when it can
# read any of the files named on the command line (the k3s kubeconfig on k3s01, the admin key on
# siem01). It reads the first byte - the operation the shipper itself could do - rather than asking
# access(2), whose answer for a capability depends on how the shell calls it (dash's test -r does
# honour CAP_DAC_READ_SEARCH; access() without AT_EACCESS would not).
for f in "$@"; do
  if [ -n "$(head -c 1 "$f" 2>/dev/null)" ]; then
    echo "sandbox broken: $f readable" >&2
    exit 1
  fi
done
exit 0
