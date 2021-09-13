# TODO List

## Driver

### Implement ECN support via the `IP_ECN` cmsg

### Rework IOCTL to accept requests over 4gigs
- The current `ULONG` is too small
- We should switch to using `METHOD_NEITHER`
- One param is a pointer to a ULONG64 length, the other the actual buffer

### Rearrange and regroup `WG_DEVICE`
- Most commonly used members should be at the top
- Members used together should be next to each other
- Holes should be minimized
- Don't stretch cachelines

### SAL Annotations
- Figure out `__rcu` best practice with SAL
- For the MuAcquireReleaseSharedExclusive functions, make SAL detect lock
  imbalance. e.g. a AcquireExclusive followed by a ReleaseShared.

## Bugs with no solution

### Forwarding/WeakHostSend breaks `IP_PKTINFO`
When forwarding or weakhostsend are enabled -- which can happen via Hotspot
mode -- the routing logic ignores `IP_PKTINFO`. This seems like a bug, but one
unlikely to be fixed. We'll need a opt-in `setsockopt` to make `IP_PKTINFO`
choose the right behavior in this case.

### TDI drivers never do the right thing with `IP_PKTINFO`
Windows only looks at Options/OptionsLength if UserBuffer==(PVOID)0x886103.
This is crazy, so nobody actually does it.

## Bug workarounds

### Remove `_NO_CRT_STDIO_INLINE` once WDK is fixed

### Remove MTU polling
When NotifyIpInterfaceChange is fixed for MTU changes, adjust the dwBuildNumber
check for the workaround thread polling.

### Remove `IP_OPTIONS`/`IPV6_RTHDR` hack
Currently we tag on an empty options cmsg to work around a bug in recent
Windows builds, where `IP_PKTINFO` gets stripped if it's passed alone.
