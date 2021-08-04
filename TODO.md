# TODO List

## Driver

### Performance

### Rearrange and regroup `WG_DEVICE`
- Most commonly used members should be at the top
- Members used together should be next to each other
- Holes should be minimized
- Don't stretch cachelines

### SAL Annotations
- Figure out `__rcu` best practice with SAL
- For the MuAcquireReleaseSharedExclusive functions, make SAL detect lock
  imbalance. e.g. a AcquireExclusive followed by a ReleaseShared.

### Remove `_NO_CRT_STDIO_INLINE` once WDK is fixed

### Make SDV work with full settings

### Figure out how to make wg-loop routing work safely

### Implement ICMP reply on error path
- Not totally essential, but nice to have
- One hard part is that we're post-NAT, and we can't dip down into the ct tuple
  like we do on linux, which could make the general concept impossible

### Implement socket route cache

### Automate CodeQL
Reference: https://docs.microsoft.com/sl-si/windows-hardware/drivers/devtest/static-tools-and-codeql
- Download CodeQL and unzip => .deps
- git clone --recurse https://github.com/microsoft/Windows-Driver-Developer-Supplemental-Tools.git => .deps
- rd /s codeqldb
- codeql.cmd database create -l=cpp -s=driver -c "msbuild driver.vcxproj /t:Rebuild" codeqldb -j 0
- codeql.cmd database analyze codeqldb windows_driver_recommended.qls --search-path=..\Windows-Driver-Developer-Supplemental-Tools --format=sarifv2.1.0 --output=driver\wireguard.sarif -j 0

### WHQL

### Fix MTU notification
- Due to a Windows bug, NotifyIpInterfaceChange does not tell us about MTU changes.

#### DVL and Static Tools Logo Test
- Recent (E)WDK DVL always includes CodeQL test results. Even if "NORUN". WHQL 1809 does not support CodeQL test results in DVL and fails Static Tools Logo Test. Those two are in conflict. Either downgrade (E)WDK, or upgrade WHQL rig.
