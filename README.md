# [WireGuard](https://www.wireguard.com/) for the NT Kernel
### High performance in-kernel WireGuard implementation for Windows

WireGuardNT is an implementation of WireGuard, for the NT Kernel as used in Windows 7, 8, 8.1, 10, and 11, supporting AMD64, x86, ARM64, and ARM processors.

#### Not the droids you're looking for

**If you've come here looking to run [WireGuard on Windows](https://git.zx2c4.com/wireguard-windows/about/), you're in the wrong place. Instead, head on over to the [WireGuard Download Page](https://www.wireguard.com/install/) to download the WireGuard application.** Alternatively, if you've come here looking to embed WireGuard into your Windows program, **you are still in the wrong place**. Instead, head on over to the [embeddable DLL service project](https://git.zx2c4.com/wireguard-windows/about/embeddable-dll-service/README.md), to get everything you need to bake WireGuard into your Windows programs. These projects use WireGuardNT inside.

## Usage

#### Download

WireGuardNT is deployed as a platform-specific `wireguard.dll` file. Install the `wireguard.dll` file side-by-side with your application. Download the dll from [the wireguard-nt download server](https://download.wireguard.com/wireguard-nt/), alongside the header file for your application described below.

#### API

Include the [`wireguard.h` file](https://git.zx2c4.com/wireguard-nt/tree/api/wireguard.h) in your project simply by copying it there and dynamically load the `wireguard.dll` using [`LoadLibraryEx()`](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexa) and [`GetProcAddress()`](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) to resolve each function, using the typedefs provided in the header file. The [`InitializeWireGuardNT` function in the example.c code](https://git.zx2c4.com/wireguard-nt/tree/example/example.c) provides this in a function that you can simply copy and paste.

With the library setup, WireGuardNT can then be used by first creating an adapter, configuring it, and then setting its status to "up". Adapters have names (e.g. "OfficeNet"), and each one belongs to a _pool_ (e.g. "WireGuard"). So, for example, the WireGuard application app creates multiple tunnels all inside of its "WireGuard" _pool_:

```C
WIREGUARD_ADAPTER_HANDLE Adapter1 = WireGuardCreateAdapter(L"WireGuard", L"OfficeNet", &SomeFixedGUID1, NULL);
WIREGUARD_ADAPTER_HANDLE Adapter2 = WireGuardCreateAdapter(L"WireGuard", L"HomeNet", &SomeFixedGUID2, NULL);
WIREGUARD_ADAPTER_HANDLE Adapter3 = WireGuardCreateAdapter(L"WireGuard", L"Data Center", &SomeFixedGUID3, NULL);
```

After creating an adapter, we can use it by setting a configuration and setting its status to "up":

```C
struct
{
    WIREGUARD_INTERFACE Interface;
    WIREGUARD_PEER FirstPeer;
    WIREGUARD_ALLOWED_IP FirstPeerAllowedIP1;
    WIREGUARD_ALLOWED_IP FirstPeerAllowedIP2;
    WIREGUARD_PEER SecondPeer;
    WIREGUARD_ALLOWED_IP SecondtPeerAllowedIP1;
} Config = {
    .Interface = {
        .Flags = WIREGUARD_INTERFACE_HAS_PRIVATE_KEY,
        .PrivateKey = ...,
        .PeersCount = 2
    },
    .FirstPeer = {
        .Flags = WIREGUARD_PEER_HAS_PUBLIC_KEY | WIREGUARD_PEER_HAS_ENDPOINT,
        .PublicKey = ...,
        .Endpoint = ...,
        .AllowedIPsCount = 2
    },
    .FirstPeerAllowedIP1 = { ... },
    ...
};
WireGuardSetConfiguration(Adapter1, &Config.Interface, sizeof(Config));
WireGuardSetAdapterState(Adapter1, WIREGUARD_ADAPTER_STATE_UP);
```

You are *highly encouraged* to read the [**example.c short example**](https://git.zx2c4.com/wireguard-nt/tree/example/example.c) to see how to put together a simple network tunnel. The example one connects to the [demo server](https://demo.wireguard.com/).

The various functions and definitions are [documented in `wireguard.h`](https://git.zx2c4.com/wireguard-nt/tree/api/wireguard.h).

## Building

**Do not distribute drivers or files named "WireGuard" or "wireguard" or similar, as they will most certainly clash with official deployments. Instead distribute [`wireguard.dll` as downloaded from the wireguard-nt download server](https://download.wireguard.com/wireguard-nt/).**

General requirements:

- [Visual Studio 2019](https://visualstudio.microsoft.com/downloads/) with Windows SDK
- [Windows Driver Kit](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)

`wireguard-nt.sln` may be opened in Visual Studio for development and building. Be sure to run `bcdedit /set testsigning on` and then reboot before to enable unsigned driver loading. The default run sequence (F5) in Visual Studio will build the example project and its dependencies.

## License

The entire contents of [this repository](https://git.zx2c4.com/wireguard-nt/), including all documentation and example code, is "Copyright © 2018-2021 WireGuard LLC. All Rights Reserved." Source code is licensed under the [GPLv2](COPYING). Prebuilt binaries from [the wireguard-nt download server](https://download.wireguard.com/wireguard-nt/) are released under a more permissive license suitable for more forms of software contained inside of the .zip files distributed there.
