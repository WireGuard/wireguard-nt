/* SPDX-License-Identifier: GPL-2.0 OR MIT
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include <winsock2.h>
#include <windows.h>
#include <ipexport.h>
#include <ifdef.h>
#include <ws2ipdef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ALIGNED
#    if defined(_MSC_VER)
#        define ALIGNED(n) __declspec(align(n))
#    elif defined(__GNUC__)
#        define ALIGNED(n) __attribute__((aligned(n)))
#    else
#        error "Unable to define ALIGNED"
#    endif
#endif

/* MinGW is missing this one, unfortunately. */
#ifndef _Post_maybenull_
#    define _Post_maybenull_
#endif

#pragma warning(push)
#pragma warning(disable : 4324) /* structure was padded due to alignment specifier */

/**
 * A handle representing WireGuard adapter
 */
typedef struct _WIREGUARD_ADAPTER *WIREGUARD_ADAPTER_HANDLE;

/**
 * Maximum pool name length including zero terminator
 */
#define WIREGUARD_MAX_POOL 256

/**
 * Creates a new WireGuard adapter.
 *
 * @param Pool          Name of the adapter pool. Zero-terminated string of up to WIREGUARD_MAX_POOL-1 characters.
 *
 * @param Name          The requested name of the adapter. Zero-terminated string of up to MAX_ADAPTER_NAME-1
 *                      characters.
 *
 * @param RequestedGUID The GUID of the created network adapter, which then influences NLA generation deterministically.
 *                      If it is set to NULL, the GUID is chosen by the system at random, and hence a new NLA entry is
 *                      created for each new adapter. It is called "requested" GUID because the API it uses is
 *                      completely undocumented, and so there could be minor interesting complications with its usage.
 *
 * @param RebootRequired  Optional pointer to a boolean flag to be set to TRUE in case SetupAPI suggests a reboot.
 *
 * @return If the function succeeds, the return value is the adapter handle. Must be released with WireGuardFreeAdapter.
 * If the function fails, the return value is NULL. To get extended error information, call GetLastError.
 */
typedef _Must_inspect_result_
_Return_type_success_(return != NULL)
_Post_maybenull_
WIREGUARD_ADAPTER_HANDLE(WINAPI WIREGUARD_CREATE_ADAPTER_FUNC)
(_In_z_ LPCWSTR Pool, _In_z_ LPCWSTR Name, _In_opt_ const GUID *RequestedGUID, _Out_opt_ BOOL *RebootRequired);

/**
 * Opens an existing WireGuard adapter.
 *
 * @param Pool          Name of the adapter pool. Zero-terminated string of up to WIREGUARD_MAX_POOL-1 characters.
 *
 * @param Name          Adapter name. Zero-terminated string of up to MAX_ADAPTER_NAME-1 characters.
 *
 * @return If the function succeeds, the return value is adapter handle. Must be released with WireGuardFreeAdapter. If
 * the function fails, the return value is NULL. To get extended error information, call GetLastError. Possible errors
 * include the following: ERROR_FILE_NOT_FOUND if adapter with given name is not found; ERROR_ALREADY_EXISTS if adapter
 * is found but not a WireGuard-class or not a member of the pool
 */
typedef _Must_inspect_result_
_Return_type_success_(return != NULL)
_Post_maybenull_
WIREGUARD_ADAPTER_HANDLE(WINAPI WIREGUARD_OPEN_ADAPTER_FUNC)(_In_z_ LPCWSTR Pool, _In_z_ LPCWSTR Name);

/**
 * Deletes a WireGuard adapter.
 *
 * @param Adapter         Adapter handle obtained with WireGuardOpenAdapter or WireGuardCreateAdapter.
 *
 * @param RebootRequired  Optional pointer to a boolean flag to be set to TRUE in case SetupAPI suggests a reboot.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
typedef _Return_type_success_(return != FALSE)
BOOL(WINAPI WIREGUARD_DELETE_ADAPTER_FUNC)
(_In_ WIREGUARD_ADAPTER_HANDLE Adapter, _Out_opt_ BOOL *RebootRequired);

/**
 * Called by WireGuardEnumAdapters for each adapter in the pool.
 *
 * @param Adapter       Adapter handle, which will be freed when this function returns.
 *
 * @param Param         An application-defined value passed to the WireGuardEnumAdapters.
 *
 * @return Non-zero to continue iterating adapters; zero to stop.
 */
typedef BOOL(CALLBACK *WIREGUARD_ENUM_CALLBACK)(_In_ WIREGUARD_ADAPTER_HANDLE Adapter, _In_ LPARAM Param);

/**
 * Enumerates all WireGuard adapters.
 *
 * @param Pool          Name of the adapter pool. Zero-terminated string of up to WIREGUARD_MAX_POOL-1 characters.
 *
 * @param Callback      Callback function. To continue enumeration, the callback function must return TRUE; to stop
 *                      enumeration, it must return FALSE.
 *
 * @param Param         An application-defined value to be passed to the callback function.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
typedef _Return_type_success_(return != FALSE)
BOOL(WINAPI WIREGUARD_ENUM_ADAPTERS_FUNC)
(_In_z_ LPCWSTR Pool, _In_ WIREGUARD_ENUM_CALLBACK Callback, _In_ LPARAM Param);

/**
 * Releases WireGuard adapter resources.
 *
 * @param Adapter       Adapter handle obtained with WireGuardOpenAdapter or WireGuardCreateAdapter.
 */
typedef VOID(WINAPI WIREGUARD_FREE_ADAPTER_FUNC)(_In_opt_ WIREGUARD_ADAPTER_HANDLE Adapter);

/**
 * Deletes all WireGuard adapters in a pool and if there are no more adapters in any other pools, also removes WireGuard
 * from the driver store, usually called by uninstallers.
 *
 * @param Pool            Name of the adapter pool. Zero-terminated string of up to WIREGUARD_MAX_POOL-1 characters.
 *
 * @param RebootRequired  Optional pointer to a boolean flag to be set to TRUE in case SetupAPI suggests a reboot.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
typedef _Return_type_success_(return != FALSE)
BOOL(WINAPI WIREGUARD_DELETE_POOL_DRIVER_FUNC)(_In_z_ LPCWSTR Pool, _Out_opt_ BOOL *RebootRequired);

/**
 * Returns the LUID of the adapter.
 *
 * @param Adapter       Adapter handle obtained with WireGuardOpenAdapter or WireGuardCreateAdapter
 *
 * @param Luid          Pointer to LUID to receive adapter LUID.
 */
typedef VOID(WINAPI WIREGUARD_GET_ADAPTER_LUID_FUNC)(_In_ WIREGUARD_ADAPTER_HANDLE Adapter, _Out_ NET_LUID *Luid);

/**
 * Returns the name of the WireGuard adapter.
 *
 * @param Adapter       Adapter handle obtained with WireGuardOpenAdapter or WireGuardCreateAdapter
 *
 * @param Name          Pointer to a string to receive adapter name
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
typedef _Must_inspect_result_
_Return_type_success_(return != FALSE)
BOOL(WINAPI WIREGUARD_GET_ADAPTER_NAME_FUNC)
(_In_ WIREGUARD_ADAPTER_HANDLE Adapter, _Out_writes_z_(MAX_ADAPTER_NAME) LPWSTR Name);

/**
 * Sets name of the WireGuard adapter.
 *
 * @param Adapter       Adapter handle obtained with WireGuardOpenAdapter or WireGuardCreateAdapter
 *
 * @param Name          Adapter name. Zero-terminated string of up to MAX_ADAPTER_NAME-1 characters.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
typedef _Return_type_success_(return != FALSE)
BOOL(WINAPI WIREGUARD_SET_ADAPTER_NAME_FUNC)
(_In_ WIREGUARD_ADAPTER_HANDLE Adapter, _In_reads_or_z_(MAX_ADAPTER_NAME) LPCWSTR Name);

/**
 * Determines the version of the WireGuard driver currently loaded.
 *
 * @return If the function succeeds, the return value is the version number. If the function fails, the return value is
 *         zero. To get extended error information, call GetLastError. Possible errors include the following:
 *         ERROR_FILE_NOT_FOUND  WireGuard not loaded
 */
typedef _Return_type_success_(return != 0)
DWORD(WINAPI WIREGUARD_GET_RUNNING_DRIVER_VERSION_FUNC)(VOID);

/**
 * Determines the level of logging, passed to WIREGUARD_LOGGER_CALLBACK.
 */
typedef enum
{
    WIREGUARD_LOG_INFO, /**< Informational */
    WIREGUARD_LOG_WARN, /**< Warning */
    WIREGUARD_LOG_ERR   /**< Error */
} WIREGUARD_LOGGER_LEVEL;

/**
 * Called by internal logger to report diagnostic messages
 *
 * @param Level         Message level.
 *
 * @param Timestamp     Message timestamp in in 100ns intervals since 1601-01-01 UTC.
 *
 * @param Message       Message text.
 */
typedef VOID(CALLBACK *WIREGUARD_LOGGER_CALLBACK)(
    _In_ WIREGUARD_LOGGER_LEVEL Level,
    _In_ DWORD64 Timestamp,
    _In_z_ LPCWSTR Message);

/**
 * Sets logger callback function.
 *
 * @param NewLogger     Pointer to callback function to use as a new global logger. NewLogger may be called from various
 *                      threads concurrently. Should the logging require serialization, you must handle serialization in
 *                      NewLogger. Set to NULL to disable.
 */
typedef VOID(WINAPI WIREGUARD_SET_LOGGER_FUNC)(_In_ WIREGUARD_LOGGER_CALLBACK NewLogger);

/**
 * Whether and how logs from the driver are collected for the callback function.
 */
typedef enum
{
    WIREGUARD_ADAPTER_LOG_OFF,           /**< No logs are generated from the driver. */
    WIREGUARD_ADAPTER_LOG_ON,            /**< Logs are generated from the driver. */
    WIREGUARD_ADAPTER_LOG_ON_WITH_PREFIX /**< Logs are generated from the driver, index-prefixed. */
} WIREGUARD_ADAPTER_LOG_STATE;

/**
 * Sets whether and how the adapter logs to the logger previously set up with WireGuardSetLoggerFunc.
 *
 * @param Adapter       Adapter handle obtained with WireGuardOpenAdapter or WireGuardCreateAdapter
 *
 * @param LogState      Adapter logging state.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
typedef _Return_type_success_(return != FALSE)
BOOL(WINAPI WIREGUARD_SET_ADAPTER_LOGGING_FUNC)
(_In_ WIREGUARD_ADAPTER_HANDLE Adapter, _In_ WIREGUARD_ADAPTER_LOG_STATE LogState);

/**
 * Determines the state of the adapter.
 */
typedef enum
{
    WIREGUARD_ADAPTER_STATE_DOWN, /**< Down */
    WIREGUARD_ADAPTER_STATE_UP,   /**< Up */
} WIREGUARD_ADAPTER_STATE;

/**
 * Sets the adapter state of the WireGuard adapter. Note: sockets are owned by the process that sets the state to up.
 *
 * @param Adapter       Adapter handle obtained with WireGuardOpenAdapter or WireGuardCreateAdapter
 *
 * @param State         Adapter state.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
typedef _Return_type_success_(return != FALSE)
BOOL(WINAPI WIREGUARD_SET_ADAPTER_STATE_FUNC)
(_In_ WIREGUARD_ADAPTER_HANDLE Adapter, _In_ WIREGUARD_ADAPTER_STATE State);

/**
 * Gets the adapter state of the WireGuard adapter.
 *
 * @param Adapter       Adapter handle obtained with WireGuardOpenAdapter or WireGuardCreateAdapter
 *
 * @param State         Pointer to adapter state.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
typedef _Must_inspect_result_
_Return_type_success_(return != FALSE)
BOOL(WINAPI WIREGUARD_GET_ADAPTER_STATE_FUNC)
(_In_ WIREGUARD_ADAPTER_HANDLE Adapter, _Out_ WIREGUARD_ADAPTER_STATE *State);

#define WIREGUARD_KEY_LENGTH 32

typedef struct _WIREGUARD_ALLOWED_IP WIREGUARD_ALLOWED_IP;
struct ALIGNED(8) _WIREGUARD_ALLOWED_IP
{
    union
    {
        IN_ADDR V4;
        IN6_ADDR V6;
    } Address;                    /**< IP address */
    ADDRESS_FAMILY AddressFamily; /**< Address family, either AF_INET or AF_INET6 */
    BYTE Cidr;                    /**< CIDR of allowed IPs */
};

typedef enum
{
    WIREGUARD_PEER_HAS_PUBLIC_KEY = 1 << 0,           /**< The PublicKey field is set */
    WIREGUARD_PEER_HAS_PRESHARED_KEY = 1 << 1,        /**< The PresharedKey field is set */
    WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE = 1 << 2, /**< The PersistentKeepAlive field is set */
    WIREGUARD_PEER_HAS_ENDPOINT = 1 << 3,             /**< The Endpoint field is set */
    WIREGUARD_PEER_REPLACE_ALLOWED_IPS = 1 << 5,      /**< Remove all allowed IPs before adding new ones */
    WIREGUARD_PEER_REMOVE = 1 << 6,                   /**< Remove specified peer */
    WIREGUARD_PEER_UPDATE = 1 << 7                    /**< Do not add a new peer */
} WIREGUARD_PEER_FLAG;

typedef struct _WIREGUARD_PEER WIREGUARD_PEER;
struct ALIGNED(8) _WIREGUARD_PEER
{
    WIREGUARD_PEER_FLAG Flags;               /**< Bitwise combination of flags */
    DWORD Reserved;                          /**< Reserved; must be zero */
    BYTE PublicKey[WIREGUARD_KEY_LENGTH];    /**< Public key, the peer's primary identifier */
    BYTE PresharedKey[WIREGUARD_KEY_LENGTH]; /**< Preshared key for additional layer of post-quantum resistance */
    WORD PersistentKeepalive;                /**< Seconds interval, or 0 to disable */
    SOCKADDR_INET Endpoint;                  /**< Endpoint, with IP address and UDP port number*/
    DWORD64 TxBytes;                         /**< Number of bytes transmitted */
    DWORD64 RxBytes;                         /**< Number of bytes received */
    DWORD64 LastHandshake;                   /**< Time of the last handshake, in 100ns intervals since 1601-01-01 UTC */
    DWORD AllowedIPsCount;                   /**< Number of allowed IP structs following this struct */
};

typedef enum
{
    WIREGUARD_INTERFACE_HAS_PUBLIC_KEY = (1 << 0),  /**< The PublicKey field is set */
    WIREGUARD_INTERFACE_HAS_PRIVATE_KEY = (1 << 1), /**< The PrivateKey field is set */
    WIREGUARD_INTERFACE_HAS_LISTEN_PORT = (1 << 2), /**< The ListenPort field is set */
    WIREGUARD_INTERFACE_REPLACE_PEERS = (1 << 3)    /**< Remove all peers before adding new ones */
} WIREGUARD_INTERFACE_FLAG;

typedef struct _WIREGUARD_INTERFACE WIREGUARD_INTERFACE;
struct ALIGNED(8) _WIREGUARD_INTERFACE
{
    WIREGUARD_INTERFACE_FLAG Flags;        /**< Bitwise combination of flags */
    WORD ListenPort;                       /**< Port for UDP listen socket, or 0 to choose randomly */
    BYTE PrivateKey[WIREGUARD_KEY_LENGTH]; /**< Private key of interface */
    BYTE PublicKey[WIREGUARD_KEY_LENGTH];  /**< Corresponding public key of private key */
    DWORD PeersCount;                      /**< Number of peer structs following this struct */
};

/**
 * Sets the configuration of the WireGuard adapter.
 *
 * @param Adapter       Adapter handle obtained with WireGuardOpenAdapter or WireGuardCreateAdapter
 *
 * @param Config        Configuration for the adapter.
 *
 * @param Bytes         Number of bytes in Config allocation.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
typedef _Return_type_success_(return != FALSE)
BOOL(WINAPI WIREGUARD_SET_CONFIGURATION_FUNC)
(_In_ WIREGUARD_ADAPTER_HANDLE Adapter, _In_reads_bytes_(Bytes) const WIREGUARD_INTERFACE *Config, _In_ DWORD Bytes);

/**
 * Gets the configuration of the WireGuard adapter.
 *
 * @param Adapter       Adapter handle obtained with WireGuardOpenAdapter or WireGuardCreateAdapter
 *
 * @param Config        Configuration for the adapter.
 *
 * @param Bytes         Pointer to number of bytes in Config allocation.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError, which if ERROR_MORE_DATA, Bytes is updated with the
 *         required size.
 */
typedef _Must_inspect_result_
_Return_type_success_(return != FALSE)
BOOL(WINAPI WIREGUARD_GET_CONFIGURATION_FUNC)
(_In_ WIREGUARD_ADAPTER_HANDLE Adapter,
 _Out_writes_bytes_all_(*Bytes) WIREGUARD_INTERFACE *Config,
 _Inout_ DWORD *Bytes);

#pragma warning(pop)

#ifdef __cplusplus
}
#endif
