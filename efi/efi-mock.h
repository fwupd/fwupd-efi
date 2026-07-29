/*
 * Copyright (C) 2024 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#define FWUP_SELFTEST_BUILD 1

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <wchar.h>

typedef void		VOID;
typedef uint8_t		UINT8;
typedef uint16_t	UINT16;
typedef uint32_t	UINT32;
typedef uint64_t	UINT64;
typedef int16_t		INT16;
typedef int64_t		INTN;
typedef uint64_t	UINTN;
typedef wchar_t		CHAR16;
typedef char		CHAR8;
typedef uint8_t		BOOLEAN;
typedef UINTN		EFI_STATUS;
typedef UINT64		EFI_PHYSICAL_ADDRESS;
typedef VOID		*EFI_HANDLE;
typedef UINT16		EFI_TPL;

#define TRUE		1
#define FALSE		0
#define EFIAPI
#define IN
#define OUT
#define OPTIONAL
#define CONST		const
#define UNUSED		__attribute__((__unused__))

#define uefi_call_wrapper(func, va_num, ...) func(__VA_ARGS__)

#define EFIERR(a)		(0x8000000000000000ULL | (a))
#define EFI_ERROR(a)		(((INTN)(a)) < 0)
#define EFI_SUCCESS		0
#define EFI_LOAD_ERROR		EFIERR(1)
#define EFI_INVALID_PARAMETER	EFIERR(2)
#define EFI_UNSUPPORTED		EFIERR(3)
#define EFI_BAD_BUFFER_SIZE	EFIERR(4)
#define EFI_BUFFER_TOO_SMALL	EFIERR(5)
#define EFI_NOT_READY		EFIERR(6)
#define EFI_OUT_OF_RESOURCES	EFIERR(9)
#define EFI_NOT_FOUND		EFIERR(14)

typedef struct {
	UINT32	Data1;
	UINT16	Data2;
	UINT16	Data3;
	UINT8	Data4[8];
} EFI_GUID;

typedef struct _EFI_DEVICE_PATH {
	UINT8	Type;
	UINT8	SubType;
	UINT8	Length[2];
} EFI_DEVICE_PATH;

typedef struct {
	UINT16	Year;
	UINT8	Month;
	UINT8	Day;
	UINT8	Hour;
	UINT8	Minute;
	UINT8	Second;
	UINT8	Pad1;
	UINT32	Nanosecond;
	INT16	TimeZone;
	UINT8	Daylight;
	UINT8	Pad2;
} EFI_TIME;

typedef struct {
	UINT32	Resolution;
	UINT32	Accuracy;
	BOOLEAN	SetsToZero;
} EFI_TIME_CAPABILITIES;

typedef struct {
	EFI_GUID	CapsuleGuid;
	UINT32		HeaderSize;
	UINT32		Flags;
	UINT32		CapsuleImageSize;
} EFI_CAPSULE_HEADER;

typedef struct {
	UINT64	Length;
	union {
		EFI_PHYSICAL_ADDRESS	DataBlock;
		EFI_PHYSICAL_ADDRESS	ContinuationPointer;
	} Union;
} EFI_CAPSULE_BLOCK_DESCRIPTOR;

typedef enum {
	EfiResetCold,
	EfiResetWarm,
	EfiResetShutdown
} EFI_RESET_TYPE;

typedef enum {
	AllocateAnyPages,
	AllocateMaxAddress,
	AllocateAddress
} EFI_ALLOCATE_TYPE;

typedef enum {
	EfiLoaderCode,
	EfiLoaderData,
	EfiMaxMemoryType
} EFI_MEMORY_TYPE;

typedef enum {
	AllHandles,
	ByRegisterNotify,
	ByProtocol
} EFI_LOCATE_SEARCH_TYPE;

#define CAPSULE_FLAGS_PERSIST_ACROSS_RESET	0x00010000
#define CAPSULE_FLAGS_INITIATE_RESET		0x00040000
#define EFI_OPEN_PROTOCOL_GET_PROTOCOL		0x00000002
#define EFI_FILE_MODE_READ			0x0000000000000001ULL

#define END_DEVICE_PATH_TYPE			0x7f
#define END_ENTIRE_DEVICE_PATH_SUBTYPE		0xff
#define MEDIA_DEVICE_PATH			0x04
#define MEDIA_FILEPATH_DP			0x04

#define EFI_VARIABLE_NON_VOLATILE		0x00000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS		0x00000002
#define EFI_VARIABLE_RUNTIME_ACCESS		0x00000004
#define EFI_VARIABLE_APPEND_WRITE		0x00000040

#define DevicePathType(a)		((a)->Type & 0x7f)
#define DevicePathSubType(a)		((a)->SubType)
#define DevicePathNodeLength(a)		((UINTN)((a)->Length[0] | ((a)->Length[1] << 8)))
#define NextDevicePathNode(a)		((EFI_DEVICE_PATH *)((UINT8 *)(a) + DevicePathNodeLength(a)))
#define IsDevicePathEndType(a)		(DevicePathType(a) == END_DEVICE_PATH_TYPE)
#define IsDevicePathEnd(a)		(IsDevicePathEndType(a) && \
					 (a)->SubType == END_ENTIRE_DEVICE_PATH_SUBTYPE)
#define SetDevicePathEndNode(a) do { \
	(a)->Type = END_DEVICE_PATH_TYPE; \
	(a)->SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE; \
	(a)->Length[0] = 4; (a)->Length[1] = 0; \
} while (0)

#define EFI_FIELD_OFFSET(TYPE, Field)	((UINTN)offsetof(TYPE, Field))

#define EFI_GLOBAL_VARIABLE \
	{ 0x8BE4DF61, 0x93CA, 0x11d2, { 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C } }
#define SIMPLE_FILE_SYSTEM_PROTOCOL \
	{ 0x964e5b22, 0x6459, 0x11d2, { 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } }
#define DEVICE_PATH_PROTOCOL \
	{ 0x09576e91, 0x6d3f, 0x11d2, { 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } }
#define EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID \
	{ 0x9042a9de, 0x23dc, 0x4a38, { 0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a } }

typedef struct {
	UINT32	MaxMode;
	UINT32	Mode;
	VOID	*Info;
	UINTN	SizeOfInfo;
	EFI_PHYSICAL_ADDRESS	FrameBufferBase;
	UINTN	FrameBufferSize;
} EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE;

typedef struct {
	VOID	*QueryMode;
	VOID	*SetMode;
	VOID	*Blt;
	EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE *Mode;
} EFI_GRAPHICS_OUTPUT_PROTOCOL;

struct _EFI_FILE_HANDLE;
typedef EFI_STATUS (*EFI_FILE_OPEN)(struct _EFI_FILE_HANDLE *file,
				    struct _EFI_FILE_HANDLE **new_handle,
				    CHAR16 *filename, UINT64 open_mode,
				    UINT64 attributes);
typedef EFI_STATUS (*EFI_FILE_CLOSE)(struct _EFI_FILE_HANDLE *file);
typedef EFI_STATUS (*EFI_FILE_READ)(struct _EFI_FILE_HANDLE *file,
				    UINTN *buf_size, VOID *buf);

typedef struct _EFI_FILE_HANDLE {
	UINT64		Revision;
	EFI_FILE_OPEN	Open;
	EFI_FILE_CLOSE	Close;
	VOID		*Delete;
	EFI_FILE_READ	Read;
} *EFI_FILE_HANDLE;

typedef struct _EFI_FILE_HANDLE EFI_FILE;

struct _EFI_FILE_IO_INTERFACE;
typedef EFI_STATUS (*EFI_VOLUME_OPEN)(struct _EFI_FILE_IO_INTERFACE *this,
				      EFI_FILE_HANDLE *root);

typedef struct _EFI_FILE_IO_INTERFACE {
	UINT64		Revision;
	EFI_VOLUME_OPEN	OpenVolume;
} EFI_FILE_IO_INTERFACE;

typedef struct {
	UINT64	Signature;
} EFI_TABLE_HEADER;

typedef EFI_STATUS (*EFI_STALL)(UINTN microseconds);
typedef EFI_STATUS (*EFI_ALLOCATE_PAGES)(EFI_ALLOCATE_TYPE type,
					 EFI_MEMORY_TYPE mem_type,
					 UINTN pages,
					 EFI_PHYSICAL_ADDRESS *memory);
typedef EFI_STATUS (*EFI_FREE_PAGES)(EFI_PHYSICAL_ADDRESS memory, UINTN pages);
typedef EFI_STATUS (*EFI_LOCATE_DEVICE_PATH)(EFI_GUID *protocol,
					     EFI_DEVICE_PATH **device_path,
					     EFI_HANDLE *device);
typedef EFI_STATUS (*EFI_HANDLE_PROTOCOL)(EFI_HANDLE handle,
					  EFI_GUID *protocol,
					  VOID **interface);
typedef EFI_STATUS (*EFI_LOCATE_HANDLE_BUFFER)(EFI_LOCATE_SEARCH_TYPE search_type,
					       EFI_GUID *protocol,
					       VOID *search_key,
					       UINTN *num_handles,
					       EFI_HANDLE **buffer);
typedef EFI_STATUS (*EFI_OPEN_PROTOCOL)(EFI_HANDLE handle,
					EFI_GUID *protocol,
					VOID **interface,
					EFI_HANDLE agent,
					EFI_HANDLE controller,
					UINT32 attributes);
typedef EFI_STATUS (*EFI_RAISE_TPL)(EFI_TPL new_tpl);

typedef struct {
	EFI_TABLE_HEADER	Hdr;
	EFI_RAISE_TPL		RaiseTPL;
	VOID			*RestoreTPL;
	EFI_ALLOCATE_PAGES	AllocatePages;
	EFI_FREE_PAGES		FreePages;
	VOID			*GetMemoryMap;
	VOID			*AllocatePool;
	VOID			*FreePool;
	VOID			*CreateEvent;
	VOID			*SetTimer;
	VOID			*WaitForEvent;
	VOID			*SignalEvent;
	VOID			*CloseEvent;
	VOID			*CheckEvent;
	VOID			*InstallProtocolInterface;
	VOID			*ReinstallProtocolInterface;
	VOID			*UninstallProtocolInterface;
	EFI_HANDLE_PROTOCOL	HandleProtocol;
	VOID			*Reserved;
	VOID			*RegisterProtocolNotify;
	EFI_LOCATE_HANDLE_BUFFER LocateHandleBuffer;
	VOID			*LocateProtocol;
	VOID			*InstallMultipleProtocolInterfaces;
	VOID			*UninstallMultipleProtocolInterfaces;
	VOID			*CalculateCrc32;
	VOID			*CopyMem;
	VOID			*SetMem;
	VOID			*CreateEventEx;
	EFI_LOCATE_DEVICE_PATH	LocateDevicePath;
	EFI_OPEN_PROTOCOL	OpenProtocol;
	VOID			*CloseProtocol;
	VOID			*OpenProtocolInformation;
	VOID			*ProtocolsPerHandle;
	VOID			*LocateHandleBuffer2;
	EFI_STALL		Stall;
} EFI_BOOT_SERVICES;

typedef EFI_STATUS (*EFI_GET_TIME)(EFI_TIME *time,
				   EFI_TIME_CAPABILITIES *capabilities);
typedef EFI_STATUS (*EFI_GET_VARIABLE)(CHAR16 *name, EFI_GUID *vendor,
				       UINT32 *attrs, UINTN *data_size,
				       VOID *data);
typedef EFI_STATUS (*EFI_GET_NEXT_VARIABLE_NAME)(UINTN *name_size,
						 CHAR16 *name,
						 EFI_GUID *vendor);
typedef EFI_STATUS (*EFI_SET_VARIABLE)(CHAR16 *name, EFI_GUID *vendor,
				       UINT32 attrs, UINTN data_size,
				       VOID *data);
typedef EFI_STATUS (*EFI_QUERY_CAPSULE_CAPABILITIES)(EFI_CAPSULE_HEADER **capsules,
						     UINTN count,
						     UINT64 *max_size,
						     EFI_RESET_TYPE *reset_type);
typedef EFI_STATUS (*EFI_UPDATE_CAPSULE)(EFI_CAPSULE_HEADER **capsules,
					 UINTN count,
					 EFI_PHYSICAL_ADDRESS sg_list);
typedef VOID (*EFI_RESET_SYSTEM)(EFI_RESET_TYPE type, EFI_STATUS status,
				 UINTN data_size, CHAR16 *data);

typedef struct {
	EFI_TABLE_HEADER		Hdr;
	EFI_GET_TIME			GetTime;
	VOID				*SetTime;
	VOID				*GetWakeupTime;
	VOID				*SetWakeupTime;
	VOID				*SetVirtualAddressMap;
	VOID				*ConvertPointer;
	EFI_GET_VARIABLE		GetVariable;
	EFI_GET_NEXT_VARIABLE_NAME	GetNextVariableName;
	EFI_SET_VARIABLE		SetVariable;
	VOID				*GetNextHighMonotonicCount;
	EFI_RESET_SYSTEM		ResetSystem;
	EFI_UPDATE_CAPSULE		UpdateCapsule;
	EFI_QUERY_CAPSULE_CAPABILITIES	QueryCapsuleCapabilities;
} EFI_RUNTIME_SERVICES;

typedef struct {
	EFI_TABLE_HEADER	Hdr;
	CHAR16			*FirmwareVendor;
	UINT32			FirmwareRevision;
	EFI_HANDLE		ConsoleInHandle;
	VOID			*ConIn;
	EFI_HANDLE		ConsoleOutHandle;
	VOID			*ConOut;
	EFI_HANDLE		StandardErrorHandle;
	VOID			*StdErr;
	EFI_RUNTIME_SERVICES	*RuntimeServices;
	EFI_BOOT_SERVICES	*BootServices;
} EFI_SYSTEM_TABLE;

extern EFI_BOOT_SERVICES *BS;
extern EFI_RUNTIME_SERVICES *RT;

static inline VOID
CopyMem(VOID *dest, const VOID *src, UINTN len)
{
	memcpy(dest, src, len);
}

static inline INTN
CompareGuid(const EFI_GUID *a, const EFI_GUID *b)
{
	return (INTN)memcmp(a, b, sizeof(EFI_GUID));
}

static inline VOID *
AllocatePool(UINTN size)
{
	return malloc(size);
}

static inline VOID *
AllocateZeroPool(UINTN size)
{
	return calloc(1, size);
}

static inline VOID
FreePool(VOID *ptr)
{
	free(ptr);
}

static inline CHAR16 *
StrDuplicate(const CHAR16 *src)
{
	if (src == NULL)
		return NULL;
	UINTN len = 0;
	while (src[len] != 0)
		len++;
	CHAR16 *dst = malloc((len + 1) * sizeof(CHAR16));
	if (dst == NULL)
		return NULL;
	memcpy(dst, src, (len + 1) * sizeof(CHAR16));
	return dst;
}

static inline INTN
StrCmp(const CHAR16 *a, const CHAR16 *b)
{
	while (*a && *a == *b) {
		a++;
		b++;
	}
	return *a - *b;
}

static inline UINTN
StrSize(const CHAR16 *s)
{
	UINTN len = 0;
	while (s[len] != 0)
		len++;
	return (len + 1) * sizeof(CHAR16);
}

static inline UINTN UNUSED
Print(const CHAR16 *fmt, ...)
{
	return 0;
}

static inline CHAR16 * UNUSED
VPoolPrint(const CHAR16 *fmt, va_list args)
{
	return StrDuplicate(L"<mock>");
}

static inline CHAR16 * UNUSED
PoolPrint(const CHAR16 *fmt, ...)
{
	return StrDuplicate(L"<mock>");
}

static inline VOID UNUSED
InitializeLib(EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
}

static inline EFI_STATUS UNUSED
LibLocateHandle(EFI_LOCATE_SEARCH_TYPE type, EFI_GUID *protocol,
		VOID *search_key, UINTN *num_handles, EFI_HANDLE **buffer)
{
	*num_handles = 0;
	*buffer = NULL;
	return EFI_NOT_FOUND;
}

static inline BOOLEAN UNUSED
LibMatchDevicePaths(const EFI_DEVICE_PATH *a, const EFI_DEVICE_PATH *b)
{
	return FALSE;
}

static inline EFI_DEVICE_PATH * UNUSED
DuplicateDevicePath(const EFI_DEVICE_PATH *dp)
{
	return NULL;
}

static inline CHAR16 * UNUSED
DevicePathToStr(const EFI_DEVICE_PATH *dp)
{
	return L"<mock-dp>";
}
