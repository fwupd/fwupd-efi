/*
 * Copyright (C) 2024 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "efi-mock.h"

#include <stdio.h>
#include <string.h>

/* BS/RT globals */
static EFI_BOOT_SERVICES mock_bs;
static EFI_RUNTIME_SERVICES mock_rt;
EFI_BOOT_SERVICES *BS = &mock_bs;
EFI_RUNTIME_SERVICES *RT = &mock_rt;

/* linker symbols referenced by fwup_debug_hook */
char UNUSED _text = 0;
char UNUSED _data = 0;

/* include the real source -- makes static functions visible */
#include "fwup-debug.c"
#include "fwup-efi.c"
#include "fwup-common.c"
#include "fwupdate.c"

static EFI_STATUS
mock_stall(UINTN microseconds)
{
	return EFI_SUCCESS;
}

static EFI_STATUS
mock_allocate_pages(EFI_ALLOCATE_TYPE type, EFI_MEMORY_TYPE mem_type,
		    UINTN pages, EFI_PHYSICAL_ADDRESS *memory)
{
	VOID *p = calloc(pages, 4096);
	if (p == NULL)
		return EFI_OUT_OF_RESOURCES;
	*memory = (EFI_PHYSICAL_ADDRESS)(UINTN)p;
	return EFI_SUCCESS;
}

static EFI_STATUS
mock_free_pages(EFI_PHYSICAL_ADDRESS memory, UINTN pages)
{
	free((VOID *)(UINTN)memory);
	return EFI_SUCCESS;
}

static EFI_STATUS
mock_get_time(EFI_TIME *time, EFI_TIME_CAPABILITIES *caps)
{
	memset(time, 0, sizeof(*time));
	time->Year = 2024;
	time->Month = 1;
	time->Day = 1;
	if (caps)
		memset(caps, 0, sizeof(*caps));
	return EFI_SUCCESS;
}

static void
mock_reset_system(EFI_RESET_TYPE type, EFI_STATUS status,
		  UINTN data_size, CHAR16 *data)
{
}
