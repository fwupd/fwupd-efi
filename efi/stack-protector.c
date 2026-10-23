/*
 * Copyright (C) 2026 Peter Jones <pjones@redhat.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <efi.h>
#include <efilib.h>

#include "fwup-cleanups.h"
#include "fwup-common.h"
#include "fwup-debug.h"
#include "fwup-efi.h"

#define SECONDS 1000000

/*
 * Before the first call to stack_protector_init(), it's important for the
 * canary it to have /something nonzero/ and to have some variability.
 * urandom would be nice, but it's not that important that it's truly
 * random, just fairly hard to predict and not stable across a bunch of
 * different machines.
 *
 * So we're just assigning it to some address that'll get relocated during
 * startup.  It'll get reset during initialization soon after.
 */
uintptr_t __stack_chk_guard = (uintptr_t)stack_protector_init;

void __attribute__((__noreturn__))
__stack_chk_fail(void)
{
	do {
		fwup_info(L"Stack corruption detected.  Shutting down in 5 seconds.\n");
		fwup_msleep(5 * SECONDS);
		RT->ResetSystem(EfiResetShutdown, EFI_SECURITY_VIOLATION, 0, NULL);

		/*
		 * We should never get here, but if we do, we have to do
		 * /something/.
		 */
		fwup_msleep(120 * SECONDS);
	} while (1);
}

/*
 * For reasons unknown, when we build for ia32 using:
 *
 * x86_64-linux-gnu-gcc -fstack-protector -mstack-protector-guard=global -m32 ...
 *
 * a few objects wind up referencing __stack_chk_fail_local() instead of
 * __stack_chk_fail().  I really don't understand why, but... eh.
 */
void __attribute__((__noreturn__)) __attribute__((__visibility__ ("hidden")))
__stack_chk_fail_local (void)
{
	__stack_chk_fail ();
}

uintptr_t
stack_protector_init(void)
{
	EFI_RNG_PROTOCOL *rng = NULL;
	EFI_STATUS efi_status;
	uintptr_t guard = __stack_chk_guard;

	efi_status = LibLocateProtocol(&rng_protocol_guid, (VOID *)&rng);
	if (EFI_ERROR(efi_status)) {
		fwup_warning(L"Could not find EFI RNG protocol: %r\n", efi_status);
		return guard;
	}

	efi_status = rng->GetRNG(rng, NULL, sizeof(guard)-1, (uint8_t *)&guard);
	if (EFI_ERROR(efi_status)) {
		fwup_warning(L"Could not get random data: %r\n", efi_status);
		return guard;
	}
	return guard;
}

// vim:fenc=utf-8:tw=75:noet
