#include "efi-mock-funcs.h"

static EFI_STATUS
fuzz_locate_handle_buffer(EFI_LOCATE_SEARCH_TYPE type, EFI_GUID *protocol,
			  VOID *key, UINTN *num, EFI_HANDLE **buf)
{
	*num = 0;
	*buf = NULL;
	return EFI_NOT_FOUND;
}

static EFI_STATUS
fuzz_get_variable(CHAR16 *name, EFI_GUID *vendor, UINT32 *attrs,
		  UINTN *data_size, VOID *data)
{
	return EFI_NOT_FOUND;
}

static EFI_STATUS
fuzz_get_next_variable_name(UINTN *name_size, CHAR16 *name, EFI_GUID *vendor)
{
	return EFI_NOT_FOUND;
}

static EFI_STATUS
fuzz_set_variable(CHAR16 *name, EFI_GUID *vendor, UINT32 attrs,
		  UINTN data_size, VOID *data)
{
	return EFI_SUCCESS;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	memset(&mock_bs, 0, sizeof(mock_bs));
	memset(&mock_rt, 0, sizeof(mock_rt));

	mock_bs.Stall = mock_stall;
	mock_bs.AllocatePages = mock_allocate_pages;
	mock_bs.FreePages = mock_free_pages;
	mock_bs.LocateHandleBuffer = fuzz_locate_handle_buffer;

	mock_rt.GetTime = mock_get_time;
	mock_rt.GetVariable = fuzz_get_variable;
	mock_rt.GetNextVariableName = fuzz_get_next_variable_name;
	mock_rt.SetVariable = fuzz_set_variable;
	mock_rt.ResetSystem = mock_reset_system;

	if (size < sizeof(EFI_CAPSULE_HEADER))
		return 0;

	UINT8 *buf = malloc(size);
	if (buf == NULL)
		return 0;
	memcpy(buf, data, size);

	fwup_check_gop_for_ux_capsule(NULL, (EFI_CAPSULE_HEADER *)buf, size);

	free(buf);
	return 0;
}
