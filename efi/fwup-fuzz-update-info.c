#include "efi-mock-funcs.h"

static const uint8_t *fuzz_data;
static size_t fuzz_size;

static EFI_STATUS
fuzz_get_variable(CHAR16 *name, EFI_GUID *vendor, UINT32 *attrs,
		  UINTN *data_size, VOID *data)
{
	if (attrs)
		*attrs = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS;

	if (data == NULL || *data_size < fuzz_size) {
		*data_size = fuzz_size;
		return EFI_BUFFER_TOO_SMALL;
	}

	*data_size = fuzz_size;
	memcpy(data, fuzz_data, fuzz_size);
	return EFI_SUCCESS;
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

	mock_rt.GetTime = mock_get_time;
	mock_rt.GetVariable = fuzz_get_variable;
	mock_rt.GetNextVariableName = fuzz_get_next_variable_name;
	mock_rt.SetVariable = fuzz_set_variable;
	mock_rt.ResetSystem = mock_reset_system;

	fuzz_data = data;
	fuzz_size = size;

	FWUP_UPDATE_TABLE out;
	memset(&out, 0, sizeof(out));
	EFI_STATUS rc = fwup_populate_update_info(L"fuzz", &out);
	if (!EFI_ERROR(rc)) {
		FreePool(out.info);
		FreePool(out.name);
	}

	return 0;
}
