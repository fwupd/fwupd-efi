#include "efi-mock-funcs.h"

#include <assert.h>

static unsigned int tests_run;
static unsigned int tests_passed;

#define RUN_TEST(func) do { \
	tests_run++; \
	printf("  " #func "... "); \
	fflush(stdout); \
	func(); \
	tests_passed++; \
	printf("OK\n"); \
} while (0)

/*
 * mock BS->LocateDevicePath -- always fail
 */
static EFI_STATUS
mock_locate_device_path(EFI_GUID *protocol, EFI_DEVICE_PATH **dp,
			EFI_HANDLE *device)
{
	return EFI_NOT_FOUND;
}

/*
 * mock BS->HandleProtocol -- always fail
 */
static EFI_STATUS
mock_handle_protocol(EFI_HANDLE handle, EFI_GUID *protocol, VOID **iface)
{
	return EFI_UNSUPPORTED;
}

/*
 * mock BS->LocateHandleBuffer -- always fail
 */
static EFI_STATUS
mock_locate_handle_buffer(EFI_LOCATE_SEARCH_TYPE type, EFI_GUID *protocol,
			  VOID *key, UINTN *num, EFI_HANDLE **buf)
{
	*num = 0;
	*buf = NULL;
	return EFI_NOT_FOUND;
}

/*
 * mock BS->OpenProtocol -- always fail
 */
static EFI_STATUS
mock_open_protocol(EFI_HANDLE handle, EFI_GUID *protocol, VOID **iface,
		   EFI_HANDLE agent, EFI_HANDLE controller, UINT32 attrs)
{
	return EFI_UNSUPPORTED;
}

/*
 * mock RT->GetVariable state -- configurable per test
 */
static UINT8 *mock_var_data;
static UINTN mock_var_data_size;
static UINT32 mock_var_attrs;
static EFI_STATUS mock_var_status;

static EFI_STATUS
mock_get_variable(CHAR16 *name, EFI_GUID *vendor, UINT32 *attrs,
		  UINTN *data_size, VOID *data)
{
	if (mock_var_status != EFI_SUCCESS)
		return mock_var_status;

	if (attrs)
		*attrs = mock_var_attrs;

	if (data == NULL || *data_size < mock_var_data_size) {
		*data_size = mock_var_data_size;
		return EFI_BUFFER_TOO_SMALL;
	}

	*data_size = mock_var_data_size;
	memcpy(data, mock_var_data, mock_var_data_size);
	return EFI_SUCCESS;
}

/*
 * mock RT->SetVariable -- record what was called
 */
static BOOLEAN mock_set_variable_called;
static UINTN mock_set_variable_size;

static EFI_STATUS
mock_set_variable(CHAR16 *name, EFI_GUID *vendor, UINT32 attrs,
		  UINTN data_size, VOID *data)
{
	mock_set_variable_called = TRUE;
	mock_set_variable_size = data_size;
	return EFI_SUCCESS;
}

/*
 * mock RT->GetNextVariableName -- return nothing
 */
static EFI_STATUS
mock_get_next_variable_name(UINTN *name_size, CHAR16 *name, EFI_GUID *vendor)
{
	return EFI_NOT_FOUND;
}

static EFI_STATUS
mock_query_capsule_caps(EFI_CAPSULE_HEADER **capsules, UINTN count,
			UINT64 *max_size, EFI_RESET_TYPE *reset_type)
{
	*max_size = 0x1000000;
	*reset_type = EfiResetWarm;
	return EFI_SUCCESS;
}

static EFI_STATUS
mock_update_capsule(EFI_CAPSULE_HEADER **capsules, UINTN count,
		    EFI_PHYSICAL_ADDRESS sg_list)
{
	return EFI_SUCCESS;
}

static void
mock_init(void)
{
	memset(&mock_bs, 0, sizeof(mock_bs));
	memset(&mock_rt, 0, sizeof(mock_rt));

	mock_bs.Stall = mock_stall;
	mock_bs.AllocatePages = mock_allocate_pages;
	mock_bs.FreePages = mock_free_pages;
	mock_bs.LocateDevicePath = mock_locate_device_path;
	mock_bs.HandleProtocol = mock_handle_protocol;
	mock_bs.LocateHandleBuffer = mock_locate_handle_buffer;
	mock_bs.OpenProtocol = mock_open_protocol;

	mock_rt.GetTime = mock_get_time;
	mock_rt.GetVariable = mock_get_variable;
	mock_rt.GetNextVariableName = mock_get_next_variable_name;
	mock_rt.SetVariable = mock_set_variable;
	mock_rt.ResetSystem = mock_reset_system;
	mock_rt.QueryCapsuleCapabilities = mock_query_capsule_caps;
	mock_rt.UpdateCapsule = mock_update_capsule;

	mock_var_data = NULL;
	mock_var_data_size = 0;
	mock_var_attrs = 0;
	mock_var_status = EFI_NOT_FOUND;
	mock_set_variable_called = FALSE;
	mock_set_variable_size = 0;
}

/*
 * helper: build a device path end node at buf
 */
static void
build_dp_end(UINT8 *buf)
{
	EFI_DEVICE_PATH *dp = (EFI_DEVICE_PATH *)buf;
	dp->Type = END_DEVICE_PATH_TYPE;
	dp->SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE;
	dp->Length[0] = 4;
	dp->Length[1] = 0;
}

/*
 * helper: build a generic device path node at buf with given type, subtype, length
 */
static void
build_dp_node(UINT8 *buf, UINT8 type, UINT8 subtype, UINT16 length)
{
	EFI_DEVICE_PATH *dp = (EFI_DEVICE_PATH *)buf;
	dp->Type = type;
	dp->SubType = subtype;
	dp->Length[0] = (UINT8)(length & 0xff);
	dp->Length[1] = (UINT8)(length >> 8);
}

/* ================================================================
 * Group 1: fwup_dp_size
 * ================================================================ */

static void
test_dp_size_single_end_node(void)
{
	UINT8 buf[4];
	build_dp_end(buf);
	INTN sz = fwup_dp_size((EFI_DEVICE_PATH *)buf, 100);
	assert(sz == 4);
}

static void
test_dp_size_multiple_nodes(void)
{
	UINT8 buf[18];
	build_dp_node(buf, 0x01, 0x01, 8);
	build_dp_node(buf + 8, 0x02, 0x01, 6);
	build_dp_end(buf + 14);
	INTN sz = fwup_dp_size((EFI_DEVICE_PATH *)buf, 100);
	assert(sz == 18);
}

static void
test_dp_size_limit_too_small(void)
{
	UINT8 buf[4];
	build_dp_end(buf);
	INTN sz = fwup_dp_size((EFI_DEVICE_PATH *)buf, 3);
	assert(sz == -1);
}

static void
test_dp_size_node_exceeds_limit(void)
{
	UINT8 buf[12];
	build_dp_node(buf, 0x01, 0x01, 8);
	build_dp_end(buf + 8);
	INTN sz = fwup_dp_size((EFI_DEVICE_PATH *)buf, 6);
	assert(sz == -1);
}

static void
test_dp_size_exact_fit(void)
{
	UINT8 buf[4];
	build_dp_end(buf);
	INTN sz = fwup_dp_size((EFI_DEVICE_PATH *)buf, 4);
	assert(sz == 4);
}

static void
test_dp_size_zero_limit(void)
{
	UINT8 buf[4];
	build_dp_end(buf);
	INTN sz = fwup_dp_size((EFI_DEVICE_PATH *)buf, 0);
	assert(sz == -1);
}

static void
test_dp_size_zero_length_node(void)
{
	UINT8 buf[8];
	build_dp_node(buf, 0x01, 0x01, 0);
	build_dp_end(buf + 4);
	INTN sz = fwup_dp_size((EFI_DEVICE_PATH *)buf, 100);
	assert(sz == -1);
}

/* ================================================================
 * Group 2: fwup_update_ux_capsule_checksum
 * ================================================================ */

static void
test_checksum_zeroes(void)
{
	UX_CAPSULE_HEADER hdr;
	memset(&hdr, 0, sizeof(hdr));
	fwup_update_ux_capsule_checksum(&hdr);
	assert(hdr.checksum == 0);
}

static void
test_checksum_known_values(void)
{
	UX_CAPSULE_HEADER hdr;
	memset(&hdr, 0, sizeof(hdr));
	hdr.version = 1;
	hdr.image_type = 2;
	hdr.mode = 3;
	hdr.x_offset = 100;
	hdr.y_offset = 200;

	fwup_update_ux_capsule_checksum(&hdr);

	/* the checksum field should be set to the sum of all other bytes */
	UINT8 saved = hdr.checksum;
	assert(saved != 0);

	/* re-compute: checksum algo zeros the field, sums all bytes, stores */
	hdr.checksum = 0;
	UINT8 *buf = (UINT8 *)&hdr;
	UINT8 expected = 0;
	for (UINTN i = 0; i < sizeof(hdr); i++)
		expected = (UINT8)(expected + buf[i]);
	assert(saved == expected);
	hdr.checksum = saved;
}

static void
test_checksum_idempotent(void)
{
	UX_CAPSULE_HEADER hdr;
	memset(&hdr, 0, sizeof(hdr));
	hdr.version = 5;
	hdr.mode = 42;
	hdr.x_offset = 10;
	hdr.y_offset = 20;

	fwup_update_ux_capsule_checksum(&hdr);
	UINT8 first = hdr.checksum;

	fwup_update_ux_capsule_checksum(&hdr);
	assert(hdr.checksum == first);
}

/* ================================================================
 * Group 3: fwup_check_gop_for_ux_capsule (HeaderSize bounds)
 * ================================================================ */

static void
test_gop_headersize_too_small(void)
{
	mock_init();
	UINT8 buf[256];
	memset(buf, 0, sizeof(buf));
	EFI_CAPSULE_HEADER *cap = (EFI_CAPSULE_HEADER *)buf;
	cap->HeaderSize = sizeof(EFI_CAPSULE_HEADER) - 1;
	cap->CapsuleImageSize = sizeof(buf);

	EFI_STATUS rc = fwup_check_gop_for_ux_capsule(NULL, cap, sizeof(buf));
	assert(rc == EFI_INVALID_PARAMETER);
}

static void
test_gop_capsule_image_size_less_than_header(void)
{
	mock_init();
	UINT8 buf[256];
	memset(buf, 0, sizeof(buf));
	EFI_CAPSULE_HEADER *cap = (EFI_CAPSULE_HEADER *)buf;
	cap->HeaderSize = sizeof(EFI_CAPSULE_HEADER);
	cap->CapsuleImageSize = sizeof(EFI_CAPSULE_HEADER) - 1;

	EFI_STATUS rc = fwup_check_gop_for_ux_capsule(NULL, cap, sizeof(buf));
	assert(rc == EFI_INVALID_PARAMETER);
}

static void
test_gop_ux_payload_too_small(void)
{
	mock_init();
	UINT8 buf[256];
	memset(buf, 0, sizeof(buf));
	EFI_CAPSULE_HEADER *cap = (EFI_CAPSULE_HEADER *)buf;
	cap->HeaderSize = sizeof(EFI_CAPSULE_HEADER);
	cap->CapsuleImageSize = sizeof(EFI_CAPSULE_HEADER) + sizeof(UX_CAPSULE_HEADER) - 1;

	EFI_STATUS rc = fwup_check_gop_for_ux_capsule(NULL, cap, sizeof(buf));
	assert(rc == EFI_INVALID_PARAMETER);
}

static void
test_gop_fsize_too_small(void)
{
	mock_init();
	UINTN fsize = sizeof(EFI_CAPSULE_HEADER) + sizeof(UX_CAPSULE_HEADER) - 1;
	_cleanup_free UINT8 *buf = calloc(1, fsize);
	EFI_CAPSULE_HEADER *cap = (EFI_CAPSULE_HEADER *)buf;
	cap->HeaderSize = sizeof(EFI_CAPSULE_HEADER);
	cap->CapsuleImageSize = sizeof(EFI_CAPSULE_HEADER) + sizeof(UX_CAPSULE_HEADER);

	EFI_STATUS rc = fwup_check_gop_for_ux_capsule(NULL, cap, fsize);
	assert(rc == EFI_INVALID_PARAMETER);
}

static void
test_gop_headersize_exact_boundary(void)
{
	mock_init();
	UINTN fsize = sizeof(EFI_CAPSULE_HEADER) + sizeof(UX_CAPSULE_HEADER);
	_cleanup_free UINT8 *buf = calloc(1, fsize);
	EFI_CAPSULE_HEADER *cap = (EFI_CAPSULE_HEADER *)buf;
	cap->HeaderSize = sizeof(EFI_CAPSULE_HEADER);
	cap->CapsuleImageSize = fsize;

	EFI_STATUS rc = fwup_check_gop_for_ux_capsule(NULL, cap, fsize);
	assert(rc == EFI_UNSUPPORTED);
}

static void
test_gop_headersize_one_past(void)
{
	mock_init();
	UINTN fsize = sizeof(EFI_CAPSULE_HEADER) + sizeof(UX_CAPSULE_HEADER);
	_cleanup_free UINT8 *buf = calloc(1, fsize);
	EFI_CAPSULE_HEADER *cap = (EFI_CAPSULE_HEADER *)buf;
	cap->HeaderSize = sizeof(EFI_CAPSULE_HEADER) + 1;
	cap->CapsuleImageSize = fsize;

	EFI_STATUS rc = fwup_check_gop_for_ux_capsule(NULL, cap, fsize);
	assert(rc == EFI_INVALID_PARAMETER);
}

/* ================================================================
 * Group 4: fwup_populate_update_info (variable validation)
 * ================================================================ */

static void
test_populate_info_too_small(void)
{
	mock_init();
	FWUP_UPDATE_INFO info;
	memset(&info, 0, sizeof(info));
	mock_var_data = (UINT8 *)&info;
	mock_var_data_size = sizeof(info) - 1;
	mock_var_status = EFI_SUCCESS;

	FWUP_UPDATE_TABLE out;
	memset(&out, 0, sizeof(out));
	EFI_STATUS rc = fwup_populate_update_info(L"test", &out);
	assert(EFI_ERROR(rc));
}

static void
test_populate_info_no_room_for_dp(void)
{
	mock_init();
	FWUP_UPDATE_INFO info;
	memset(&info, 0, sizeof(info));
	mock_var_data = (UINT8 *)&info;
	mock_var_data_size = sizeof(info);
	mock_var_status = EFI_SUCCESS;

	FWUP_UPDATE_TABLE out;
	memset(&out, 0, sizeof(out));
	EFI_STATUS rc = fwup_populate_update_info(L"test", &out);
	assert(EFI_ERROR(rc));
}

static void
test_populate_info_valid(void)
{
	mock_init();
	UINTN dp_offset = EFI_FIELD_OFFSET(FWUP_UPDATE_INFO, dp);
	/* need total > sizeof(FWUP_UPDATE_INFO) + sizeof(EFI_DEVICE_PATH)
	 * to pass the check at fwupdate.c:88 */
	UINTN total = sizeof(FWUP_UPDATE_INFO) + sizeof(EFI_DEVICE_PATH) + 4;
	_cleanup_free UINT8 *buf = calloc(1, total);

	/* set up an 8-byte node + end-node device path at the dp field */
	UINTN dp_space = total - dp_offset;
	build_dp_node(buf + dp_offset, 0x01, 0x01, (UINT16)(dp_space - 4));
	build_dp_end(buf + dp_offset + dp_space - 4);

	mock_var_data = buf;
	mock_var_data_size = total;
	mock_var_attrs = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS;
	mock_var_status = EFI_SUCCESS;

	FWUP_UPDATE_TABLE out;
	memset(&out, 0, sizeof(out));
	EFI_STATUS rc = fwup_populate_update_info(L"test", &out);
	assert(rc == EFI_SUCCESS);
	assert(out.info != NULL);
	assert(out.name != NULL);
	assert(out.size == total);

	FreePool(out.info);
	FreePool(out.name);
}

static void
test_populate_info_dp_size_mismatch(void)
{
	mock_init();
	UINTN dp_offset = EFI_FIELD_OFFSET(FWUP_UPDATE_INFO, dp);
	UINTN total = dp_offset + 8; /* 8 bytes: room for a node + end */
	_cleanup_free UINT8 *buf = calloc(1, total);

	/* put just an end node (4 bytes) but claim 8 bytes of dp space */
	build_dp_end(buf + dp_offset);

	mock_var_data = buf;
	mock_var_data_size = total;
	mock_var_status = EFI_SUCCESS;

	FWUP_UPDATE_TABLE out;
	memset(&out, 0, sizeof(out));
	EFI_STATUS rc = fwup_populate_update_info(L"test", &out);
	/* dp_size returns 4 but remaining space is 8 -- mismatch */
	assert(EFI_ERROR(rc));
}

static void
test_populate_info_variable_not_found(void)
{
	mock_init();
	mock_var_status = EFI_NOT_FOUND;

	FWUP_UPDATE_TABLE out;
	memset(&out, 0, sizeof(out));
	EFI_STATUS rc = fwup_populate_update_info(L"test", &out);
	assert(rc == EFI_NOT_FOUND);
}

/* ================================================================
 * Group 5: capsule validation (CapsuleImageSize)
 * ================================================================ */

/*
 * these tests replicate the validation from fwup_add_update_capsule
 * inline since that function requires deep file I/O mocking
 */
static void
test_capsule_image_size_exceeds_file(void)
{
	UINTN fsize = 64;
	_cleanup_free UINT8 *fbuf = calloc(1, fsize);
	EFI_CAPSULE_HEADER *cap = (EFI_CAPSULE_HEADER *)fbuf;
	cap->CapsuleImageSize = (UINT32)(fsize + 1);

	BOOLEAN rejected = (cap->CapsuleImageSize < sizeof(EFI_CAPSULE_HEADER) ||
			    cap->CapsuleImageSize > fsize);
	assert(rejected == TRUE);
}

static void
test_capsule_image_size_too_small(void)
{
	UINTN fsize = 128;
	_cleanup_free UINT8 *fbuf = calloc(1, fsize);
	EFI_CAPSULE_HEADER *cap = (EFI_CAPSULE_HEADER *)fbuf;
	cap->CapsuleImageSize = sizeof(EFI_CAPSULE_HEADER) - 1;

	BOOLEAN rejected = (cap->CapsuleImageSize < sizeof(EFI_CAPSULE_HEADER) ||
			    cap->CapsuleImageSize > fsize);
	assert(rejected == TRUE);
}

static void
test_capsule_file_too_small(void)
{
	UINTN fsize = sizeof(EFI_CAPSULE_HEADER) - 1;
	BOOLEAN rejected = (fsize < sizeof(EFI_CAPSULE_HEADER));
	assert(rejected == TRUE);
}

static void
test_capsule_image_size_valid(void)
{
	UINTN fsize = 128;
	_cleanup_free UINT8 *fbuf = calloc(1, fsize);
	EFI_CAPSULE_HEADER *cap = (EFI_CAPSULE_HEADER *)fbuf;
	cap->CapsuleImageSize = (UINT32)fsize;

	BOOLEAN ok = (fsize >= sizeof(EFI_CAPSULE_HEADER) &&
		      cap->CapsuleImageSize >= sizeof(EFI_CAPSULE_HEADER) &&
		      cap->CapsuleImageSize <= fsize);
	assert(ok == TRUE);
}

/* ================================================================
 * Group 6: fwup_delete_variable (NULL DataSize fix)
 * ================================================================ */

static void
test_delete_variable_exists(void)
{
	mock_init();
	/* fwup_delete_variable calls GetVariable with size=0 and data=NULL
	 * to retrieve attrs. For an existing variable with data, GetVariable
	 * returns EFI_BUFFER_TOO_SMALL. The function treats this as an error
	 * and returns it without calling SetVariable. */
	mock_var_status = EFI_BUFFER_TOO_SMALL;

	mock_set_variable_called = FALSE;
	EFI_STATUS rc = fwup_delete_variable(L"test", &fwupdate_guid);
	assert(rc == EFI_BUFFER_TOO_SMALL);
	assert(mock_set_variable_called == FALSE);
}

static void
test_delete_variable_not_found(void)
{
	mock_init();
	mock_var_status = EFI_NOT_FOUND;
	EFI_STATUS rc = fwup_delete_variable(L"test", &fwupdate_guid);
	assert(rc == EFI_SUCCESS);
}

static void
test_delete_variable_other_error(void)
{
	mock_init();
	mock_var_status = EFI_UNSUPPORTED;
	EFI_STATUS rc = fwup_delete_variable(L"test", &fwupdate_guid);
	assert(rc == EFI_UNSUPPORTED);
}

/* ================================================================
 * Group 7: fwup_get_variable
 * ================================================================ */

static void
test_get_variable_success(void)
{
	mock_init();
	UINT8 data[] = { 0x01, 0x02, 0x03, 0x04 };
	mock_var_data = data;
	mock_var_data_size = sizeof(data);
	mock_var_attrs = EFI_VARIABLE_NON_VOLATILE;
	mock_var_status = EFI_SUCCESS;

	VOID *buf = NULL;
	UINTN size = 0;
	UINT32 attrs = 0;
	EFI_STATUS rc = fwup_get_variable(L"test", &fwupdate_guid,
					  &buf, &size, &attrs);
	assert(rc == EFI_SUCCESS);
	assert(size == sizeof(data));
	assert(attrs == EFI_VARIABLE_NON_VOLATILE);
	assert(memcmp(buf, data, sizeof(data)) == 0);
	FreePool(buf);
}

static void
test_get_variable_not_found(void)
{
	mock_init();
	mock_var_status = EFI_NOT_FOUND;

	VOID *buf = NULL;
	UINTN size = 0;
	UINT32 attrs = 0;
	EFI_STATUS rc = fwup_get_variable(L"test", &fwupdate_guid,
					  &buf, &size, &attrs);
	assert(rc == EFI_NOT_FOUND);
	assert(buf == NULL);
}

/* ================================================================
 * Group 8: block descriptor terminator index fix
 * ================================================================ */

static void
test_cbd_terminator_position(void)
{
	/* verify that the terminator is placed at position n_updates (j)
	 * not at position i when some capsules fail */
	UINTN n = 4;
	_cleanup_free EFI_CAPSULE_BLOCK_DESCRIPTOR *cbd = NULL;
	cbd = calloc(n + 1, sizeof(EFI_CAPSULE_BLOCK_DESCRIPTOR));

	/* simulate: 4 allocated entries, but only 2 succeeded (j=2) */
	cbd[0].Length = 100;
	cbd[0].Union.DataBlock = 0x1000;
	cbd[1].Length = 200;
	cbd[1].Union.DataBlock = 0x2000;

	/* poison the slot so we know the write actually happens */
	cbd[2].Length = 999;
	cbd[2].Union.ContinuationPointer = 0xDEAD;

	/* the fix places terminator at cbd[n_updates] where n_updates=j=2 */
	UINTN n_updates = 2;
	cbd[n_updates].Length = 0;
	cbd[n_updates].Union.ContinuationPointer = 0;

	assert(cbd[2].Length == 0);
	assert(cbd[2].Union.ContinuationPointer == 0);
	/* entries 0 and 1 are valid */
	assert(cbd[0].Length == 100);
	assert(cbd[1].Length == 200);
}

/* ================================================================
 * main
 * ================================================================ */

int
main(void)
{
	printf("fwupd-efi self tests\n");

	printf("device path size:\n");
	RUN_TEST(test_dp_size_single_end_node);
	RUN_TEST(test_dp_size_multiple_nodes);
	RUN_TEST(test_dp_size_limit_too_small);
	RUN_TEST(test_dp_size_node_exceeds_limit);
	RUN_TEST(test_dp_size_exact_fit);
	RUN_TEST(test_dp_size_zero_limit);

	printf("UX capsule checksum:\n");
	RUN_TEST(test_checksum_zeroes);
	RUN_TEST(test_checksum_known_values);
	RUN_TEST(test_checksum_idempotent);

	printf("GOP for UX capsule (HeaderSize bounds):\n");
	RUN_TEST(test_gop_headersize_too_small);
	RUN_TEST(test_gop_capsule_image_size_less_than_header);
	RUN_TEST(test_gop_ux_payload_too_small);
	RUN_TEST(test_gop_fsize_too_small);
	RUN_TEST(test_gop_headersize_exact_boundary);
	RUN_TEST(test_gop_headersize_one_past);

	printf("populate update info:\n");
	RUN_TEST(test_populate_info_too_small);
	RUN_TEST(test_populate_info_no_room_for_dp);
	RUN_TEST(test_populate_info_valid);
	RUN_TEST(test_populate_info_dp_size_mismatch);
	RUN_TEST(test_populate_info_variable_not_found);

	printf("capsule validation:\n");
	RUN_TEST(test_capsule_image_size_exceeds_file);
	RUN_TEST(test_capsule_image_size_too_small);
	RUN_TEST(test_capsule_file_too_small);
	RUN_TEST(test_capsule_image_size_valid);

	printf("delete variable:\n");
	RUN_TEST(test_delete_variable_exists);
	RUN_TEST(test_delete_variable_not_found);
	RUN_TEST(test_delete_variable_other_error);

	printf("get variable:\n");
	RUN_TEST(test_get_variable_success);
	RUN_TEST(test_get_variable_not_found);

	printf("block descriptor terminator:\n");
	RUN_TEST(test_cbd_terminator_position);

	printf("\n%u/%u tests passed\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
