import pytest

from cfdi_vault.sat_metadata_zip_state import MetadataZipReceipt, MetadataZipReceiptError


class _StorageKeySubclass(str):
    pass


@pytest.mark.parametrize("storage_key", (None, 7, [], True, _StorageKeySubclass(
    "sat-metadata/cmp-0123456789ab/work-abcdef012345/packages/1-bbbbbbbbbbbb.zip",
)))
def test_receipt_constructor_rejects_non_exact_storage_key_types(storage_key: object) -> None:
    with pytest.raises(MetadataZipReceiptError, match="zip-receipt-invalid") as captured:
        MetadataZipReceipt(
            "run-0123456789ab", "pkg-0123456789ab", "cmp-0123456789ab", "work-abcdef012345",
            "b" * 64, 123, True, storage_key,  # type: ignore[arg-type]
        )
    assert captured.value.__cause__ is captured.value.__context__ is None
