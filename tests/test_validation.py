import os
from pathlib import Path

import pytest

from patatt import RES_VALID, PatattMessage, validate_message


@pytest.mark.parametrize(
    'sample_file', ['ed25519-signed.txt', 'pgp-signed.txt', 'openssh-signed.txt']
)
def test_validate(sample_file: str) -> None:
    """Test validation of an ed25519 signed message from samples directory."""
    # Path to the sample file
    toplevel = Path(__file__).parent.parent
    sample_path = os.path.join(toplevel, 'samples', sample_file)
    sources_path = os.path.join(toplevel, '.keys')

    # Read the signed message
    with open(sample_path, 'rb') as f:
        signed_data = f.read()

    # # Create a PatattMessage object from the signed data
    # message = PatattMessage(signed_data)

    # Validate the message
    results = validate_message(signed_data, [sources_path])

    # Check validation results
    assert results, 'Validation should return results'

    # At least one valid signature should be found
    valid_signatures = [r for r in results if r[0] == RES_VALID]
    assert valid_signatures, 'Should find at least one valid signature'

    # Reusing cached key material must preserve validation results.
    assert validate_message(signed_data, [sources_path]) == results

    # Print validation details for debugging
    print(f'Found {len(valid_signatures)} valid signatures:')
    for result in valid_signatures:
        _status, _algo, keytype, identity, selector, _errors = result
        print(f'  - {keytype} signature by {identity} ({selector})')


@pytest.mark.parametrize('sample_file', ['ed25519-signed.txt', 'openssh-signed.txt'])
def test_validate_requires_public_key(sample_file: str) -> None:
    sample_path = Path(__file__).parent.parent / 'samples' / sample_file
    message = PatattMessage(sample_path.read_bytes())
    signature = message.get_sigs()[0]
    identity = signature.get_field_as_str('i')
    assert identity is not None, 'Sample signature must identify its signer'

    with pytest.raises(
        RuntimeError, match='keyinfo must be a string or bytes, not NoneType'
    ):
        message.validate(identity, None)
