import base64
from unittest.mock import MagicMock, patch

import pytest

from patatt import DevsigHeader, NoKeyError, ValidationError

# Status output captured from real gpg 2.4 runs of
# "gpg --verify --output - --status-fd=2".
# A signature that was tampered with (gpg exits with 1):
BADSIG_STATUS = b"""[GNUPG:] PLAINTEXT 62 1791176735
[GNUPG:] PLAINTEXT_LENGTH 5
[GNUPG:] NEWSIG
[GNUPG:] KEY_CONSIDERED C7CB17FE6660C7E2B8F285A83C320AE3582D9EC9 0
[GNUPG:] BADSIG 3C320AE3582D9EC9 t@example.com
[GNUPG:] FAILURE gpg-exit 33554433
"""

# A good signature, but the key is not in the keyring (gpg exits with 2):
NO_PUBKEY_STATUS = b"""[GNUPG:] PLAINTEXT 62 1791176735
[GNUPG:] PLAINTEXT_LENGTH 5
[GNUPG:] NEWSIG
[GNUPG:] ERRSIG 3C320AE3582D9EC9 22 10 00 1791176735 9 C7CB17FE6660C7E2B8F285A83C320AE3582D9EC9
[GNUPG:] NO_PUBKEY 3C320AE3582D9EC9
[GNUPG:] FAILURE gpg-exit 33554433
"""

# The signature content does not matter, because gpg is mocked.
SIGDATA = base64.b64encode(b'fake signature')


class TestValidateOpenpgpErrors:
    """A gpg failure must be reported as the right kind of error."""

    @patch('patatt.gpg_run_command')
    def test_bad_signature_is_validation_error(self, mock_gpg: MagicMock) -> None:
        """A bad signature must not be reported as a missing key."""
        mock_gpg.return_value = (1, b'', BADSIG_STATUS)
        with pytest.raises(ValidationError) as excinfo:
            DevsigHeader._validate_openpgp(SIGDATA, None)
        # NoKeyError is a subclass of ValidationError, so check the exact type
        assert type(excinfo.value) is ValidationError

    @patch('patatt.gpg_run_command')
    def test_missing_key_is_nokey_error(self, mock_gpg: MagicMock) -> None:
        """A signature by a key we don't have must raise NoKeyError."""
        mock_gpg.return_value = (2, b'', NO_PUBKEY_STATUS)
        with pytest.raises(NoKeyError):
            DevsigHeader._validate_openpgp(SIGDATA, None)

    @patch('patatt.gpg_run_command')
    def test_failure_without_status_is_validation_error(
        self, mock_gpg: MagicMock
    ) -> None:
        """If gpg fails without any status output, it is not a missing key."""
        mock_gpg.return_value = (2, b'', b'')
        with pytest.raises(ValidationError) as excinfo:
            DevsigHeader._validate_openpgp(SIGDATA, None)
        assert type(excinfo.value) is ValidationError
