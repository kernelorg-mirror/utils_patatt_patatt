from typing import Callable
from unittest.mock import MagicMock, patch

import pytest

from patatt import (
    IDENTITYCACHE,
    KEYCACHE,
    DevsigHeader,
    GitConfigType,
    NoKeyError,
    get_algo_keydata,
)

# Output of "gpg --with-colons --fingerprint", trimmed to the lines that
# _sign_openpgp() parses.
GPG_FINGERPRINT_OUTPUT = (
    b'pub:u:255:22:3C320AE3582D9EC9:1791176735:::u:::scESC:::::ed25519:::0:\n'
    b'fpr:::::::::C7CB17FE6660C7E2B8F285A83C320AE3582D9EC9:\n'
    b'uid:u::::1791176735::0000000000000000000000000000000000000000::'
    b'test@example.com::::::::::0:\n'
)


def _make_mock_get_config(
    usercfg: GitConfigType,
    gpgcfg: GitConfigType,
) -> Callable[..., GitConfigType]:
    """Return a mock get_config_from_git that dispatches on the regexp arg."""

    def _mock(regexp: str, **kwargs: object) -> GitConfigType:
        if regexp == r'user\..*':
            return dict(usercfg)
        if regexp == r'gpg\..*':
            # When called with section='ssh', return empty (irrelevant here)
            if kwargs.get('section'):
                return {}
            return dict(gpgcfg)
        return {}

    return _mock


class TestGetAlgoKeydataSSHSigningKey:
    """Tests for the user.signingkey + gpg.format detection in get_algo_keydata."""

    def setup_method(self) -> None:
        """Clear the caches before each test to avoid cross-test pollution."""
        KEYCACHE.clear()
        IDENTITYCACHE.clear()

    @patch('patatt.get_config_from_git')
    def test_ssh_format_uses_openssh(self, mock_gcfg: MagicMock) -> None:
        """When gpg.format=ssh, user.signingkey should get the openssh: prefix."""
        mock_gcfg.side_effect = _make_mock_get_config(
            usercfg={
                'email': 'test@example.com',
                'signingkey': '/home/user/.ssh/id_ed25519.pub',
            },
            gpgcfg={'format': 'ssh'},
        )
        config: GitConfigType = {'identity': 'test@example.com'}
        algo, keydata = get_algo_keydata(config)

        assert algo == 'openssh'
        assert keydata == '/home/user/.ssh/id_ed25519.pub'
        assert config['signingkey'] == 'openssh:/home/user/.ssh/id_ed25519.pub'

    @patch('patatt.get_config_from_git')
    def test_gpg_format_uses_openpgp(self, mock_gcfg: MagicMock) -> None:
        """When gpg.format=gpg (explicit), user.signingkey should get the openpgp: prefix."""
        mock_gcfg.side_effect = _make_mock_get_config(
            usercfg={'email': 'test@example.com', 'signingkey': 'DEADBEEF'},
            gpgcfg={'format': 'gpg'},
        )
        config: GitConfigType = {'identity': 'test@example.com'}
        algo, keydata = get_algo_keydata(config)

        assert algo == 'openpgp'
        assert keydata == 'DEADBEEF'
        assert config['signingkey'] == 'openpgp:DEADBEEF'

    @patch('patatt.get_config_from_git')
    def test_no_gpg_format_defaults_to_openpgp(self, mock_gcfg: MagicMock) -> None:
        """When gpg.format is not set, default to openpgp."""
        mock_gcfg.side_effect = _make_mock_get_config(
            usercfg={'email': 'test@example.com', 'signingkey': 'ABCD1234'},
            gpgcfg={},  # no 'format' key at all
        )
        config: GitConfigType = {'identity': 'test@example.com'}
        algo, keydata = get_algo_keydata(config)

        assert algo == 'openpgp'
        assert keydata == 'ABCD1234'

    @patch('patatt.get_config_from_git')
    def test_no_signingkey_raises_nokeyerror(self, mock_gcfg: MagicMock) -> None:
        """When neither patatt.signingkey nor user.signingkey is set, raise NoKeyError."""
        mock_gcfg.side_effect = _make_mock_get_config(
            usercfg={'email': 'test@example.com'},
            gpgcfg={},
        )
        config: GitConfigType = {'identity': 'test@example.com'}

        with pytest.raises(NoKeyError, match='patatt.signingkey is not set'):
            get_algo_keydata(config)

    @patch('patatt.get_config_from_git')
    def test_patatt_signingkey_skips_user_signingkey(
        self, mock_gcfg: MagicMock
    ) -> None:
        """When patatt.signingkey is already set, user.signingkey is not consulted."""
        mock_gcfg.side_effect = _make_mock_get_config(
            usercfg={'email': 'test@example.com', 'signingkey': 'SHOULD_NOT_BE_USED'},
            gpgcfg={'format': 'ssh'},
        )
        config: GitConfigType = {
            'identity': 'test@example.com',
            'signingkey': 'openpgp:MY_GPG_KEY',
        }
        algo, keydata = get_algo_keydata(config)

        assert algo == 'openpgp'
        assert keydata == 'MY_GPG_KEY'

    @patch('patatt.get_config_from_git')
    def test_identity_from_user_email(self, mock_gcfg: MagicMock) -> None:
        """When config has no identity, it should be set from user.email."""
        mock_gcfg.side_effect = _make_mock_get_config(
            usercfg={'email': 'auto@example.com', 'signingkey': 'SOMEKEY'},
            gpgcfg={'format': 'ssh'},
        )
        config: GitConfigType = {}
        algo, _keydata = get_algo_keydata(config)

        assert config['identity'] == 'auto@example.com'
        assert algo == 'openssh'

    @patch('patatt.get_config_from_git')
    def test_identitycache_hit_skips_lookup(self, mock_gcfg: MagicMock) -> None:
        """When identity is already in IDENTITYCACHE, return cached result directly."""
        IDENTITYCACHE['cached@example.com'] = ('openssh', '/cached/key')

        mock_gcfg.side_effect = _make_mock_get_config(
            usercfg={'email': 'cached@example.com'},
            gpgcfg={},
        )
        config: GitConfigType = {'identity': 'cached@example.com'}
        algo, keydata = get_algo_keydata(config)

        assert algo == 'openssh'
        assert keydata == '/cached/key'

    @patch('patatt.gpg_run_command')
    @patch('patatt.get_config_from_git')
    def test_signingkey_equal_to_identity_signs(
        self, mock_gcfg: MagicMock, mock_gpg: MagicMock
    ) -> None:
        """Signing must work when user.signingkey is spelled like user.email.

        This is a common way to name a GPG key. The identity lookup and the
        fingerprint lookup in _sign_openpgp() both use this string as a key,
        so they must not read each other's cached data.
        """
        mock_gcfg.side_effect = _make_mock_get_config(
            usercfg={'email': 'test@example.com', 'signingkey': 'test@example.com'},
            gpgcfg={},
        )
        mock_gpg.side_effect = [
            (0, b'signature', b''),
            (0, GPG_FINGERPRINT_OUTPUT, b''),
        ]
        config: GitConfigType = {'identity': 'test@example.com'}
        algo, keydata = get_algo_keydata(config)
        assert (algo, keydata) == ('openpgp', 'test@example.com')

        _bdata, keyfp = DevsigHeader._sign_openpgp(b'payload', keydata)
        assert keyfp == b'C7CB17FE6660C7E2B8F285A83C320AE3582D9EC9'

    @patch('patatt.get_config_from_git')
    def test_unknown_gpg_format_defaults_to_openpgp(self, mock_gcfg: MagicMock) -> None:
        """An unrecognized gpg.format value should fall through to openpgp."""
        mock_gcfg.side_effect = _make_mock_get_config(
            usercfg={'email': 'test@example.com', 'signingkey': 'SOMEKEY'},
            gpgcfg={'format': 'x509'},  # not 'ssh', so should be openpgp
        )
        config: GitConfigType = {'identity': 'test@example.com'}
        algo, keydata = get_algo_keydata(config)

        assert algo == 'openpgp'
        assert keydata == 'SOMEKEY'
