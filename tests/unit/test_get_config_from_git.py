from unittest.mock import MagicMock, patch

from patatt import get_config_from_git


def _zformat(*pairs: tuple[str, str]) -> bytes:
    """Build git config -z output: each entry is 'key\\nvalue' joined by NUL."""
    return b'\x00'.join(f'{key}\n{value}'.encode() for key, value in pairs) + b'\x00'


class TestGetConfigMultivals:
    """Tests for repeated-key (multivals) handling in get_config_from_git."""

    @patch('patatt.git_run_command')
    def test_repeated_multival_keeps_all_values(self, mock_git: MagicMock) -> None:
        """A repeated multivals key must preserve every value, in order."""
        mock_git.return_value = (
            0,
            _zformat(
                ('patatt.keyringsrc', 'ref:refs/heads/one'),
                ('patatt.keyringsrc', 'ref:refs/heads/two'),
                ('patatt.keyringsrc', 'ref:refs/heads/three'),
            ),
            b'',
        )
        config = get_config_from_git(r'patatt\..*', multivals=['keyringsrc'])

        assert config['keyringsrc'] == [
            'ref:refs/heads/one',
            'ref:refs/heads/two',
            'ref:refs/heads/three',
        ]

    @patch('patatt.git_run_command')
    def test_single_multival_is_still_a_list(self, mock_git: MagicMock) -> None:
        """A multivals key present once should still come back as a one-item list."""
        mock_git.return_value = (
            0,
            _zformat(('patatt.keyringsrc', 'ref:refs/heads/only')),
            b'',
        )
        config = get_config_from_git(r'patatt\..*', multivals=['keyringsrc'])

        assert config['keyringsrc'] == ['ref:refs/heads/only']

    @patch('patatt.git_run_command')
    def test_non_multival_key_is_a_scalar(self, mock_git: MagicMock) -> None:
        """A key not listed in multivals keeps last-wins scalar behavior."""
        mock_git.return_value = (
            0,
            _zformat(
                ('patatt.signingkey', 'ed25519:first'),
                ('patatt.signingkey', 'ed25519:second'),
            ),
            b'',
        )
        config = get_config_from_git(r'patatt\..*', multivals=['keyringsrc'])

        assert config['signingkey'] == 'ed25519:second'
