from __future__ import annotations

import base64
import hashlib
from io import BytesIO

import pytest

from patatt import DevsigHeader


class TestDevsigHeader:
    def test_initialization(self) -> None:
        """Test that DevsigHeader initializes correctly."""
        header = DevsigHeader()
        assert header.hdata['v'] == b'1'
        assert header.hval is None

    def test_from_bytes(self) -> None:
        """Test parsing a header from bytes."""
        header_bytes = (
            b'v=1; a=ed25519-sha256; t=1623456789; i=test@example.com; bh=abcd1234'
        )
        header = DevsigHeader(header_bytes)

        assert header.get_field_as_str('v') == '1'
        assert header.get_field_as_str('a') == 'ed25519-sha256'
        assert header.get_field_as_str('t') == '1623456789'
        assert header.get_field_as_str('i') == 'test@example.com'
        assert header.get_field_as_bytes('bh') == b'abcd1234'

    def test_set_field(self) -> None:
        """Test setting fields in the header."""
        header = DevsigHeader()

        header.set_field('a', 'ed25519-sha256')
        header.set_field('i', 'test@example.com')
        header.set_field('binary', b'binary-data')

        assert header.get_field_as_str('a') == 'ed25519-sha256'
        assert header.get_field_as_str('i') == 'test@example.com'
        assert header.get_field_as_bytes('binary') == b'binary-data'

    def test_set_body(self) -> None:
        """Test setting the body and calculating the body hash."""
        header = DevsigHeader()
        body = b'This is a test body'

        header.set_body(body)

        # Calculate the expected hash
        hashed = hashlib.sha256()
        hashed.update(body)
        expected_hash = base64.b64encode(hashed.digest())

        assert header._body_hash == expected_hash

    def test_set_body_with_maxlen(self) -> None:
        """Test setting the body with a maxlen parameter."""
        header = DevsigHeader()
        body = b'This is a test body'
        maxlen = 10

        header.set_body(body, maxlen=maxlen)

        # Calculate the expected hash based on truncated body
        hashed = hashlib.sha256()
        hashed.update(body[:maxlen])
        expected_hash = base64.b64encode(hashed.digest())

        assert header._body_hash == expected_hash
        assert 'l' in header.hdata
        print(header.hdata)
        assert header.hdata['l'] == b'10'

    def test_set_headers_sign_mode(self, sample_email_bytes: bytes) -> None:
        """Test setting headers in sign mode."""
        header = DevsigHeader()

        # Parse the sample email to get headers
        headers: list[bytes] = []
        with BytesIO(sample_email_bytes) as fh:
            while True:
                line = fh.readline()
                if not line or not line.strip():
                    break
                headers.append(line)

        header.set_headers(headers, mode='sign')

        # Check that required headers were processed
        assert header.get_field_as_bytes('h') is not None
        h = header.get_field_as_bytes('h')
        assert h is not None
        assert b'from:subject' in h or b'subject:from' in h

    def test_sanity_check_fails_without_required_fields(self) -> None:
        """Test that sanity_check fails if required fields are not set."""
        header = DevsigHeader()

        with pytest.raises(RuntimeError, match='Must set "a" field first'):
            header.sanity_check()

        header.set_field('a', 'ed25519-sha256')

        with pytest.raises(RuntimeError, match='Must use set_body first'):
            header.sanity_check()

        header.set_body(b'Test body')

        with pytest.raises(RuntimeError, match='Must use set_headers first'):
            header.sanity_check()

    def test_sign_ed25519(self, sample_ed25519_key_pair: dict[str, bytes]) -> None:
        """Sign and verify with both freshly loaded and cached key data."""
        for payload in (b'first message', b'second message'):
            signed, public_key = DevsigHeader._sign_ed25519(
                payload, sample_ed25519_key_pair['private']
            )
            assert public_key == sample_ed25519_key_pair['public']
            assert DevsigHeader._validate_ed25519(signed, public_key) == payload
