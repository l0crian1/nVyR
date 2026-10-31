"""The shared RPC limit bounds encoded bytes, not configuration entry counts."""

from io import BytesIO
import json
import struct

import pytest

from nvyr.errors import RouterError
from nvyr.protocol import MAX_FRAME, encode, receive


def test_encode_accepts_exactly_64_mib_and_rejects_one_extra_byte():
    assert MAX_FRAME == 64 * 1024 * 1024
    overhead = len(json.dumps({'text': ''}).encode('utf-8'))
    text = 'x' * (MAX_FRAME - overhead)
    frame = encode({'text': text})

    assert len(frame) == MAX_FRAME + 4
    assert struct.unpack('!I', frame[:4])[0] == MAX_FRAME
    del frame

    with pytest.raises(RouterError) as error:
        encode({'text': text + 'x'})

    assert f'{MAX_FRAME + 1:,} bytes' in str(error.value)
    assert f'64 MiB limit ({MAX_FRAME:,} bytes)' in str(error.value)
    assert 'Split' not in str(error.value)


def test_receive_rejects_oversized_header_without_reading_body():
    class Socket:
        def __init__(self):
            self.header = BytesIO(struct.pack('!I', MAX_FRAME + 1))

        def recv(self, length):
            assert self.header.tell() < 4, 'Oversized body must not be read'
            return self.header.read(length)

    with pytest.raises(RouterError, match='64 MiB limit') as error:
        receive(Socket())

    assert f'{MAX_FRAME + 1:,} bytes' in str(error.value)
