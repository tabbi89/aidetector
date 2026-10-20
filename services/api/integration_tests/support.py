import time

import pytest


def wait_for(store, key):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if store.get(key):
            return
        time.sleep(0.02)
    pytest.fail(f'Worker did not reach synchronization point: {key}')
