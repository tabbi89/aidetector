"""Dedicated DB and namespaced Redis, with a separately running worker process."""
import os
import subprocess
import sys
import uuid
from types import SimpleNamespace
from urllib.parse import urlparse

import pytest
import redis
from alembic import command
from alembic.config import Config
from celery import Celery
from cryptography.fernet import Fernet
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from tests.harness import open_test_database
from tests.harness import test_database_url as validate_test_url


@pytest.fixture(scope='session')
def worker(tmp_path_factory):
    broker = os.environ.get('TEST_REDIS_URL')
    if not broker or urlparse(broker).hostname not in {'localhost', '127.0.0.1', 'redis'}:
        pytest.fail('Set TEST_REDIS_URL to a local test Redis service')
    database = os.environ.get('TEST_DATABASE_URL')
    if not database:
        pytest.fail('Set TEST_DATABASE_URL to a dedicated database ending in _test')
    # Use a separate database from the ordinary suite, including its migrations.
    from sqlalchemy.engine import make_url

    target = make_url(validate_test_url(settings.database_url, database))
    target = target.set(database=target.database.removesuffix('_test') + '_worker_test')
    engine = open_test_database(
        settings.database_url,
        target.render_as_string(hide_password=False), required=True,
    )
    with engine.begin() as connection:
        config = Config('alembic.ini')
        config.attributes['connection'] = connection
        command.upgrade(config, 'head')
    prefix = 'aidetector-integration-' + uuid.uuid4().hex + ':'
    queue = prefix + 'scans'
    store = redis.Redis.from_url(broker)
    store.ping()
    app = Celery('integration-client', broker=broker, backend=broker)
    app.conf.update(broker_transport_options={'global_keyprefix': prefix},
                    result_backend_transport_options={'global_keyprefix': prefix})
    env = dict(os.environ, DATABASE_URL=target.render_as_string(hide_password=False),
               REDIS_URL=broker, TEST_WORKER_PREFIX=prefix,
               VAULT_KEY=Fernet.generate_key().decode())
    log_path = tmp_path_factory.mktemp('worker') / 'worker.log'
    process = None
    scan_ids = []
    try:
        with log_path.open('w') as log:
            process = subprocess.Popen([
                sys.executable, '-m', 'celery', '-A', 'integration_tests.worker_app',
                'worker', '--pool=threads', '--concurrency=2', '--queues', queue,
                '--hostname', prefix, '--without-gossip', '--without-mingle',
                '--without-heartbeat', '--loglevel=WARNING',
            ], env=env, stdout=log, stderr=subprocess.STDOUT)
            app.send_task('ping', queue=queue).get(timeout=25)
            yield SimpleNamespace(app=app, store=store, prefix=prefix, queue=queue,
                                  sessions=sessionmaker(engine, expire_on_commit=False),
                                  scan_ids=scan_ids)
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        # Remove only keys in this run's random namespace. Never FLUSHDB.
        for key in store.scan_iter(match=prefix + '*'):
            store.delete(key)
        app.close()
        store.close()
        from sqlalchemy import delete

        from app.models.scan import Scan

        with engine.begin() as connection:
            connection.execute(delete(Scan).where(Scan.id.in_(scan_ids)))
        engine.dispose()
        if process is not None and process.returncode not in (0, -15):
            print(log_path.read_text())

