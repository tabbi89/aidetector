"""Real Celery worker; only scanner target transport and AI providers are faked."""
import json
import os

import redis
from fastapi.testclient import TestClient

from app.core.config import Settings, settings

# Do not inherit adjunct URLs, binaries, credentials, or AI settings from .env.
for name, field in Settings.model_fields.items():
    if name not in {'database_url', 'redis_url', 'vault_key'}:
        setattr(settings, name, field.get_default(call_default_factory=True))

from app.engine.oob import NullOobClient  # noqa: E402
from app.engine.runner import run_scan  # noqa: E402
from app.workers import tasks  # noqa: E402
from app.workers.celery_app import celery  # noqa: E402
from tests.fakes import FakeCascade, FakePlanner  # noqa: E402
from tests.vulnapp import vulnapp  # noqa: E402

prefix = os.environ['TEST_WORKER_PREFIX']
celery.conf.update(
    task_always_eager=False,
    broker_transport_options={'global_keyprefix': prefix},
    result_backend_transport_options={'global_keyprefix': prefix},
)
store = redis.Redis.from_url(settings.redis_url)


def controlled_run(db, scan, *, options):
    sid = str(scan.id)
    store.set(prefix + sid + ':options', json.dumps(options.to_dict()), ex=120)
    waiting = store.get(prefix + sid + ':wait')

    class Client:
        def __init__(self, target):
            self.target = target
            self.first = True

        def request(self, method, path, **kwargs):
            if self.first and waiting:
                self.first = False
                store.set(prefix + sid + ':entered', '1', ex=120)
                if store.blpop(prefix + sid + ':release', timeout=15) is None:
                    raise RuntimeError('test did not release target request')
            return self.target.request(method, path, **kwargs)

    with TestClient(vulnapp) as target:
        return run_scan(db, scan, options=options, client=Client(target),
                        oob=NullOobClient(), cascade=FakeCascade(),
                        planner=FakePlanner(lambda op: "high"))


tasks.run_scan = controlled_run
