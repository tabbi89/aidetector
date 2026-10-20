"""Upgrade real old data and compare deployed DDL with ORM metadata."""
import uuid

from alembic import command
from alembic.config import Config
from sqlalchemy import text


def test_migration_head_matches_models(db_engine):
    with db_engine.begin() as connection:
        config = Config('alembic.ini')
        config.attributes['connection'] = connection
        command.check(config)


def test_upgrade_preserves_existing_scan_and_backfills_defaults(db_engine):
    # DDL + seed + upgrade are rolled back together, leaving the shared test
    # schema at head even if an assertion fails. Never touches the app database.
    with db_engine.connect() as connection:
        transaction = connection.begin()
        try:
            config = Config('alembic.ini')
            config.attributes['connection'] = connection
            command.downgrade(config, '0001')
            scan_id, op_id = uuid.uuid4(), uuid.uuid4()
            connection.execute(text(
                "INSERT INTO scans (id, target_base_url) VALUES (:id, 'http://migration.test')"
            ), {'id': scan_id})
            connection.execute(text(
                "INSERT INTO operations (id, scan_id, method, path) "
                "VALUES (:id, :scan, 'GET', '/existing')"
            ), {'id': op_id, 'scan': scan_id})
            command.upgrade(config, 'head')
            row = connection.execute(text(
                'SELECT target_base_url, tenant_id, progress, cancel_requested, triage, '
                'requests_per_second '
                'FROM scans WHERE id = :id'
            ), {'id': scan_id}).one()
            assert tuple(row) == ('http://migration.test', 'default', 0, False, {}, 10)
            assert connection.execute(text(
                'SELECT enabled FROM operations WHERE id = :id'
            ), {'id': op_id}).scalar_one() is True
            command.check(config)
        finally:
            transaction.rollback()


def test_duplicate_name_upgrade_allocates_names_that_are_actually_free(db_engine):
    # 0040 renames duplicates to `<name>-dup-<id prefix>`. A previously legal
    # row may already hold that name, and two duplicates may share a prefix:
    # the upgrade must still reach head with every identity kept.
    with db_engine.connect() as connection:
        transaction = connection.begin()
        try:
            config = Config('alembic.ini')
            config.attributes['connection'] = connection
            command.downgrade(config, '0039')
            scan_id = uuid.uuid4()
            connection.execute(text(
                "INSERT INTO scans (id, target_base_url) VALUES (:id, 'http://migration.test')"
            ), {'id': scan_id})
            rows = [
                ('00000000-0000-4000-8000-000000000001', 'alice'),
                ('11111111-0000-4000-8000-000000000002', 'alice'),
                ('11111111-0000-4000-8000-000000000003', 'alice'),
                ('22222222-0000-4000-8000-000000000004', 'alice-dup-11111111'),
            ]
            for row_id, name in rows:
                connection.execute(text(
                    "INSERT INTO credential_profiles "
                    "(id, scan_id, name, role, auth_type, secret_ref) "
                    "VALUES (:id, :scan, :name, 'user', 'bearer', 'enc')"
                ), {'id': row_id, 'scan': scan_id, 'name': name})
            command.upgrade(config, 'head')
            names = dict(connection.execute(text(
                'SELECT id::text, name FROM credential_profiles WHERE scan_id = :scan'
            ), {'scan': scan_id}).all())
            assert len(names) == 4
            assert len(set(names.values())) == 4
            assert names['00000000-0000-4000-8000-000000000001'] == 'alice'
            assert names['22222222-0000-4000-8000-000000000004'] == 'alice-dup-11111111'
            command.check(config)
        finally:
            transaction.rollback()
