import os

import boto3
import pytest
from moto import mock_aws

from misconfig.storage import Store

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": REGION}.items():
        monkeypatch.setenv(k, v)


@pytest.fixture
def aws():
    """A mocked AWS account (moto) and a boto3 session pointing at it."""
    with mock_aws():
        yield boto3.session.Session(region_name=REGION)


@pytest.fixture(params=["sqlite"] + (["postgres"] if os.environ.get("TEST_DATABASE_URL") else []))
def store(request):
    if request.param == "sqlite":
        s = Store("sqlite:///:memory:")
    else:
        s = Store(os.environ["TEST_DATABASE_URL"])
        cur = s.conn.cursor()
        cur.execute("DROP TABLE IF EXISTS findings")
        cur.execute("DROP TABLE IF EXISTS scans")
        s.conn.commit()
    s.init_schema()
    yield s
    s.close()
