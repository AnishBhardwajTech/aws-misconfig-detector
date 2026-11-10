"""pytest-bdd step definitions for the Gherkin scenarios in tests/features."""

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from helpers import open_sg, public_bucket, secure_bucket
from misconfig.remediation import remediate
from misconfig.scanner import run_scan

scenarios("network_exposure.feature", "s3_data_protection.feature", "iam_hygiene.feature")


@pytest.fixture
def state():
    return {}


@given("a mocked AWS account", target_fixture="session")
def session(aws):
    return aws


@given(parsers.parse('a security group allows port {port:d} from "{cidr}"'))
def sg_rule(session, port, cidr):
    open_sg(session, port, cidr=cidr, name=f"sg-{port}-{cidr.replace('/', '_')}")


@given(parsers.parse('a bucket "{name}" with a public-read ACL'))
def bucket_public(session, name):
    public_bucket(session, name)


@given(parsers.parse('a hardened bucket "{name}"'))
def bucket_hardened(session, name):
    secure_bucket(session, name)


@given(parsers.parse('an IAM user "{name}" with a console password and no MFA'))
def console_user(session, name):
    iam = session.client("iam")
    iam.create_user(UserName=name)
    iam.create_login_profile(UserName=name, Password="An-initial-Passw0rd!")


@given("the account has no password policy")
def no_policy(session):
    pass  # a fresh mocked account has none


@when("I run the scan")
def do_scan(session, state):
    state["result"] = run_scan(session)


@when("I auto-remediate every finding")
def do_remediate(session, state):
    for f in state["result"].findings:
        remediate(f, session, dry_run=False)


@then(parsers.parse('I see a "{severity}" finding for check "{check_id}"'))
def see_finding(state, severity, check_id):
    matches = [f for f in state["result"].findings if f.check_id == check_id]
    assert matches, f"expected a {check_id} finding"
    assert all(f.severity.value == severity for f in matches)
    state["last"] = matches[0]


@then("the finding is marked as publicly exposed")
def is_public(state):
    assert state["last"].public_exposure


@then(parsers.parse('there is no finding for check "{check_id}"'))
def no_finding(state, check_id):
    assert not [f for f in state["result"].findings if f.check_id == check_id]


@then(parsers.parse('the account grade is worse than "{grade}"'))
def grade_worse(state, grade):
    assert state["result"].grade > grade
