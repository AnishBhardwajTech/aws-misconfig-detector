from __future__ import annotations

from functools import lru_cache

import boto3


class ScanContext:
    """Per-region view of the account with cached boto3 clients."""

    def __init__(self, session: boto3.session.Session, region: str, account_id: str):
        self.session = session
        self.region = region
        self.account_id = account_id
        self._clients: dict[str, object] = {}

    def client(self, service: str):
        if service not in self._clients:
            self._clients[service] = self.session.client(service, region_name=self.region)
        return self._clients[service]

    # Shared, expensive lookups cached per context
    @lru_cache(maxsize=None)
    def iam_users(self) -> tuple[dict, ...]:
        users = []
        for page in self.client("iam").get_paginator("list_users").paginate():
            users.extend(page["Users"])
        return tuple(users)

    @lru_cache(maxsize=None)
    def buckets(self) -> tuple[str, ...]:
        return tuple(b["Name"] for b in self.client("s3").list_buckets().get("Buckets", []))

    @lru_cache(maxsize=None)
    def security_groups(self) -> tuple[dict, ...]:
        groups = []
        for page in self.client("ec2").get_paginator("describe_security_groups").paginate():
            groups.extend(page["SecurityGroups"])
        return tuple(groups)

    @lru_cache(maxsize=None)
    def instances(self) -> tuple[dict, ...]:
        out = []
        for page in self.client("ec2").get_paginator("describe_instances").paginate():
            for r in page["Reservations"]:
                out.extend(i for i in r["Instances"] if i["State"]["Name"] != "terminated")
        return tuple(out)

    def __hash__(self):  # lru_cache on methods needs a hashable self
        return id(self)
