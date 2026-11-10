Feature: Protect data stored in S3
  Buckets must not be public and must be encrypted and versioned.

  Background:
    Given a mocked AWS account

  Scenario: A bucket with a public-read ACL is critical
    Given a bucket "customer-exports" with a public-read ACL
    When I run the scan
    Then I see a "CRITICAL" finding for check "S3-001"
    And the account grade is worse than "B"

  Scenario: A hardened bucket passes the data protection checks
    Given a hardened bucket "audit-archive"
    When I run the scan
    Then there is no finding for check "S3-001"
    And there is no finding for check "S3-004"
    And there is no finding for check "S3-005"
    And there is no finding for check "S3-006"

  Scenario: Remediation locks down a public bucket
    Given a bucket "customer-exports" with a public-read ACL
    When I run the scan
    And I auto-remediate every finding
    And I run the scan
    Then there is no finding for check "S3-001"
