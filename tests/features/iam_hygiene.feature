Feature: IAM identity hygiene

  Background:
    Given a mocked AWS account

  Scenario: Console users must use MFA
    Given an IAM user "intern" with a console password and no MFA
    When I run the scan
    Then I see a "HIGH" finding for check "IAM-008"

  Scenario: Missing password policy is fixed automatically
    Given the account has no password policy
    When I run the scan
    Then I see a "HIGH" finding for check "IAM-003"
    When I auto-remediate every finding
    And I run the scan
    Then there is no finding for check "IAM-003"
    And there is no finding for check "IAM-004"
