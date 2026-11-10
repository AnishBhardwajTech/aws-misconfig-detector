Feature: Detect network exposure in EC2 security groups
  As a cloud security engineer
  I want world-open admin and database ports flagged
  So that attackers cannot reach them from the internet

  Background:
    Given a mocked AWS account

  Scenario Outline: Admin port open to the internet is critical
    Given a security group allows port <port> from "0.0.0.0/0"
    When I run the scan
    Then I see a "CRITICAL" finding for check "<check>"
    And the finding is marked as publicly exposed

    Examples:
      | port | check   |
      | 22   | EC2-001 |
      | 3389 | EC2-002 |

  Scenario: A port restricted to the corporate network is not flagged
    Given a security group allows port 22 from "10.0.0.0/8"
    When I run the scan
    Then there is no finding for check "EC2-001"

  Scenario: Auto-remediation closes an open SSH port
    Given a security group allows port 22 from "0.0.0.0/0"
    When I run the scan
    And I auto-remediate every finding
    And I run the scan
    Then there is no finding for check "EC2-001"
