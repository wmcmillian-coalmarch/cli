Feature: site wipe

  Scenario: Wipe content for an Environment
    @vcr site-wipe
    Given I am authenticated
    And a site named "[[test_site_name]]"
    When I run "terminus site wipe --site=[[test_site_name]] --env=dev"
    Then I should get:
    """
    Successfully wiped
    """
