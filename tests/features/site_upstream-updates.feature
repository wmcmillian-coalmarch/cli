Feature: site upstream updates

  Scenario: Show and apply updates for an environment
    @vcr site-upstream-updates
    Given I am authenticated
    And a site named "[[test_site_name]]"
    When I run "terminus site upstream-updates --site=[[test_site_name]] --update=dev"
    Then I should get:
    """
    Updates applied
    """
