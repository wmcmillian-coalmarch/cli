<?php

namespace Terminus\Models\Collections;

use Terminus\Models\Collections\TerminusCollection;

class SiteUserMemberships extends TerminusCollection {
  protected $site;

  /**
   * Adds this user as a member to the site
   *
   * @param [string] $email Email of team member to add
   * @param [string] $role  Role to assign to the new user
   * @return [workflow] $workflow
   **/
  public function addMember($email, $role) {
    $workflow = $this->site->workflows->create(
      'add_site_user_membership',
      array('params' => array('user_email' => $email, 'role' => $role))
    );
    return $workflow;
  }

  /**
   * Lists all team emembers
   *
   * @return [array] SiteUserMembership objects for each team member
   */
  public function all() {
    $user_memberships = array_values($this->models);
    return $user_memberships;
  }

  /**
   * Fetches model data from API and instantiates its model instances
   *
   * @param [boolean] $paged True to use paginated API requests
   * @return [SiteUserMemberships] $this
   */
  public function fetch($paged = false) {
    parent::fetch(true);
    return $this;
  }

  /**
   * Returns UUID of user with given email address
   *
   * @param [string] $email An email address to search for
   * @return [SiteUserMembership] $users[$email]
   */
  public function findByEmail($email) {
    $users  = array();
    $models = $this->all();
    foreach ($models as $user_member) {
      $user = $user_member->get('user');
      if ($user->email == $email) {
        return $user_member;
      }
    }
    return null;
  }

  /**
   * Retrieves and fills in team member data
   *
   * @return [SiteUserMemberships] $this
   */
  protected function getFetchUrl() {
    $url = 'sites/' . $this->site->get('id') . '/memberships/users';
    return $url;
  }

  /**
   * Names the model-owner of this collection
   *
   * @return [string] $owner_name
   */
  protected function getOwnerName() {
    return 'site';
  }

}
