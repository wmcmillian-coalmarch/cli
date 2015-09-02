<?php

namespace Terminus\Models;

use Terminus\Models\TerminusModel;

class SiteOrganizationMembership extends TerminusModel {
  protected $site;
  protected $organization;

  /**
   * Returns organization object within SiteOrganizationMembership object
   *
   * @return [Organization] $this->organization
   *   Org associated with this SiteOrganizationMembership
   */
  public function getOrganization() {
    if (!isset($this->organization)) {
      $this->organization = new Organization($this->id);
    }
    return $this->organization;
  }

  /**
   * Remove membership of organization
   *
   * @return [Workflow] $workflow
   **/
  public function removeMember() {
    $workflow = $this->site->workflows->create(
      'remove_site_organization_membership',
      array('params' => array('organization_id' => $this->id))
    );
    return $workflow;
  }

  /**
   * Changes the role of the given member
   *
   * @param [string] $role Desired role for this organization
   * @return [Workflow] $workflow
   */
  public function setRole($role) {
    $workflow = $this->site->workflows->create(
      'update_site_organization_membership',
      array('params' => array('organization_id' => $this->id, 'role' => $role))
    );
    return $workflow;
  }

}
