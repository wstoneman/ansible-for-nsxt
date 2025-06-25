#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2018 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause OR GPL-3.0-only
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
# BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}
DOCUMENTATION = '''
---
module: nsxt_security_services
short_description: 'Create a new security Service.'
description: "Creates a new Security Service using the specified Ports and nested Services. services is a
              required parameter. display_name & description are optional parameters"
version_added: '1.0'
author: 'William Stoneman'
options:
    hostname:
        description: 'Deployed NSX manager hostname.'
        required: true
        type: str
    username:
        description: 'The username to authenticate with the NSX manager.'
        required: true
        type: str
    password:
        description: 'The password to authenticate with the NSX manager.'
        required: true
        type: str
    service_entries:
        description: "Represents the ports and nested Services."
        required: true
        type: list
    display_name:
        description: 'Display name'
        required: true
        type: str
    description:
        description: 'Description of the resource'
        required: false
        type: str
    tags:
        description: 'Opaque identifier meaningful to the API user'
        required: false
        type: list
    state:
        choices:
            - present
            - absent
        description: "State can be either 'present' or 'absent'.
                      'present' is used to create or update resource.
                      'absent' is used to delete resource."
        required: true

'''

EXAMPLES = '''
- name: Create a new Security Service
  nsxt_security_services:
    hostname: "10.192.167.137"
    username: "admin"
    password: "Admin!23Admin"
    validate_certs: False
    display_name: "IPBlock-Tenant-1"
    description: "IPBlock-Tenant-1 Description"
    service_entries:
      - display_name: "ICMP Echo Reply"
        nested_service_path: "/infra/services/ICMP_Echo_Reply"
        resource_type: "NestedServiceServiceEntry"
      - display_name: "ICMP Echo Request"
        nested_service_path: "/infra/services/ICMP_Echo_Request"
        resource_type: "NestedServiceServiceEntry"
      - display_name: "HTTPS"
        nested_service_path: "/infra/services/HTTPS"
        resource_type: "NestedServiceServiceEntry"
      - display_name: "SSH"
        nested_service_path: "/infra/services/SSH"
        resource_type: "NestedServiceServiceEntry"
      - display_name: "RDP"
        nested_service_path: "/infra/services/RDP"
        resource_type: "NestedServiceServiceEntry"
    state: present
'''

RETURN = '''# '''

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.ansible_for_nsxt.plugins.module_utils.vmware_nsxt import vmware_argument_spec, request, \
    validate_nsx_mp_support
from ansible.module_utils._text import to_native


def get_service_params(args=None):
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args


def get_services(module, manager_url, mgr_username, mgr_password, validate_certs):
    try:
        (rc, resp) = request(manager_url + '/infra/services/', headers=dict(Accept='application/json'),
                             url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs,
                             ignore_errors=True)
    except Exception as err:
        module.fail_json(msg='Error accessing services. Error [%s]' % (to_native(err)))
    return resp


def get_services_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, display_name):
    services = get_services(module, manager_url, mgr_username, mgr_password, validate_certs)
    for service in services['results']:
        if service.__contains__('display_name') and service['display_name'] == display_name:
            return service
    return None


def check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, service_params):
    existing_services = get_services_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs,
                                                       service_params['display_name'])
    if existing_services is None:
        return False
    if existing_services['service_entries'] != service_params['service_entries']:
        return True
    return False


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(display_name=dict(required=True, type='str'),
                         service_entries=dict(required=True, type='list'),
                         description=dict(required=False, type='list'),
                         tags=dict(required=False, type='list'),
                         state=dict(required=True, choices=['present', 'absent']))

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    service_params = get_service_params(module.params.copy())
    state = module.params['state']
    mgr_hostname = module.params['hostname']
    mgr_username = module.params['username']
    mgr_password = module.params['password']
    validate_certs = module.params['validate_certs']
    display_name = module.params['display_name']
    manager_url = 'https://{}/policy/api/v1'.format(mgr_hostname)

    # err_msg = 'NSX v9.0.0 and above do not support MP resources in nsxt_ip_blocks.py. Please use nsxt_policy_ip_block.py module.'
    # validate_nsx_mp_support(module, manager_url, mgr_username, mgr_password, validate_certs, err_msg)

    service_dict = get_services_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs,
                                                display_name)
    service_id, revision = None, None
    if service_dict:
        service_id = service_dict['display_name'].replace(" ", "_")
        revision = service_dict['_revision']

    if state == 'present':
        headers = dict(Accept="application/json")
        headers['Content-Type'] = 'application/json'
        updated = check_for_update(module, manager_url, mgr_username, mgr_password, validate_certs, service_params)

        if not updated:
            # add the block
            if module.check_mode:
                module.exit_json(changed=True, debug_out=str(json.dumps(service_params)), id='12345')
            request_data = json.dumps(service_params)
            body_data = {
                'display_name': service_params['display_name'],
                'service_entries': service_params['service_entries'],
                'id': service_params['display_name'].replace(" ", "_")
            }

            try:
                if service_id:
                    module.exit_json(changed=False, id=service_id,
                                     message="Service with display_name %s already exist." % module.params[
                                         'display_name'])
                id = service_params['display_name'].replace(" ", "_")
                (rc, resp) = request(manager_url + '/infra/services/%s' % id, data=json.dumps(body_data).encode(), headers=headers,
                                     method='PUT',
                                     url_username=mgr_username, url_password=mgr_password,
                                     validate_certs=validate_certs, ignore_errors=True)


            except Exception as err:
                module.fail_json(
                    msg="Failed to add Service 1. Request body [%s]. Error[%s]." % (service_params, to_native(err)))
            #time.sleep(5)
            module.exit_json(changed=True, id=resp["id"], body=resp,
                             message="Service with display name %s created." % service_params['display_name'])
        else:
            id = service_dict['display_name'].replace(" ", "_")
            module.fail_json(msg="Failed to create Service with id %s, as object already exists" % (
            id, ))



    elif state == 'absent':
        # delete the array
        id = service_id
        if id is None:
            module.exit_json(changed=False, msg='No service exist with display name %s' % display_name)
        if module.check_mode:
            module.exit_json(changed=True, debug_out=str(json.dumps(service_params)), id=id)
        try:
            (rc, resp) = request(manager_url + "/infra/services/%s" % id, method='DELETE',
                                 url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs)
        except Exception as err:
            module.fail_json(msg="Failed to delete Service with id %s. Error[%s]." % (id, to_native(err)))

        time.sleep(5)
        module.exit_json(changed=True, object_name=id, message="Service with block id %s deleted." % id)


if __name__ == '__main__':
    main()