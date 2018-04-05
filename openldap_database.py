#!/usr/bin/python

# Copyright 2018, Development Gateway <info@developmentgateway.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# Uses portions of ldap_entry.py by Peter Sagerson and Jiri Tyr, GPL v3

from __future__ import absolute_import
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

try:
    import ldap
    import ldap.modlist
    import ldap.sasl

    HAS_LDAP = True
except ImportError:
    HAS_LDAP = False

from ansible.module_utils.basic import AnsibleModule
def main():
    module = AnsibleModule(
        argument_spec = {
            'access': dict(default = {}, type = 'dict'),
            'backend': dict(default = 'mdb', choices = ['bdb', 'hdb', 'mdb']),
            'database_config': dict(default = {}, type = 'dict'),
            'directory': dict(),
            'indexes': dict(default = {}, type = 'dict'),
            'limits': dict(default = {}, type = 'dict'),
            'read_only': dict(default = False, type = 'bool'),
            'root_dn': dict(),
            'root_pw': dict(),
            'suffix': dict(required = True),
            'updateref': dict(default = None)
        }
    )

    if not HAS_LDAP:
        module.fail_json(msg = "Missing required 'ldap' module (install python-ldap package).")

if __name__ == '__main__':
    main()
