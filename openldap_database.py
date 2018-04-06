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

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native

class OpenldapDatabase(object):
    def __init__(self, module):
        self._module = module
        self._connection = self._connect()
        self._dn = self._get_dn()

    def _connect(self):
        """Connect to slapd thru a socket using EXTERNAL auth."""

        connection = ldap.initialize('ldapi:///')
        try:
            connection.sasl_interactive_bind_s('', ldap.sasl.external())
        except ldap.LDAPError as e:
            self._module.fail_json(
                msg = 'Can\'t bind to local socket',
                details = to_native(e),
                exception = traceback.format_exc()
            )

        return connection

    def _get_dn(self):
        dn = None
        result = self._connection.search_s(
            base = 'cn=config',
            scope = ldap.SCOPE_ONELEVEL,
            filterstr = '(olcSuffix=%s)' % self._module.params['suffix'],
            attrlist = ['dn'],
            attrsonly = True
        )
        for dn, ignored in result:
            break

        return dn

    def create(self):
        pass

    def delete(self):
        pass

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
            'state': dict(default = 'present', choices = ['present', 'absent']),
            'suffix': dict(required = True),
            'updateref': dict(default = None)
        }
    )

    if not HAS_LDAP:
        module.fail_json(msg = "Missing required 'ldap' module (install python-ldap package).")

    db = OpenldapDatabase(module)

    try:
        if module.params['state'] == 'absent':
            changed = db.delete()
        else:
            changed = db.create()
    except Exception as e:
        module.fail_json(
            msg = 'Database operation failed',
            details = to_native(e),
            exception = traceback.format_exc()
        )

    module.exit_json(changed = changed)

if __name__ == '__main__':
    main()
