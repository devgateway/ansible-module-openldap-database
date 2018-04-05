#!/usr/bin/python

# Copyright 2018, Development Gateway <info@developmentgateway.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

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

if __name__ == '__main__':
    main()
