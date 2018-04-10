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

import traceback, os, stat, copy

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native

class DatabaseEntry(object):
    ATTR_SUFFIX = 'olcSuffix'
    ATTR_DBDIR = 'olcDbDirectory'
    ATTR_DATABASE = 'olcDatabase'

    _map = {
        'directory': ATTR_DBDIR,
        'read_only': 'olcReadOnly',
        'root_dn': 'olcRootDN',
        'root_pw': 'olcRootPW',
        'suffix': ATTR_SUFFIX,
        'updateref': 'olcUpdateref'
    }

    _hooks = ['access', 'backend', 'config', 'indexes', 'limits']

    def __init__(self, params):
        object.__setattr__(self, 'attrs', {})

        for name, value in params.iteritems():
            self.__setattr__(name, value)

    def __setattr__(self, name, value):
        if not value and type(value) is not bool:
            return

        if name in self.__class__._map:
            attr_name = self.__class__._map[name]
            if type(value) is bool:
                value = ['TRUE'] if value else ['FALSE']
            elif type(value) is not list:
                value = [value]
            self.attrs[attr_name] = value
        elif name in self.__class__._hooks:
            method = getattr(self, '_set_' + name)
            method(value)
        elif name == 'state':
            pass
        else:
            raise AttributeError('Unknown property: {}'.format(name))

    def _set_access(self, access):
        access_list = []
        for rule in access:
            what = rule['to']
            by_who = map(
                lambda who: 'by ' + who,
                rule['by']
            )
            access_list.append(' '.join(['to', what] + by_who))

        if access_list:
            self.attrs['olcAccess'] = self._numbered_list(access_list)

    def _set_backend(self, value):
        self.attrs[self.__class__.ATTR_DATABASE] = [value.lower()]
        self.attrs['objectClass'] = ['olc{}Config'.format(value.capitalize())]

        dn = '{}={},cn=config'.format(self.__class__.ATTR_DATABASE, value)
        object.__setattr__(self, 'dn', dn)

    def _set_config(self, values):
        other_options = {}
        for key, value in values.iteritems():
            if type(value) is dict:
                other_options[key] = value
            else:
                other_options[key] = [str(value)]
        self.attrs.update(other_options)

    def set_name(self, name):
        self.attrs[self.__class__.ATTR_DATABASE] = name

    def _set_indexes(self, index_dict):
        indexes = map(
            lambda key_val_tuple: ' '.join(key_val_tuple),
            index_dict.iteritems()
        )
        if indexes:
            self.attrs['olcDbIndex'] = indexes

    def _set_limits(self, limits):
        def format_limit(limit_dict):
            for selector, limits in limit_dict.iteritems():
                limit_keyvals = map(
                    lambda elem: '='.join(elem),
                    limits.iteritems()
                )
                return ' '.join([selector] + limit_keyvals)

        if limits:
            limit_strings = map(format_limit, limits)
            self.attrs['olcLimits'] = self._numbered_list(limit_strings)

    @staticmethod
    def _numbered_list(lst):
        numbered = []
        i = 0
        for elem in lst:
            numbered.append('{{{}}}{}'.format(i, elem))
            i = i + 1

        return numbered

class OpenldapDatabase(object):
    def __init__(self, module):
        self._module = module
        self._connection = self._connect()
        self._dn = None
        self._attrs = None

        result = self._connection.search_s(
            base = 'cn=config',
            scope = ldap.SCOPE_ONELEVEL,
            filterstr = '({}={})'.format(
                DatabaseEntry.ATTR_SUFFIX,
                self._module.params['suffix']
            )
        )
        for dn, attrs in result:
            self._dn = dn
            self._attrs = attrs
            break

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

    def create(self, entry):
        """Create a database from scratch."""

        modlist = ldap.modlist.addModlist(entry.attrs)

        if not self._module.check_mode:
            self._connection.add_s(entry.dn, modlist)

        return True

    def update(self, entry):
        """Update an existing database."""

        new_entry = copy.deepcopy(entry)
        new_entry.set_name(self._attrs[DatabaseEntry.ATTR_DATABASE])
        modlist = ldap.modlist.modifyModlist(self._attrs, new_entry.attrs)

        if not self._module.check_mode:
            self._connection.modify_s(self._dn, modlist)

        return bool(modlist)

    def delete(self):
        """Delete a database and its files."""

        def get_config_path():
            """Return a valid configuration LDIF path for a database."""

            relative_path = self._dn.split(',')
            relative_path.reverse()
            relative_path[1] = relative_path[1] + '.ldif'

            config_path = os.path.join('/etc/openldap/slapd.d', *relative_path) # TODO

            if not os.path.exists(config_path):
                config_path = None

            return config_path

        def list_db_files():
            """List regular files in DB directory."""

            database_dir = self._attrs[DatabaseEntry.ATTR_DBDIR][0]
            entries = map(
                lambda path: os.path.join(database_dir, path),
                os.listdir(database_dir)
            )
            # select only regular files
            file_names = filter(
                lambda path: stat.S_ISREG(os.stat(path).st_mode),
                entries
            )

            return file_names

        changed = False

        if self._dn:
            config_path = get_config_path()
            file_names = list_db_files()
            changed = bool(config_path or file_names)
            if not self._module.check_mode:
                if config_path:
                    os.unlink(config_path)

                for path in file_names:
                    os.unlink(path)

        return changed

def main():
    module = AnsibleModule(
        argument_spec = {
            'access': dict(default = [], type = 'list'),
            'backend': dict(default = 'mdb', choices = ['bdb', 'hdb', 'mdb']),
            'config': dict(default = {}, type = 'dict'),
            'directory': dict(),
            'indexes': dict(default = {}, type = 'dict'),
            'limits': dict(default = [], type = 'list'),
            'read_only': dict(default = False, type = 'bool'),
            'root_dn': dict(),
            'root_pw': dict(),
            'state': dict(default = 'present', choices = ['present', 'absent']),
            'suffix': dict(required = True),
            'updateref': dict(default = None)
        },
        supports_check_mode = True
    )

    if not HAS_LDAP:
        module.fail_json(msg = 'Missing required "ldap" module (install python-ldap package)')

    if module.params['state'] == 'present' and not module.params['directory']:
        module.fail_json(msg = 'The argument "directory" is required to create a database.')

    db = OpenldapDatabase(module)

    try:
        if module.params['state'] == 'absent':
            changed = db.delete()
        else:
            entry = DatabaseEntry(module.params)
            if db._dn:
                changed = db.update(entry)
            else:
                changed = db.create(entry)
    except Exception as e:
        module.fail_json(
            msg = 'Database operation failed',
            details = to_native(e),
            exception = traceback.format_exc()
        )

    module.exit_json(changed = changed)

if __name__ == '__main__':
    main()
