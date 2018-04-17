#!/usr/bin/python

# Copyright 2018, Development Gateway <info@developmentgateway.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# Uses portions of ldap_entry.py by Peter Sagerson and Jiri Tyr, GPL v3

from __future__ import absolute_import
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: openldap_database
short_description: Add or remove OpenLDAP databases
description:
  - Create, configure, or delete OpenLDAP databases.
  - This module does not manage database content.
  - Delete feature is not officially supported by OpenLDAP, thus provided "as is".
  - Check mode is fully supported.
version_added: null
author: Development Gateway (@devgateway)
options:
  access:
    description:
      - A list of access rules. Each rule is a dictionary.
    suboptions:
      to:
        description:
          - Selector for entries and/or attributes to which ACL applies.
      by:
        description:
          - List of entities being granted access, and their access level (as a string).
  backend:
    description:
      - Database type.
      - You cannot change the backend after the database has been created.
    default: mdb
    choices: [bdb, hdb, mdb]
  config:
    description:
      - Dictionary of other database-specific options, e.g. C(olcDbMaxSize).
      - Keys must be valid attribute names, typically starting with "olc".
      - Values must be either scalars (to be converted to strings), or lists of strings.
  directory:
    description:
      - Directory where database files will be stored.
      - This directory must exist and be writable by OpenLDAP daemon.
      - Required if I(state=present).
  indexes:
    description:
      - Dictionary of indexes; all other indexes will be deleted.
      - Keys are comma-separated attribute names.
      - Values are index types, e.g. C(pres) or C(eq).
  limits:
    description:
      - List of dictionaries, with only one member each.
      - The key is subject selector.
      - The value is a dictionary of limit types and their values.
  read_only:
    description:
      - Whether to put the database in read-only mode.
    default: no
  root_dn:
    description:
      - DN of the database admin which will not be subject to access control.
  root_pw:
    description:
      - Password for the C(root_dn) account.
  state:
    description:
      - Use C(present) to create or update the DB, or C(absent) to delete.
      - Delete operation is not officially supported by OpenLDAP.
    default: present
    choices: [absent, present]
  suffix:
    description:
      - Database suffix, e.g. C(dc=example,dc=org).
    required: true
  syncrepl:
    description:
      - List of dictionaries of syncrepl/olcSyncrepl parameters
  updateref:
    description:
      - URL to return to clients which submit update requests upon the replica.
notes:
  - After deletion, you MUST restart OpenLDAP daemon, or it will keep serving ghost data.
  - For additional info, see L(OpenLDAP Admin's Guide, http://www.openldap.org/doc/admin24/).
requirements:
  - python-ldap
'''

EXAMPLES = '''
- name: Start OpenLDAP daemon
  service:
    name: slapd
    state: started

- name: Delete stock database
  openldap_database:
    suffix: dc=my-domain,dc=com
    state: absent
  register: stock_db

- name: Restart OpenLDAP daemon
  service:
    name: slapd
    state: restarted
  when: stock_db.changed

- name: Create database subdirectory
  file:
    path: /var/lib/ldap/example
    state: directory
    mode: 0700
    owner: ldap
    group: ldap

- name: Create example database
  openldap_database:
    suffix: dc=example,dc=org
    directory: /var/lib/ldap/example
    root_dn: cn=admin,dc=example,dc=org
    root_pw: hunter2
    indexes:
      objectClass,gidNumber,uid,uidNumber,cn: eq
      entryCSN: eq
      entryUUID: eq
    config:
      olcDbMaxSize: 52428800
    limits:
      - dn.exact="cn=replication,ou=system,dc=example,dc=org":
          size: unlimited
          time: unlimited
      - group/groupOfNames/member="cn=admins,ou=groups,dc=example,dc=org":
          size: unlimited
          time: unlimited
      - "*":
          size: 200
    access:
      - to: attrs=userPassword
        by:
          - anonymous auth
          - dn="cn=replication,ou=system,dc=example,dc=org" read
          - group.exact="cn=admins,ou=groups,dc=example,dc=org" write
          - self write
          - set="this/manager & user" write
      - to: dn.subtree="ou=system,dc=example,dc=org"
        by:
          - self.level{1} read
          - group.exact="cn=admins,ou=groups,dc=example,dc=org" write
    syncrepl:
      - rid: 42
        provider: ldap://master-ldap.example.org
        searchbase: dc=example,dc=org
'''

try:
    import ldap
    import ldap.modlist
    import ldap.sasl

    HAS_LDAP = True
except ImportError:
    HAS_LDAP = False

import traceback, os, stat, subprocess

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native

class OpenldapDatabase(object):
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

    _hooks = ['access', 'backend', 'config', 'indexes', 'limits', 'syncrepl']

    def __init__(self, module):
        self._module = module

        # get current attribute values from LDAP (if present)
        self._connection = self._connect()
        (self._dn, self._old_attrs) = self._find_database(module.params['suffix'])
        self._exists = bool(self._dn)

        # set desired attribute values from module parameters
        self._attrs = {}

        for name, value in module.params.iteritems():
            self._set_attribute(name, value)

    def _find_database(self, suffix):
        """Find the DB DN and entry in LDAP."""

        search_results = self._connection.search_s(
            base = 'cn=config',
            scope = ldap.SCOPE_ONELEVEL,
            filterstr = '({}={})'.format(self.__class__.ATTR_SUFFIX, suffix)
        )
        for database in search_results:
            return database

        # if not found
        return (None, {})

    def _connect(self):
        """Connect to slapd thru a socket using EXTERNAL auth."""

        # Slapd can only be managed over a local socket
        connection = ldap.initialize('ldapi:///')
        try:
            # bind as Ansible user (default: root)
            connection.sasl_interactive_bind_s('', ldap.sasl.external())
        except ldap.LDAPError as e:
            self._module.fail_json(
                msg = 'Can\'t bind to local socket',
                details = to_native(e),
                exception = traceback.format_exc()
            )

        return connection

    def _set_attribute(self, name, value):
        """Set an entry attribute by module param name."""

        # ignore uninitialized values
        if not value and type(value) is not bool:
            return

        if name in self.__class__._map:
            # values are taken (almost) literally
            attr_name = self.__class__._map[name]
            self._attrs[attr_name] = self._format_value(value)
        elif name in self.__class__._hooks:
            # values must be processed first
            method = getattr(self, '_set_attr_' + name)
            method(value)
        elif name == 'state':
            # ignore module param
            pass
        else:
            raise AttributeError('Unknown property: {}'.format(name))

    def _set_attr_access(self, access):
        """Set olcAccess attribute."""

        # interpolate the structure into a list of numbered strings
        access_list = []
        for rule in access:
            what = rule['to']
            by_who = map(
                lambda who: 'by ' + who,
                rule['by']
            )
            access_list.append(' '.join(['to', what] + by_who))

        if access_list:
            self._attrs['olcAccess'] = self._numbered_list(access_list)

    def _set_attr_backend(self, backend):
        """Set objectClass and olcDatabase attributes, and the DN."""

        # database config object class, e.g. olcBdbConfig
        self._attrs['objectClass'] = ['olc{}Config'.format(backend.capitalize())]
        db_name = self.__class__.ATTR_DATABASE # shortcut

        if self._exists:
            # keep the number assigned by Slapd
            self._attrs[db_name] = self._old_attrs[db_name]
        else:
            # format a new database name, and let Slapd assign it a number
            self._attrs[db_name] = [backend.lower()]
            self._dn = '{}={},cn=config'.format(self.__class__.ATTR_DATABASE, backend)

    def _set_attr_config(self, config):
        """Set miscellaneous DB attributes."""

        other_options = {}
        for key, value in config.iteritems():
            if type(value) is list:
                # if it's already a list, assume it's already properly formed
                other_options[key] = value
            else:
                # otherwise, coerce all values to strings, and wrap them into an array
                other_options[key] = [str(value)]
        self._attrs.update(other_options)

    def _set_attr_indexes(self, indexes):
        """Set olcDbIndex attribute."""

        # each string is a comma-separated attribute name list and an index type
        index_strings = map(
            lambda key_val_tuple: ' '.join(key_val_tuple),
            indexes.iteritems()
        )
        if index_strings:
            self._attrs['olcDbIndex'] = index_strings

    def _set_attr_limits(self, limits):
        """Set olcLimits attribute."""

        def format_limit(limit_dict):
            """To the selector (who), append all its limits."""

            # get the only key in the dict
            who = list(limit_dict.iterkeys())[0]
            their_limit = self._format_dict(limit_dict[who])

            return who + ' ' + their_limit

        if limits:
            all_limits = map(format_limit, limits)
            self._attrs['olcLimits'] = self._numbered_list(all_limits)

    def _set_attr_syncrepl(self, syncrepl):
        """Set olcSyncrepl attribute."""

        if syncrepl:
            syncrepl_strings = map(self._format_dict, syncrepl)
            self._attrs['olcSyncrepl'] = self._numbered_list(syncrepl_strings)

    @staticmethod
    def _format_value(value):
        """Convert value to array."""

        type_ = type(value)
        if type_ is bool:
            # format boolean as an uppercase string
            result = ['TRUE'] if value else ['FALSE']
        elif type_ is dict:
            result = [self._format_dict(value)]
        elif type_ is not list:
            result = [value]
        else:
            result = value

        return result

    @staticmethod
    def _format_dict(dct):
        """Format dict as 'key1=val1 key2=val2' string."""

        # convert values to strings, and form 'key=value' pairs
        keyval_pairs = map(
            lambda keyval: '='.join(map(str, keyval)),
            dct.iteritems()
        )

        return ' '.join(keyval_pairs)

    @staticmethod
    def _numbered_list(lst):
        """Insert Slapd-style numbering in the list."""

        numbered = []
        i = 0
        for elem in lst:
            numbered.append('{{{}}}{}'.format(i, elem))
            i = i + 1

        return numbered

    def ensure_present(self):
        """Create or update a database."""

        if self._exists:
            # database exists, but we might need to modify it
            ldap_function = self._connection.modify_s
            modlist = ldap.modlist.modifyModlist(self._old_attrs, self._attrs)
            # if any changes prepared
            changed = bool(modlist)
        else:
            # database missing altogether, create it from scratch
            ldap_function = self._connection.add_s
            modlist = ldap.modlist.addModlist(self._attrs)
            # creating will always change things
            changed = True

        if not self._module.check_mode:
            ldap_function(self._dn, modlist)

        return changed

    @staticmethod
    def _get_config_dir():
        slaptest = subprocess.Popen(['slaptest', '-uvd', 'Trace'], stderr = subprocess.PIPE)
        (stdin, stderr) = slaptest.communicate()

        base_name = 'cn=config.ldif'
        try:
            end = stderr.find('/' + base_name)
            if end == -1:
                raise RuntimeError('{} not found in slaptest output'.format(base_name))
            start = stderr.rfind('"', 0, end)
            if start == -1:
                raise RuntimeError('unable to parse slaptest output')

            config_dir = stderr[start + 1:end]
        except RuntimeError as e:
            config_dir = None
            predefined_dirs = [
                '/etc/openldap/slapd.d',
                '/etc/ldap/slapd.d'
            ]
            for directory in predefined_dirs:
                if os.path.isdir(directory):
                    config_dir = directory
                    break

            if config_dir is None:
                msg = 'Unable to guess slapd.d directory. Also, {}. Looked in: {}'.format(
                    e.msg,
                    ', '.join(predefined_dirs)
                )
                raise RuntimeError(msg)

        return config_dir

    def _get_config_path(self):
        """Return a valid configuration LDIF path for a database."""

        # config file for 'olcDatabase{1}mdb,cn=config' is at 'cn=config/olcDatabase{1}mdb.ldif'
        relative_path = self._dn.split(',')
        relative_path.reverse()
        relative_path[1] = relative_path[1] + '.ldif'

        config_dir = self._get_config_dir()
        config_path = os.path.join(config_dir, *relative_path)

        # the config file might already have been deleted
        if not os.path.exists(config_path):
            config_path = None

        return config_path

    def _list_db_files(self):
        """List regular files in DB directory."""

        # list files/dirs immediately in the dir, but not in subdirs
        database_dir = self._old_attrs[self.__class__.ATTR_DBDIR][0]
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

    def ensure_absent(self):
        """Delete a database and its files."""

        # the whole operation is hackish, as deletion is not officially supported

        changed = False

        if self._exists:
            delete_queue = self._list_db_files()

            config_path = self._get_config_path()
            if config_path:
                delete_queue.append(config_path)

            changed = bool(delete_queue)

            if not self._module.check_mode:
                map(os.unlink, delete_queue)

        # now the user MUST restart Slapd, or it will keep serving the DB entry from memory
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
            'root_pw': dict(no_log = True),
            'state': dict(default = 'present', choices = ['present', 'absent']),
            'syncrepl': dict(default = [], type = 'list'),
            'suffix': dict(required = True),
            'updateref': dict(default = None)
        },
        supports_check_mode = True
    )

    # check if imports succeeded
    if not HAS_LDAP:
        module.fail_json(msg = 'Missing required "ldap" module (install python-ldap package)')

    # check arguments sanity
    if module.params['state'] == 'present' and not module.params['directory']:
        module.fail_json(msg = 'The argument "directory" is required to create a database.')

    try:
        db = OpenldapDatabase(module)

        if module.params['state'] == 'absent':
            changed = db.ensure_absent()
        else:
            changed = db.ensure_present()
    except Exception as e:
        module.fail_json(
            msg = 'Database operation failed',
            details = to_native(e),
            exception = traceback.format_exc()
        )

    module.exit_json(changed = changed)

if __name__ == '__main__':
    main()
