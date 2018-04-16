# openldap\_database

A module for Ansible to add or remove OpenLDAP databases.

## Description

Create, configure, or delete OpenLDAP databases. This module does not manage database content.
Delete feature is not officially supported by OpenLDAP, thus provided "as is". Check mode is fully
supported.

## Options

### `access`

A list of access rules. Each rule is a dictionary.

Dictionary members:

- `to`: Selector for entries and/or attributes to which ACL applies.

- `by`: List of entities being granted access, and their access level (as a string).

### `backend`

Database type. You cannot change the backend after the database has been created.

Default: `mdb`

Choices: `bdb`, `hdb`, `mdb`

### `config`

Dictionary of other database-specific options, e.g. `olcDbMaxSize`. Keys must be valid attribute
names, typically starting with `olc`. Values must be either scalars (to be converted to strings),
or lists of strings.

### `directory`

Directory where database files will be stored. This directory must exist and be writable by
OpenLDAP daemon.

Required if `state=present`.

### `indexes`

Dictionary of indexes; all other indexes will be deleted. Keys are comma-separated attribute names.
Values are index types, e.g. `pres` or `eq`.

### `limits`

List of dictionaries, with only one member each. The key is subject selector. The value is a
dictionary of limit types and their values.

### `read_only`

Whether to put the database in read-only mode.

Default: no

### `root_dn`

DN of the database admin which will not be subject to access control.

### `root_pw`

Password for the *root_dn* account.

### `state`

Use `present` to create or update the DB, or `absent` to delete. Delete operation is not officially
supported by OpenLDAP.

Default: present

Choices: absent, present

### `suffix`

Database suffix, e.g. `dc=example,dc=org`. This option is required.

### `syncrepl`

List of dictionaries of syncrepl/olcSyncrepl parameters

### `updateref`

URL to return to clients which submit update requests upon the replica.

## Notes

- After deletion, you MUST restart OpenLDAP daemon, or it will keep serving ghost data.

- For additional info, see [OpenLDAP Admin's Guide](http://www.openldap.org/doc/admin24/).

## Requirements

- python-ldap

## Copyright

2018, Development Gateway, GPL v.3+
