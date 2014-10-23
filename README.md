# ldapjs-sql

This is a small utility for bridging a MySQL database full of users to LDAP.
The whole thing is pretty hacky - I just wanted to get ejabberd
up-and-running with an already-existing db of users.

After installing with NPM, you can run `ldapjs-sql /path/to/config/file`.

Alternatively, you can set the config file path with
`npm config set ldapjs-sql.configfile /path/to/config/file` then run with
`npm start`.

Your config file needs to be a JSON file. See `config.json.example`
for an example file.

The config file basically defines what sql queries to use to populate
the LDAP tree. I'll write more details soon, but basically, whatever
columns your SQL query returns will become attributes in LDAP.

For example, if your database contains a `people` table
with a `first_name` and `last_name` field, your SQL will be something like:

```
select
 concat_ws(' ',p.first_name, p.last_name) as cn,
 concat_ws(' ',p.first_name, p.last_name) as displayname,
 p.first_name as givenname,
 p.last_name as sn,
from
person p
```

The server startup can take a few seconds - the server will accept
requests, but not respond to queries until all the SQL queries have
completed.

There's a list of specific fields that will trigger neat functionality.
This list is currently incomplete:

* `userpassword` - this will make the LDAP object auth-able. The server
  never actually sends the `userpassword` field on the wire, this is
  strictly meant for providing a bind function.
