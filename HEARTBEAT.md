# HEARTBEAT

## Changes

Added authorization feature via HTTP basic auth. All code is extracted into separate package `auth`.

## Users management

Create or update an existing user:
```
$ curl admin:secret@localhost:8081/users -d '{
  "username": "test",
  "password": "secret",
  "globs":    ["foo.*", "bar.baz"]
}'
```

List users:
```
$ curl admin:secret@localhost:8081/users
```

Find user:
```
$ curl admin:secret@localhost:8081/users/test
```

Delete user:
```
$ curl -X DELETE admin:secret@localhost:8081/users/test
```
