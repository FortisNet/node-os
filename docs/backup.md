# Backup and restore

A backup is a plain folder: a copy of the node's database and a manifest
(`fortis-backup.manifest`) listing every file with its size and SHA-256.
Anything that can copy a folder can therefore move one: a volume snapshot,
`rsync`, object storage, another cloud. Nothing in it is specific to one
provider.

```sh
native-controller CONFIG backup            # prints the folder it wrote
native-controller CONFIG restore FOLDER    # a folder from here or elsewhere
```

- **`backup`** stops the node, takes the database's own lock, copies, writes
  the manifest and starts the node again. The node is down for as long as the
  copy takes. The backup taken automatically before every update has the same
  manifest, so every backup is restorable the same way.
- **`restore`** checks the whole folder against its manifest before touching
  anything: a missing, changed or unlisted file, a path that leaves the
  folder, or an unsupported storage format is refused, and the node keeps
  running. It then moves the current database aside as a backup of its own
  (`...-before-restore`), copies the backup in, checks it again in place and
  starts the node. If the node does not come up healthy, the previous
  database is put back.

What a backup does not contain: secrets (the environment file, provider
keys), the certificate account key, or certificates, which are issued again.
It is not encrypted and not signed. The manifest proves a backup is complete
and undamaged; it does not prove who made it. Folders are readable by the
administrator only, and guarding a backup that leaves the host is the
operator's job.
