# Operating a host

How to reach a host, where its logs are, and what it shows about itself.

## Reaching a host and reading its logs

A host made from the image (a DigitalOcean Droplet, or a virtual machine on
any other cloud) is reached over SSH, with the key chosen when it was
created. There is no password login and no root login: log in as `alpine` and
use `doas` for anything that needs the administrator.

```sh
# Replace ADDRESS with the host's public address, and the key path with yours.
ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes alpine@ADDRESS
```

`-i` names the key. `-o IdentitiesOnly=yes` makes SSH offer only that key;
without it, SSH may try every key it knows first and be refused for too many
attempts. To avoid typing both each time, add this to `~/.ssh/config` and
then use `ssh fortis-host`:

```
Host fortis-host
    HostName ADDRESS
    User alpine
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
```

The first connection asks to confirm the host's key; that is expected for a
new host. If the address was used by an earlier host, SSH refuses with a
"host key has changed" warning: remove the old entry with
`ssh-keygen -R ADDRESS` and connect again.

**What to read once you are in.**

| What | Command | Notes |
| --- | --- | --- |
| Which image this is | `cat /etc/fortis-image` | Commit, build time, base image |
| The boot report (boot check image) | `cat /var/log/fortis-bootcheck.txt` | Written once, a minute or two after first boot |
| The system log | `doas tail -n 200 /var/log/messages` | Boot, network, SSH and first-boot messages |
| First-boot messages only | `doas grep tiny-cloud /var/log/messages` | Network setup, the SSH key, disk growth |
| Services and their state | `rc-status` | What is started, stopped or crashed |
| Follow the log as it grows | `doas tail -f /var/log/messages` | Ctrl-C to stop |

To fetch one thing without opening a session, put the command after the
address:

```sh
ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes alpine@ADDRESS cat /var/log/fortis-bootcheck.txt
```

**On a host made from the node host image**, the orchestrator's own log is
`/var/log/fortis-orchestrator.log`, and the rest are under its state folder
`/var/lib/fortis/state`, readable by the administrator only.

| What | Command |
| --- | --- |
| Health, as the orchestrator sees it | `doas fortis status` |
| First boot, certificates, installs and updates | `doas tail -n 200 /var/log/fortis-orchestrator.log` |
| The node's output | `doas tail -n 200 /var/lib/fortis/state/log/node.log` |
| The keeper: starts, stops, how the node ended | `doas tail -n 200 /var/lib/fortis/state/log/keeper.log` |
| The page server | `doas tail -n 200 /var/lib/fortis/state/log/page.log` |
| A candidate release under preflight | `doas tail -n 200 /var/lib/fortis/state/log/preflight.log` |
| The host's settings | `doas cat /etc/fortis/orchestrator.conf` |
| The firewall rules in force | `doas nft list ruleset` |

A new host needs a minute or two after it is created: the first page on
`http://ADDRESS/` says what it is waiting for, and `https://ADDRESS/` answers
once the certificate is issued and the node is installed.
[image/README.md](../image/README.md) describes the steps.

Each log is limited in size and keeps one older file beside it (`node.log.1`).
From outside, `http://ADDRESS/health` and `/health.json` show the same health
report without logging in.

**If SSH does not answer.** Use the cloud's own console (on DigitalOcean:
the Droplet's page, Access, Recovery Console). The boot report is printed
there as well. No account has a password, so the console shows output but
cannot be used to log in; if a host cannot be reached at all, destroy it and
create another rather than try to repair it by hand.

## The first page and health

The orchestrator is the only author of what this host shows about itself. It
writes five finished files, every few seconds and whenever something changes:

| File | Shown at | What it is |
| --- | --- | --- |
| `index.html` | `/` | The first page: what this host is, the node's state in plain words, its public identity (DID), the installed release, what the host is doing about newer releases (or, without automatic updates, an available or staged update with the command to use), and links into the node |
| `health.html` | `/health` | The health report as a page, with the node's DID |
| `health.json` | `/health.json` | The same report for monitoring tools, in a fixed, versioned form; `identity` holds the DID and machine ID ([fortis-did.md](fortis-did.md#136-the-did-on-the-hosts-pages)) |
| `node.json` | `/node.json` | Which release runs, what this Node OS can run, what the host is doing about newer releases ([releases.md](releases.md#what-the-host-shows)), and the node's `identity` |
| `health.status` | | One line, `STATUS WRITTEN_MS`, so whoever serves the report can answer with the right status code and notice a report that nobody refreshes |

- **Self-contained.** One file each: no script, and nothing loaded from
  elsewhere. The wordmark and the background image are inside the page.
  [assets/page-shell.html](../assets/page-shell.html) is the design; the
  build compiles it into the orchestrator.
- **Nothing private.** No paths, keys, setting values, device identifiers or
  provider answers. The node's DID and machine ID are shown because they are
  public by design: every signature the node makes carries them.
- **200 or 503.** `/health` and `/health.json` answer 200 only when every
  check is healthy and the node serves, and 503 when the report is more than
  a minute old. `/node.json` always answers 200: a newer release, or a
  release store that does not answer, does not make a host unhealthy.
- **Who serves them.** While no node runs (nothing installed yet, an update
  or a restart in progress, stopped), the page server does, on the public
  HTTP port, from its own container with no network. It serves exactly `/`,
  `/health`, `/health.json`, `/node.json` and certificate challenges, and
  answers anything else with a short notice.

While the node runs, it serves these same files at `/`, `/health` and
`/health.json`, over HTTPS. `/node.json` is new: a node release serves it
once it knows the file, and until then it is answered only while no node
runs.

## Updates of the node

A host with a release store installs newer node releases by itself; a host
without one (the default) runs what its image brought until an operator
installs something else. [releases.md](releases.md) has the whole story.

| To do this | Command |
| --- | --- |
| See what the host is doing about releases | Open `/`, or `/node.json` |
| See what the store offers | `doas fortis releases` |
| Install one release by hand | `doas fortis fetch VERSION`, then `doas fortis update VERSION` |
| Keep a host on the release it has | Set `FORTIS_NATIVE_AUTO_UPDATE=0` in `/etc/fortis/orchestrator.conf` |
| Follow the other channel | Set `FORTIS_NATIVE_CHANNEL=edge` (or `stable`). Having these two channels is provisional and expected to change |

Settings are read again at every step, so a change needs no restart. While
the host downloads or installs a release, other `fortis` commands answer
"another update is active": wait for it to finish.

Not built yet: HTTPS on the page server. Until then, a visitor arriving over
`https://` while no node runs gets no answer; `http://` works.
