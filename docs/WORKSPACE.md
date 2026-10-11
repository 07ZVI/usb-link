# One source repository

The checkout root is the development repository and the GitHub repository. Edit,
test, commit and push here. There is no separate public-source copy to refresh.

Run once after cloning:

```sh
python3 scripts/project.py setup
```

This enables the versioned commit/push checks and fast-forward-only pulls for
this checkout. Hooks require Python 3.9 or newer. They check staged contents before
commit and reachable local Git history before push. These pattern checks are a
guard against mistakes, not a guarantee that arbitrary sensitive data is detected.

## Local-only files

Keep signing keys, credentials, device captures, raw logs, recovery records,
historical repositories, third-party installers and local tools under `.local/`.
The entire directory is ignored by Git. Build outputs remain ignored under
`out/`, `desktop/bin/`, `desktop/obj/` and the generated launcher assets directory.
Clones do not receive these files. Builds may select locally installed tools
through `USBLINK_GO` and `USBLINK_DOTNET`.

Do not force-add local-only files. `.gitignore` does not remove an already tracked
file or erase older commits. The publication checks also reject local-only paths
that were force-added. If a secret enters history, remove it from the history
before publication and rotate it if it has been exposed.

## Everyday synchronization

With the GitHub remote and credentials configured:

```sh
git status
git pull --ff-only
# Edit and run the checks appropriate to the change.
git add <changed-source-paths>
git diff --cached
git commit -m "Describe the change"
git push
```

Commit or otherwise preserve local changes before pulling. A divergent history
requires an explicit merge or rebase; never use a force push merely to make it
match. Local and remote source are synchronized when their branch commit IDs
match. Private local files and generated outputs intentionally remain local.

GitHub account credentials are managed by Git/SSH or GitHub CLI, outside tracked
source. Run `python3 scripts/project.py setup` on every new clone because Git
does not automatically enable repository-supplied hooks.
