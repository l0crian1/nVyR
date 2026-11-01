# Installation and image management

For implementation and testing, see the [developer guide](../dev/installation.md).

nVyR installs complete images, with GRUB boot selection independent of configuration
commits. Image-changing commands require **net-admin** or higher access at configd's
authenticated execution boundary. `show system image` is available to all roles.

## Install from the live ISO

Boot the ISO using BIOS or UEFI. VGA and 115200 8N1 serial consoles are enabled;
log in as `nvyr` with password `nvyr`, then run:

```
install image
```

The initial confirmation precedes disk probing or installation changes. Choose an
eligible disk from the numbered list (largest by default). Mounted disks, the live
boot medium, readonly disks, identifiable removable USB flash drives and disks
smaller than 4 GiB are excluded. Choose **erase** for a fresh installation or
**add** to preserve an existing nVyR installation before any old filesystem is read.
The final plan shows the disk identity, image version/name, configuration source,
SSH key choice and boot default. Nothing is installed until the final confirmation.
Adding to an existing installation requires readable filesystems and a valid image
catalog. If its ext4 filesystem needs journal recovery, cleanly boot/shut down its
installed system or repair it offline before retrying. A fresh installation skips
that inspection and does not require repairing filesystems it will erase.

A fresh installation erases the selected disk, creates GPT BIOS boot, EFI System
and ext4 partitions, and installs both GRUB firmware targets. If the live session
has a user-saved configuration, choose whether to retain it; otherwise factory
defaults are selected without offering retention. Only a fresh installation asks whether to enable developer administration (default No).
The initial account is sys-admin unless developer access is selected, in which case
it is dev-admin. Image additions and upgrades never ask this question and preserve
the existing choice, including factory configuration resets.

Then supply an initial administrator username
and password. The password is hashed immediately; plaintext is not written to disk
or passed in process arguments. Fresh installation selects the new image by default.
Secure Boot is not supported; disable it when booting this unsigned image.

Adding from live media copies `/config` from the disk's **default** image. Existing
images and their configuration remain untouched. You choose retained/factory
configuration, SSH host-key transfer, and whether to select the new default.

## Upgrade from an installed image

```
add system image release.iso
add system image /config/nvyr-images/release.iso
add system image https://example.net/nvyr.iso
```

A bare filename resolves inside `/config/nvyr-images/`; Tab suggests ISO filenames.
HTTP(S) downloads begin only after the initial confirmation. HTTPS uses certificate
verification and cannot redirect to HTTP. Automatic downloads are removed after
success; supplied local files are preserved. A cancelled/failed installation retains
a completed automatic download for retrying.

The new image receives an independent copy of the **running** image's `/config`,
including ownership, permissions, ACLs and extended attributes. A factory choice
preserves user files but resets nVyR's configuration, journals and managed accounts.
Factory credentials are `nvyr` / `nvyr`; replace them after boot. SSH host keys are
transferred only when selected, otherwise generated on first use.

### Files changing during an upgrade

Running applications can change files under `/config` while the installer copies
them. If rsync reports vanished source files (exit 24), the installer shows the
diagnostics and identifies affected container volumes where possible. It recommends
disabling those containers, committing, and retrying installation, then asks:

```text
Continue with this copy anyway? [y/N]
```

Press Enter or answer `n` to discard the staged image. The running image and boot
selection remain unchanged. Answer `y` to continue with the copied data, accepting
that application data may be incomplete or inconsistent. Other copy errors,
including permission failures and disk exhaustion, remain fatal. Containers are
never disabled automatically.

For example, before retrying a copy affected by ntopng:

```text
set container name ntopng disable
commit
```

Do not save this change unless you also want the container disabled after reboot.
To enable it again on the running image when ready:

```text
delete container name ntopng disable
commit
```

Even a successful live copy does not guarantee a consistent application database.
Disable applications that require a consistent copy, or use their supported backup
mechanism. If a container provides your remote access, arrange another access path
before disabling it.

### Manage installed images

```
show system image

set system boot image release-name

rename system image old-name to new-name

delete system image unused-name
```

Image names support letters, digits, dots, underscores and hyphens (1–64 characters).
The image table has `Image`, `Running`, and `Default` columns, with `Yes` identifying
the running image and the selected boot default independently.
Commands suggest installed names. Renaming changes the display name, not mounted
paths. Deletion requires confirmation and rejects the running/default image or an
image containing mounted filesystems. GRUB selects the configured default after
five seconds. Select a previous image to roll back; that image retains its own state.

## Persistence and permissions

Each image contains its own SquashFS, kernel, initrd, writable OverlayFS upper/work
directories and `/config`. System file edits survive reboots **of that image**.
Upgrades start with a clean OS overlay and copy `/config`; they do not carry arbitrary
changes under `/etc`, `/usr` or `/home` into the new OS.

CLI users have private persistent workspaces at `/config/users/<username>`,
mounted into their session as `/home/user`. Workload mounts use
`/config/containers/`; see [container storage](containers.md#persistence-and-resource-limits).
The full `/config` tree and saved configuration are not mounted into CLI sessions.
Configd owns saved-file writes. Dev-admins retain host access and can override
filesystem permissions; use the configuration API and `save` for supported edits.

Developer-access policy is copied with `/config/.nvyr`. Each image's GRUB entry
also has a one-boot developer recovery alternative; see [login and recovery](login.md#recovery).

Configuration retention is offered for a saved non-factory configuration.
Use `save` before upgrading if you want your current changes retained.

Ctrl+C cancels guided prompts and downloads without a traceback or subprocess error.
Partial downloads are removed; complete downloads remain available for retrying.
Cancellation does not undo a successfully published image or disk erasure already
confirmed by the operator.

Do not delete `.nvyr` to clear only saved configuration: it contains account
identity and recovery information. The installer keeps it private even though its
parent `/config` is available for user files.


## Upgrade behavior

Image hashes detect corruption, not publisher authenticity; install only trusted images.
The new image validates retained configuration when it boots. A successful installation
confirms image transfer and integrity, not compatibility of every retained setting.

Stop workloads that write persistent files before upgrading if you need a consistent
copy of their data. Operating-system updates use complete images; unmanaged package
upgrades are not supported.
