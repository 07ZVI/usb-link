# End-user release scope

USB Link provides USB networking and SMB management. The temporary upload receiver,
WebDAV file service, received-files UI and developer file sender have been removed.
The confined folder catalog and filesystem protections remain for compatibility SMB.
HTTP on the USB service port is limited to network diagnostics; the old upload,
WebDAV and upgrade-discovery routes do not serve files or credentials.

Developer remote maintenance is not a supported release option. The normal TCP
upgrade listener, raw-USB upgrade API, invitation generator, remote staging and
apply implementations have been removed. Public entry methods return an error;
old enabled/auto-upgrade settings are cleared when the protected local journal
manager starts. There is no UI/IPC switch to enable them. The developer publisher
and its command have been deleted and are not built or packaged. The public
launcher no longer accepts the remote-install or remote update-worker commands.

Protected local installation, ownership, rollback journals and recovery helpers
remain where needed for existing installations. Historical names and schemas in
these helpers are not an exposed remote-upgrade feature. Existing user data in
old received-files directories is preserved; removal of a feature does not delete
user files. Exact-owned old maintenance firewall rules are cleaned up through the
existing ownership checks; unrelated rules are never removed.

Release checks cover removed HTTP routes, stale remote consent, SMB regression,
package contents and absence of removed developer components. Source-level and
cross-build checks do not establish real Windows listener/firewall behavior.
Before a stable release, verify on Windows that TCP 47775 has no listener, old
config cannot enable maintenance, raw USB cannot advertise an upgrade API, local
installation/rollback work, and SMB remains usable on Mac and iPad.

No binary release is declared hardware-accepted by these software checks.
