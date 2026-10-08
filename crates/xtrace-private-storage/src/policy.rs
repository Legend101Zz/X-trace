//! Pure private-storage admission policy.
//!
//! Everything here is a function of facts already read from the filesystem (owner, mode, ACL
//! bytes or `ls` listing text, filesystem type). Nothing in this module performs I/O, so every
//! row of the policy can be pinned by a table test. The platform probes that gather the facts
//! live in `probe`, and the descriptor/identity orchestration lives in `admission`.
//!
//! Three directory roles exist, and they differ on purpose:
//!
//! * [`DirectoryRole::PrivateLeaf`]: a directory that will hold private state. Owner is the
//!   current user, mode is exactly `0700`, and on Linux it carries no ACL at all.
//! * [`DirectoryRole::Traversed`]: an ancestor that is only walked through on the way to a
//!   private root. Owner is the current user or root, and group/other write bits are clear. On
//!   Linux its access ACL may name other principals but must grant none of them write, and any
//!   well-formed default ACL is accepted (it only shapes children created later).
//! * [`DirectoryRole::Container`]: an existing directory admitted for traversal and for creating
//!   private children, but never for creating private files. It follows the traversed policy; the
//!   children it creates are re-admitted as private leaves, which refuses an inherited ACL.
//!
//! [`DirectoryRole::Sealed`] is a private leaf that was deliberately made read-only (a retained
//! Java pack snapshot): the same owner and ACL rules as a private leaf with a fixed mode.
//!
//! macOS has a single listing-based ACL policy for every role: only `deny` entries from a fixed
//! vocabulary, and a fixed file-flag vocabulary.

/// How strictly a directory is judged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryRole {
    /// A directory that will hold private state: owner-only `0700`, no Linux ACL.
    PrivateLeaf,
    /// An ancestor that is only walked through.
    Traversed,
    /// An existing container that may only create private children.
    Container,
    /// A private directory sealed to a fixed read-only mode.
    Sealed { mode: u32 },
}

/// Ownership and permission-bit rule for one role.
///
/// `mode` may include file-type and setid bits; only the permission bits are compared. Every
/// directory that is admitted also had to pass the [`DirectoryRole::Traversed`] rule, because the
/// ancestor walk applies it to the final component as well (see `admission`).
pub(crate) fn directory_metadata_admits(
    role: DirectoryRole,
    owner: u32,
    mode: u32,
    current_uid: u32,
) -> bool {
    match role {
        DirectoryRole::PrivateLeaf => owner == current_uid && mode & 0o7777 == 0o700,
        DirectoryRole::Sealed { mode: sealed } => owner == current_uid && mode & 0o7777 == sealed,
        DirectoryRole::Traversed | DirectoryRole::Container => {
            (owner == current_uid || owner == 0) && mode & 0o022 == 0
        }
    }
}

/// Linux ACL rule for one role, given the raw `system.posix_acl_access` and
/// `system.posix_acl_default` attribute values (`None` when absent).
#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_directory_acl_admits(
    role: DirectoryRole,
    access: Option<&[u8]>,
    default: Option<&[u8]>,
) -> bool {
    match role {
        DirectoryRole::PrivateLeaf | DirectoryRole::Sealed { .. } => {
            access.is_none() && default.is_none()
        }
        DirectoryRole::Traversed | DirectoryRole::Container => {
            access.is_none_or(linux_access_acl_grants_no_foreign_write)
                && default.is_none_or(linux_default_acl_is_well_formed)
        }
    }
}

/// macOS ACL rule for a directory, given the `/bin/ls -ldeO` listing text. Role independent.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn macos_directory_listing_admits(text: &str, expected_path: &str) -> bool {
    parse_macos_acl_listing_kind(text, expected_path, b'd')
}

/// macOS ACL rule for a regular file, given the `/bin/ls -ldeO` listing text.
#[cfg(target_os = "macos")]
pub(crate) fn macos_file_listing_admits(text: &str, expected_path: &str) -> bool {
    parse_macos_acl_listing_kind(text, expected_path, b'-')
}

/// Linux filesystem-type rule: local ext4, XFS and btrfs only. Network, FUSE, overlay, tmpfs and
/// unknown filesystems fail closed until their ownership semantics are reviewed.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_filesystem_admitted(f_type: u64) -> bool {
    matches!(f_type, 0xef53 | 0x5846_5342 | 0x9123_683e)
}

/// macOS filesystem rule: APFS or HFS+ mounted with ownership enforced.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn macos_filesystem_admitted(type_name: &[u8], mount_flags: u32) -> bool {
    const MNT_IGNORE_OWNERSHIP: u32 = 0x0020_0000;
    mount_flags & MNT_IGNORE_OWNERSHIP == 0 && matches!(type_name, b"apfs" | b"hfs")
}

/// Parses a Linux `system.posix_acl_*` xattr (version 2, 8-byte entries) into `(tag, perm)`
/// pairs; `None` for anything malformed, so unknown shapes stay refused.
#[cfg(any(target_os = "linux", test))]
fn parse_linux_acl(bytes: &[u8]) -> Option<Vec<(u16, u16)>> {
    const VERSION: u32 = 2;
    const UNDEFINED_ID: u32 = u32::MAX;
    const MAX_ENTRIES: usize = 64;
    let (header, body) = bytes.split_at_checked(4)?;
    if u32::from_le_bytes(header.try_into().ok()?) != VERSION
        || body.len() % 8 != 0
        || body.len() / 8 > MAX_ENTRIES
    {
        return None;
    }
    let mut entries = Vec::new();
    for entry in body.chunks_exact(8) {
        let tag = u16::from_le_bytes([entry[0], entry[1]]);
        let perm = u16::from_le_bytes([entry[2], entry[3]]);
        let id = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
        let named = matches!(tag, 0x02 | 0x08);
        let unnamed = matches!(tag, 0x01 | 0x04 | 0x10 | 0x20);
        if perm > 7 || !(named || unnamed) || (unnamed && id != UNDEFINED_ID) {
            return None;
        }
        entries.push((tag, perm));
    }
    Some(entries)
}

#[cfg(any(target_os = "linux", test))]
fn linux_access_acl_grants_no_foreign_write(bytes: &[u8]) -> bool {
    const USER_OBJ: u16 = 0x01;
    const WRITE: u16 = 0x02;
    parse_linux_acl(bytes).is_some_and(|entries| {
        entries.iter().any(|(tag, _)| *tag == USER_OBJ)
            && entries.iter().all(|(tag, perm)| *tag == USER_OBJ || perm & WRITE == 0)
    })
}

#[cfg(any(target_os = "linux", test))]
fn linux_default_acl_is_well_formed(bytes: &[u8]) -> bool {
    parse_linux_acl(bytes).is_some()
}

#[cfg(any(target_os = "macos", test))]
fn parse_macos_acl_listing_kind(text: &str, expected_path: &str, kind: u8) -> bool {
    if text.contains('\r') || !text.is_ascii() || !text.ends_with('\n') {
        return false;
    }
    let mut lines = text.lines();
    let Some(header) = lines.next() else { return false };
    let Some(prefix) = header.strip_suffix(expected_path) else { return false };
    let Some(prefix) = prefix.strip_suffix(' ') else { return false };
    let fields = prefix.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() != 9
        || fields[1].parse::<u64>().is_err()
        || !valid_owner_name(fields[2])
        || !valid_owner_name(fields[3])
        || !valid_macos_flags(fields[4])
        || fields[5].parse::<u64>().is_err()
        || !matches!(
            fields[6],
            "Jan"
                | "Feb"
                | "Mar"
                | "Apr"
                | "May"
                | "Jun"
                | "Jul"
                | "Aug"
                | "Sep"
                | "Oct"
                | "Nov"
                | "Dec"
        )
        || fields[7].is_empty()
        || fields[7].len() > 2
        || !fields[7].bytes().all(|byte| byte.is_ascii_digit())
        || !(fields[8].contains(':') || fields[8].bytes().all(|byte| byte.is_ascii_digit()))
        || (fields[8].contains(':') && fields[8].len() != 5)
        || (!fields[8].contains(':') && fields[8].len() != 4)
    {
        return false;
    }
    let mode = fields[0].as_bytes();
    if mode.len() < 10 || mode[0] != kind || !valid_posix_mode(&mode[1..10]) {
        return false;
    }
    let suffix = &mode[10..];
    if !(suffix.is_empty() || suffix == b"+" || suffix == b"@" || suffix == b"+@") {
        return false;
    }
    let acl_required = suffix.contains(&b'+');
    let mut saw_acl = false;
    let mut expected_index = 0_u32;
    for line in lines {
        let Some((index, body)) = line.trim().split_once(':') else { return false };
        let Ok(index) = index.parse::<u32>() else { return false };
        if index != expected_index {
            return false;
        }
        let Some(next) = expected_index.checked_add(1) else { return false };
        expected_index = next;
        let words = body.split_ascii_whitespace().collect::<Vec<_>>();
        if words.len() < 3 || !valid_acl_principal(words[0]) {
            return false;
        }
        let effects = words
            .iter()
            .enumerate()
            .filter(|(_, word)| matches!(**word, "allow" | "deny"))
            .collect::<Vec<_>>();
        if effects.len() != 1 {
            return false;
        }
        let (effect_index, effect) = effects[0];
        if *effect != "deny" || effect_index == 0 || effect_index + 1 >= words.len() {
            return false;
        }
        if words[1..effect_index].iter().any(|word| {
            !matches!(
                *word,
                "inherited"
                    | "file_inherit"
                    | "directory_inherit"
                    | "limit_inherit"
                    | "only_inherit"
                    | "no_propagate"
            )
        }) {
            return false;
        }
        let rights = words[effect_index + 1..].join("");
        let parsed = rights.split(',').collect::<Vec<_>>();
        const RIGHTS: &[&str] = &[
            "read",
            "write",
            "append",
            "delete",
            "execute",
            "readattr",
            "writeattr",
            "readextattr",
            "writeextattr",
            "readsecurity",
            "writesecurity",
            "chown",
        ];
        if parsed.is_empty()
            || parsed.iter().any(|right| right.is_empty() || !RIGHTS.contains(right))
        {
            return false;
        }
        saw_acl = true;
    }
    (!acl_required || saw_acl) && (!saw_acl || suffix.contains(&b'@') || acl_required)
}

#[cfg(any(target_os = "macos", test))]
fn valid_owner_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

#[cfg(any(target_os = "macos", test))]
fn valid_acl_principal(value: &str) -> bool {
    let Some((kind, name)) = value.split_once(':') else { return false };
    matches!(kind, "user" | "group")
        && !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'$'))
}

#[cfg(any(target_os = "macos", test))]
/// `ls -O` file flags admitted on a directory: `sunlnk` (sticky-like unlink restriction) and
/// `restricted` (SIP) only narrow what can be changed, and `hidden` (UF_HIDDEN) is a Finder
/// visibility bit (e.g. `/Volumes`) that changes neither ownership nor access. Anything else
/// (`opaque`, `uchg`, `dataless`, ...) stays refused so unknown semantics fail closed.
fn valid_macos_flags(flags: &str) -> bool {
    if flags == "-" {
        return true;
    }
    let mut seen = std::collections::BTreeSet::new();
    flags
        .split(',')
        .all(|flag| matches!(flag, "sunlnk" | "restricted" | "hidden") && seen.insert(flag))
}

#[cfg(any(target_os = "macos", test))]
fn valid_posix_mode(mode: &[u8]) -> bool {
    const PERMISSIONS: [&[u8]; 9] =
        [b"r-", b"w-", b"xSs-", b"r-", b"w-", b"xSs-", b"r-", b"w-", b"xTt-"];
    mode.len() == PERMISSIONS.len()
        && mode.iter().zip(PERMISSIONS).all(|(actual, allowed)| allowed.contains(actual))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "tests assert on fixture setup")]
mod tests {
    use super::*;

    #[test]
    fn traversal_acl_parser_admits_read_only_acls_and_refuses_foreign_write() {
        fn acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
            let mut out = 2_u32.to_le_bytes().to_vec();
            for (tag, perm, id) in entries {
                out.extend_from_slice(&tag.to_le_bytes());
                out.extend_from_slice(&perm.to_le_bytes());
                out.extend_from_slice(&id.to_le_bytes());
            }
            out
        }
        const NONE: u32 = u32::MAX;
        let base = [(1, 7, NONE), (4, 5, NONE), (32, 5, NONE)];
        assert!(linux_access_acl_grants_no_foreign_write(&acl(&base)));
        let read_only_named =
            [(1, 7, NONE), (2, 5, 1000), (4, 5, NONE), (16, 5, NONE), (32, 5, NONE)];
        assert!(linux_access_acl_grants_no_foreign_write(&acl(&read_only_named)));
        let writable_named_user =
            [(1, 7, NONE), (2, 7, 1000), (4, 5, NONE), (16, 7, NONE), (32, 5, NONE)];
        assert!(!linux_access_acl_grants_no_foreign_write(&acl(&writable_named_user)));
        let writable_named_group =
            [(1, 7, NONE), (4, 5, NONE), (8, 2, 7), (16, 7, NONE), (32, 5, NONE)];
        assert!(!linux_access_acl_grants_no_foreign_write(&acl(&writable_named_group)));
        let writable_other = [(1, 7, NONE), (4, 5, NONE), (32, 2, NONE)];
        assert!(!linux_access_acl_grants_no_foreign_write(&acl(&writable_other)));
        let writable_group_owner = [(1, 7, NONE), (4, 7, NONE), (32, 5, NONE)];
        assert!(!linux_access_acl_grants_no_foreign_write(&acl(&writable_group_owner)));
        assert!(!linux_access_acl_grants_no_foreign_write(&[]));
        assert!(!linux_access_acl_grants_no_foreign_write(&[2, 0, 0, 0, 1, 0]));
        let mut wrong_version = acl(&base);
        wrong_version[0] = 3;
        assert!(!linux_access_acl_grants_no_foreign_write(&wrong_version));
        assert!(!linux_access_acl_grants_no_foreign_write(&acl(&[(0x40, 5, NONE)])));
        assert!(!linux_access_acl_grants_no_foreign_write(&acl(&[(1, 8, NONE)])));
        assert!(!linux_access_acl_grants_no_foreign_write(&acl(&[(1, 7, 5)])));
        assert!(!linux_access_acl_grants_no_foreign_write(&acl(&[(2, 4, 5)])));
        assert!(linux_default_acl_is_well_formed(&acl(&base)));
        assert!(linux_default_acl_is_well_formed(&acl(&[])));
        assert!(!linux_default_acl_is_well_formed(&[1, 2, 3]));
    }

    #[test]
    fn parses_real_macos_directory_headers_and_deny_only_acl() {
        let root = "drwxr-xr-x 22 root wheel sunlnk 704 Feb 25 2026 /\n";
        assert!(macos_directory_listing_admits(root, "/"));

        let home = concat!(
            "drwxr-xr-x@ 4 alice staff - 128 Oct 4 00:23 /Users/alice/Documents\n",
            "0: group:everyone deny delete\n",
        );
        assert!(macos_directory_listing_admits(home, "/Users/alice/Documents"));

        let restricted = "drwxr-xr-x 6 root wheel restricted 192 Feb 25 2026 /System\n";
        assert!(macos_directory_listing_admits(restricted, "/System"));
        assert!(!macos_directory_listing_admits(
            "drwxr-xr-x 6 root wheel unknown 192 Feb 25 2026 /System\n",
            "/System",
        ));
        assert!(macos_directory_listing_admits(
            "drwxr-xr-x@ 4 alice staff - 128 Oct 4 00:23 /Users/alice/Documents\n",
            "/Users/alice/Documents",
        ));
        assert!(!macos_directory_listing_admits(
            "drwxr-xr-x+ 4 alice staff - 128 Oct 4 00:23 /Users/alice/Documents\n",
            "/Users/alice/Documents",
        ));
    }

    #[test]
    fn macos_flags_admit_hidden_volumes_and_refuse_unknown_flags() {
        let listing =
            |flags: &str| format!("drwxr-xr-x 7 root wheel {flags} 224 Oct 8 01:32 /Volumes\n");
        for ok in ["hidden", "hidden,sunlnk", "sunlnk,hidden", "hidden,restricted", "-"] {
            assert!(macos_directory_listing_admits(&listing(ok), "/Volumes"), "{ok}");
        }
        for bad in [
            "uchg",
            "opaque",
            "hidden,uchg",
            "hidden,hidden",
            "hidden,",
            ",hidden",
            "Hidden",
            "dataless",
            "schg",
            "nodump",
        ] {
            assert!(!macos_directory_listing_admits(&listing(bad), "/Volumes"), "{bad}");
        }
        // hidden never excuses an ACL entry (write bits are enforced from st_mode, not this parser).
        assert!(!macos_directory_listing_admits(
            "drwxr-xr-x+ 7 root wheel hidden 224 Oct 8 01:32 /Volumes\n0: user:evil allow write\n",
            "/Volumes",
        ));
    }

    #[test]
    fn parser_rejects_acl_allow_and_malformed_headers() {
        let allow = concat!(
            "drwxr-xr-x@ 4 alice staff - 128 Oct 4 00:23 /Users/alice/Documents\n",
            "0: group:everyone allow delete\n",
        );
        assert!(!macos_directory_listing_admits(allow, "/Users/alice/Documents"));
        assert!(!macos_directory_listing_admits(
            "extra drwxr-xr-x 22 root wheel sunlnk 704 Feb 25 2026 /\n",
            "/",
        ));
    }

    fn acl_bytes(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut out = 2_u32.to_le_bytes().to_vec();
        for (tag, perm, id) in entries {
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&perm.to_le_bytes());
            out.extend_from_slice(&id.to_le_bytes());
        }
        out
    }

    const NONE: u32 = u32::MAX;
    const UID: u32 = 1000;

    /// Filesystem facts for one row.
    enum Filesystem {
        Linux(u64),
        Macos(&'static [u8], u32),
    }

    /// ACL facts for one row: raw Linux attributes or a macOS `ls -ldeO` listing.
    enum Acl {
        Linux { access: Option<Vec<u8>>, default: Option<Vec<u8>> },
        Macos(&'static str),
    }

    struct Row {
        name: &'static str,
        role: DirectoryRole,
        owner: u32,
        mode: u32,
        filesystem: Filesystem,
        acl: Acl,
        admit: bool,
    }

    const EXT4: Filesystem = Filesystem::Linux(0xef53);

    fn no_acl() -> Acl {
        Acl::Linux { access: None, default: None }
    }

    fn row(
        name: &'static str,
        role: DirectoryRole,
        owner: u32,
        mode: u32,
        filesystem: Filesystem,
        acl: Acl,
        admit: bool,
    ) -> Row {
        Row { name, role, owner, mode, filesystem, acl, admit }
    }

    fn acl_verdict(role: DirectoryRole, acl: &Acl) -> bool {
        match acl {
            Acl::Linux { access, default } => {
                linux_directory_acl_admits(role, access.as_deref(), default.as_deref())
            }
            Acl::Macos(listing) => {
                let first = listing.lines().next().unwrap_or("");
                let path = first.rsplit_once(' ').map_or("", |parts| parts.1);
                macos_directory_listing_admits(listing, path)
            }
        }
    }

    /// Composes the real policy functions exactly as `admission` does: every admitted directory
    /// passes the walk's traversal rule first, then its own role's rules.
    fn admits(row: &Row) -> bool {
        let filesystem = match row.filesystem {
            Filesystem::Linux(f_type) => linux_filesystem_admitted(f_type),
            Filesystem::Macos(name, flags) => macos_filesystem_admitted(name, flags),
        };
        directory_metadata_admits(DirectoryRole::Traversed, row.owner, row.mode, UID)
            && directory_metadata_admits(row.role, row.owner, row.mode, UID)
            && filesystem
            && acl_verdict(DirectoryRole::Traversed, &row.acl)
            && acl_verdict(row.role, &row.acl)
    }

    const LEAF: DirectoryRole = DirectoryRole::PrivateLeaf;
    const WALKED: DirectoryRole = DirectoryRole::Traversed;
    const CONTAINER: DirectoryRole = DirectoryRole::Container;
    const SEALED: DirectoryRole = DirectoryRole::Sealed { mode: 0o500 };

    #[test]
    fn directory_policy_table_pins_every_role_and_fact() {
        let read_only_named =
            acl_bytes(&[(1, 7, NONE), (2, 5, 12345), (4, 5, NONE), (16, 5, NONE), (32, 5, NONE)]);
        let writable_named_user =
            acl_bytes(&[(1, 7, NONE), (2, 7, 12345), (4, 5, NONE), (16, 7, NONE), (32, 5, NONE)]);
        let writable_named_group =
            acl_bytes(&[(1, 7, NONE), (4, 5, NONE), (8, 2, 7), (16, 7, NONE), (32, 5, NONE)]);
        let writable_other = acl_bytes(&[(1, 7, NONE), (4, 5, NONE), (32, 2, NONE)]);
        let stock_home_default =
            acl_bytes(&[(1, 7, NONE), (2, 7, 1000), (4, 5, NONE), (16, 7, NONE), (32, 5, NONE)]);
        let base = acl_bytes(&[(1, 7, NONE), (4, 5, NONE), (32, 5, NONE)]);
        let malformed = vec![1_u8, 2, 3];
        let linux =
            |access: Option<Vec<u8>>, default: Option<Vec<u8>>| Acl::Linux { access, default };

        let clean = "drwxr-xr-x 4 alice staff - 128 Oct 4 00:23 /d\n";
        let deny_only = concat!(
            "drwxr-xr-x@ 4 alice staff - 128 Oct 4 00:23 /d\n",
            "0: group:everyone deny delete\n",
        );
        let allow_entry = concat!(
            "drwxr-xr-x+ 4 alice staff - 128 Oct 4 00:23 /d\n",
            "0: user:evil allow write\n",
        );
        let plus_without_entries = "drwxr-xr-x+ 4 alice staff - 128 Oct 4 00:23 /d\n";
        let flags = |value: &'static str| match value {
            "hidden" => "drwxr-xr-x 7 root wheel hidden 224 Oct 8 01:32 /d\n",
            "sunlnk" => "drwxr-xr-x 22 root wheel sunlnk 704 Feb 25 2026 /d\n",
            "restricted" => "drwxr-xr-x 6 root wheel restricted 192 Feb 25 2026 /d\n",
            "uchg" => "drwxr-xr-x 7 root wheel uchg 224 Oct 8 01:32 /d\n",
            "opaque" => "drwxr-xr-x 7 root wheel opaque 224 Oct 8 01:32 /d\n",
            "hidden,uchg" => "drwxr-xr-x 7 root wheel hidden,uchg 224 Oct 8 01:32 /d\n",
            _ => "",
        };
        let apfs = || Filesystem::Macos(b"apfs", 0);
        let mac = |listing: &'static str| Acl::Macos(listing);

        let rows = vec![
            // --- owner and permission bits, per role (Linux ext4, no ACL) ---
            row("leaf 0700 owned", LEAF, UID, 0o40700, EXT4, no_acl(), true),
            row("leaf 0750", LEAF, UID, 0o40750, EXT4, no_acl(), false),
            row("leaf 0770", LEAF, UID, 0o40770, EXT4, no_acl(), false),
            row("leaf 0707", LEAF, UID, 0o40707, EXT4, no_acl(), false),
            row("leaf 0755", LEAF, UID, 0o40755, EXT4, no_acl(), false),
            row("leaf setgid 2700", LEAF, UID, 0o42700, EXT4, no_acl(), false),
            row("leaf 0500", LEAF, UID, 0o40500, EXT4, no_acl(), false),
            row("leaf root-owned 0700", LEAF, 0, 0o40700, EXT4, no_acl(), false),
            row("leaf foreign-owned 0700", LEAF, 2000, 0o40700, EXT4, no_acl(), false),
            row("walked owned 0755", WALKED, UID, 0o40755, EXT4, no_acl(), true),
            row("walked root 0755", WALKED, 0, 0o40755, EXT4, no_acl(), true),
            row("walked foreign 0755", WALKED, 2000, 0o40755, EXT4, no_acl(), false),
            row("walked group-writable", WALKED, UID, 0o40775, EXT4, no_acl(), false),
            row("walked other-writable", WALKED, UID, 0o40757, EXT4, no_acl(), false),
            row("walked sticky world-writable", WALKED, 0, 0o41777, EXT4, no_acl(), false),
            row("walked 0555", WALKED, 0, 0o40555, EXT4, no_acl(), true),
            row("container owned 0755", CONTAINER, UID, 0o40755, EXT4, no_acl(), true),
            row("container root 0755", CONTAINER, 0, 0o40755, EXT4, no_acl(), true),
            row("container foreign", CONTAINER, 2000, 0o40755, EXT4, no_acl(), false),
            row("container group-writable", CONTAINER, UID, 0o40775, EXT4, no_acl(), false),
            row("container other-writable", CONTAINER, UID, 0o40757, EXT4, no_acl(), false),
            row("sealed 0500 owned", SEALED, UID, 0o40500, EXT4, no_acl(), true),
            row("sealed but still 0700", SEALED, UID, 0o40700, EXT4, no_acl(), false),
            row("sealed root-owned", SEALED, 0, 0o40500, EXT4, no_acl(), false),
            row("sealed group-readable", SEALED, UID, 0o40550, EXT4, no_acl(), false),
            // --- Linux access and default ACLs, per role ---
            row("linux no ACL leaf", LEAF, UID, 0o40700, EXT4, linux(None, None), true),
            row(
                "linux plain base ACL leaf",
                LEAF,
                UID,
                0o40700,
                EXT4,
                linux(Some(base.clone()), None),
                false,
            ),
            row(
                "linux plain base ACL walked",
                WALKED,
                UID,
                0o40755,
                EXT4,
                linux(Some(base.clone()), None),
                true,
            ),
            row(
                "linux read-only named user, leaf",
                LEAF,
                UID,
                0o40700,
                EXT4,
                linux(Some(read_only_named.clone()), None),
                false,
            ),
            row(
                "linux read-only named user, walked",
                WALKED,
                UID,
                0o40755,
                EXT4,
                linux(Some(read_only_named.clone()), None),
                true,
            ),
            row(
                "linux read-only named user, container",
                CONTAINER,
                UID,
                0o40755,
                EXT4,
                linux(Some(read_only_named.clone()), None),
                true,
            ),
            row(
                "linux read-only named user, sealed",
                SEALED,
                UID,
                0o40500,
                EXT4,
                linux(Some(read_only_named.clone()), None),
                false,
            ),
            row(
                "linux writable named user, walked",
                WALKED,
                UID,
                0o40755,
                EXT4,
                linux(Some(writable_named_user.clone()), None),
                false,
            ),
            row(
                "linux writable named user, container",
                CONTAINER,
                UID,
                0o40755,
                EXT4,
                linux(Some(writable_named_user.clone()), None),
                false,
            ),
            row(
                "linux writable named user, leaf",
                LEAF,
                UID,
                0o40700,
                EXT4,
                linux(Some(writable_named_user), None),
                false,
            ),
            row(
                "linux writable named group, walked",
                WALKED,
                UID,
                0o40755,
                EXT4,
                linux(Some(writable_named_group), None),
                false,
            ),
            row(
                "linux writable other entry, walked",
                WALKED,
                UID,
                0o40755,
                EXT4,
                linux(Some(writable_other), None),
                false,
            ),
            row(
                "linux malformed access ACL, walked",
                WALKED,
                UID,
                0o40755,
                EXT4,
                linux(Some(malformed.clone()), None),
                false,
            ),
            row(
                "linux default ACL only, leaf",
                LEAF,
                UID,
                0o40700,
                EXT4,
                linux(None, Some(stock_home_default.clone())),
                false,
            ),
            row(
                "linux default ACL only, walked",
                WALKED,
                UID,
                0o40755,
                EXT4,
                linux(None, Some(stock_home_default.clone())),
                true,
            ),
            row(
                "linux default ACL only, container",
                CONTAINER,
                UID,
                0o40755,
                EXT4,
                linux(None, Some(stock_home_default.clone())),
                true,
            ),
            row(
                "linux default ACL only, sealed",
                SEALED,
                UID,
                0o40500,
                EXT4,
                linux(None, Some(stock_home_default)),
                false,
            ),
            row(
                "linux malformed default ACL, walked",
                WALKED,
                UID,
                0o40755,
                EXT4,
                linux(None, Some(malformed)),
                false,
            ),
            row(
                "linux default ACL, empty body",
                WALKED,
                UID,
                0o40755,
                EXT4,
                linux(None, Some(acl_bytes(&[]))),
                true,
            ),
            // --- filesystem type ---
            row("ext4", LEAF, UID, 0o40700, Filesystem::Linux(0xef53), no_acl(), true),
            row("xfs", LEAF, UID, 0o40700, Filesystem::Linux(0x5846_5342), no_acl(), true),
            row("btrfs", LEAF, UID, 0o40700, Filesystem::Linux(0x9123_683e), no_acl(), true),
            row("tmpfs", LEAF, UID, 0o40700, Filesystem::Linux(0x0102_1994), no_acl(), false),
            row("overlayfs", LEAF, UID, 0o40700, Filesystem::Linux(0x794c_7630), no_acl(), false),
            row("nfs", LEAF, UID, 0o40700, Filesystem::Linux(0x6969), no_acl(), false),
            row("fuse", LEAF, UID, 0o40700, Filesystem::Linux(0x6573_5546), no_acl(), false),
            row("apfs", LEAF, UID, 0o40700, apfs(), mac(clean), true),
            row("hfs", LEAF, UID, 0o40700, Filesystem::Macos(b"hfs", 0), mac(clean), true),
            row(
                "apfs ignoring ownership",
                LEAF,
                UID,
                0o40700,
                Filesystem::Macos(b"apfs", 0x0020_0000),
                mac(clean),
                false,
            ),
            row(
                "apfs with other mount flags",
                LEAF,
                UID,
                0o40700,
                Filesystem::Macos(b"apfs", 0x0000_1000),
                mac(clean),
                true,
            ),
            row("msdos", LEAF, UID, 0o40700, Filesystem::Macos(b"msdos", 0), mac(clean), false),
            row("macos nfs", LEAF, UID, 0o40700, Filesystem::Macos(b"nfs", 0), mac(clean), false),
            row(
                "macos empty type",
                LEAF,
                UID,
                0o40700,
                Filesystem::Macos(b"", 0),
                mac(clean),
                false,
            ),
            // --- macOS listing ACLs and flags (role independent) ---
            row("macos clean, leaf", LEAF, UID, 0o40700, apfs(), mac(clean), true),
            row("macos clean, walked", WALKED, UID, 0o40755, apfs(), mac(clean), true),
            row("macos deny-only ACL, leaf", LEAF, UID, 0o40700, apfs(), mac(deny_only), true),
            row("macos deny-only ACL, walked", WALKED, UID, 0o40755, apfs(), mac(deny_only), true),
            row(
                "macos deny-only ACL, container",
                CONTAINER,
                UID,
                0o40755,
                apfs(),
                mac(deny_only),
                true,
            ),
            row("macos allow entry, leaf", LEAF, UID, 0o40700, apfs(), mac(allow_entry), false),
            row("macos allow entry, walked", WALKED, UID, 0o40755, apfs(), mac(allow_entry), false),
            row(
                "macos allow entry, container",
                CONTAINER,
                UID,
                0o40755,
                apfs(),
                mac(allow_entry),
                false,
            ),
            row(
                "macos plus without entries",
                WALKED,
                UID,
                0o40755,
                apfs(),
                mac(plus_without_entries),
                false,
            ),
            row("macos flag hidden", WALKED, 0, 0o40755, apfs(), mac(flags("hidden")), true),
            row("macos flag sunlnk", WALKED, 0, 0o40755, apfs(), mac(flags("sunlnk")), true),
            row(
                "macos flag restricted",
                WALKED,
                0,
                0o40755,
                apfs(),
                mac(flags("restricted")),
                true,
            ),
            row("macos flag uchg", WALKED, 0, 0o40755, apfs(), mac(flags("uchg")), false),
            row("macos flag opaque", WALKED, 0, 0o40755, apfs(), mac(flags("opaque")), false),
            row(
                "macos flag hidden,uchg",
                WALKED,
                0,
                0o40755,
                apfs(),
                mac(flags("hidden,uchg")),
                false,
            ),
            row(
                "macos hidden never excuses a leaf mode",
                LEAF,
                0,
                0o40755,
                apfs(),
                mac(flags("hidden")),
                false,
            ),
        ];

        let mut failures = Vec::new();
        for case in &rows {
            if admits(case) != case.admit {
                failures.push(case.name);
            }
        }
        assert!(failures.is_empty(), "policy rows disagree: {failures:?}");
    }

    #[test]
    fn macos_acl_parser_accepts_deny_only_and_rejects_allows_or_ambiguous_output() {
        let header = "drwx------+ 3 xtrace-test staff - 96 Oct 4 12:00 /private/root\n";
        assert!(macos_directory_listing_admits(
            &format!("{header} 0: group:everyone deny delete\n"),
            "/private/root"
        ));
        assert!(!macos_directory_listing_admits(
            &format!("{header} 0: user:other allow read,write\n"),
            "/private/root"
        ));
        assert!(!macos_directory_listing_admits(
            &format!("{header} 0: user:other inherited allow read\n"),
            "/private/root"
        ));
        assert!(!macos_directory_listing_admits(
            &format!("{header} 0: group:everyone deny read,,write\n"),
            "/private/root"
        ));
        assert!(!macos_directory_listing_admits(
            "lrwx------+ 1 xtrace-test staff - 12 Oct 4 12:00 /private/root\n 0: group:everyone deny delete\n",
            "/private/root"
        ));
        assert!(!macos_directory_listing_admits(
            &format!("{header} 1: group:everyone deny delete\n"),
            "/private/root"
        ));
        assert!(!macos_directory_listing_admits("not a stat line\n", "/private/root"));
        assert!(!macos_directory_listing_admits(
            "drwx------+@+ 3 xtrace-test staff - 96 Oct 4 12:00 /private/root\n",
            "/private/root"
        ));
        assert!(!macos_directory_listing_admits(&format!("{header}\r\n"), "/private/root"));
        assert!(macos_directory_listing_admits(
            "drwx------ 3 xtrace-test staff - 96 Oct 4 12:00 /private/root\n",
            "/private/root"
        ));
        assert!(!macos_directory_listing_admits(header, "/private/root"));
        assert!(!macos_directory_listing_admits(
            "dssssssss 3 xtrace-test staff - 96 Oct 4 12:00 /private/root\n",
            "/private/root"
        ));
        assert!(macos_directory_listing_admits(
            "drwxr-xr-x@ 4 example staff - 128 Oct 4 00:23 /Volumes/Example SSD/project\n",
            "/Volumes/Example SSD/project"
        ));
        assert!(macos_directory_listing_admits(
            "drwxr-xr-x 4 example staff - 128 Oct 3 2026 /Users/example\n",
            "/Users/example"
        ));
        assert!(!macos_directory_listing_admits(
            "drwxr-xr-x@ 4 example staff 128 Oct 4 00:23 /private/root\n",
            "/private/root"
        ));
        assert!(!macos_directory_listing_admits(
            "drwxr-xr-x@ 4 example staff - 128 Oct 4 00:23 /private/root extra\n",
            "/private/root"
        ));
        for (listing, path) in [
            ("drwxr-xr-x 22 root wheel sunlnk 704 Feb 25 2026 /\n", "/"),
            ("drwxr-xr-x 5 root wheel restricted 160 Oct 4 00:23 /System\n", "/System"),
            ("drwxr-xr-x@ 4 example staff - 128 Oct 4 00:23 /Users\n", "/Users"),
            (
                "drwxr-xr-x@ 4 example staff - 128 Oct 4 00:23 /Users/example/Documents\n 0: group:everyone deny delete\n",
                "/Users/example/Documents",
            ),
        ] {
            assert!(macos_directory_listing_admits(listing, path), "{listing}");
        }
        assert!(!macos_directory_listing_admits(
            "drwxr-xr-x 5 root wheel unknown 160 Oct 4 00:23 /System\n",
            "/System"
        ));
        assert!(!macos_directory_listing_admits(
            "drwxr-xr-x+ 5 root wheel - 160 Oct 4 00:23 /System\n",
            "/System"
        ));
    }

    #[test]
    fn macos_acl_parser_accepts_known_system_flags_and_deny_only_extended_acl() {
        for header in [
            "drwxr-xr-x 22 root wheel sunlnk 704 Feb 25 2026 /\n",
            "drwxr-xr-x 5 root wheel restricted 160 Oct 4 00:23 /System\n",
            "drwxr-xr-x@ 4 example staff - 128 Oct 4 00:23 /Users\n",
            "drwxr-xr-x@ 4 example staff - 128 Oct 4 00:23 /Users/example/Documents\n 0: group:everyone deny delete\n",
        ] {
            let path = header
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().last())
                .expect("fixture path");
            assert!(macos_directory_listing_admits(header, path), "{header}");
        }
        assert!(!macos_directory_listing_admits(
            "drwxr-xr-x 5 root wheel unexpected 160 Oct 4 00:23 /System\n",
            "/System"
        ));
        assert!(!macos_directory_listing_admits(
            "drwxr-xr-x+ 5 root wheel - 160 Oct 4 00:23 /System\n",
            "/System"
        ));
    }
}
