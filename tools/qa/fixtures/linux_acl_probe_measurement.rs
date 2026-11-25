#![forbid(unsafe_code)]

use std::{
    fs::{self, File},
    hint::black_box,
    os::unix::fs::{OpenOptionsExt, symlink},
    path::Path,
    time::Instant,
};

use rustix::{
    fs::{Mode, OFlags, XattrFlags, fgetxattr, fsetxattr, getxattr, lgetxattr, open},
    io::Errno,
};

const ACL: &str = "system.posix_acl_access";
const BUFFER: usize = 16 * 1024;
const CALLS: usize = 20_000;
const PAIRS: usize = 5;

fn admits(result: Result<usize, Errno>) -> bool {
    matches!(result, Err(Errno::NOENT | Errno::NODATA))
}

enum Target<'a> {
    Name(&'a Path),
    Descriptor(&'a File),
}

impl Target<'_> {
    fn probe(&self, size_only: bool) -> Result<usize, Errno> {
        if size_only {
            match self {
                Self::Name(path) => lgetxattr(*path, ACL, &mut [0_u8; 0]),
                Self::Descriptor(file) => fgetxattr(*file, ACL, &mut [0_u8; 0]),
            }
        } else {
            let mut buffer = [0; BUFFER];
            match self {
                Self::Name(path) => lgetxattr(*path, ACL, buffer.as_mut_slice()),
                Self::Descriptor(file) => fgetxattr(*file, ACL, buffer.as_mut_slice()),
            }
        }
    }

    fn verify(&self, expected: bool) {
        for size_only in [false, true] {
            assert_eq!(admits(self.probe(size_only)), expected, "admission changed");
        }
    }
}

fn acl(users: u32) -> Vec<u8> {
    let mut result = 2_u32.to_le_bytes().to_vec();
    let mut entry = |tag: u16, permissions: u16, id: u32| {
        result.extend(tag.to_le_bytes());
        result.extend(permissions.to_le_bytes());
        result.extend(id.to_le_bytes());
    };
    entry(1, 6, u32::MAX);
    for index in 0..users {
        entry(2, 4, 60_000 + index);
    }
    for tag in [4, 16, 32] {
        entry(tag, 0, u32::MAX);
    }
    result
}

fn create(path: &Path) -> File {
    File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("create private fixture file")
}

fn measure(target: &Target<'_>, size_only: bool, expected: bool, calls: usize) -> u128 {
    let now = Instant::now();
    let mut admitted = 0;
    for _ in 0..calls {
        admitted += admits(black_box(target).probe(black_box(size_only))) as usize;
    }
    let elapsed = now.elapsed().as_nanos();
    assert_eq!(black_box(admitted), if expected { calls } else { 0 });
    elapsed
}

fn pairs(name: &str, target: &Target<'_>, expected: bool) {
    target.verify(expected);
    for variant in [false, true] {
        measure(target, variant, expected, 1_000);
    }
    for pair in 0..PAIRS {
        let order = if pair % 2 == 0 { [false, true] } else { [true, false] };
        let mut times = [0; 2];
        for size_only in order {
            times[size_only as usize] = measure(target, size_only, expected, CALLS);
        }
        println!(
            "timing fixture={name} pair={} calls={CALLS} baseline_ns={} size_only_ns={}",
            pair + 1,
            times[0],
            times[1]
        );
    }
}

fn main() {
    let root = std::env::var_os("XTRACE_ACL_PROBE_SCRATCH").expect("private scratch required");
    let root = Path::new(&root);
    let absent = root.join("no-acl");
    let absent_file = create(&absent);
    assert_eq!(Target::Name(&absent).probe(false), Err(Errno::NODATA));
    assert_eq!(Target::Descriptor(&absent_file).probe(false), Err(Errno::NODATA));
    let missing = root.join("absent-name");
    for variant in [false, true] {
        assert_eq!(Target::Name(&missing).probe(variant), Err(Errno::NOENT));
    }
    let metadata_only = File::from(
        open(&absent, OFlags::PATH | OFlags::NOFOLLOW, Mode::empty())
            .expect("open metadata descriptor"),
    );
    for variant in [false, true] {
        assert_eq!(Target::Descriptor(&metadata_only).probe(variant), Err(Errno::BADF));
    }
    let cases = [
        (Err(Errno::NODATA), Err(Errno::NODATA), true),
        (Err(Errno::NOENT), Err(Errno::NOENT), true),
        (Ok(0), Ok(0), false),
        (Ok(44), Ok(44), false),
        (Err(Errno::RANGE), Ok(BUFFER + 1), false),
        (Err(Errno::BADF), Err(Errno::BADF), false),
        (Err(Errno::NOTSUP), Err(Errno::NOTSUP), false),
        (Err(Errno::ACCESS), Err(Errno::ACCESS), false),
        (Err(Errno::PERM), Err(Errno::PERM), false),
        (Err(Errno::IO), Err(Errno::IO), false),
    ];
    for (baseline, size_only, expected) in cases {
        assert_eq!(admits(baseline), expected);
        assert_eq!(admits(size_only), expected);
    }
    println!(
        "decisions absent=observed missing=observed descriptor_badf=observed additional_errors_and_sizes=table"
    );
    pairs("named_absent", &Target::Name(&absent), true);
    pairs("descriptor_absent", &Target::Descriptor(&absent_file), true);

    let present = root.join("with-acl");
    let present_file = create(&present);
    match fsetxattr(&present_file, ACL, &acl(1), XattrFlags::empty()) {
        Ok(()) => {
            for target in [Target::Name(&present), Target::Descriptor(&present_file)] {
                assert!(target.probe(false).is_ok());
                assert_eq!(target.probe(false), target.probe(true));
                target.verify(false);
            }
            pairs("named_present", &Target::Name(&present), false);
            pairs("descriptor_present", &Target::Descriptor(&present_file), false);

            let link = root.join("no-follow-link");
            symlink(&present, &link).expect("create fixture symlink");
            assert!(
                getxattr(link.as_path(), ACL, &mut [0_u8; 0]).is_ok(),
                "followed control needs a real ACL"
            );
            let named_link = Target::Name(&link);
            assert!(named_link.probe(false).is_err());
            assert_eq!(named_link.probe(false), named_link.probe(true));

            fs::rename(&present, root.join("retained-inode")).expect("rename fixture");
            let _replacement = create(&present);
            Target::Name(&present).verify(true);
            Target::Descriptor(&present_file).verify(false);
            println!(
                "decisions present=observed last_component_no_follow=observed descriptor_retains_inode=observed"
            );
        }
        Err(Errno::NOTSUP) => println!(
            "decisions present=unsupported last_component_no_follow=unsupported descriptor_retains_inode=unsupported errno={}",
            Errno::NOTSUP.raw_os_error()
        ),
        Err(error) => {
            panic!("ordinary ACL fixture could not be set errno={}", error.raw_os_error())
        }
    }

    let large = root.join("oversized-acl");
    let large_file = create(&large);
    match fsetxattr(&large_file, ACL, &acl(2_060), XattrFlags::empty()) {
        Ok(()) => {
            for target in [Target::Name(&large), Target::Descriptor(&large_file)] {
                assert_eq!(target.probe(false), Err(Errno::RANGE));
                assert!(target.probe(true).is_ok_and(|len| len > BUFFER));
                target.verify(false);
            }
            println!("decisions oversized=observed");
        }
        // setxattr reports ENOTSUP for unavailable support and ERANGE for a size limit.
        // Space/quota, access, invalid ACL and I/O failures are not capability evidence.
        Err(error @ (Errno::NOTSUP | Errno::RANGE)) => {
            println!("decisions oversized=table_only errno={}", error.raw_os_error());
        }
        Err(error) => {
            panic!("oversized ACL fixture could not be set errno={}", error.raw_os_error())
        }
    }
    println!("acl_probe_measurement_complete");
}
