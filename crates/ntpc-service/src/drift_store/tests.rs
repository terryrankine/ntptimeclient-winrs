use std::fs;

use super::*;

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "ntpc-drift-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&p).expect("temp dir");
        Self(p)
    }
    fn store(&self) -> FileDriftStore {
        FileDriftStore::new(&self.0)
    }
    fn write(&self, bytes: &[u8]) {
        fs::write(self.0.join(FILE_NAME), bytes).expect("write");
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn load_text(text: &str) -> Option<f64> {
    let d = TempDir::new("t");
    d.write(text.as_bytes());
    d.store().load().map(Ppm::value)
}

#[test]
fn drift_store_ignores_out_of_range_value() {
    assert_eq!(load_text("v1 500.1\n"), None);
    assert_eq!(load_text("v1 -500.1\n"), None);
    assert_eq!(load_text("v1 1e9\n"), None);
    assert_eq!(load_text("v1 -1e300\n"), None);
    assert_eq!(load_text("v1 1e400\n"), None);
}

#[test]
fn drift_store_ignores_corrupt_file() {
    for text in [
        "",
        "\n",
        "   \n",
        "garbage",
        "v1",
        "v1 \n",
        "v1 abc\n",
        "12.5\n",
        "v1 12.5 extra\n",
        "v2 12.5\n",
        "V1 12.5\n",
        "v1,12.5\n",
        "v1 12.5\nv1 3.0\n",
        "v1 0x10\n",
        "v1 --5\n",
        "\u{0}\u{0}\u{0}",
    ] {
        assert_eq!(load_text(text), None, "{text:?}");
    }
}

#[test]
fn boundary_values_are_accepted() {
    assert_eq!(load_text("v1 500\n"), Some(500.0));
    assert_eq!(load_text("v1 500.0\n"), Some(500.0));
    assert_eq!(load_text("v1 -500\n"), Some(-500.0));
    assert_eq!(load_text("v1 0\n"), Some(0.0));
    assert_eq!(load_text("v1 -0.0\n"), Some(-0.0));
}

#[test]
fn just_outside_the_boundary_is_rejected() {
    assert_eq!(load_text("v1 500.0001\n"), None);
    assert_eq!(load_text("v1 -500.0001\n"), None);
    assert_eq!(load_text("v1 500.00000000001\n"), None);
}

#[test]
fn non_finite_values_are_rejected() {
    for t in ["NaN", "nan", "inf", "-inf", "infinity", "+Infinity"] {
        assert_eq!(load_text(&format!("v1 {t}\n")), None, "{t}");
    }
}

#[test]
fn missing_file_loads_none() {
    let d = TempDir::new("missing");
    assert_eq!(d.store().load(), None);
}

#[test]
fn missing_directory_loads_none() {
    let d = TempDir::new("nodir");
    let s = FileDriftStore::new(d.0.join("does").join("not").join("exist"));
    assert_eq!(s.load(), None);
}

#[test]
fn unreadable_file_loads_none() {
    let d = TempDir::new("unreadable");
    // A directory where the file should be cannot be read as a file.
    fs::create_dir(d.0.join(FILE_NAME)).expect("dir");
    let s = d.store();
    assert_eq!(s.load(), None);
    assert!(matches!(s.last_load_note(), Some(LoadNote::Unreadable(_))));
}

#[test]
fn non_utf8_file_loads_none() {
    let d = TempDir::new("utf8");
    d.write(&[0xff, 0xfe, b'v', b'1']);
    let s = d.store();
    assert_eq!(s.load(), None);
    assert_eq!(s.last_load_note(), Some(LoadNote::NotUtf8));
}

#[test]
fn oversize_file_is_rejected_by_size_alone() {
    let d = TempDir::new("big");
    // A valid first line followed by padding. Only the size rule can reject it.
    let mut body = b"v1 12.5\n".to_vec();
    body.resize(usize::try_from(MAX_FILE_BYTES).expect("fits") + 1, b' ');
    d.write(&body);
    let s = d.store();
    assert_eq!(s.load(), None);
    assert_eq!(s.last_load_note(), Some(LoadNote::TooLarge));
}

#[test]
fn file_at_the_size_limit_is_read() {
    let d = TempDir::new("limit");
    let mut body = b"v1 12.5\n".to_vec();
    body.resize(usize::try_from(MAX_FILE_BYTES).expect("fits"), b' ');
    d.write(&body);
    assert_eq!(d.store().load().map(Ppm::value), Some(12.5));
}

#[test]
fn huge_file_is_not_read_into_memory() {
    // 8 MiB of text. The reader stops after the limit plus one byte.
    let d = TempDir::new("huge");
    d.write(&vec![b'9'; 8 * 1024 * 1024]);
    let s = d.store();
    assert_eq!(s.load(), None);
    assert_eq!(s.last_load_note(), Some(LoadNote::TooLarge));
}

#[test]
fn save_then_load_round_trips() {
    let d = TempDir::new("rt");
    let s = d.store();
    for v in [0.0, 12.345_678_9, -499.999, 500.0, -500.0, 1e-9, 0.1 + 0.2] {
        s.save(Ppm::new(v)).expect("save");
        let got = s.load().expect("load").value();
        assert!(got.to_bits() == v.to_bits(), "{v} came back as {got}");
    }
    assert_eq!(s.last_load_note(), None);
}

#[test]
fn saved_file_has_a_version_marker_and_one_line() {
    let d = TempDir::new("fmt");
    let s = d.store();
    s.save(Ppm::new(-3.25)).expect("save");
    let text = fs::read_to_string(s.path()).expect("read");
    assert_eq!(text, "v1 -3.25\n");
    assert!(
        u64::try_from(text.len()).expect("fits") <= MAX_FILE_BYTES,
        "the file fits under the read limit"
    );
}

#[test]
fn save_creates_the_directory() {
    let d = TempDir::new("mk");
    let s = FileDriftStore::new(d.0.join("a").join("b"));
    s.save(Ppm::new(1.0)).expect("save");
    assert_eq!(s.load().map(Ppm::value), Some(1.0));
}

#[test]
fn save_replaces_an_existing_file() {
    // On Windows std::fs::rename replaces an existing target. This runs that
    // path twice and checks that the second value wins.
    let d = TempDir::new("replace");
    let s = d.store();
    s.save(Ppm::new(1.0)).expect("first");
    s.save(Ppm::new(2.0)).expect("second over an existing file");
    assert_eq!(s.load().map(Ppm::value), Some(2.0));
}

#[test]
fn save_leaves_no_temp_file() {
    let d = TempDir::new("notmp");
    let s = d.store();
    s.save(Ppm::new(7.0)).expect("save");
    s.save(Ppm::new(8.0)).expect("save");
    let mut names: Vec<String> = fs::read_dir(&d.0)
        .expect("dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, [FILE_NAME]);
    assert!(!s.temp_path().exists());
}

#[test]
fn leftover_temp_file_does_not_break_load() {
    let d = TempDir::new("leftover");
    let s = d.store();
    s.save(Ppm::new(4.5)).expect("save");
    // A crash after writing the temp file and before the rename.
    fs::write(s.temp_path(), b"v1 99").expect("temp");
    assert_eq!(s.load().map(Ppm::value), Some(4.5));
}

#[test]
fn leftover_temp_file_with_no_main_file_loads_none() {
    let d = TempDir::new("leftover2");
    let s = d.store();
    fs::write(s.temp_path(), b"v1 99").expect("temp");
    assert_eq!(s.load(), None);
    assert_eq!(s.last_load_note(), Some(LoadNote::Missing));
}

#[test]
fn leftover_temp_file_does_not_break_save() {
    let d = TempDir::new("leftover3");
    let s = d.store();
    fs::write(s.temp_path(), b"half writ").expect("temp");
    s.save(Ppm::new(6.0)).expect("save over stale temp");
    assert_eq!(s.load().map(Ppm::value), Some(6.0));
    assert!(!s.temp_path().exists());
}

#[test]
fn failed_save_keeps_the_old_value() {
    let d = TempDir::new("keep");
    let s = d.store();
    s.save(Ppm::new(3.0)).expect("save");
    // A directory squatting on the temp name makes the write fail.
    fs::remove_file(s.temp_path()).ok();
    fs::create_dir(s.temp_path()).expect("squat");
    let e = s.save(Ppm::new(9.0)).expect_err("must fail");
    assert!(matches!(e, StoreError::Io(_)));
    assert_eq!(s.load().map(Ppm::value), Some(3.0));
}

#[test]
fn save_rejects_a_value_load_would_refuse() {
    let d = TempDir::new("range");
    let s = d.store();
    s.save(Ppm::new(1.0)).expect("save");
    assert!(s.save(Ppm::new(500.5)).is_err());
    assert!(s.save(Ppm::new(-500.5)).is_err());
    assert_eq!(s.load().map(Ppm::value), Some(1.0), "old value kept");
}

#[test]
fn save_error_names_no_secret_and_says_why() {
    let d = TempDir::new("msg");
    let s = d.store();
    let StoreError::Io(m) = s.save(Ppm::new(900.0)).expect_err("range");
    assert!(m.contains("500"), "{m}");
}

#[test]
fn crlf_and_padding_are_accepted() {
    assert_eq!(load_text("v1 12.5\r\n"), Some(12.5));
    assert_eq!(load_text("  v1   12.5  \n\n"), Some(12.5));
}

#[test]
fn notes_say_why() {
    let d = TempDir::new("notes");
    let s = d.store();
    assert_eq!(s.load(), None);
    assert_eq!(s.last_load_note(), Some(LoadNote::Missing));

    d.write(b"junk");
    assert_eq!(s.load(), None);
    assert_eq!(s.last_load_note(), Some(LoadNote::BadFormat));

    d.write(b"v1 NaN");
    assert_eq!(s.load(), None);
    assert_eq!(s.last_load_note(), Some(LoadNote::NotFinite));

    d.write(b"v1 600");
    assert_eq!(s.load(), None);
    assert_eq!(s.last_load_note(), Some(LoadNote::OutOfRange(600.0)));

    d.write(b"v1 5");
    assert_eq!(s.load().map(Ppm::value), Some(5.0));
    assert_eq!(s.last_load_note(), None, "a good load clears the note");
}

#[test]
fn notes_display_without_file_text() {
    let d = TempDir::new("disp");
    d.write(b"SuperSecretValue123");
    let s = d.store();
    let note = s.load_checked().expect_err("bad");
    let shown = format!("{note} {note:?}");
    assert!(!shown.contains("SuperSecret"), "{shown}");
}

#[test]
fn works_through_the_trait_object() {
    let d = TempDir::new("dyn");
    let s = d.store();
    let dynamic: &dyn DriftStore = &s;
    dynamic.save(Ppm::new(2.5)).expect("save");
    assert_eq!(dynamic.load().map(Ppm::value), Some(2.5));
}
