use std::fs;
use std::io::Write;
use std::path::Path;

use aegis_core::model::{JournalEntry, JournalStage};
use assert_cmd::Command;
use assert_fs::prelude::*;
use chrono::Utc;
use tempfile::tempdir;

const PASSWORD: &str = "test-pass";

fn run_cmd(home: &Path) -> Command {
    let mut cmd = Command::cargo_bin("aegis-fs").expect("binary");
    cmd.arg("--home").arg(home);
    cmd
}

fn init_home(home: &Path) {
    run_cmd(home)
        .arg("init")
        .arg("--password")
        .arg(PASSWORD)
        .arg("--confirm-password")
        .arg(PASSWORD)
        .assert()
        .success();
}

#[test]
fn round_trip_without_compression() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    init_home(&home);

    let payload = assert_fs::NamedTempFile::new("sample.bin").unwrap();
    payload.write_binary(&vec![42_u8; 2 * 1024 * 1024]).unwrap();

    run_cmd(&home)
        .arg("pack")
        .arg("--password")
        .arg(PASSWORD)
        .arg("--id")
        .arg("fileA")
        .arg(payload.path())
        .assert()
        .success();

    let out = dir.path().join("restoredA.bin");
    run_cmd(&home)
        .arg("unpack")
        .arg("--password")
        .arg(PASSWORD)
        .arg("--id")
        .arg("fileA")
        .arg("--overwrite")
        .arg(&out)
        .assert()
        .success();

    let original = fs::read(payload.path()).unwrap();
    let restored = fs::read(&out).unwrap();
    assert_eq!(original, restored);
}

#[test]
fn round_trip_with_compression() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    init_home(&home);

    let payload = assert_fs::NamedTempFile::new("sample.bin").unwrap();
    payload.write_binary(&vec![1_u8; 4 * 1024 * 1024]).unwrap();

    run_cmd(&home)
        .arg("pack")
        .arg("--password")
        .arg(PASSWORD)
        .arg("--id")
        .arg("fileB")
        .arg("--compress")
        .arg(payload.path())
        .assert()
        .success();

    let out = dir.path().join("restoredB.bin");
    run_cmd(&home)
        .arg("unpack")
        .arg("--password")
        .arg(PASSWORD)
        .arg("--id")
        .arg("fileB")
        .arg("--overwrite")
        .arg(&out)
        .assert()
        .success();

    let original = fs::read(payload.path()).unwrap();
    let restored = fs::read(&out).unwrap();
    assert_eq!(original, restored);
}

#[test]
fn shard_loss_recovers() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    init_home(&home);

    let payload = assert_fs::NamedTempFile::new("sample.bin").unwrap();
    payload.write_binary(&vec![7_u8; 3 * 1024 * 1024]).unwrap();

    run_cmd(&home)
        .arg("pack")
        .arg("--password")
        .arg(PASSWORD)
        .arg("--id")
        .arg("fileC")
        .arg(payload.path())
        .assert()
        .success();

    let shard_path = home.join("objects").join("fileC").join("shard_4.bin");
    fs::remove_file(shard_path).unwrap();

    let out = dir.path().join("restoredC.bin");
    run_cmd(&home)
        .arg("unpack")
        .arg("--password")
        .arg(PASSWORD)
        .arg("--id")
        .arg("fileC")
        .arg("--overwrite")
        .arg(&out)
        .assert()
        .success();
}

#[test]
fn corruption_detected_and_recovered() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    init_home(&home);

    let payload = assert_fs::NamedTempFile::new("sample.bin").unwrap();
    payload.write_binary(&vec![9_u8; 3 * 1024 * 1024]).unwrap();

    run_cmd(&home)
        .arg("pack")
        .arg("--password")
        .arg(PASSWORD)
        .arg("--id")
        .arg("fileD")
        .arg("--compress")
        .arg(payload.path())
        .assert()
        .success();

    let shard_path = home.join("objects").join("fileD").join("shard_1.bin");
    let mut data = fs::read(&shard_path).unwrap();
    data[0] ^= 0x55;
    fs::write(&shard_path, data).unwrap();

    let out = dir.path().join("restoredD.bin");
    run_cmd(&home)
        .arg("unpack")
        .arg("--password")
        .arg(PASSWORD)
        .arg("--id")
        .arg("fileD")
        .arg("--overwrite")
        .arg(&out)
        .assert()
        .success();
}

#[test]
fn crash_resume_completes() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    init_home(&home);

    let payload = assert_fs::NamedTempFile::new("sample.bin").unwrap();
    payload.write_binary(&vec![3_u8; 1024 * 1024]).unwrap();

    let journal_path = home.join("objects").join("resume").join("journal.json");
    fs::create_dir_all(journal_path.parent().unwrap()).unwrap();
    let entry = JournalEntry {
        stage: JournalStage::Sharded,
        updated_at: Utc::now(),
    };
    fs::write(&journal_path, serde_json::to_vec(&[entry]).unwrap()).unwrap();

    run_cmd(&home)
        .arg("pack")
        .arg("--password")
        .arg(PASSWORD)
        .arg("--id")
        .arg("resume")
        .arg(payload.path())
        .assert()
        .success();

    let out = dir.path().join("restoredE.bin");
    run_cmd(&home)
        .arg("unpack")
        .arg("--password")
        .arg(PASSWORD)
        .arg("--id")
        .arg("resume")
        .arg("--overwrite")
        .arg(&out)
        .assert()
        .success();
}

#[test]
#[ignore]
fn heavy_round_trip() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    init_home(&home);

    let payload = assert_fs::NamedTempFile::new("sample.bin").unwrap();
    // Write ~1 GiB without holding it all in memory at once
    {
        let mut file = fs::File::create(payload.path()).unwrap();
        let chunk = vec![0xAB_u8; 1024 * 1024];
        for _ in 0..1024 {
            file.write_all(&chunk).unwrap();
        }
    }

    run_cmd(&home)
        .arg("pack")
        .arg("--password")
        .arg(PASSWORD)
        .arg("--id")
        .arg("heavy")
        .arg("--compress")
        .arg(payload.path())
        .assert()
        .success();

    let out = dir.path().join("restoredF.bin");
    run_cmd(&home)
        .arg("unpack")
        .arg("--password")
        .arg(PASSWORD)
        .arg("--id")
        .arg("heavy")
        .arg("--overwrite")
        .arg(&out)
        .assert()
        .success();
}
