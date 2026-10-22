use bootlegger_core::dispersion::SecretPayload;
use bootlegger_format::{DecoyFile, TarEngine};
use std::fs;
use std::process::Command;

#[test]
fn test_gnu_tar_interoperability() {
    let test_dir = std::env::temp_dir().join("bootlegger_test_compat");
    let extract_dir = test_dir.join("extracted_by_gnu_tar");
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&extract_dir).unwrap();

    let decoys = vec![
        DecoyFile::new("src/main.rs", b"fn main() { println!(\"Hello Bootlegger!\"); }".to_vec()),
        DecoyFile::new("Cargo.toml", b"[package]\nname = \"demo\"\nversion = \"0.1.0\"\n".to_vec()),
        DecoyFile::new("README.md", b"# Legitimate Open Source Project\nThis is a standard README.\n".to_vec()),
        DecoyFile::new("docs/architecture.txt", vec![b'A'; 2345]),
        DecoyFile::new("data/records.csv", vec![b'B'; 4123]),
        DecoyFile::new("tests/integration.rs", vec![b'C'; 1789]),
    ];

    let secret = SecretPayload::new("passwords.kdbx", b"SUPER_SENSITIVE_KEYSTORE_DATA_998877".to_vec());
    let password = b"ultra-secure-key-123456";

    // 1. Pack with Bootlegger
    let archive_bytes = TarEngine::pack(&decoys, &secret, password, true, Some(0.10)).unwrap();
    let archive_path = test_dir.join("test_carrier.tar");
    fs::write(&archive_path, &archive_bytes).unwrap();

    // 2. Run GNU tar -tvf (inspect contents)
    let tar_tvf = Command::new("tar")
        .arg("-tvf")
        .arg(&archive_path)
        .output()
        .expect("Failed to run GNU tar");

    assert!(tar_tvf.status.success(), "GNU tar -tvf failed: {}", String::from_utf8_lossy(&tar_tvf.stderr));
    let stdout = String::from_utf8_lossy(&tar_tvf.stdout);
    assert!(stdout.contains("src/main.rs"));
    assert!(stdout.contains("Cargo.toml"));
    assert!(stdout.contains("README.md"));

    // 3. Run GNU tar -xf (extract all files)
    let tar_xf = Command::new("tar")
        .arg("-xf")
        .arg(&archive_path)
        .arg("-C")
        .arg(&extract_dir)
        .output()
        .expect("Failed to run GNU tar -xf");

    assert!(tar_xf.status.success(), "GNU tar -xf failed: {}", String::from_utf8_lossy(&tar_xf.stderr));

    // Verify all decoy files match original bit-for-bit
    for decoy in &decoys {
        let extracted_path = extract_dir.join(&decoy.path);
        assert!(extracted_path.exists(), "Extracted file does not exist: {:?}", extracted_path);
        let content = fs::read(&extracted_path).unwrap();
        assert_eq!(content, decoy.content, "Content mismatch for {:?}", decoy.path);
    }

    // 4. Recover secret with Bootlegger
    let (recovered, tripwire) = TarEngine::unpack_secret(&archive_bytes, password).unwrap();
    assert_eq!(recovered.filename, "passwords.kdbx");
    assert_eq!(recovered.data, b"SUPER_SENSITIVE_KEYSTORE_DATA_998877");
    assert!(tripwire.is_some());

    // Clean up
    let _ = fs::remove_dir_all(&test_dir);
}
