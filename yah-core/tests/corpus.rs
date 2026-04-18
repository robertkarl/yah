use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use yah_core::{Capability, Classifier, Context};

#[derive(Deserialize)]
struct Fixture {
    command: String,
    capabilities: Vec<String>,
    notes: Option<String>,
    context: FixtureContext,
}

#[derive(Deserialize)]
struct FixtureContext {
    cwd: String,
    project_root: String,
    home: String,
    #[serde(default)]
    env: HashMap<String, String>,
}

fn load_fixtures() -> Vec<(String, Fixture)> {
    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut fixtures = Vec::new();

    for entry in fs::read_dir(&fixture_dir).expect("failed to read fixtures dir") {
        let entry = entry.expect("failed to read dir entry");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let name = path
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
        let fixture: Fixture = toml::from_str(&content)
            .unwrap_or_else(|e| panic!("failed to parse {}: {}", path.display(), e));
        fixtures.push((name, fixture));
    }

    fixtures.sort_by(|a, b| a.0.cmp(&b.0));
    fixtures
}

#[test]
fn corpus_tests() {
    let fixtures = load_fixtures();
    assert!(
        fixtures.len() >= 50,
        "Expected at least 50 fixtures, got {}",
        fixtures.len()
    );

    let mut classifier = Classifier::new();
    let mut passed = 0;
    let mut failed = 0;
    let mut failures = Vec::new();

    for (name, fixture) in &fixtures {
        let ctx = Context {
            cwd: PathBuf::from(&fixture.context.cwd),
            project_root: PathBuf::from(&fixture.context.project_root),
            home: PathBuf::from(&fixture.context.home),
            env: fixture.context.env.clone(),
        };

        let actual = classifier.classify(&fixture.command, &ctx);
        let expected: HashSet<Capability> = fixture
            .capabilities
            .iter()
            .map(|s| {
                Capability::from_str_name(s)
                    .unwrap_or_else(|| panic!("unknown capability '{}' in fixture {}", s, name))
            })
            .collect();

        if actual == expected {
            passed += 1;
        } else {
            failed += 1;
            let actual_sorted: Vec<String> = {
                let mut v: Vec<_> = actual.iter().collect();
                v.sort();
                v.iter().map(|c| c.to_string()).collect()
            };
            let expected_sorted: Vec<String> = {
                let mut v: Vec<_> = expected.iter().collect();
                v.sort();
                v.iter().map(|c| c.to_string()).collect()
            };
            failures.push(format!(
                "  FAIL {}: cmd={:?}\n    expected: [{}]\n    actual:   [{}]\n    notes: {}",
                name,
                fixture.command,
                expected_sorted.join(", "),
                actual_sorted.join(", "),
                fixture.notes.as_deref().unwrap_or("")
            ));
        }
    }

    println!("\n--- CORPUS SCORECARD ---");
    println!("Total:  {}", passed + failed);
    println!("Passed: {}", passed);
    println!("Failed: {}", failed);

    if !failures.is_empty() {
        println!("\nFailures:");
        for f in &failures {
            println!("{}", f);
        }
        panic!(
            "{} of {} corpus tests failed",
            failed,
            passed + failed
        );
    }
}
