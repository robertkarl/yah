#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::path::PathBuf;
use yah_core::{Classifier, Context};

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    command: String,
    cwd: String,
    project_root: String,
    home: String,
}

fuzz_target!(|input: FuzzInput| {
    let ctx = Context {
        cwd: PathBuf::from(&input.cwd),
        project_root: PathBuf::from(&input.project_root),
        home: PathBuf::from(&input.home),
        env: HashMap::new(),
    };
    let mut classifier = Classifier::new();
    let _ = classifier.classify(&input.command, &ctx);
});
