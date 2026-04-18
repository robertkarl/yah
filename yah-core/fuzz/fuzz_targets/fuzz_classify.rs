#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::path::PathBuf;
use yah_core::{Classifier, Context};

fuzz_target!(|data: &str| {
    let ctx = Context {
        cwd: PathBuf::from("/home/user/project"),
        project_root: PathBuf::from("/home/user/project"),
        home: PathBuf::from("/home/user"),
        env: HashMap::new(),
    };
    let mut classifier = Classifier::new();
    let _ = classifier.classify(data, &ctx);
});
