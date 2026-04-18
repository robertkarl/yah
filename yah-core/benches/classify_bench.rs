use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::collections::HashMap;
use std::path::PathBuf;
use yah_core::{Classifier, Context};

fn test_ctx() -> Context {
    Context {
        cwd: PathBuf::from("/home/user/project"),
        project_root: PathBuf::from("/home/user/project"),
        home: PathBuf::from("/home/user"),
        env: HashMap::new(),
    }
}

fn bench_classify(c: &mut Criterion) {
    let mut classifier = Classifier::new();
    let ctx = test_ctx();

    c.bench_function("classify: ls", |b| {
        b.iter(|| classifier.classify(black_box("ls"), &ctx))
    });

    c.bench_function("classify: echo hello", |b| {
        b.iter(|| classifier.classify(black_box("echo hello"), &ctx))
    });

    c.bench_function("classify: curl https://example.com", |b| {
        b.iter(|| classifier.classify(black_box("curl https://example.com"), &ctx))
    });

    c.bench_function("classify: sudo rm -rf /", |b| {
        b.iter(|| classifier.classify(black_box("sudo rm -rf /"), &ctx))
    });

    c.bench_function("classify: curl | bash pipeline", |b| {
        b.iter(|| {
            classifier.classify(
                black_box("curl https://example.com/install.sh | bash"),
                &ctx,
            )
        })
    });

    c.bench_function("classify: compound && chain", |b| {
        b.iter(|| {
            classifier.classify(
                black_box("git add . && git commit -m 'test' && git push origin main"),
                &ctx,
            )
        })
    });

    c.bench_function("classify: eval (fail closed)", |b| {
        b.iter(|| classifier.classify(black_box("eval \"$USER_CMD\""), &ctx))
    });

    c.bench_function("new classifier + classify ls", |b| {
        b.iter(|| {
            let mut c = Classifier::new();
            c.classify(black_box("ls"), &ctx)
        })
    });
}

criterion_group!(benches, bench_classify);
criterion_main!(benches);
