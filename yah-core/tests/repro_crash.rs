use std::collections::HashMap;
use std::path::PathBuf;
use yah_core::{Classifier, Context};

#[test]
fn repro_tree_sitter_bash_serialize_crash() {
    // Exact fields from `cargo +nightly fuzz fmt fuzz_classify_context <artifact>`
    let ctx = Context {
        cwd: PathBuf::from("%H&00<=\x07&&&6<iiiiiiii"),
        project_root: PathBuf::from("iiiiiiiiiiiiiiiiiibbbbbbbbbbbb6iiii"),
        home: PathBuf::from(""),
        env: HashMap::new(),
    };

    // Command extracted from the crash artifact via `cargo fuzz fmt`.
    // This is the exact command string that triggers the tree-sitter-bash
    // scanner serialize overflow.
    let command = "..~6>.>~6>bbbbbbbbiiiiibbbbbiiiiiiiiii\x0700<\x07%H&00<=\x07&&&%&061<H\x07%H&00<=\x07&&&6<iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii\x0700<\x07%H&00<=\x07&&&%&060<H\x07%H&00<=\x07&&&6<iiiiiiiiiiiiiiiiiiiiiiiiiiiiii\x0700<\x07%H&00<=\x07&:&&&&060<H\x07%H&00<=\x07&&&6<iiiiiiiiiiiiiiiiiiiiiiiiiiiiii&00<&&%=&\x07&060<H\x07%iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii\x0700<\x07%H&00<=\x07&&&%&060<H\x07%H&00<\x07\x0f<iiiiii<=\x07&&&%&060<H\x07%iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiyiiiiiiiiiiiiiii\x0700<\x07%H&00<=\x07&&&%&00<=\x07&&&%&060<H\x07%H&00<=\x07&&&6<iiiiiiiiiiiiiiiiiiiiiiiiiiiiii\x0700<\x07%H&00<=\x07&:&&%&060<H\x07%H&00<=\x07&&&6<iiiiiiiiiiiiiiiiiiiiiiiiiiiiii&00<=\x07&&&%&060<H\x07%iiibbbbbbbbbbbbbbbb6iiiiiiiiiiiiiiiiiii\x0700<\x07%H&00<=\x07&&&%&060<H\x07%H&00\x01&\x07&&&6<iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii/f`$\x01a`<VZ<<<<<~.<<<~$-0<=\x07&&&%&0\nod`,\tK\x07$\t.`k\t~$..2...60<H\x07%H&00<=\x07&&&6<iiiiiii\x0700<\x07%H&)0<=\x07&&&%&060<H\x07%H&00<=\x07&&&6<iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii\x0700<\x07%H&00<=\x07&&&%&060<H\x07%H&00<=\x07&&&6<iiiiiiiiiiiiiiiiiibbbbbbbbbbbbbbbbbbbbbbb6iiiiiiiiiiiiiiiiiii\x070iii\x0700<\x07%H&00<=\x07&&&%&060<H\x07%H&00<=\x07&&&6<iiiiiiiiiiiiiiiiiibbbbbbbbbbbbbbbbbbbbbbb6iiiiiiiiiiiiiiiiiii\x0700<&!<iiiiiiiiiiiiiiiiii`iiiiiiiiiiiiiiiii\x0700<\x16%H&00<=\x07&&&%&060<H\x07%H&00<=\x07&&&6<iiiiiiiiiiiiiiiiiiiiiiiiiiiiii\x0700<\x07%H&00<=\x07&:&&%/f`$\x01a`<VZ<<<<<~.<<<~$-iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiibbbbbbbbbbbbbbbbbbbbbbb6iiiiIiiiiiiiiiiiiii\x070iii\x0700<\x07%H&00<=\x07&&&%&060<H\x07%Hiiiiiiiiiiiiiiiiiiiiiiiiiiiiii\x0700<\x07%H&00<=\x07&:&&%&060<H\x07%H&00<=\x07&&&6<iiiiiiiiiiiiiiiiiiiiiiiiiiiiii&00<=\x07&&&%&060<H\x07%iiibbbbbbbbbbbbbbbb6iiiiiiiiiiiiiiiiiii\x0700<\x07%H&00<=\x07&&&%&060<H\x07%H&00\x01&\x07&&&6<iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii/f`$\x01a`<VZ<<<<<~.<<<~$-0<=\x07&&&%&060<H\x07%H&00<=\x07&&&6<iiiiiii\x0700<\x07%H&00<=\x07&&&%&060<H\x07%H&00<iiiiiiiiiiiiiii\x0700<\x07%H&00<=\x07&&&%&060<H\x07%H&00<=\x07&&&6<iiiiiiiiiiiiiiiiiibbbbbbbbbbbbbbbbbbbbbbb6iiiiiiiiiiiiiiiiiii\x070iii\x0700<\x07%H&00<=\x07&&&%&060<H\x07%H&00<=\x07&&&6<iiiiiiiiiiiiiiiiiibbbbbbbbbbbbbbbbbbbbbbb6iiiiiiiiiiiiiiiiiii\x0700<&!<iiiiiiiiiiiiiiiiii&iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii\x0700<\x07%H&0<\x07%H&00<=\x07&:&&%/f`$\x01a`<VZ<<<<<~.<<<~$-iiiiiiiiiiiiiiiiiiiiiiiiiii&00%H&00<=\x07&&&6<iiiiiii\x0700<\x07%H&00<=\x07&&&%&060<H\x07%H&00<=iiiiiiiiiiiiii\x0700<\x07%H&00<=\x07&&&%&060<H\x07%H&00<=\x07&&&6<iiiiiiiiiiiiiiiiiiiiiiiiiiiiii\x0700<\x07%H&00<=\x07&:&&%&060<H\x07%H&00<=\x07&&&6<iiiiiiiii\x0700<\x07%H&00<=\x07&:&&%&060<H\x07";

    let mut classifier = Classifier::new();
    // This should not panic/abort. If tree-sitter-bash's serialize bug is
    // present, this will SIGABRT and the test process dies.
    let _result = classifier.classify(command, &ctx);
}
