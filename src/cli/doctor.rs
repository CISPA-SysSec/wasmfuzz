use std::path::Path;

use crate::{cow_memory::RestoreDirtyLKMMapping, ir::ModuleSpec};

pub(crate) fn run(program: Option<String>) {
    print_system_info();
    if let Some(program) = program {
        println!();
        let spec = super::parse_program(Path::new(&program));
        check_program(&spec);
    }
}

fn check_program(spec: &ModuleSpec) {
    /*
    - Program parsed correctly
    - Active features?
    - TestOneInput? malloc, init func?
    */
    println!("Module summary for {:?}", spec.filename);
    println!(
        "  module size:  {}",
        humansize::format_size(spec.wasm_binary.len(), humansize::DECIMAL)
    );
    println!("  functions:    {}", spec.functions.len());
    println!(
        "  instructions: {}",
        spec.functions
            .iter()
            .map(|f| f.operators.len())
            .sum::<usize>(),
    );
    println!(
        "  basic blocks: {}",
        spec.functions
            .iter()
            .map(|f| f.basic_block_starts.len())
            .sum::<usize>()
    );
    println!(
        "  edges:        {} (filtered)",
        spec.functions
            .iter()
            .map(|f| f.critical_insn_edges.len())
            .sum::<usize>(),
    );
    let have_test_one_input = spec.exported_funcs.contains_key("LLVMFuzzerTestOneInput");
    let have_malloc = spec.exported_funcs.contains_key("malloc");
    let have_wasmfuzz_malloc = spec.exported_funcs.contains_key("wasmfuzz_malloc");
    println!("  exports:");
    if !have_test_one_input || !(have_malloc || have_wasmfuzz_malloc) {
        println!("    [!] No `LLVMFuzzerTestOneInput` export found.");
        println!("    [!] No `malloc` or `wasmfuzz_malloc` export found.");
        println!("        This is required for wasmfuzz-style fuzzing!");
    } else {
        let markers = ["[-]", "[+]"];
        println!(
            "    {} `LLVMFuzzerTestOneInput`",
            markers[have_test_one_input as usize]
        );
        println!(
            "    {} `malloc` / {} `wasmfuzz_malloc`",
            markers[have_malloc as usize], markers[have_wasmfuzz_malloc as usize]
        );
        println!(
            "    {} `LLVMFuzzerInitialize` / {} `_initialize` / {} `init`",
            markers[spec.exported_funcs.contains_key("LLVMFuzzerInitialize") as usize],
            markers[spec.exported_funcs.contains_key("_initialize") as usize],
            markers[spec.exported_funcs.contains_key("init") as usize]
        );
    }

    // Print instructions / WASM proposals in use?
}

fn print_system_info() {
    let default_features: &[(bool, &'static str)] = &[
        (cfg!(feature = "reports"), "HTML Coverage Reports"),
        (
            cfg!(feature = "compressed_harnesses"),
            "ZStandard-compressed Harnesses (foo.wasm.zst)",
        ),
    ];
    let extra_features: &[(bool, &'static str)] = &[
        (cfg!(feature = "concolic"), "Concolic Tracing"),
        (
            cfg!(feature = "concolic_bitwuzla"),
            "Bitwuzla backend for concolic solver",
        ),
        (
            cfg!(feature = "concolic_z3"),
            "Z3 backend for concolic solver",
        ),
        (cfg!(feature = "with_mimalloc"), "mimalloc allocator"),
        (cfg!(feature = "tracy"), "Tracy Profiler Instrumentation"),
    ];
    println!("Compile-time features:");
    for (enabled, feature) in default_features {
        if *enabled {
            println!("  [+] {}", feature);
        } else {
            println!("  [-] {} (disabled!)", feature);
        }
    }

    if extra_features.iter().any(|(enabled, _)| *enabled) {
        println!("Non-default features:");
        for (enabled, feature) in extra_features {
            if *enabled {
                println!("[+] {}", feature);
            }
        }
    }

    println!("Memory restore strategy:");
    println!("  [*] CoW-based memory restore (default)");
    if RestoreDirtyLKMMapping::is_available() {
        println!("  [+] RestoreDirtyLKMMapping available (/dev/restore-dirty)");
    } else {
        println!("  [-] RestoreDirtyLKMMapping not available (/dev/restore-dirty)");
    }
    /*
    - Memory limit? available parallelism?
    - CPU affinity?
    */
}
