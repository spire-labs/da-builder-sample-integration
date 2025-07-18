use std::fs;
use std::path::Path;
use std::process::Command;
use serde_json::Value;

fn main() {
    // Monitor out/ directory for Forge artifact changes
    println!("cargo:rerun-if-changed=out/");

    // Directories to scan for Solidity contracts
    let contract_dirs = [
        "src/proposers/",
        "src/mocks/",
        "src/interfaces/",
        // Easy to add new directories here:
        // "src/new_contracts/",
    ];

    // Set up cargo rerun-if-changed for contract directories
    for dir in &contract_dirs {
        println!("cargo:rerun-if-changed={dir}");
    }

    // Always run forge build - it handles its own dependency checking
    println!("cargo:warning=Running 'forge build'...");
    
    // Get the project root directory (where Cargo.toml is located)
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    
    let status = Command::new("forge")
        .arg("build")
        .current_dir(&manifest_dir) // Ensure forge runs in project root
        .status();
    
    match status {
        Ok(exit_status) => {
            if !exit_status.success() {
                panic!("Failed to run 'forge build'. Make sure Foundry is installed and you're in the project root.");
            }
            println!("cargo:warning=Forge build completed successfully.");
        }
        Err(e) => {
            panic!("Failed to execute 'forge build': {e}. Make sure Foundry is installed and available in PATH.");
        }
    }

    // Folders to scan (remove trailing slash for file system operations)
    let folders: Vec<&str> = contract_dirs.iter()
        .map(|dir| dir.trim_end_matches('/')) // Remove trailing slash
        .collect();
    let mut contracts = Vec::new();

    for folder in &folders {
        if let Ok(entries) = fs::read_dir(folder) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "sol" {
                        if let Some(stem) = path.file_stem() {
                            if let Some(name) = stem.to_str() {
                                contracts.push((name.to_string(), path.file_name().unwrap().to_str().unwrap().to_string()));
                            }
                        }
                    }
                }
            }
        }
    }

    if contracts.is_empty() {
        panic!("No .sol contracts found in proposers, mocks, or interfaces folders!");
    }

    // Read all contract artifacts and ABIs
    let mut sol_macros = String::from("// AUTO-GENERATED FILE. DO NOT EDIT MANUALLY.\n// This file is generated by build.rs from Forge contract artifacts (out/*.json).\n// Any changes will be overwritten. To update, run `forge build` and then `cargo build`.\n\n#![allow(dead_code)]\n\nuse alloy_sol_types::sol;\n\n");
    
    // Generate bytecode constants first (only for contracts with actual bytecode)
    let mut bytecode_constants = String::new();
    for (contract_name, file_name) in &contracts {
        let artifact_path = format!("out/{file_name}/{contract_name}.json");
        if !Path::new(&artifact_path).exists() {
            println!("cargo:warning=Artifact not found for {contract_name}. Run 'forge build' first.");
            continue;
        }
        let content = fs::read_to_string(&artifact_path)
            .unwrap_or_else(|_| panic!("Failed to read artifact: {artifact_path}"));
        let artifact: Value = serde_json::from_str(&content).unwrap();
        let bytecode = artifact["bytecode"]["object"].as_str().unwrap_or("");
        
        // Only generate bytecode constant if it's not empty and not just "0x"
        if !bytecode.is_empty() && bytecode != "0x" {
            bytecode_constants.push_str(&format!("pub const {}_BYTECODE: &str = \"0x{}\";\n", 
                contract_name.to_uppercase(), 
                bytecode.trim_start_matches("0x")));
        }
    }
    
    if !bytecode_constants.is_empty() {
        sol_macros.push_str("// Contract bytecode constants\n");
        sol_macros.push_str(&bytecode_constants);
        sol_macros.push('\n');
    }
    
    // Generate sol! macros for all contracts/interfaces
    for (contract_name, file_name) in &contracts {
        let artifact_path = format!("out/{file_name}/{contract_name}.json");
        if !Path::new(&artifact_path).exists() {
            continue;
        }
        let content = fs::read_to_string(&artifact_path)
            .unwrap_or_else(|_| panic!("Failed to read artifact: {artifact_path}"));
        let artifact: Value = serde_json::from_str(&content).unwrap();
        let abi = &artifact["abi"];
        
        sol_macros.push_str(&format!("// {contract_name} contract interface\n"));
        sol_macros.push_str(&format!("sol! {{\n    #[sol(rpc)]\n    contract {} {{\n{}    }}\n}}\n\n", contract_name, abi_to_sol_functions(abi)));
    }
    
    fs::write("src/generated_contracts.rs", sol_macros).unwrap();
    println!("cargo:rustc-env=CONTRACTS_GENERATED=true");
}

fn abi_to_sol_functions(abi: &Value) -> String {
    let mut functions = String::new();
    if let Some(abi_array) = abi.as_array() {
        for item in abi_array {
            if let Some(item_type) = item["type"].as_str() {
                match item_type {
                    "function" => {
                        if let Some(function_str) = abi_item_to_sol_function(item) {
                            functions.push_str(&function_str);
                            functions.push('\n');
                        }
                    }
                    "event" => {
                        if let Some(event_str) = abi_item_to_sol_event(item) {
                            functions.push_str(&event_str);
                            functions.push('\n');
                        }
                    }
                    "error" => {
                        if let Some(error_str) = abi_item_to_sol_error(item) {
                            functions.push_str(&error_str);
                            functions.push('\n');
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    functions
}

fn abi_item_to_sol_function(item: &Value) -> Option<String> {
    let name = item["name"].as_str()?;
    let empty_vec = Vec::new();
    let inputs = item["inputs"].as_array().unwrap_or(&empty_vec);
    let outputs = item["outputs"].as_array().unwrap_or(&empty_vec);
    let state_mutability = item["stateMutability"].as_str().unwrap_or("nonpayable");
    // Skip functions with tuple or tuple[] parameters (unsupported by sol! macro)
    if inputs.iter().any(|input| {
        let t = input["type"].as_str().unwrap_or("");
        t.starts_with("tuple")
    }) {
        println!("cargo:warning=Skipping function {name} due to tuple parameter (unsupported by sol! macro)");
        return None;
    }
    if outputs.iter().any(|output| {
        let t = output["type"].as_str().unwrap_or("");
        t.starts_with("tuple")
    }) {
        println!("cargo:warning=Skipping function {name} due to tuple return type (unsupported by sol! macro)");
        return None;
    }
    let mut function = format!("        function {name}(");
    // Add input parameters
    let input_params: Vec<String> = inputs
        .iter()
        .map(|input| {
            let input_type = input["type"].as_str().unwrap_or("uint256");
            let input_name = input["name"].as_str().unwrap_or("param");
            format!("{input_type} {input_name}")
        })
        .collect();
    function.push_str(&input_params.join(", "));
    function.push_str(") ");
    // Add state mutability
    match state_mutability {
        "view" => function.push_str("public view "),
        "pure" => function.push_str("public pure "),
        "payable" => function.push_str("public payable "),
        _ => function.push_str("public "),
    }
    // Add return type
    if outputs.is_empty() {
        function.push(';');
    } else if outputs.len() == 1 {
        let output_type = outputs[0]["type"].as_str().unwrap_or("uint256");
        function.push_str(&format!("returns ({output_type});"));
    } else {
        let output_types: Vec<String> = outputs
            .iter()
            .map(|output| output["type"].as_str().unwrap_or("uint256").to_string())
            .collect();
        function.push_str(&format!("returns ({});", output_types.join(", ")));
    }
    Some(function)
}

fn abi_item_to_sol_event(item: &Value) -> Option<String> {
    let name = item["name"].as_str()?;
    let empty_vec = Vec::new();
    let inputs = item["inputs"].as_array().unwrap_or(&empty_vec);
    let anonymous = item["anonymous"].as_bool().unwrap_or(false);
    let mut event = format!("    event {name}(");
    // Add input parameters
    let input_params: Vec<String> = inputs
        .iter()
        .map(|input| {
            let input_type = input["type"].as_str().unwrap_or("uint256");
            let input_name = input["name"].as_str().unwrap_or("param");
            let indexed = input["indexed"].as_bool().unwrap_or(false);
            if indexed {
                format!("{input_type} indexed {input_name}")
            } else {
                format!("{input_type} {input_name}")
            }
        })
        .collect();
    event.push_str(&input_params.join(", "));
    event.push(')');
    if anonymous {
        event.push_str(" anonymous");
    }
    event.push(';');
    Some(event)
}

fn abi_item_to_sol_error(item: &Value) -> Option<String> {
    let name = item["name"].as_str()?;
    let empty_vec = Vec::new();
    let inputs = item["inputs"].as_array().unwrap_or(&empty_vec);
    let mut error = format!("    error {name}(");
    // Add input parameters
    let input_params: Vec<String> = inputs
        .iter()
        .map(|input| {
            let input_type = input["type"].as_str().unwrap_or("uint256");
            let input_name = input["name"].as_str().unwrap_or("param");
            format!("{input_type} {input_name}")
        })
        .collect();
    error.push_str(&input_params.join(", "));
    error.push_str(");");
    Some(error)
} 