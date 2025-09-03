use alloy::primitives::{Address, U256};
use alloy_rpc_types::{TransactionRequest, TransactionInput, TransactionReceipt};
use alloy::primitives::TxKind;
use alloy_network::TransactionBuilder4844;
use alloy_dyn_abi::DynSolValue;
use alloy_sol_types::SolCall;
mod client;
use client::DABuilderClient;
use std::process;
use std::env;
use alloy::primitives::Bytes;
use alloy::primitives::utils::parse_units;
// Use the auto-generated contract bindings from build.rs
mod generated_contracts;
use generated_contracts::*;

type ConfigTuple = (String, String, u64, String, Address, Address);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("demo");
    
    // Handle help command before loading configuration
    if matches!(command, "help" | "--help" | "-h") {
        print_help();
        return Ok(());
    }
    
    // Load configuration
    let (rpc_url, private_key, chain_id, da_builder_rpc_url, gas_tank_address, proposer_multicall_address) = load_configuration()?;

    // Create the DA Builder client
    let client = match DABuilderClient::new(&rpc_url, &private_key, chain_id, gas_tank_address) {
        Ok(client) => {
            println!("✅ DA Builder client initialized");
            println!("  Address: {}", client.address());
            client
        }
        Err(e) => {
            eprintln!("❌ Failed to initialize DA Builder client: {e}");
            process::exit(1);
        }
    };

    match command {
        "demo" => {
            println!("🚀 DA Builder Sample Integration");
            println!("================================");
            println!();
            
            // Prompt user to continue
            prompt_user_confirmation(&rpc_url, &da_builder_rpc_url, chain_id, gas_tank_address, proposer_multicall_address, &client)?;

            // Execute all steps
            check_wallet_balance(&client, chain_id).await?;
            let proposer_address = deploy_trustless_proposer(&client, proposer_multicall_address).await?;
            setup_eip7702_account_code(&client, proposer_address).await?;
            check_and_deposit_to_gas_tank(&client).await?;
            let client = configure_da_builder_rpc(client, &da_builder_rpc_url).await?;
            let inbox_address = deploy_mock_inbox(&client).await?;
            submit_da_builder_transactions(&client, inbox_address).await?;
            monitor_onchain_execution(&client).await?;

            // Print completion summary
            print_completion_summary(&client, chain_id);
            
            Ok(())
        }
        "account-status" => show_account_status(&client).await,
        "deposit" => deposit_to_gas_tank(&client).await,
        "send" => send_custom_tx(client, &args, &da_builder_rpc_url).await,
        _ => {
            eprintln!("❌ Unknown command: {command}");
            print_help();
            process::exit(1);
        }
    }
}

fn u256_to_eth(u: U256) -> f64 {
    let s = u.to_string();
    let v = s.parse::<f64>().unwrap_or(0.0);
    v / 1e18
}

/// Load and validate configuration from environment variables
fn load_configuration() -> Result<ConfigTuple, Box<dyn std::error::Error>> {
    // Get target chain configuration first
    let target_chain = env::var("TARGET_CHAIN").unwrap_or_else(|_| "hoodi".to_string());
    
    let rpc_url = env::var("RPC_URL").unwrap_or_else(|_| {
        match target_chain.as_str() {
            "holesky" => "https://ethereum-holesky-rpc.publicnode.com".to_string(),
            "hoodi" => "https://ethereum-hoodi-rpc.publicnode.com".to_string(),
            "mainnet" => {
                eprintln!("❌ RPC_URL environment variable is required for mainnet deployment");
                eprintln!("Please set: export RPC_URL=\"your_mainnet_rpc_endpoint\"");
                process::exit(1);
            }
            _ => "https://ethereum-hoodi-rpc.publicnode.com".to_string(),
        }
    });
    let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY environment variable is required");
    
    // Get chain ID and DA Builder RPC URL based on target chain
    let (chain_id, da_builder_rpc_url_default) = match target_chain.as_str() {
        "holesky" => (17000u64, "https://da-builder.holesky.spire.dev/".to_string()),
        "hoodi" => (560048u64, "https://da-builder.hoodi.spire.dev/".to_string()),
        "mainnet" => (1u64, "https://da-builder.mainnet.spire.dev/".to_string()),
        _ => {
            eprintln!("❌ Unsupported target chain: {target_chain}");
            eprintln!("Supported chains: holesky, hoodi, mainnet");
            process::exit(1);
        }
    };
    let da_builder_rpc_url = env::var("DA_BUILDER_RPC_URL").unwrap_or(da_builder_rpc_url_default);
    
    // Get Gas Tank address based on target chain (can be overridden)
    let gas_tank_address = match target_chain.as_str() {
        "holesky" => {
            env::var("GAS_TANK_ADDRESS")
                .unwrap_or_else(|_| "0x18Fa15ea0A34a7c4BCA01bf7263b2a9Ac0D32e92".to_string())
                .parse::<Address>()?
        }
        "hoodi" => {
            env::var("GAS_TANK_ADDRESS")
                .unwrap_or_else(|_| "0x18Fa15ea0A34a7c4BCA01bf7263b2a9Ac0D32e92".to_string())
                .parse::<Address>()?
        }
        "mainnet" => {
            env::var("GAS_TANK_ADDRESS")
                .unwrap_or_else(|_| "0x2565c0A726cB0f2F79cd16510c117B4da6a6534b".to_string())
                .parse::<Address>()?
        }
        _ => unreachable!(),
    };

    // Get ProposerMulticall address based on target chain (can be overridden)
    let proposer_multicall_address = match target_chain.as_str() {
        "holesky" => {
            env::var("PROPOSER_MULTICALL_ADDRESS")
                .unwrap_or_else(|_| "0x5132dCe9aD675b2ac5E37D69D2bC7399764b5469".to_string())
                .parse::<Address>()?
        }
        "hoodi" => {
            env::var("PROPOSER_MULTICALL_ADDRESS")
                .unwrap_or_else(|_| "0x5132dCe9aD675b2ac5E37D69D2bC7399764b5469".to_string())
                .parse::<Address>()?
        }
        "mainnet" => {
            env::var("PROPOSER_MULTICALL_ADDRESS")
                .unwrap_or_else(|_| "0x9ccc2f3ecdE026230e11a5c8799ac7524f2bb294".to_string())
                .parse::<Address>()?
        }
        _ => unreachable!(),
    };

    Ok((rpc_url, private_key, chain_id, da_builder_rpc_url, gas_tank_address, proposer_multicall_address))
}

/// Prompt user to confirm configuration and continue with execution
fn prompt_user_confirmation(
    rpc_url: &str,
    da_builder_rpc_url: &str,
    chain_id: u64,
    gas_tank_address: Address,
    proposer_multicall_address: Address,
    client: &DABuilderClient,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📋 Configuration Summary:");
    println!("  RPC URL: {rpc_url}");
    println!("  DA Builder RPC URL: {da_builder_rpc_url}");
    println!("  Target Chain: {} (Chain ID: {})", env::var("TARGET_CHAIN").unwrap_or_else(|_| "hoodi".to_string()), chain_id);
    println!("  Gas Tank: {gas_tank_address}");
    println!("  ProposerMulticall: {proposer_multicall_address}");
    println!("  Wallet Address: {}", client.address());
    println!();
    println!("⚠️  This will execute all DA Builder integration steps including:");
    println!("   • TrustlessProposer deployment");
    println!("   • EIP-7702 account code setup");
    println!("   • Gas Tank balance management");
    println!("   • DA Builder transaction submission (regular + blob)");
    println!();
    
    let mut input = String::new();
    print!("Continue with execution? (y/n): ");
    std::io::Write::flush(&mut std::io::stdout()).expect("Failed to flush stdout");
    std::io::stdin().read_line(&mut input).expect("Failed to read input");
    
    match input.trim().to_lowercase().as_str() {
        "y" | "yes" => {
            println!("🚀 Proceeding with execution...");
            println!();
            Ok(())
        }
        "n" | "no" => {
            println!("❌ Execution cancelled by user");
            process::exit(0);
        }
        _ => {
            println!("❌ Invalid input. Please enter 'y' or 'n'");
            process::exit(1);
        }
    }
}


/// Step 1: Check wallet balance
async fn check_wallet_balance(client: &DABuilderClient, chain_id: u64) -> Result<(), Box<dyn std::error::Error>> {
    println!("\nStep 1: Checking wallet balance");
    println!("--------------------------------");
    
    let balance = match client.get_balance(client.address()).await {
        Ok(balance) => {
            println!("✅ Current balance: {} wei ({:.6} ETH)", balance, u256_to_eth(balance));
            balance
        }
        Err(e) => {
            eprintln!("❌ Failed to get balance: {e}");
            process::exit(1);
        }
    };
    
    // Check if balance is sufficient for deployment and operations
    let min_balance = U256::from(100000000000000000u64); // 0.1 ETH
    if balance < min_balance {
        eprintln!("❌ Insufficient balance for deployment and operations!");
        eprintln!("   Current balance: {:.6} ETH", u256_to_eth(balance));
        eprintln!("   Required minimum: {:.6} ETH", u256_to_eth(min_balance));
        
        // Show appropriate faucet based on chain
        match chain_id {
            17000 => {
                eprintln!("   Get Holesky testnet ETH from:");
                eprintln!("   • https://holesky-faucet.pk910.de/ (PoW faucet)");
                eprintln!("   • https://faucet.quicknode.com/ethereum/holesky");
                eprintln!("   • https://bwarelabs.com/faucets/ethereum-holesky");
            }
            560048 => {
                eprintln!("   Get Hoodi testnet ETH from:");
                eprintln!("   • https://hoodi-faucet.pk910.de/");
            }
            _ => {
                eprintln!("   Get testnet ETH from appropriate faucet for your network");
            }
        }
        
        process::exit(1);
    }
    
    Ok(())
}

/// Step 2: Deploy TrustlessProposer contract
async fn deploy_trustless_proposer(client: &DABuilderClient, proposer_multicall_address: Address) -> Result<Address, Box<dyn std::error::Error>> {
    println!("\nStep 2: Deploying TrustlessProposer contract");
    println!("----------------------------------------------");
    
    // Deploy using the simplified CREATE2 method with defaults
    let proposer_address = match client.deploy_create2_if_not_exists_with_defaults(
        TRUSTLESSPROPOSER_BYTECODE,
        &[DynSolValue::Address(proposer_multicall_address)], // ProposerMulticall address constructor argument
    ).await {
        Ok(address) => {
            println!("✅ TrustlessProposer deployed/verified at: {address}");
            address
        }
        Err(e) => {
            eprintln!("❌ Failed to deploy TrustlessProposer: {e}");
            process::exit(1);
        }
    };
    
    Ok(proposer_address)
}

/// Step 3: Set up EIP-7702 account code
async fn setup_eip7702_account_code(client: &DABuilderClient, proposer_address: Address) -> Result<(), Box<dyn std::error::Error>> {
    println!("\nStep 3: Setting up EIP-7702 account code");
    println!("----------------------------------------");
    
    // Check current account code state
    let (has_code, is_correct_proposer) = client.check_eoa_account_code(proposer_address).await?;
    
    if has_code {
        if is_correct_proposer {
            println!("✅ EOA already has the correct Proposer code set");
            println!("   No setup needed - your account is already configured");
        } else {
            println!("⚠️  EOA has different account code set");
            println!("   Updating to the new Proposer version...");
            let setup_tx = client.setup_eip7702_account_code(proposer_address).await?;
            handle_transaction_receipt(setup_tx, "EIP-7702 account code update").await?;
            
            // Verify the setup worked
            client.verify_eip7702_setup(proposer_address).await?;
            println!("✅ EIP-7702 setup verification passed");
        }
    } else {
        println!("📝 Setting up EIP-7702 account code for the first time");
        let setup_tx = client.setup_eip7702_account_code(proposer_address).await?;
        handle_transaction_receipt(setup_tx, "EIP-7702 account code setup").await?;
        println!("   Your EOA now has contract code that delegates to the TrustlessProposer");
        
        // Verify the setup worked
        client.verify_eip7702_setup(proposer_address).await?;
        println!("✅ EIP-7702 setup verification passed");
    }
    
    Ok(())
}

/// Step 4: Check and deposit to Gas Tank if needed
async fn check_and_deposit_to_gas_tank(client: &DABuilderClient) -> Result<(), Box<dyn std::error::Error>> {
    println!("\nStep 4: Checking Gas Tank balance");
    println!("----------------------------------");
    
    let gas_tank_balance = client.gas_tank_balance().await?;
    println!("Current Gas Tank balance: {} wei ({:.6} ETH)", gas_tank_balance, u256_to_eth(gas_tank_balance));
    
    let min_balance = U256::from(100000000000000000u64); // 0.1 ETH
    if gas_tank_balance < min_balance {
        println!("⚠️  Low Gas Tank balance detected, depositing funds...");
        let deposit_amount = U256::from(100000000000000000u64); // 0.1 ETH
        let deposit_tx = client.deposit_to_gas_tank(deposit_amount).await?;
        handle_transaction_receipt(deposit_tx, "Gas Tank deposit").await?;
        
        let new_balance = client.gas_tank_balance().await?;
        println!("✅ New Gas Tank balance: {} wei ({:.6} ETH)", new_balance, u256_to_eth(new_balance));
    } else {
        println!("✅ Sufficient Gas Tank balance, no deposit needed");
    }
    
    Ok(())
}

/// Step 5: Configure DA Builder RPC for cost savings
async fn configure_da_builder_rpc(client: DABuilderClient, da_builder_rpc_url: &str) -> Result<DABuilderClient, Box<dyn std::error::Error>> {
    println!("\nStep 5: Configuring DA Builder RPC");
    println!("-----------------------------------");
    let client = client.with_da_builder_rpc(da_builder_rpc_url)?;
    println!("✅ DA Builder RPC configured");
    println!("   All subsequent transactions will use DA Builder for cost savings");
    
    Ok(client)
}

/// Step 6: Deploy the MockInbox contract
async fn deploy_mock_inbox(client: &DABuilderClient) -> Result<Address, Box<dyn std::error::Error>> {
    println!("\nStep 6: Deploying MockInbox contract");
    println!("------------------------------------");
    
    // Deploy using the simplified CREATE2 method with defaults
    let inbox_address = match client.deploy_create2_if_not_exists_with_defaults(
        MOCKINBOX_BYTECODE,
        &[], // No constructor arguments for MockInbox
    ).await {
        Ok(address) => {
            println!("✅ MockInbox deployed/verified at: {address}");
            address
        }
        Err(e) => {
            eprintln!("❌ Failed to deploy MockInbox: {e}");
            process::exit(1);
        }
    };
    
    Ok(inbox_address)
}

/// Step 7: Submit transactions to DA Builder
async fn submit_da_builder_transactions(client: &DABuilderClient, inbox_address: Address) -> Result<(), Box<dyn std::error::Error>> {
    println!("\nStep 7: Submitting transactions to DA Builder");
    println!("----------------------------------------------");
    
    // Compose the desired transaction to the MockInbox contract
    let target = inbox_address;
    
    // Create function call data for MockInbox.sendMessage(address target, bytes calldata data)
    let target_address = Address::from([0x42; 20]); // Example target address
    let message_data = "Hello from DA Builder!".as_bytes();
    
    // ABI encode: sendMessage(address target, bytes calldata data)
    // Use the function selector from the generated abigen bindings
    let send_message_selector = MockInbox::sendMessageCall::SELECTOR;
    
    let args = vec![
        DynSolValue::Address(target_address),
        DynSolValue::Bytes(message_data.to_vec()),
    ];
    
    let mut data = send_message_selector.to_vec();
    for arg in args {
        data.extend(arg.abi_encode());
    }
    
    let value = U256::ZERO;
    
    // Set deadline (1 hour from now)
    let deadline_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() + 3600;
    
    // Example 1: Regular transaction (no blob data)
    println!("Example 1: Regular transaction without blob data");
    println!("  Calling MockInbox.sendMessage() with regular calldata");
    let regular_tx_request = TransactionRequest {
        to: Some(TxKind::Call(target)),
        input: TransactionInput::new(Bytes::from(data.clone())),
        value: Some(value),
        gas: Some(200_000),
        max_fee_per_gas: Some(20_000_000_000u128), // 20 gwei
        max_priority_fee_per_gas: Some(2_000_000_000u128), // 2 gwei
        ..Default::default()
    };
    let regular_pending_tx = client.send_da_builder_transaction(
        regular_tx_request,
        deadline_secs,
    ).await?;
    println!("✅ Regular transaction submitted to DA Builder");
    println!("   DA Builder internal hash: {}", regular_pending_tx.tx_hash());
    
    // Wait for regular transaction to be processed before submitting blob transaction
    println!("\n⏳ Waiting for regular transaction to be processed...");
    handle_transaction_receipt(regular_pending_tx, "Regular DA Builder transaction").await?;
    
    // Example 2: Blob transaction with blob data
    println!("\nExample 2: Blob transaction with blob data");
    println!("  Calling MockInbox.sendMessage() with blob data for cost savings");
    let blob_data = Bytes::from("This is a large message that will be stored in a blob for cost savings. It could be any large data that doesn't need to be on-chain but needs to be referenced. Blobs are much cheaper than storing data in calldata.");
    
    // Create blob sidecar with the blob data
    let mut builder = alloy::consensus::SidecarBuilder::<alloy::consensus::SimpleCoder>::new();
    builder.ingest(&blob_data);
    let sidecar = builder.build()?;
    
    let blob_tx_request = TransactionRequest {
        to: Some(TxKind::Call(target)),
        input: TransactionInput::new(Bytes::from(data.clone())),
        value: Some(value),
        gas: Some(200_000),
        max_fee_per_gas: Some(20_000_000_000u128), // 20 gwei
        max_priority_fee_per_gas: Some(2_000_000_000u128), // 2 gwei
        max_fee_per_blob_gas: Some(15_000_000_000u128), // 15 gwei
        ..Default::default()
    }.with_blob_sidecar(sidecar);
    let blob_pending_tx = client.send_da_builder_transaction(
        blob_tx_request,
        deadline_secs,
    ).await?;
    println!("✅ Blob transaction submitted to DA Builder");
    println!("   DA Builder internal hash: {}", blob_pending_tx.tx_hash());
    
    // Wait for blob transaction to be processed
    println!("\n⏳ Waiting for blob transaction to be processed...");
    handle_transaction_receipt(blob_pending_tx, "Blob DA Builder transaction").await?;
    
    println!("\n✅ All DA Builder transactions processed and confirmed on-chain");
    
    Ok(())
}

/// Step 8: Monitor on-chain execution
async fn monitor_onchain_execution(client: &DABuilderClient) -> Result<(), Box<dyn std::error::Error>> {
    println!("\nStep 8: Monitoring on-chain execution");
    println!("-------------------------------------");
    println!("✅ All transactions have been submitted and confirmed");
    println!("The DA Builder service has executed the transactions on-chain");
    println!("You can monitor the execution on Etherscan:");
    println!("  Hoodi Etherscan: https://hoodi.etherscan.io/");
    println!("  Search for your address: {}", client.address());
    
    Ok(())
}

/// Step 9: Demonstrate account closing (optional)
/// Print completion summary
fn print_completion_summary(client: &DABuilderClient, chain_id: u64) {
    println!("\n🎉 Integration completed successfully!");
    println!("=====================================");
    println!("All steps have been completed:");
    println!("✅ TrustlessProposer deployed");
    println!("✅ EIP-7702 account code setup");
    println!("✅ Gas Tank balance checked and topped up if needed");
    println!("✅ DA Builder RPC configured for cost savings");
    println!("✅ Mock Inbox deployed for testing");
    println!("✅ Regular transaction submitted to DA Builder");
    println!("✅ Blob transaction submitted to DA Builder");
    println!("✅ All transactions confirmed on-chain");
    println!();
    println!("Library Features Demonstrated:");
    println!("  • send_da_builder_transaction() - DA Builder transactions with automatic EIP-712 signing");
    println!("  • Automatic provider selection based on transaction type");
    println!("  • Configurable deadlines for EIP-712 signatures");
    println!("  • Optional blob data support for EIP-4844 cost savings");
    println!("  • Conditional blob transaction creation (only when blob data provided)");
    println!("  • Simplified API - no need to manually handle EIP-712 encoding");
    println!("  • Gas Tank withdrawal recovery and account management");
    println!("  • CREATE2 deterministic deployment with transaction parameter control");
    println!();
    let explorer = match chain_id {
        1 => "https://etherscan.io",
        17000 => "https://holesky.etherscan.io",
        560048 => "https://hoodi.etherscan.io",
        _ => "https://etherscan.io",
    };
    println!("Check the transactions on the explorer:");
    println!("  {}/address/{}", explorer, client.address());
} 

/// Print help information
fn print_help() {
    println!("🚀 DA Builder Sample Integration - CLI");
    println!("======================================");
    println!();
    println!("Usage: cargo run [COMMAND]");
    println!();
    println!("Commands:");
    println!("  demo              Run the full DA Builder integration demo (default)");
    println!("  account-status    Show current account status and Gas Tank balance");
    println!("  deposit           Deposit funds to Gas Tank");
    println!("  send              Send a custom transaction via DA Builder");
    println!("  help              Show this help message");
    println!();
    println!("Environment Variables:");
    println!("  PRIVATE_KEY       Your wallet private key (required)");
    println!("  TARGET_CHAIN      Target chain: holesky, hoodi (default), mainnet");
    println!("  RPC_URL           RPC endpoint (auto-configured for testnets)");
    println!("  GAS_TANK_ADDRESS  Gas Tank contract address (auto-configured)");
    println!("  PROPOSER_MULTICALL_ADDRESS  ProposerMulticall address (auto-configured)");
    println!();
    println!("Examples:");
    println!("  cargo run                    # Run full demo");
    println!("  cargo run account-status     # Check account status");
    println!("  cargo run deposit            # Deposit to Gas Tank");
    println!("  cargo run send -- --to 0x... --data 0x... --value 0.01eth");
}

/// Show current account status
async fn show_account_status(client: &DABuilderClient) -> Result<(), Box<dyn std::error::Error>> {
    println!("📊 Account Status");
    println!("=================");
    println!("Address: {}", client.address());
    
    // Check wallet balance
    let balance = client.get_balance(client.address()).await?;
    println!("Wallet Balance: {} wei ({:.6} ETH)", balance, u256_to_eth(balance));
    
    // On-chain balance
    let gas_tank_balance = client.gas_tank_balance().await?;
    println!("On-chain Balance: {} wei ({:.6} ETH)", gas_tank_balance, u256_to_eth(gas_tank_balance));

    // Off-chain: fetch account info via DA Builder vendor RPC using the reusable client
    let (_rpc_balance, outstanding) = client.fetch_account_info_via_rpc(client.address()).await?;
    let available = gas_tank_balance.saturating_sub(outstanding);
    println!("Outstanding Charge (off-chain): {} wei ({:.6} ETH)", outstanding, u256_to_eth(outstanding));
    println!("Available Balance: {} wei ({:.6} ETH)", available, u256_to_eth(available));
    
    Ok(())
}

/// Send a user-provided transaction through DA Builder
async fn send_custom_tx(
    client: DABuilderClient,
    args: &[String],
    da_builder_rpc_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Ensure DA Builder RPC is configured
    let client = client.with_da_builder_rpc(da_builder_rpc_url)?;

    // Parse flags after the command name
    let mut to: Option<Address> = None;
    let mut data: Bytes = Bytes::new();
    let mut value: U256 = U256::ZERO;
    let mut gas: Option<u64> = None;
    let mut max_fee_per_gas: Option<u128> = None;
    let mut max_priority_fee_per_gas: Option<u128> = None;
    let mut deadline_secs: Option<u64> = None;

    let mut i = 2; // args[0]=bin, args[1]=send
    while i < args.len() {
        match args[i].as_str() {
            "--to" => {
                i += 1; if i >= args.len() { break; }
                to = Some(args[i].parse::<Address>()?);
            }
            "--data" | "--calldata" => {
                i += 1; if i >= args.len() { break; }
                let s = args[i].trim_start_matches("0x");
                let bytes = hex::decode(s)?;
                data = Bytes::from(bytes);
            }
            "--value" => {
                i += 1; if i >= args.len() { break; }
                value = parse_value_to_wei(&args[i])?;
            }
            "--gas" => {
                i += 1; if i >= args.len() { break; }
                gas = Some(args[i].parse::<u64>()?);
            }
            "--max-fee-per-gas" => {
                i += 1; if i >= args.len() { break; }
                max_fee_per_gas = Some(parse_gwei_to_wei(&args[i])?);
            }
            "--max-priority-fee-per-gas" => {
                i += 1; if i >= args.len() { break; }
                max_priority_fee_per_gas = Some(parse_gwei_to_wei(&args[i])?);
            }
            "--deadline" => {
                i += 1; if i >= args.len() { break; }
                deadline_secs = Some(args[i].parse::<u64>()?);
            }
            _ => {}
        }
        i += 1;
    }

    let to = to.ok_or_else(|| eyre::eyre!("--to <address> is required"))?;
    let deadline = deadline_secs.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + 3600
    });

    let tx = TransactionRequest {
        to: Some(TxKind::Call(to)),
        input: TransactionInput::new(data),
        value: Some(value),
        gas,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        ..Default::default()
    };

    let pending = client.send_da_builder_transaction(tx, deadline).await?;
    println!("✅ Transaction submitted to DA Builder");
    println!("   DA Builder internal hash: {}", pending.tx_hash());
    let receipt = pending.get_receipt().await?;
    println!("✅ Mined: {}", receipt.transaction_hash);
    Ok(())
}

fn parse_value_to_wei(s: &str) -> Result<U256, Box<dyn std::error::Error>> {
    let lower = s.trim().to_lowercase();
    if lower.starts_with("0x") {
        let bytes = hex::decode(lower.trim_start_matches("0x"))?;
        return Ok(U256::from_be_slice(&bytes));
    }
    let (num_str, unit) = if lower.ends_with("ether") {
        (lower.trim_end_matches("ether").trim(), "ether")
    } else if lower.ends_with("eth") {
        (lower.trim_end_matches("eth").trim(), "ether")
    } else if lower.ends_with("gwei") {
        (lower.trim_end_matches("gwei").trim(), "gwei")
    } else if lower.ends_with("wei") {
        (lower.trim_end_matches("wei").trim(), "wei")
    } else {
        // default: treat as wei decimal
        return Ok(U256::from(lower.parse::<u128>()?));
    };
    let v: U256 = parse_units(num_str, unit)?.into();
    Ok(v)
}

fn parse_gwei_to_wei(s: &str) -> Result<u128, Box<dyn std::error::Error>> {
    let lower = s.trim().to_lowercase();
    let (num_str, unit) = if lower.ends_with("gwei") {
        (lower.trim_end_matches("gwei").trim(), "gwei")
    } else if lower.ends_with("wei") {
        (lower.trim_end_matches("wei").trim(), "wei")
    } else {
        // default: assume wei
        (lower.as_str(), "wei")
    };
    let v: U256 = parse_units(num_str, unit)?.into();
    if v > U256::from(u128::MAX) { return Err("value too large for u128".into()); }
    Ok(v.to::<u128>())
}

/// Helper function to handle transaction receipts and check for failures
async fn handle_transaction_receipt(
    pending_tx: alloy_provider::PendingTransactionBuilder<alloy_network::Ethereum>,
    operation_name: &str,
) -> Result<TransactionReceipt, Box<dyn std::error::Error>> {
    let receipt = pending_tx.get_receipt().await?;
    
    // Check if the transaction succeeded
    if !receipt.status() {
        return Err(format!(
            "❌ {} failed - transaction reverted. Transaction hash: {}",
            operation_name, receipt.transaction_hash
        ).into());
    }
    
    println!("✅ {} completed successfully: {}", operation_name, receipt.transaction_hash);
    Ok(receipt)
}

async fn deposit_to_gas_tank(client: &DABuilderClient) -> Result<(), Box<dyn std::error::Error>> {
    println!("💰 Gas Tank Deposit");
    println!("===================");
    let current_balance = client.gas_tank_balance().await?;
    println!("Current Gas Tank balance: {} wei ({:.6} ETH)", current_balance, u256_to_eth(current_balance));
    let wallet_balance = client.get_balance(client.address()).await?;
    println!("Wallet balance: {} wei ({:.6} ETH)", wallet_balance, u256_to_eth(wallet_balance));
    let min_balance = U256::from(10000000000000000u64);
    let suggested_amount = if current_balance < min_balance { min_balance } else { U256::from(5000000000000000u64) };
    println!("Suggested deposit amount: {} wei ({:.6} ETH)", suggested_amount, u256_to_eth(suggested_amount));
    let mut input = String::new();
    print!("Enter deposit amount in ETH (or press Enter for suggested amount): ");
    std::io::Write::flush(&mut std::io::stdout()).expect("Failed to flush stdout");
    std::io::stdin().read_line(&mut input).expect("Failed to read input");
    let deposit_amount = if input.trim().is_empty() { suggested_amount } else {
        match input.trim().parse::<f64>() {
            Ok(eth_amount) => {
                let wei_amount = U256::from((eth_amount * 1e18) as u128);
                if wei_amount > wallet_balance { eprintln!("❌ Insufficient wallet balance for deposit"); return Ok(()); }
                wei_amount
            }
            Err(_) => { eprintln!("❌ Invalid amount. Using suggested amount."); suggested_amount }
        }
    };
    println!("📋 Depositing {} wei ({:.6} ETH) to Gas Tank...", deposit_amount, u256_to_eth(deposit_amount));
    let deposit_tx = client.deposit_to_gas_tank(deposit_amount).await?;
    handle_transaction_receipt(deposit_tx, "Gas Tank deposit").await?;
    let new_balance = client.gas_tank_balance().await?;
    println!("✅ Deposit completed successfully!");
    println!("💰 New Gas Tank balance: {} wei ({:.6} ETH)", new_balance, u256_to_eth(new_balance));
    Ok(())
}
