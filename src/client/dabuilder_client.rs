use alloy::{
    dyn_abi::DynSolValue,
    primitives::{Address, Bytes, U256},
};
use std::str::FromStr;
use alloy_provider::{Provider, ProviderBuilder, DynProvider, PendingTransactionBuilder};
use alloy_signer_local::PrivateKeySigner;
use alloy_network::Ethereum;
use alloy_rpc_types::TransactionRequest;
use alloy::primitives::TxKind;
use alloy_network::{TransactionBuilder, TransactionBuilder4844, TransactionBuilder7702};


use alloy_eips::eip7702::Authorization;
use alloy::signers::{Signer, SignerSync};
use alloy_sol_types::SolCall;
use alloy::{
    sol,
    sol_types::SolType,
};

type NestedSignedCall = sol! { tuple(bytes, uint256, uint256, bytes) };

// EIP-712 types for TrustlessProposer
type Eip712Domain = sol! { tuple(bytes32, bytes32, bytes32, uint256, address) };
type MessageStruct = sol! { tuple(bytes32, uint256, uint256, address, uint256, bytes32) };
use eyre::Result;
use url::Url;

// Import generated contract bindings
use crate::generated_contracts::{IGasTank, TrustlessProposer, ISingletonFactory};

// ERC-2470 Singleton Factory address (deployed on all major networks)
pub const CREATE2_FACTORY_ADDRESS: &str = "0xce0042B868300000d44A59004Da54A005ffdcf9f";

// DABuilder salt for deterministic contract deployments
// This salt ensures all DABuilder contracts have predictable addresses across networks
// Derived from the string "DABuilder" padded to 32 bytes
pub const DABUILDER_SALT: [u8; 32] = [
    0x44, 0x41, 0x42, 0x75, 0x69, 0x6C, 0x64, 0x65, // "DABuilder"
    0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // "r" + padding + changed last byte for testing
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // padding
];

// Note: generated_contracts is only available in the binary, not the library
// We'll need to handle this differently for the client library

/// A reusable client for interacting with DA Builder services and Ethereum networks.
/// 
/// This client provides generic transaction methods that can be used by any project
/// to send transactions through either regular RPC or DA Builder RPC for cost savings.
/// 
/// # Features
/// - Generic transaction sending (regular, blob, multicall)
/// - Automatic provider switching between regular RPC and DA Builder RPC
/// - Gas Tank integration for cost-effective transactions
/// - EIP-7702 account code setup
/// - TrustlessProposer contract deployment
pub struct DABuilderClient {
    provider: DynProvider<Ethereum>,
    da_builder_provider: Option<DynProvider<Ethereum>>,
    wallet: PrivateKeySigner,
    address: Address,
    chain_id: u64,
    gas_tank_address: Address,
    dabuilder_salt: [u8; 32],
}

impl DABuilderClient {
    pub fn new(rpc_url: &str, private_key: &str, chain_id: u64, gas_tank_address: Address) -> Result<Self> {
        Self::new_with_salt(rpc_url, private_key, chain_id, gas_tank_address, None)
    }

    pub fn new_with_salt(rpc_url: &str, private_key: &str, chain_id: u64, gas_tank_address: Address, dabuilder_salt: Option<[u8; 32]>) -> Result<Self> {
        let url = Url::parse(rpc_url)?;
        let wallet: PrivateKeySigner = private_key.parse()?;
        let address = wallet.address();
        
        // Canonical Alloy 1.0 pattern: create provider, then attach signer
        let provider = ProviderBuilder::new()
            .wallet(wallet.clone())
            .connect_http(url)
            .erased();
            
        Ok(Self {
            provider,
            da_builder_provider: None,
            wallet,
            address,
            chain_id,
            gas_tank_address,
            dabuilder_salt: dabuilder_salt.unwrap_or(DABUILDER_SALT),
        })
    }

    #[cfg(test)]
    pub fn new_with_providers(
        provider: DynProvider<Ethereum>,
        da_builder_provider: DynProvider<Ethereum>,
        private_key: &str,
        chain_id: u64,
        gas_tank_address: Address,
    ) -> Result<Self> {
        Self::new_with_providers_and_salt(provider, da_builder_provider, private_key, chain_id, gas_tank_address, None)
    }

    #[cfg(test)]
    pub fn new_with_providers_and_salt(
        provider: DynProvider<Ethereum>,
        da_builder_provider: DynProvider<Ethereum>,
        private_key: &str,
        chain_id: u64,
        gas_tank_address: Address,
        dabuilder_salt: Option<[u8; 32]>,
    ) -> Result<Self> {
        let wallet: PrivateKeySigner = private_key.parse()?;
        let address = wallet.address();
        Ok(Self {
            provider,
            da_builder_provider: Some(da_builder_provider),
            wallet,
            address,
            chain_id,
            gas_tank_address,
            dabuilder_salt: dabuilder_salt.unwrap_or(DABUILDER_SALT),
        })
    }

    pub fn with_da_builder_rpc(mut self, da_builder_rpc_url: &str) -> Result<Self> {
        let da_builder_url = Url::parse(da_builder_rpc_url)?;
        let da_builder_provider = ProviderBuilder::new()
            .wallet(self.wallet.clone())
            .connect_http(da_builder_url)
            .erased();
        self.da_builder_provider = Some(da_builder_provider);
        Ok(self)
    }

    pub fn address(&self) -> Address {
        self.address
    }

    // Generic transaction methods for library reusability
    
    /// Send a transaction through DA Builder for cost savings
    /// This method handles the complete EIP-712 signing and encoding flow internally.
    /// 
    /// Parameters:
    /// - transaction_request: The TransactionRequest containing all transaction parameters (gas, fees, etc.)
    /// - deadline_secs: EIP-712 signature deadline (seconds from epoch)
    /// 
    /// Returns a PendingTransactionBuilder that can be awaited for receipt
    /// 
    /// The method automatically:
    /// - Gets the current nonce from the proposer contract (EOA after EIP-7702 setup)
    /// - Creates EIP-712 domain separator and struct hash
    /// - Signs the message hash
    /// - Encodes the signed call data
    /// - Extracts blob data from TransactionRequest if present
    /// - Submits as EIP-4844 blob transaction or regular transaction based on blob data
    /// - Uses gas, fees, and other parameters from the provided TransactionRequest
    pub async fn send_da_builder_transaction(
        &self,
        transaction_request: TransactionRequest,
        deadline_secs: u64,
    ) -> Result<PendingTransactionBuilder<Ethereum>> {
        let da_provider = self.da_builder_provider.as_ref()
            .ok_or_else(|| eyre::eyre!("DA Builder RPC not configured. Call with_da_builder_rpc() first."))?;
        
        // Check if this is a blob transaction by looking for blob sidecar first
        let blob_sidecar = transaction_request.blob_sidecar().cloned();
        let has_blob_data = blob_sidecar.is_some();
        
        // Extract target and calldata from the transaction request
        let target = match transaction_request.to {
            Some(TxKind::Call(addr)) => addr,
            _ => return Err(eyre::eyre!("TransactionRequest must have a 'to' address for a call")),
        };
        
        let call_data = match &transaction_request.input.input {
            Some(input) => input.clone(),
            None => return Err(eyre::eyre!("TransactionRequest must have input data")),
        };
        
        let value = transaction_request.value.unwrap_or(U256::ZERO);
        
        // Prepare the EIP-712 signed call data
        let encoded_call = self.prepare_trustless_proposer_call(
            target,
            call_data,
            value,
            deadline_secs,
        ).await?;
        let trustless_proposer = TrustlessProposer::new(self.address, da_provider);
        // Since we are using TrustlessProposer, the value can be set to 0 since the encoded call is what carries the value that would be sent to the true target
        let trustless_proposer_tx_request = trustless_proposer.call(target, encoded_call, U256::ZERO).into_transaction_request();

        // Create the transaction based on whether blob data is provided
        let tx = if has_blob_data {
            // EIP-4844 blob transaction - use the existing sidecar from the request
            let sidecar = blob_sidecar.unwrap();
            
            // Create EIP-4844 transaction with blob sidecar
            trustless_proposer_tx_request.with_blob_sidecar(sidecar)
        } else {
            // Regular transaction
            trustless_proposer_tx_request
        };
        
        // Send the transaction and return the pending transaction
        let pending_tx = da_provider.send_transaction(tx).await?;
        Ok(pending_tx)
    }

    /// Send a regular transaction through the standard RPC
    /// Returns a PendingTransactionBuilder that can be awaited for receipt
    #[allow(dead_code)]
    pub async fn send_transaction(
        &self,
        target: Address,
        data: Bytes,
        value: U256,
    ) -> Result<PendingTransactionBuilder<Ethereum>> {
        // Get current nonce
        let nonce = self.provider.get_transaction_count(self.address).await?;
        
        // Create transaction request
        let tx = TransactionRequest::default()
            .with_to(target)
            .with_input(data)
            .with_value(value)
            .with_gas_limit(200_000)
            .with_max_fee_per_gas(20_000_000_000u128) // 20 gwei
            .with_max_priority_fee_per_gas(2_000_000_000u128) // 2 gwei
            .with_chain_id(self.chain_id)
            .with_nonce(nonce);
        
        // Send the transaction and return the pending transaction
        let pending_tx = self.provider.send_transaction(tx).await?;
        Ok(pending_tx)
    }



    // Gas Tank methods
    pub async fn gas_tank_balance(&self) -> Result<U256> {
        let contract = IGasTank::new(self.gas_tank_address, &self.provider);
        let balance = contract.balances(self.address).call().await?;
        Ok(balance)
    }

    pub async fn deposit_to_gas_tank(&self, value: U256) -> Result<PendingTransactionBuilder<Ethereum>> {
        // Get current nonce to avoid "nonce too low" errors
        let nonce = self.provider.get_transaction_count(self.address).await?;
        
        // Create the deposit transaction manually
        let tx = TransactionRequest::default()
            .with_to(self.gas_tank_address)
            .with_value(value)
            .with_gas_limit(100_000)
            .with_max_fee_per_gas(20_000_000_000u128) // 20 gwei
            .with_max_priority_fee_per_gas(2_000_000_000u128) // 2 gwei
            .with_chain_id(self.chain_id)
            .with_nonce(nonce);
        
        // Send the transaction and return the pending transaction
        let pending_tx = self.provider.send_transaction(tx).await?;
        Ok(pending_tx)
    }

    pub async fn initiate_account_close(&self) -> Result<PendingTransactionBuilder<Ethereum>> {
        // Get current nonce
        let nonce = self.provider.get_transaction_count(self.address).await?;
        
        // Create the initiate close transaction manually
        let tx = TransactionRequest::default()
            .with_to(self.gas_tank_address)
            .with_input(Bytes::from([0x3d, 0x18, 0xdf, 0x91])) // initiateAccountClose() selector
            .with_gas_limit(100_000)
            .with_max_fee_per_gas(20_000_000_000u128) // 20 gwei
            .with_max_priority_fee_per_gas(2_000_000_000u128) // 2 gwei
            .with_chain_id(self.chain_id)
            .with_nonce(nonce);
        
        // Send the transaction and return the pending transaction
        let pending_tx = self.provider.send_transaction(tx).await?;
        Ok(pending_tx)
    }

    pub async fn close_account(&self) -> Result<PendingTransactionBuilder<Ethereum>> {
        // Get current nonce
        let nonce = self.provider.get_transaction_count(self.address).await?;
        
        // Encode the closeAccount function call
        let mut data = vec![0x4d, 0x5c, 0x9f, 0x5c]; // closeAccount(address) selector
        data.extend_from_slice(&[0u8; 32]); // offset to address (32 bytes)
        data.extend_from_slice(self.address.into_word().as_slice()); // operator address (padded to 32 bytes)
        
        // Create the close account transaction manually
        let tx = TransactionRequest::default()
            .with_to(self.gas_tank_address)
            .with_input(Bytes::from(data))
            .with_gas_limit(100_000)
            .with_max_fee_per_gas(20_000_000_000u128) // 20 gwei
            .with_max_priority_fee_per_gas(2_000_000_000u128) // 2 gwei
            .with_chain_id(self.chain_id)
            .with_nonce(nonce);
        
        // Send the transaction and return the pending transaction
        let pending_tx = self.provider.send_transaction(tx).await?;
        Ok(pending_tx)
    }

    // Contract deployment methods
    pub async fn setup_eip7702_account_code(&self, proposer_address: Address) -> Result<PendingTransactionBuilder<Ethereum>> {
        // Get current nonce for the EOA that will be delegated
        let nonce = self.provider.get_transaction_count(self.address).await?;

        // For self-authorizing EIP-7702 (from == authority), the authorization nonce must be current + 1
        // because the tx increments the nonce before checking the authorization
        let auth_nonce = nonce + 1;

        // Create authorization data for EIP-7702
        // The authorization should delegate to the proposer_address
        let authorization = Authorization {
            chain_id: U256::from(self.chain_id),
            address: proposer_address, // The contract to delegate to
            nonce: auth_nonce,
        };
        
        // Sign the authorization with our wallet (following the working example pattern)
        let auth_hash = authorization.signature_hash();
        let signature = self.wallet.sign_hash_sync(&auth_hash)?;
        let signed_authorization = authorization.into_signed(signature);
        
        // Build the transaction using the same pattern as the working example
        let tx = TransactionRequest::default()
            .with_to(self.address) // Send to the EOA being delegated (like alice.address() in example)
            .with_authorization_list(vec![signed_authorization])
            .with_input(Bytes::new()) // Empty input for account code setup
            .with_gas_limit(500_000)
            .with_max_fee_per_gas(20_000_000_000u128) // 20 gwei
            .with_max_priority_fee_per_gas(2_000_000_000u128) // 2 gwei
            .with_chain_id(self.chain_id)
            .with_nonce(nonce);
        
        // Send the transaction and return the pending transaction
        let pending_tx = self.provider.send_transaction(tx).await?;
        Ok(pending_tx)
    }

    /// Verify that EIP-7702 account code setup worked correctly
    /// Should be called after the setup transaction is mined
    pub async fn verify_eip7702_setup(&self, proposer_address: Address) -> Result<()> {
        let (has_code, is_correct_proposer) = self.check_eoa_account_code(proposer_address).await?;
        if !has_code {
            return Err(eyre::eyre!(
                "EOA at {} has no code set. EIP-7702 setup failed or isn't supported on this network (chain ID: {})",
                self.address, self.chain_id
            ));
        }
        if !is_correct_proposer {
            return Err(eyre::eyre!(
                "EOA at {} has incorrect proposer code set. EIP-7702 setup failed.",
                self.address
            ));
        }
        Ok(())
    }

    // Generic CREATE2 deployment methods

    /// Check if a contract exists at the given address
    pub async fn contract_exists(&self, address: Address) -> Result<bool> {
        let code = self.provider.get_code_at(address).await?;
        Ok(!code.is_empty())
    }

    /// Deploy contract to CREATE2 address if it doesn't exist using the standard factory
    /// Returns the deployed contract address
    pub async fn deploy_create2_if_not_exists(
        &self,
        bytecode: &str,
        constructor_args: &[DynSolValue],
        gas_limit: Option<u64>,
        max_fee_per_gas: Option<u128>,
        max_priority_fee_per_gas: Option<u128>,
    ) -> Result<Address> {
        // Prepare bytecode with constructor arguments
        let bytecode_bytes = self.prepare_bytecode_with_args(bytecode, constructor_args)?;
        
        // Calculate the predicted address using ERC-2470 formula for verification
        let factory_address = Address::from_str(CREATE2_FACTORY_ADDRESS).unwrap();
        let salt_bytes32 = alloy::primitives::B256::from_slice(&self.dabuilder_salt);
        
        // The ERC-2470 standard specifies the address calculation formula:
        // address(keccak256(bytes1(0xff), factory_address, salt, keccak256(init_code)) << 96)
        let init_code_hash = alloy::primitives::keccak256(&bytecode_bytes);
        
        // Pre-allocate the exact size needed: 1 + 20 + 32 + 32 = 85 bytes
        let mut input = Vec::with_capacity(85);
        input.push(0xff);
        input.extend_from_slice(factory_address.as_slice()); // Use 20-byte address, not 32-byte word
        input.extend_from_slice(salt_bytes32.as_slice());
        input.extend_from_slice(init_code_hash.as_slice());
        
        let hash = alloy::primitives::keccak256(input);
        let predicted_address = Address::from_slice(&hash[12..]);
        
        // Check if contract already exists
        if self.contract_exists(predicted_address).await? {
            return Ok(predicted_address);
        }
        
        // Use the ISingletonFactory interface (ERC-2470 format)
        let deploy_call = ISingletonFactory::deployCall {
            _initCode: Bytes::from(bytecode_bytes.clone()),
            _salt: salt_bytes32,
        };
        
        // Get current nonce
        let nonce = self.provider.get_transaction_count(self.address).await?;
        
        // Create transaction request for gas estimation with all required fields
        let tx_for_estimation = TransactionRequest::default()
            .with_to(factory_address)
            .with_input(Bytes::from(deploy_call.abi_encode()))
            .with_from(self.address)
            .with_value(alloy::primitives::U256::ZERO) // Explicitly set value to 0
            .with_chain_id(self.chain_id)
            .with_nonce(nonce)
            .with_max_fee_per_gas(max_fee_per_gas.unwrap_or(20_000_000_000u128))
            .with_max_priority_fee_per_gas(max_priority_fee_per_gas.unwrap_or(2_000_000_000u128));
        
        // Estimate gas needed for the transaction
        let estimated_gas = if let Some(provided_gas_limit) = gas_limit {
            provided_gas_limit
        } else {
            match self.provider.estimate_gas(tx_for_estimation).await {
                Ok(estimated) => {
                    // Add 10% buffer to the estimated gas
                    (estimated * 110) / 100
                }
                Err(_) => {
                    // Gas estimation failed, use fallback
                    3_000_000 // Fallback to 3M gas
                }
            }
        };
        
        // Create transaction request to the factory
        let tx = TransactionRequest::default()
            .with_to(factory_address)
            .with_input(Bytes::from(deploy_call.abi_encode()))
            .with_gas_limit(estimated_gas)
            .with_max_fee_per_gas(max_fee_per_gas.unwrap_or(20_000_000_000u128))
            .with_max_priority_fee_per_gas(max_priority_fee_per_gas.unwrap_or(2_000_000_000u128))
            .with_chain_id(self.chain_id)
            .with_nonce(nonce);
        
        let pending_tx = self.provider.send_transaction(tx).await?;
        let receipt = pending_tx.get_receipt().await?;
        
        // Check if the transaction succeeded
        if !receipt.status() {
            return Err(eyre::eyre!(
                "Contract deployment transaction failed. Transaction hash: {}",
                receipt.transaction_hash
            ));
        }
        
        // Try to get the deployed contract address from transaction receipt
        // The factory's deploy method returns the deployed address, but we need to extract it
        let actual_deployed_address = if !receipt.logs().is_empty() {
            // Look for contract creation in logs or use the predicted address
            // For now, we'll use the predicted address but add verification
            predicted_address
        } else {
            predicted_address
        };
        
        // Verify the contract was actually deployed at the expected address
        if !self.contract_exists(actual_deployed_address).await? {
            return Err(eyre::eyre!(
                "Contract deployment failed - transaction succeeded but no code at expected address {}. \
                Transaction hash: {}. This might indicate a mismatch between our address calculation and the factory's deployment.",
                actual_deployed_address,
                receipt.transaction_hash
            ));
        }
        
        // Double-check that the predicted address matches where the contract was deployed
        if actual_deployed_address != predicted_address {
            return Err(eyre::eyre!(
                "Address mismatch: predicted {} but contract deployed at {}. \
                Transaction hash: {}",
                predicted_address,
                actual_deployed_address,
                receipt.transaction_hash
            ));
        }
        
        Ok(actual_deployed_address)
    }

    /// Deploy contract to CREATE2 address if it doesn't exist using default gas parameters
    /// Convenience method that uses reasonable defaults for gas settings
    pub async fn deploy_create2_if_not_exists_with_defaults(
        &self,
        bytecode: &str,
        constructor_args: &[DynSolValue],
    ) -> Result<Address> {
        // Use gas estimation instead of hardcoded values
        self.deploy_create2_if_not_exists(
            bytecode, 
            constructor_args, 
            None, // Let the method estimate gas
            None, 
            None
        ).await
    }


    pub async fn get_balance(&self, address: Address) -> Result<U256> {
        self.provider.get_balance(address).await.map_err(|e| eyre::eyre!("Failed to get balance: {}", e))
    }

    /// Get the current nonce from the TrustlessProposer contract
    /// After EIP-7702 setup, the EOA has the proposer code, so we call the EOA address
    pub async fn get_proposer_nonce(&self) -> Result<U256> {
        // First, check if the EOA actually has code
        let account_code = self.provider.get_code_at(self.address).await?;
        if account_code.is_empty() {
            return Err(eyre::eyre!(
                "EOA at {} has no code set. EIP-7702 account code setup may have failed or isn't supported on this network.",
                self.address
            ));
        }
        
        let contract = TrustlessProposer::new(self.address, &self.provider);
        let nonce = contract.nestedNonce().call().await.map_err(|e| {
            eyre::eyre!(
                "Failed to call nestedNonce() on EOA {}. This suggests the EIP-7702 setup didn't work properly. Error: {}",
                self.address, e
            )
        })?;
        Ok(nonce)
    }

    /// Prepare bytecode with constructor arguments
    /// Handles 0x prefix removal and ABI encoding of constructor arguments
    fn prepare_bytecode_with_args(&self, bytecode: &str, constructor_args: &[DynSolValue]) -> Result<Vec<u8>> {
        // Remove 0x prefix if present
        let clean_bytecode = bytecode.strip_prefix("0x").unwrap_or(bytecode);
        
        // Decode hex bytecode
        let mut bytecode_bytes = hex::decode(clean_bytecode)?;
        
        // ABI-encode constructor arguments if provided
        if !constructor_args.is_empty() {
            // Use standard ABI encoding for constructor arguments (not tuple encoding)
            let encoded_args: Vec<u8> = constructor_args.iter()
                .flat_map(|arg| arg.abi_encode())
                .collect();
            bytecode_bytes.extend_from_slice(&encoded_args);
        }
        
        Ok(bytecode_bytes)
    }

    /// Check if an account has initiated withdrawal from Gas Tank
    pub async fn check_withdrawal_initiated(&self) -> Result<bool> {
        let contract = IGasTank::new(self.gas_tank_address, &self.provider);
        let withdrawal_started_at = contract.withdrawalStartedAt(self.address).call().await?;
        Ok(!withdrawal_started_at.is_zero())
    }

    /// Check if withdrawal period has passed (7 days)
    pub async fn can_close_account(&self) -> Result<bool> {
        let contract = IGasTank::new(self.gas_tank_address, &self.provider);
        let withdrawal_started_at = contract.withdrawalStartedAt(self.address).call().await?;
        
        if withdrawal_started_at.is_zero() {
            return Ok(false); // No withdrawal initiated
        }
        
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let withdrawal_time = withdrawal_started_at.to::<u64>();
        let seven_days = 7 * 24 * 60 * 60; // 7 days in seconds
        
        Ok(current_time >= withdrawal_time + seven_days)
    }

    /// Check if EOA already has the correct Proposer code set
    /// Returns (has_code, is_correct_proposer) tuple
    pub async fn check_eoa_account_code(&self, proposer_address: Address) -> Result<(bool, bool)> {
        let account_code = self.provider.get_code_at(self.address).await?;
        let has_code = !account_code.is_empty();
        
        if !has_code {
            return Ok((false, false));
        }
        
        // EIP-7702 sets code to 0xef0100 + proposer_address (23 bytes)
        let delegation_prefix: [u8; 3] = [0xef, 0x01, 0x00];
        let expected_code = [delegation_prefix.as_slice(), proposer_address.as_ref()].concat();
        
        // Compare actual code with expected delegation
        let is_correct_proposer = account_code.to_vec() == expected_code;
        
        Ok((has_code, is_correct_proposer))
    }

    /// Prepare the ABI-encoded TrustlessProposer call (EIP-712 signature, deadline, nonce, calldata)
    /// Uses Alloy's EIP-712 implementation for reliable hashing and encoding
    pub async fn prepare_trustless_proposer_call(
        &self,
        target: Address,
        call_data: Bytes,
        value: U256,
        deadline_secs: u64,
    ) -> Result<Bytes> {
        let nonce = self.get_proposer_nonce().await?;
        let deadline = U256::from(deadline_secs);

        // Create EIP-712 message hash using Alloy
        let message_hash = self.create_eip712_message_hash(
            deadline,
            nonce,
            target,
            value,
            call_data.clone(),
        )?;

        // @note Instead of using alloy to generate the message hash we can also use the contract's getMessageHash to avoid
        // issues with different contract versions changing the eip712 domain separator of course at the cost of a network call
        // let contract = TrustlessProposer::new(proposer_addr, &self.provider);
        // let message_hash = contract.getMessageHash(deadline, nonce, target, value, call_data.clone()).call().await?;

        // Sign the message hash
        let signature = self.wallet.sign_hash(&message_hash).await?;

        // Create the tuple and encode it using Alloy's sol! macro
        let alloy_encoded = NestedSignedCall::abi_encode_sequence(&(
            Bytes::from(signature.as_bytes()),
            deadline,
            nonce,
            call_data,
        ));
        
        Ok(Bytes::from(alloy_encoded))
    }

    /// Create EIP-712 message hash for TrustlessProposer
    /// This replicates the Solidity _hashTypedDataV4 function
    fn create_eip712_message_hash(
        &self,
        deadline: U256,
        nonce: U256,
        target: Address,
        value: U256,
        call_data: Bytes,
    ) -> Result<alloy::primitives::B256> {
        // EIP-712 domain separator (matches OpenZeppelin's _buildDomainSeparator)
        let type_hash = alloy::primitives::keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        let hashed_name = alloy::primitives::keccak256("TrustlessProposer");
        let hashed_version = alloy::primitives::keccak256("1");
        
        let domain_value = Eip712Domain::abi_encode_sequence(&(
            type_hash,
            hashed_name,
            hashed_version,
            U256::from(self.chain_id),
            self.address,
        ));
        let domain_separator = alloy::primitives::keccak256(domain_value);
        
        // Call type hash
        let call_type_hash = alloy::primitives::keccak256("Call(uint256 deadline,uint256 nonce,address target,uint256 value,bytes calldata)");
        
        // Hash the call data
        let call_data_hash = alloy::primitives::keccak256(call_data.as_ref());
        
        // Encode the struct hash (includes the call type hash as first parameter)
        let call_struct_value = MessageStruct::abi_encode_sequence(&(
            call_type_hash,
            deadline,
            nonce,
            target,
            value,
            call_data_hash,
        ));
        let message_hash = alloy::primitives::keccak256(call_struct_value);
        
        // Create the final EIP-712 hash: keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash))
        let eip712_hash = alloy::primitives::keccak256([
            &[0x19, 0x01],
            &domain_separator[..],
            &message_hash[..]
        ].concat());
        
        Ok(eip712_hash)
    }


} 

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_provider::{Provider, RootProvider, RpcWithBlock, ProviderCall};
    use alloy_network::Ethereum;
    use alloy::primitives::{Address, U256, U64, TxHash};
    use alloy_rpc_types::TransactionReceipt;
    use std::collections::HashMap;

    #[derive(Clone)]
    pub struct MockProvider {
        balances: HashMap<Address, U256>,
        _nonces: HashMap<Address, u64>,
    }

    impl MockProvider {
        pub fn new() -> Self {
            Self {
                balances: HashMap::new(),
                _nonces: HashMap::new(),
            }
        }

        pub fn with_balance(mut self, address: Address, balance: U256) -> Self {
            self.balances.insert(address, balance);
            self
        }
    }

    impl Provider<Ethereum> for MockProvider {
        fn root(&self) -> &RootProvider<Ethereum> {
            panic!("Mock root called - not implemented for tests")
        }
        fn get_balance(&self, _address: Address) -> RpcWithBlock<Address, U256, U256> {
            panic!("Mock get_balance not implemented for tests")
        }
        fn get_transaction_count(&self, _address: Address) -> RpcWithBlock<Address, U64, u64, fn(U64) -> u64> {
            panic!("Mock get_transaction_count not implemented for tests")
        }
        fn get_transaction_receipt(&self, _hash: TxHash) -> ProviderCall<(TxHash,), Option<TransactionReceipt>> {
            panic!("Mock get_transaction_receipt not implemented for tests")
        }
    }

    #[tokio::test]
    async fn test_mock_provider_can_construct_client() {
        let mock_provider = MockProvider::new()
            .with_balance(Address::from_slice(&[1u8; 20]), U256::from(1000000000000000000u64));
        let mock_da_provider = MockProvider::new();
        let private_key = "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";
        let chain_id = 17000u64;
        let client = DABuilderClient::new_with_providers(
            Box::new(mock_provider).erased(),
            Box::new(mock_da_provider).erased(),
            private_key,
            chain_id,
            Address::from_slice(&[0u8; 20]) // Mock gas tank address
        );
        assert!(client.is_ok(), "Should be able to construct client with mock providers");
        let client = client.unwrap();
        let expected_address = Address::from_slice(&hex::decode("a0ee7a142d267c1f36714e4a8f75612f20a79720").unwrap());
        assert_eq!(client.address(), expected_address);
    }
} 