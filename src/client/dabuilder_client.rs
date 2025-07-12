use alloy::primitives::{Address, U256, Bytes};
use std::str::FromStr;
use alloy_provider::{Provider, ProviderBuilder, DynProvider, PendingTransactionBuilder};
use alloy_signer_local::PrivateKeySigner;
use alloy_network::Ethereum;
use alloy_rpc_types::TransactionRequest;
use alloy::primitives::TxKind;
use alloy_network::{TransactionBuilder, TransactionBuilder4844};
use alloy_dyn_abi::DynSolValue;
use alloy::consensus::{SidecarBuilder, SimpleCoder};
use alloy_eips::eip7702::Authorization;
use alloy::signers::Signer;
use alloy_sol_types::SolCall;
use eyre::Result;
use url::Url;

// Import generated contract bindings
use crate::generated_contracts::{IGasTank, TrustlessProposer, ICreate2Factory};

// Standard Foundry CREATE2 factory address
pub const CREATE2_FACTORY_ADDRESS: &str = "0x4e59b44847b379578588920cA78FbF26c0B4956C";

// DABuilder salt for deterministic contract deployments
// This salt ensures all DABuilder contracts have predictable addresses across networks
// Derived from the string "DABuilder" padded to 32 bytes
pub const DABUILDER_SALT: [u8; 32] = [
    0x44, 0x41, 0x42, 0x75, 0x69, 0x6C, 0x64, 0x65, // "DABuilder"
    0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // "r" + padding
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
}

impl DABuilderClient {
    pub fn new(rpc_url: &str, private_key: &str, chain_id: u64) -> Result<Self> {
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
        })
    }

    #[cfg(test)]
    pub fn new_with_providers(
        provider: DynProvider<Ethereum>,
        da_builder_provider: DynProvider<Ethereum>,
        private_key: &str,
        chain_id: u64,
    ) -> Result<Self> {
        let wallet: PrivateKeySigner = private_key.parse()?;
        let address = wallet.address();
        Ok(Self {
            provider,
            da_builder_provider: Some(da_builder_provider),
            wallet,
            address,
            chain_id,
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

    /// Get the DABuilder salt for deterministic contract deployments
    pub fn dabuilder_salt() -> &'static [u8; 32] {
        &DABUILDER_SALT
    }

    // Generic transaction methods for library reusability
    
    /// Send a transaction through DA Builder for cost savings
    /// This method handles the complete EIP-712 signing and encoding flow internally.
    /// 
    /// Parameters:
    /// - proposer_address: The TrustlessProposer contract address
    /// - transaction_request: The TransactionRequest containing all transaction parameters (gas, fees, etc.)
    /// - deadline_secs: EIP-712 signature deadline (seconds from epoch)
    /// - blob_data: Optional data to store in blob for cost savings (if provided, uses EIP-4844)
    /// 
    /// Returns a PendingTransactionBuilder that can be awaited for receipt
    /// 
    /// The method automatically:
    /// - Gets the current nonce from the proposer contract
    /// - Creates EIP-712 domain separator and struct hash
    /// - Signs the message hash
    /// - Encodes the signed call data
    /// - Creates blob sidecar if blob_data is provided
    /// - Submits as EIP-4844 blob transaction or regular transaction based on blob_data
    /// - Uses gas, fees, and other parameters from the provided TransactionRequest
    pub async fn send_da_builder_transaction(
        &self,
        proposer_address: Address,
        transaction_request: TransactionRequest,
        deadline_secs: u64,
        blob_data: Option<Bytes>,
    ) -> Result<PendingTransactionBuilder<Ethereum>> {
        let da_provider = self.da_builder_provider.as_ref()
            .ok_or_else(|| eyre::eyre!("DA Builder RPC not configured. Call with_da_builder_rpc() first."))?;
        
        // Extract target and calldata from the transaction request
        let target = match transaction_request.to {
            Some(TxKind::Call(addr)) => addr,
            _ => return Err(eyre::eyre!("TransactionRequest must have a 'to' address for a call")),
        };
        
        let call_data = match transaction_request.input.input {
            Some(input) => input,
            None => return Err(eyre::eyre!("TransactionRequest must have input data")),
        };
        
        let value = transaction_request.value.unwrap_or(U256::ZERO);
        
        // Prepare the EIP-712 signed call data
        let encoded_call = self.prepare_trustless_proposer_call(
            proposer_address,
            target,
            call_data,
            value,
            deadline_secs,
        ).await?;
        
        // Get current nonce for the transaction
        let nonce = self.provider.get_transaction_count(self.address).await?;
        
        // Create the transaction based on whether blob data is provided
        let tx = if let Some(blob_data) = blob_data {
            // EIP-4844 blob transaction
            
            // Create blob sidecar with the blob data
            let mut builder = SidecarBuilder::<SimpleCoder>::new();
            builder.ingest(&blob_data);
            let sidecar = builder.build()?;
            
            // Create EIP-4844 transaction with blob sidecar
            TransactionRequest::default()
                .with_blob_sidecar(sidecar)
                .with_to(proposer_address)
                .with_input(encoded_call)
                .with_value(value)
                .with_gas_limit(transaction_request.gas.unwrap_or(200_000))
                .with_max_fee_per_gas(transaction_request.max_fee_per_gas.unwrap_or(20_000_000_000u128))
                .with_max_priority_fee_per_gas(transaction_request.max_priority_fee_per_gas.unwrap_or(2_000_000_000u128))
                .with_max_fee_per_blob_gas(transaction_request.max_fee_per_blob_gas.unwrap_or(15_000_000_000u128))
                .with_chain_id(self.chain_id)
                .with_nonce(nonce)
        } else {
            // Regular transaction
            TransactionRequest::default()
                .with_to(proposer_address)
                .with_input(encoded_call)
                .with_value(value)
                .with_gas_limit(transaction_request.gas.unwrap_or(200_000))
                .with_max_fee_per_gas(transaction_request.max_fee_per_gas.unwrap_or(20_000_000_000u128))
                .with_max_priority_fee_per_gas(transaction_request.max_priority_fee_per_gas.unwrap_or(2_000_000_000u128))
                .with_chain_id(self.chain_id)
                .with_nonce(nonce)
        };
        
        // Send the transaction and return the pending transaction
        let pending_tx = da_provider.send_transaction(tx).await?;
        Ok(pending_tx)
    }

    /// Send a regular transaction through the standard RPC
    /// Returns a PendingTransactionBuilder that can be awaited for receipt
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
    pub async fn gas_tank_balance(&self, gas_tank: Address, account: Address) -> Result<U256> {
        let contract = IGasTank::new(gas_tank, &self.provider);
        let balance = contract.balances(account).call().await?;
        Ok(balance)
    }

    pub async fn deposit_to_gas_tank(&self, gas_tank: Address, value: U256) -> Result<PendingTransactionBuilder<Ethereum>> {
        // Get current nonce to avoid "nonce too low" errors
        let nonce = self.provider.get_transaction_count(self.address).await?;
        
        // Create the deposit transaction manually
        let tx = TransactionRequest::default()
            .with_to(gas_tank)
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

    pub async fn initiate_account_close(&self, gas_tank: Address) -> Result<PendingTransactionBuilder<Ethereum>> {
        // Get current nonce
        let nonce = self.provider.get_transaction_count(self.address).await?;
        
        // Create the initiate close transaction manually
        let tx = TransactionRequest::default()
            .with_to(gas_tank)
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

    pub async fn close_account(&self, gas_tank: Address, operator: Address) -> Result<PendingTransactionBuilder<Ethereum>> {
        // Get current nonce
        let nonce = self.provider.get_transaction_count(self.address).await?;
        
        // Encode the closeAccount function call
        let mut data = vec![0x4d, 0x5c, 0x9f, 0x5c]; // closeAccount(address) selector
        data.extend_from_slice(&[0u8; 32]); // offset to address (32 bytes)
        data.extend_from_slice(&operator.into_word().as_slice()); // operator address (padded to 32 bytes)
        
        // Create the close account transaction manually
        let tx = TransactionRequest::default()
            .with_to(gas_tank)
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
    pub async fn setup_eip7702_account_code(&self, _proposer_address: Address) -> Result<PendingTransactionBuilder<Ethereum>> {
        // Get current nonce
        let nonce = self.provider.get_transaction_count(self.address).await?;
        
        // Create authorization data for EIP-7702
        let authorization = Authorization {
            chain_id: U256::from(self.chain_id),
            address: self.address,
            nonce: nonce,
        };
        
        // Sign the authorization with our wallet
        let signature = self.wallet.sign_message(authorization.signature_hash().as_slice()).await?;
        let signed_authorization = authorization.into_signed(signature);
        
        // Create EIP-7702 transaction
        let tx = TransactionRequest {
            nonce: Some(nonce),
            value: Some(U256::ZERO),
            to: Some(TxKind::Call(self.address)), // Send to self for account code setup
            gas: Some(500_000),
            max_fee_per_gas: Some(20_000_000_000u128), // 20 gwei
            max_priority_fee_per_gas: Some(2_000_000_000u128), // 2 gwei
            chain_id: Some(self.chain_id),
            input: Bytes::new().into(),
            authorization_list: Some(vec![signed_authorization]),
            ..Default::default()
        };
        
        // Send the transaction and return the pending transaction
        let pending_tx = self.provider.send_transaction(tx).await?;
        Ok(pending_tx)
    }

    // Generic CREATE2 deployment methods
    /// Calculate the CREATE2 address for given bytecode and salt using the standard factory
    pub fn calculate_create2_address(&self, bytecode: &[u8], salt: &[u8; 32]) -> Address {
        // CREATE2: keccak256(0xff ++ factory_address ++ salt ++ keccak256(init_code))[12:]
        let init_code_hash = alloy::primitives::keccak256(bytecode);
        
        // Parse the factory address
        let factory_address = Address::from_str(CREATE2_FACTORY_ADDRESS).unwrap();
        
        // Pre-allocate the exact size needed: 1 + 20 + 32 + 32 = 85 bytes
        let mut input = Vec::with_capacity(85);
        input.push(0xff);
        input.extend_from_slice(&factory_address.into_word().as_slice());
        input.extend_from_slice(salt);
        input.extend_from_slice(init_code_hash.as_slice());
        
        let hash = alloy::primitives::keccak256(input);
        Address::from_slice(&hash[12..])
    }

    /// Check if a contract exists at the given address
    pub async fn contract_exists(&self, address: Address) -> Result<bool> {
        let code = self.provider.get_code_at(address).await?;
        Ok(!code.is_empty())
    }

    /// Deploy contract to CREATE2 address if it doesn't exist using the standard factory
    /// Returns the deployed contract address
    pub async fn deploy_create2_if_not_exists(
        &self,
        bytecode: &[u8],
        salt: &[u8; 32],
        transaction_request: TransactionRequest,
    ) -> Result<Address> {
        let predicted_address = self.calculate_create2_address(bytecode, salt);
        
        // Check if contract already exists
        if self.contract_exists(predicted_address).await? {
            return Ok(predicted_address);
        }
        
        // Deploy using the CREATE2 factory
        let factory_address = Address::from_str(CREATE2_FACTORY_ADDRESS).unwrap();
        
        // Convert salt to bytes32
        let salt_bytes32 = alloy::primitives::B256::from_slice(salt);
        
        // Call the factory's deploy function
        let deploy_call = ICreate2Factory::deployCall {
            salt: salt_bytes32,
            bytecode: Bytes::from(bytecode.to_vec()),
        };
        
        // Get current nonce
        let nonce = self.provider.get_transaction_count(self.address).await?;
        
        // Create transaction request to the factory
        let tx = TransactionRequest::default()
            .with_to(factory_address)
            .with_input(Bytes::from(deploy_call.abi_encode()))
            .with_gas_limit(transaction_request.gas.unwrap_or(500_000))
            .with_max_fee_per_gas(transaction_request.max_fee_per_gas.unwrap_or(20_000_000_000u128))
            .with_max_priority_fee_per_gas(transaction_request.max_priority_fee_per_gas.unwrap_or(2_000_000_000u128))
            .with_chain_id(self.chain_id)
            .with_nonce(nonce);
        
        let pending_tx = self.provider.send_transaction(tx).await?;
        let _receipt = pending_tx.get_receipt().await?;
        
        Ok(predicted_address)
    }



    pub async fn get_balance(&self, address: Address) -> Result<U256> {
        self.provider.get_balance(address).await.map_err(|e| eyre::eyre!("Failed to get balance: {}", e))
    }

    /// Get the current nonce from the TrustlessProposer contract
    pub async fn get_proposer_nonce(&self, proposer_address: Address) -> Result<U256> {
        let contract = TrustlessProposer::new(proposer_address, &self.provider);
        let nonce = contract.nestedNonce().call().await?;
        Ok(nonce)
    }

    /// Prepare bytecode with constructor arguments
    /// Handles 0x prefix removal and ABI encoding of constructor arguments
    pub fn prepare_bytecode_with_args(&self, bytecode: &str, constructor_args: &[DynSolValue]) -> Result<Vec<u8>> {
        // Remove 0x prefix if present
        let clean_bytecode = if bytecode.starts_with("0x") {
            &bytecode[2..]
        } else {
            bytecode
        };
        
        // Decode hex bytecode
        let mut bytecode_bytes = hex::decode(clean_bytecode)?;
        
        // ABI-encode constructor arguments if provided
        if !constructor_args.is_empty() {
            let encoded_args = DynSolValue::abi_encode_packed(&DynSolValue::Tuple(constructor_args.to_vec()));
            bytecode_bytes.extend_from_slice(&encoded_args);
        }
        
        Ok(bytecode_bytes)
    }

    /// Check if an account has initiated withdrawal from Gas Tank
    pub async fn check_withdrawal_initiated(&self, gas_tank: Address, account: Address) -> Result<bool> {
        let contract = IGasTank::new(gas_tank, &self.provider);
        let withdrawal_started_at = contract.withdrawalStartedAt(account).call().await?;
        Ok(!withdrawal_started_at.is_zero())
    }

    /// Check if withdrawal period has passed (7 days)
    pub async fn can_close_account(&self, gas_tank: Address, account: Address) -> Result<bool> {
        let contract = IGasTank::new(gas_tank, &self.provider);
        let withdrawal_started_at = contract.withdrawalStartedAt(account).call().await?;
        
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
        // Get the current account code
        let account_code = self.provider.get_code_at(self.address).await?;
        let has_code = !account_code.is_empty();
        
        if !has_code {
            return Ok((false, false));
        }
        
        // Check if the code matches the expected Proposer bytecode
        // We'll compare the deployed bytecode with the expected bytecode
        let expected_bytecode = self.provider.get_code_at(proposer_address).await?;
        
        // For now, we'll do a simple length comparison
        // In a production system, you might want to do a more sophisticated comparison
        let is_correct_proposer = account_code.len() == expected_bytecode.len();
        
        Ok((true, is_correct_proposer))
    }

    /// Prepare the ABI-encoded TrustlessProposer call (EIP-712 signature, deadline, nonce, calldata)
    /// Uses the contract's getMessageHash function for reliable hashing
    pub async fn prepare_trustless_proposer_call(
        &self,
        proposer_address: Address,
        target: Address,
        call_data: Bytes,
        value: U256,
        deadline_secs: u64,
    ) -> Result<Bytes> {
        let nonce = self.get_proposer_nonce(proposer_address).await?;
        let deadline = U256::from(deadline_secs);
        
        // Use the TrustlessProposer contract's getMessageHash function
        let contract = TrustlessProposer::new(proposer_address, &self.provider);
        let message_hash = contract.getMessageHash(deadline, nonce, target, value, call_data.clone()).call().await?;
        
        // Sign the message hash (convert FixedBytes to Vec<u8> then to Bytes for signing)
        let message_hash_vec = message_hash.to_vec();
        let message_hash_bytes = Bytes::from(message_hash_vec);
        let signature = self.wallet.sign_message(&message_hash_bytes).await?;
        
        // Encode (signature, deadline, nonce, callData)
        let encoded = [
            DynSolValue::Bytes(signature.as_bytes().to_vec()).abi_encode(),
            DynSolValue::Uint(deadline, 32).abi_encode(),
            DynSolValue::Uint(nonce, 32).abi_encode(),
            DynSolValue::Bytes(call_data.to_vec()).abi_encode(),
        ].concat();
        Ok(Bytes::from(encoded))
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
            chain_id
        );
        assert!(client.is_ok(), "Should be able to construct client with mock providers");
        let client = client.unwrap();
        let expected_address = Address::from_slice(&hex::decode("a0ee7a142d267c1f36714e4a8f75612f20a79720").unwrap());
        assert_eq!(client.address(), expected_address);
    }
} 