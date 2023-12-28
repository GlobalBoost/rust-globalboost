// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Blockdata constants.
//!
//! This module provides various constants relating to the blockchain and
//! consensus code. In particular, it defines the genesis block and its
//! single transaction.
//!

use core::default::Default;

use bitcoin_internals::impl_array_newtype;
use hex_lit::hex;

use crate::hashes::{Hash, sha256d};
use crate::blockdata::script;
use crate::blockdata::opcodes::all::*;
use crate::blockdata::locktime::absolute;
use crate::blockdata::transaction::{OutPoint, Transaction, TxOut, TxIn, Sequence};
use crate::blockdata::block::{self, Block};
use crate::blockdata::witness::Witness;
use crate::network::constants::Network;
use crate::pow::CompactTarget;
use crate::internal_macros::impl_bytes_newtype;

/// How many satoshis are in "one bitcoin".
pub const COIN_VALUE: u64 = 100_000_000;
/// How many seconds between blocks we expect on average.
pub const TARGET_BLOCK_SPACING: u32 = 600;
/// How many blocks between diffchanges.
pub const DIFFCHANGE_INTERVAL: u32 = 2016;
/// How much time on average should occur between diffchanges.
pub const DIFFCHANGE_TIMESPAN: u32 = 14 * 24 * 3600;
/// The maximum allowed weight for a block, see BIP 141 (network rule).
pub const MAX_BLOCK_WEIGHT: u32 = 4_000_000;
/// The minimum transaction weight for a valid serialized transaction.
pub const MIN_TRANSACTION_WEIGHT: u32 = 4 * 60;
/// The factor that non-witness serialization data is multiplied by during weight calculation.
pub const WITNESS_SCALE_FACTOR: usize = 4;
/// The maximum allowed number of signature check operations in a block.
pub const MAX_BLOCK_SIGOPS_COST: i64 = 80_000;
/// Mainnet (bitcoin) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_MAIN: u8 = 77; // 0x4D
/// Mainnet (bitcoin) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_MAIN: u8 = 139; // 0x8B
/// Test (tesnet, signet, regtest) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_TEST: u8 = 111; // 0x6f
/// Test (tesnet, signet, regtest) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_TEST: u8 = 196; // 0xc4
/// The maximum allowed script size.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// How may blocks between halvings.
pub const SUBSIDY_HALVING_INTERVAL: u32 = 240_000;
/// Maximum allowed value for an integer in Script.
pub const MAX_SCRIPTNUM_VALUE: u32 = 0x80000000; // 2^31
/// Number of blocks needed for an output from a coinbase transaction to be spendable.
pub const COINBASE_MATURITY: u32 = 100;

/// The maximum value allowed in an output (useful for sanity checking,
/// since keeping everything below this value should prevent overflows
/// if you are doing anything remotely sane with monetary values).
pub const MAX_MONEY: u64 = 24_000_000 * COIN_VALUE;

/// Constructs and returns the coinbase (and only) transaction of the Bitcoin genesis block.
fn bitcoin_genesis_tx() -> Transaction {
    // Base
    let mut ret = Transaction {
        version: 1,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    // Inputs
    let in_script = script::Builder::new().push_int(486604799)
                                          .push_int_non_minimal(4)
                                          .push_slice(b"Brics nations to create $100bn development bank")
                                          .into_script();
    ret.input.push(TxIn {
        previous_output: OutPoint::null(),
        script_sig: in_script,
        sequence: Sequence::MAX,
        witness: Witness::default(),
    });

    // Outputs
    let script_bytes = hex!("0465b6cdba122a93c06742cd8ba9ad6bda35e715badcc3cd87f8d7a1fd2c3eeb74bb9d8100d7c0ea33892c5c953a6c2d9d6ec1a6789d141ce63e3bf8fdb92cb313");
    let out_script = script::Builder::new()
        .push_slice(script_bytes)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    ret.output.push(TxOut {
        value: 367 * COIN_VALUE,
        script_pubkey: out_script
    });

    // end
    ret
}

/// Constructs and returns the genesis block.
pub fn genesis_block(network: Network) -> Block {
    let txdata = vec![bitcoin_genesis_tx()];
    let hash: sha256d::Hash = txdata[0].txid().into();
    let merkle_root = hash.into();
    match network {
        Network::Bitcoin => {
            Block {
                header: block::Header {
                    version: block::Version::ONE,
                    prev_blockhash: Hash::all_zeros(),
                    merkle_root,
                    time: 1410213600,
                    bits: CompactTarget::from_consensus(0x1e0ffff0),
                    nonce: 237174
                },
                txdata,
            }
        }
        Network::Testnet => {
            Block {
                header: block::Header {
                    version: block::Version::ONE,
                    prev_blockhash: Hash::all_zeros(),
                    merkle_root,
                    time: 1410213600,
                    bits: CompactTarget::from_consensus(0x1e0ffff0),
                    nonce: 237174
                },
                txdata,
            }
        }
        Network::Signet => {
            Block {
                header: block::Header {
                    version: block::Version::ONE,
                    prev_blockhash: Hash::all_zeros(),
                    merkle_root,
                    time: 1410213600,
                    bits: CompactTarget::from_consensus(0x207fffff),
                    nonce: 12348
                },
                txdata,
            }
        }
        Network::Regtest => {
            Block {
                header: block::Header {
                    version: block::Version::ONE,
                    prev_blockhash: Hash::all_zeros(),
                    merkle_root,
                    time: 1410213600,
                    bits: CompactTarget::from_consensus(0x207fffff),
                    nonce: 12348
                },
                txdata,
            }
        }
    }
}

/// The uniquely identifying hash of the target blockchain.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainHash([u8; 32]);
impl_array_newtype!(ChainHash, u8, 32);
impl_bytes_newtype!(ChainHash, 32);

impl ChainHash {
    // Mainnet value can be verified at https://github.com/lightning/bolts/blob/master/00-introduction.md
    /// `ChainHash` for mainnet bitcoin.
    pub const BITCOIN: Self = Self([
        223, 90, 141, 20, 190, 139, 1, 106, 2, 127, 236, 4, 137, 223, 194, 35, 26, 54, 129, 240,
        210, 148, 83, 64, 242, 115, 173, 148, 1, 5, 40, 46,
    ]);
    /// `ChainHash` for testnet bitcoin.
    pub const TESTNET: Self = Self([67, 73, 127, 215, 248, 38, 149, 113, 8, 244, 163, 15, 217, 206, 195, 174, 186, 121, 151, 32, 132, 233, 14, 173, 1, 234, 51, 9, 0, 0, 0, 0]);
    /// `ChainHash` for signet bitcoin.
    pub const SIGNET: Self = Self([246, 30, 238, 59, 99, 163, 128, 164, 119, 160, 99, 175, 50, 178, 187, 201, 124, 159, 249, 240, 31, 44, 66, 37, 233, 115, 152, 129, 8, 0, 0, 0]);
    /// `ChainHash` for regtest bitcoin.
    pub const REGTEST: Self = Self([6, 34, 110, 70, 17, 26, 11, 89, 202, 175, 18, 96, 67, 235, 91, 191, 40, 195, 79, 58, 94, 51, 42, 31, 199, 178, 183, 60, 241, 136, 145, 15]);

    /// Returns the hash of the `network` genesis block for use as a chain hash.
    ///
    /// See [BOLT 0](https://github.com/lightning/bolts/blob/ffeece3dab1c52efdb9b53ae476539320fa44938/00-introduction.md#chain_hash)
    /// for specification.
    pub const fn using_genesis_block(network: Network) -> Self {
        let hashes = [Self::BITCOIN, Self::TESTNET, Self::SIGNET, Self::REGTEST];
        hashes[network as usize]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::network::constants::Network;
    use crate::consensus::encode::serialize;
    use crate::blockdata::locktime::absolute;
    use crate::internal_macros::hex;

    #[test]
    fn bitcoin_genesis_first_transaction() {
        let gen = bitcoin_genesis_tx();

        assert_eq!(gen.version, 1);
        assert_eq!(gen.input.len(), 1);
        assert_eq!(gen.input[0].previous_output.txid, Hash::all_zeros());
        assert_eq!(gen.input[0].previous_output.vout, 0xFFFFFFFF);
        assert_eq!(serialize(&gen.input[0].script_sig),
                   hex!("4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73"));

        assert_eq!(gen.input[0].sequence, Sequence::MAX);
        assert_eq!(gen.output.len(), 1);
        assert_eq!(serialize(&gen.output[0].script_pubkey),
                   hex!("434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"));
        assert_eq!(gen.output[0].value, 367 * COIN_VALUE);
        assert_eq!(gen.lock_time, absolute::LockTime::ZERO);

        assert_eq!(gen.wtxid().to_string(), "acd715d33d3288f616bfe281819a4d84bdea206b8c06088eec584095f5de891c");
    }

    #[test]
    fn bitcoin_genesis_full_block() {
        let gen = genesis_block(Network::Bitcoin);

        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(gen.header.merkle_root.to_string(), "acd715d33d3288f616bfe281819a4d84bdea206b8c06088eec584095f5de891c");

        assert_eq!(gen.header.time, 1410213600);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1e0ffff0));
        assert_eq!(gen.header.nonce, 237174);
        assert_eq!(gen.header.block_hash().to_string(), "2e28050194ad73f2405394d2f081361a23c2df8904ec7f026a018bbe148d5adf");
    }

    #[test]
    fn testnet_genesis_full_block() {
        let gen = genesis_block(Network::Testnet);
        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(gen.header.merkle_root.to_string(), "acd715d33d3288f616bfe281819a4d84bdea206b8c06088eec584095f5de891c");
        assert_eq!(gen.header.time, 1410213600);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1e0ffff0));
        assert_eq!(gen.header.nonce, 237174);
        assert_eq!(gen.header.block_hash().to_string(), "2e28050194ad73f2405394d2f081361a23c2df8904ec7f026a018bbe148d5adf");
    }

    #[test]
    fn signet_genesis_full_block() {
        let gen = genesis_block(Network::Signet);
        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(gen.header.merkle_root.to_string(), "acd715d33d3288f616bfe281819a4d84bdea206b8c06088eec584095f5de891c");
        assert_eq!(gen.header.time, 1410213600);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x207fffff));
        assert_eq!(gen.header.nonce, 12348);
        assert_eq!(gen.header.block_hash().to_string(), "9d78dbf0deeb8c66bf816db67d551e5f537d410de22e0e962836efc819bc35c3");
    }

    // The *_chain_hash tests are sanity/regression tests, they verify that the const byte array
    // representing the genesis block is the same as that created by hashing the genesis block.
    fn chain_hash_and_genesis_block(network: Network) {
        use crate::hashes::sha256;

        // The genesis block hash is a double-sha256 and it is displayed backwards.
        let genesis_hash = genesis_block(network).block_hash();
        // We abuse the sha256 hash here so we get a LowerHex impl that does not print the hex backwards.
        let hash = sha256::Hash::from_slice(genesis_hash.as_byte_array()).unwrap();
        let want = format!("{:02x}", hash);

        let chain_hash = ChainHash::using_genesis_block(network);
        let got = format!("{:02x}", chain_hash);

        // Compare strings because the spec specifically states how the chain hash must encode to hex.
        assert_eq!(got, want);

        match network {
            Network::Bitcoin => {},
            Network::Testnet => {},
            Network::Signet => {},
            Network::Regtest => {},
            // Update ChainHash::using_genesis_block and chain_hash_genesis_block with new variants.
        }
    }

    macro_rules! chain_hash_genesis_block {
        ($($test_name:ident, $network:expr);* $(;)*) => {
            $(
                #[test]
                fn $test_name() {
                    chain_hash_and_genesis_block($network);
                }
            )*
        }
    }

    chain_hash_genesis_block! {
        mainnet_chain_hash_genesis_block, Network::Bitcoin;
        testnet_chain_hash_genesis_block, Network::Testnet;
        signet_chain_hash_genesis_block, Network::Signet;
        regtest_chain_hash_genesis_block, Network::Regtest;
    }

    // Test vector taken from: https://github.com/lightning/bolts/blob/master/00-introduction.md
    #[test]
    fn mainnet_chain_hash_test_vector() {
        let got = ChainHash::using_genesis_block(Network::Bitcoin).to_string();
        let want = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000";
        assert_eq!(got, want);
    }
}
