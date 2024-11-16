
use bip39::{Mnemonic, /*MnemonicType,*/ Language, Seed};
use bitcoin::bip32::{Xpriv /*ExtendedPrivKey*/, DerivationPath, Xpub};
use bitcoin::network::Network;
use bitcoin::address::Address;
use secp256k1::Secp256k1;

use std::str::FromStr;

fn main() {
    for i in 0..4 {
        bitcoin_testnet(i);
    }
    println!("------------------------------------------------------------------");
    bitcoin_mainnet();
}

fn bitcoin_testnet(addr_index: u32) {
    let words = "box find chat planet stairs stomach luxury such jungle photo scorpion prepare";

    // Your additional passphrase
    let passphrase = "";

    // Create a Mnemonic from the phrase
    let mnemonic = Mnemonic::from_phrase(words, Language::English).expect("Invalid mnemonic phrase");

    // get the phrase
    let phrase: &str = mnemonic.phrase();
    println!("Seed-Words (BIP-39): {}", phrase);
    println!("Passphrase (\"additional word\"): {}", passphrase);

    // get the HD wallet seed
    let seed = Seed::new(&mnemonic, passphrase);

    // get the HD wallet seed as raw bytes
    let seed_bytes: &[u8] = seed.as_bytes();

    // print the HD wallet seed as a hex string
    println!("Seed: {:X}", seed);

    // ---------------------- create a bitcoin address from this seed

    // Create a secp256k1 context
    let secp = Secp256k1::new();

    // Generate an extended private key
    let xpriv = Xpriv::new_master(Network::Bitcoin, seed.as_bytes()).expect("Failed to create master key");

    // Derive the private key using the derivation path
    let path = format!("m/84'/1'/0'/0/{}", &addr_index);
    let derivation_path = DerivationPath::from_str(&path).expect("Invalid derivation path");
    let derived_xpriv = xpriv.derive_priv(&secp, &derivation_path).expect("Failed to derive private key");

    println!("Private xpriv (Testnet): {}", derived_xpriv);

    // Get the associated extended public key (Xpub)
    let xpub = Xpub::from_priv(&secp, &derived_xpriv);
    println!("Public xpub (Testnet): {}", xpub);
    let pubkey = derived_xpriv.private_key.public_key(&secp);
    let btc_pubkey = bitcoin::PublicKey::new(pubkey);

    // Convert the extended public key to a compressed public key

    // Generate the Bitcoin address from the public key
    let non_witness_address = Address::p2pkh(&btc_pubkey, Network::Testnet);
    // Print the Bitcoin address
    println!("Bitcoin(Testnet) non_witness address: {}", non_witness_address);

    let private_key = bitcoin::PrivateKey {
        compressed: true,
        network: bitcoin::NetworkKind::Test,
        inner: derived_xpriv.private_key,
    };
    let btc_compressed_pubkey = bitcoin::CompressedPublicKey::from_private_key(&secp, &private_key);
    let witness_address = Address::p2wpkh(&btc_compressed_pubkey.unwrap(), Network::Testnet);
    println!("Bitcoin(Testnet) witness address {}: {}", path, witness_address);
}

fn bitcoin_mainnet() {
    // This is not used in the real world! No bitcoin to find here!
    let phrase = "used quarter other stuff south street unit various ivory march copy come capable include goat mixture pumpkin social race defense jealous light fault slow";
    // 10C6849EE3C29354178A245CE84262BAFC4CE24808BC7EC1C498CC98193CA92B19DEC896EF3416DE048B7C068D59EEE76B3CA8277B6C6EAA09B40CB6917D36DF

    // Your additional passphrase
    let passphrase = "mypassphrase";

    // Create a Mnemonic from the phrase
    let mnemonic = Mnemonic::from_phrase(phrase, Language::English).expect("Invalid mnemonic phrase");

    // get the phrase
    let phrase: &str = mnemonic.phrase();
    println!("24 Words (BIP-39): {}", phrase);
    println!("Passphrase (\"25. word\"): {}", passphrase);

    // get the HD wallet seed
    let seed = Seed::new(&mnemonic, passphrase);

    // get the HD wallet seed as raw bytes
    let seed_bytes: &[u8] = seed.as_bytes();

    // print the HD wallet seed as a hex string
    println!("Seed: {:X}", seed);

    // ---------------------- create a bitcoin address from this seed

    // Create a secp256k1 context
    let secp = Secp256k1::new();

    // Generate an extended private key
    let xpriv = Xpriv::new_master(Network::Bitcoin, seed.as_bytes()).expect("Failed to create master key");

    // Derive the private key using the derivation path m/84'/0'/0'/0/0
    let derivation_path = DerivationPath::from_str("m/84'/0'/0'/0/0").expect("Invalid derivation path");
    let derived_xpriv = xpriv.derive_priv(&secp, &derivation_path).expect("Failed to derive private key");

    println!("Private xpriv: {}", derived_xpriv);

    // Get the associated extended public key (Xpub)
    let xpub = Xpub::from_priv(&secp, &derived_xpriv);
    println!("Public xpub: {}", xpub);
    let pubkey = derived_xpriv.private_key.public_key(&secp);
    let btc_pubkey = bitcoin::PublicKey::new(pubkey);

    // Generate the Bitcoin address from the public key
    let non_witness_address = Address::p2pkh(&btc_pubkey, Network::Bitcoin);
    // Print the Bitcoin address
    println!("Bitcoin non_witness address: {}", non_witness_address);

    // Convert the extended public key to a compressed public key
    let private_key = bitcoin::PrivateKey {
        compressed: true,
        network: bitcoin::NetworkKind::Main,
        inner: derived_xpriv.private_key,
    };
    let btc_compressed_pubkey = bitcoin::CompressedPublicKey::from_private_key(&secp, &private_key);
    let witness_address = Address::p2wpkh(&btc_compressed_pubkey.unwrap(), Network::Bitcoin);
    println!("Bitcoin witness address: {}", witness_address);
}
