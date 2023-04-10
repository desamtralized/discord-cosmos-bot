#[macro_use]
extern crate dotenv_codegen;

pub mod shared;

use bip39::Mnemonic;
use cosmrs::{
    bank, bip32,
    crypto::secp256k1,
    rpc::HttpClient,
    tendermint::chain::Id,
    tx::{BodyBuilder, Fee, Msg, SignDoc, SignerInfo},
    AccountId, Coin,
};
use cosmwasm_std::{Decimal, Uint128};
use discord::{
    model::{Event, Message},
    Discord,
};
use dotenv::dotenv;
use shared::AccountResponse;
use sled::Db;
use std::str::FromStr;

const SUPPORTED_DENOMS: &'static [&'static str] = &["ukuji"];

#[tokio::main]
async fn main() {
    dotenv().ok();
    // Log in to Discord using a bot token from the environment
    let discord = Discord::from_bot_token(&dotenv!("DISCORD_TOKEN")).expect("login failed");

    // Establish and use a websocket connection
    let (mut connection, _) = discord.connect().expect("connect failed");
    println!("Ready.");
    loop {
        match connection.recv_event() {
            Ok(Event::MessageCreate(message)) => {
                println!("{} says: {}", message.author.name, message.content);
                if message.content.starts_with("/send") {
                    handle_send_coins(&discord, &message).await;
                } else if message.content == "!quit" {
                    println!("Quitting.");
                    break;
                }
            }
            Ok(_) => {}
            Err(discord::Error::Closed(code, body)) => {
                println!("Gateway closed on us with code {:?}: {}", code, body);
                break;
            }
            Err(err) => println!("Receive error: {:?}", err),
        }
    }
}

/// Handle the /send command.
/// The format is /send 1 kuji @user.
async fn handle_send_coins(discord: &Discord, message: &Message) {
    // Split message using spaces and extract the amount, denom and recipient.
    // Skip the first part of the message which is the command.
    let parts = message.content.split(" ").skip(1).collect::<Vec<&str>>();
    // extract amount, denom and recipient.
    let (amount, denom, _recipient) = match parts.as_slice() {
        [amount, denom, recipient] => (amount, denom, recipient),
        _ => {
            send_wrong_format_error_msg(discord, message);
            return;
        }
    };

    // Check if the denom is supported.
    if !SUPPORTED_DENOMS.contains(&denom) {
        discord
            .send_message(
                message.channel_id,
                &format!("Unsupported denom: {}", denom),
                "",
                false,
            )
            .unwrap();
        return;
    }

    // Create a cosmrs::Coin from the amount and denom.
    let coin = Coin::new(Uint128::from_str(amount).unwrap().u128(), denom).unwrap();

    let path = "m/44'/118'/0'/0/0"
        .parse::<bip32::DerivationPath>()
        .unwrap();
    let user_id = message.author.id.to_string();
    let mnemonic = get_or_create_wallet_for_user(user_id);
    let seed = mnemonic.to_seed("");
    let sender_priv_key = secp256k1::SigningKey::derive_from_path(seed, &path).unwrap();
    let sender_pub_key = sender_priv_key.public_key();
    let sender_addr = sender_pub_key.account_id(dotenv!("ADDR_PREFIX")).unwrap();
    let account_data = fetch_account_details(&sender_addr).await.unwrap();
    let mut tx_body_builder = BodyBuilder::new();

    // Get the mentioned user.
    let mentioned_user = message.mentions.first().unwrap();
    // load or create the wallet of the mentioned user.
    let receiver_mnemonic = get_or_create_wallet_for_user(mentioned_user.id.to_string());
    let receiver_seed = receiver_mnemonic.to_seed("");
    let receiver_priv_key = secp256k1::SigningKey::derive_from_path(receiver_seed, &path).unwrap();
    let receiver_pub_key = receiver_priv_key.public_key();
    let receiver_addr = receiver_pub_key.account_id(dotenv!("ADDR_PREFIX")).unwrap();

    // Create a send message.
    let send_msg = bank::MsgSend {
        from_address: sender_addr.clone(),
        to_address: receiver_addr.clone(),
        amount: vec![coin],
    }
    .into_any()
    .unwrap();

    tx_body_builder.msgs(vec![send_msg]);
    let tx_body = tx_body_builder.finish();
    let account_number = account_data
        .account
        .account_number
        .clone()
        .parse::<i64>()
        .unwrap() as u64;
    let chain_id = dotenv!("CHAIN_ID").parse::<Id>().unwrap();
    let signer_info = SignerInfo::single_direct(
        Some(sender_pub_key.clone()),
        account_data
            .account
            .sequence
            .clone()
            .parse::<i64>()
            .unwrap() as u64,
    );
    let gas_amount = Coin {
        amount: 320u128,
        denom: "ukuji".parse().unwrap(),
    };
    let auth_info = signer_info.auth_info(Fee::from_amount_and_gas(gas_amount, 250_000u64));
    let sign_doc = SignDoc::new(&tx_body, &auth_info, &chain_id, account_number).unwrap();
    let tx_signed = sign_doc.sign(&sender_priv_key).unwrap();
    let rpc_url = dotenv!("RPC");
    let client = HttpClient::new(rpc_url).unwrap();
    let res = tx_signed.broadcast_commit(&client).await.unwrap();
    println!("{}", res.deliver_tx.info.to_string());
    println!("res: {:#?}", res);

    // # Authorize send (or Open Trade Msg)
    // kujirad tx authz grant kujira1g65s9hctnz89m0rqgs2tmuzjqsy998mxsfg9px "send" --from maker --spend-limit "1000000ukuji" $GAS -y -b block
    // # Grant Fee
    // kujirad tx feegrant grant kujira1gqhxtrsve4f2pcp65fr8l5t86pu7v0cx8kptcv kujira1g65s9hctnz89m0rqgs2tmuzjqsy998mxsfg9px --from taker --spend-limit 1000000ukuji $GAS -y -b block
    // # Generate Tx
    // kujirad tx bank send kujira1gqhxtrsve4f2pcp65fr8l5t86pu7v0cx8kptcv kujira1g65s9hctnz89m0rqgs2tmuzjqsy998mxsfg9px 200000ukuji --from taker --generate-only > tx.json
    // # Exec Tx
    // kujirad tx authz exec tx.json --from cryptoless --fee-account kujira1gqhxtrsve4f2pcp65fr8l5t86pu7v0cx8kptcv $GAS -y -b block
}

fn get_or_create_wallet_for_user(user_id: String) -> Mnemonic {
    let path = "db";
    let db = sled::open(path).unwrap();
    if db.contains_key(&user_id).unwrap() {
        let wallet = db.get(&user_id).unwrap();
        match wallet {
            Some(wallet) => {
                let phrase = String::from_utf8(wallet.to_vec()).unwrap();
                return Mnemonic::from_str(phrase.as_str()).unwrap();
            }
            None => {}
        }
    }
    create_mnemonic(&db, &user_id)
}

fn create_mnemonic(db: &Db, user_id: &String) -> Mnemonic {
    let mnemonic = Mnemonic::generate_in(bip39::Language::English, 12).unwrap();
    // TODO, we can generate a salted passphrase from the user_id.
    let phrase = mnemonic.to_string();
    db.insert(user_id, phrase.as_bytes()).unwrap();
    mnemonic
}

/// Send an error message to the user.
fn send_wrong_format_error_msg(discord: &Discord, message: &Message) {
    discord
        .send_message(
            message.channel_id,
            "Wrong message format, must be '/send 1 kuji @user'",
            "",
            false,
        )
        .unwrap();
}

/// Derive a key from a seed phrase.
/// The path is m/44'/118'/0'/0/0.
/// The path is the same as the one used by the Cosmos Hub.
fn _derive_key_from_seed(seed_words: &str) -> secp256k1::SigningKey {
    let path = "m/44'/118'/0'/0/0"
        .parse::<bip32::DerivationPath>()
        .unwrap();
    let mnemonic = Mnemonic::parse_normalized(&seed_words).unwrap();
    let seed = mnemonic.to_seed("");
    secp256k1::SigningKey::derive_from_path(seed, &path).unwrap()
}

async fn fetch_account_details(
    sender_addr: &AccountId,
) -> Result<AccountResponse, Box<dyn std::error::Error>> {
    let account_url = format!(
        "{}cosmos/auth/v1beta1/accounts/{}",
        dotenv!("LCD"),
        sender_addr.to_string()
    );
    let account_res = reqwest::get(account_url).await.unwrap();
    // print Address from AccountId
    println!("address: {}", sender_addr.to_string());
    let account_data = account_res.json::<AccountResponse>().await.unwrap();
    Ok(account_data)
}

#[test]
fn test() {
    let parts = "/send 1.5 kuji @samb".split(" ").collect::<Vec<&str>>();

    let amount = parts[1].parse::<f64>().unwrap();
    // convert from f64 to Uint128
    Decimal::from(amount)
        .mul(Decimal::from_u128(1_000_000))
        .unwrap()
        .to_u128()
        .unwrap();
    let amount = Uint128::from(amount as u128);

    println!("amount: {}", amount)
}
