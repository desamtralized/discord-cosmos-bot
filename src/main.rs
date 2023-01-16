#[macro_use]
extern crate dotenv_codegen;

pub mod shared;

use bip39::Mnemonic;
use cosmrs::{
    bank, bip32,
    crypto::secp256k1,
    tx::{BodyBuilder, Msg},
    AccountId, Coin,
};
use cosmwasm_std::Uint128;
use discord::{
    model::{Event, Message},
    Discord,
};
use shared::AccountResponse;
use sled::Db;
use std::{env, str::FromStr};

const SUPPORTED_DENOMS: &'static [&'static str] = &["ukuji"];

#[tokio::main]
async fn main() {
    // Log in to Discord using a bot token from the environment
    let discord = Discord::from_bot_token(&env::var("DISCORD_TOKEN").expect("Expected token"))
        .expect("login failed");

    // Establish and use a websocket connection
    let (mut connection, _) = discord.connect().expect("connect failed");
    println!("Ready.");
    loop {
        match connection.recv_event() {
            Ok(Event::MessageCreate(message)) => {
                println!("{} says: {}", message.author.name, message.content);
                if message.content.starts_with("/send") {
                    handle_send_coins(&discord, &message);
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
    let (amount, denom, recipient) = match parts.as_slice() {
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

    // Create a send message.
    let send_msg = bank::MsgSend {
        from_address: AccountId::from_str("").unwrap(),
        to_address: AccountId::from_str("").unwrap(),
        amount: vec![coin],
    }
    .into_any()
    .unwrap();

    let user_id = message.author.id.to_string();

    // Fetch the account details of the granter.
    let account_data = fetch_account_details(&granter).await.unwrap();
    let mut tx_body_builder = BodyBuilder::new();
    tx_body_builder.msgs(vec![basic_allowance, msg_grant_allowance]);

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
    if db.contains_key(user_id).unwrap() {
        let wallet = db.get(user_id).unwrap();
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
fn derive_key_from_seed(seed_words: &str) -> secp256k1::SigningKey {
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
    let account_data = account_res.json::<AccountResponse>().await.unwrap();
    Ok(account_data)
}

#[test]
fn test() {
    let parts = "/send 1 kuji @samb".split(" ").collect::<Vec<&str>>();

    println!("parts: {:?}", parts);
}
