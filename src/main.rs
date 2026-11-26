use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use clap::{Parser, Subcommand};
use k256::SecretKey as K256SecretKey;
use pczt::{Pczt, roles::signer::Signer};
use pkcs8::DecodePrivateKey;
use ripemd::Ripemd160;
use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(about = "Sign a policy-approved transparent P2PKH input in a Zallet PCZT")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print transaction-relevant fields for preparing an independent signing policy.
    Inspect {
        #[arg(long)]
        pczt: PathBuf,
    },
    /// Sign a pure-transparent P2PKH PCZT after exact policy checks.
    Sign {
        #[arg(long)]
        pczt: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    tx_version: u32,
    consensus_branch_id: u32,
    expiry_height: u32,
    inputs: Vec<ExpectedInput>,
    outputs: Vec<ExpectedOutput>,
    max_fee_zat: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedInput {
    /// Bytes as encoded in the PCZT, emitted by this tool's `inspect` command.
    prevout_txid_raw_hex: String,
    prevout_index: u32,
    value_zat: u64,
    script_pubkey_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedOutput {
    value_zat: u64,
    script_pubkey_hex: String,
}

#[derive(Serialize)]
struct Summary {
    tx_version: u32,
    consensus_branch_id: u32,
    consensus_branch_id_hex: String,
    expiry_height: u32,
    inputs: Vec<InputSummary>,
    outputs: Vec<OutputSummary>,
    transparent_fee_zat: Option<u64>,
    shielded_data_present: bool,
}

#[derive(Serialize)]
struct InputSummary {
    prevout_txid_raw_hex: String,
    prevout_index: u32,
    value_zat: u64,
    script_pubkey_hex: String,
}

#[derive(Serialize)]
struct OutputSummary {
    value_zat: u64,
    script_pubkey_hex: String,
    user_address: Option<String>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Inspect { pczt } => {
            let pczt = read_pczt(&pczt)?;
            let summary = summarize(&pczt);
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        Command::Sign {
            pczt,
            key,
            policy,
            output,
        } => {
            let pczt = read_pczt(&pczt)?;
            let policy: Policy = serde_json::from_slice(
                &fs::read(&policy)
                    .with_context(|| format!("reading policy {}", policy.display()))?,
            )
            .context("parsing signing policy JSON")?;
            let secret_key = read_secp256k1_key(&key)?;
            validate_policy(&pczt, &policy, &secret_key)?;

            let mut signer = Signer::new(pczt)
                .map_err(|error| anyhow::anyhow!("PCZT is not signable: {error:?}"))?;
            for index in 0..policy.inputs.len() {
                signer
                    .sign_transparent(index, &secret_key)
                    .map_err(|error| {
                        anyhow::anyhow!("signing transparent input {index}: {error:?}")
                    })?;
            }

            let encoded = BASE64.encode(
                signer
                    .finish()
                    .serialize()
                    .map_err(|error| anyhow::anyhow!("serializing signed PCZT: {error:?}"))?,
            );
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)
                .with_context(|| {
                    format!(
                        "creating output file {} (existing files are never overwritten)",
                        output.display()
                    )
                })?;
            file.write_all(encoded.as_bytes())?;
            file.write_all(b"\n")?;
            println!("Signed PCZT written to {}", output.display());
        }
    }
    Ok(())
}

fn read_pczt(path: &PathBuf) -> Result<Pczt> {
    let text =
        fs::read_to_string(path).with_context(|| format!("reading PCZT {}", path.display()))?;
    let payload = extract_pczt_payload(&text)?;
    let bytes = BASE64.decode(payload).context("PCZT is not valid base64")?;
    Pczt::parse(&bytes).context("invalid or unsupported PCZT encoding")
}

fn extract_pczt_payload(text: &str) -> Result<String> {
    let trimmed = text.trim();
    if trimmed.starts_with('{') {
        let value: serde_json::Value =
            serde_json::from_str(trimmed).context("parsing Zallet RPC JSON")?;
        let payload = value
            .get("pczt")
            .and_then(serde_json::Value::as_str)
            .context("RPC JSON must contain a string field named `pczt`")?;
        return Ok(payload.to_owned());
    }
    if trimmed.starts_with('"') {
        return serde_json::from_str(trimmed).context("parsing quoted base64 PCZT string");
    }
    Ok(trimmed.to_owned())
}

fn summarize(pczt: &Pczt) -> Summary {
    let inputs = pczt
        .transparent()
        .inputs()
        .iter()
        .map(|input| InputSummary {
            prevout_txid_raw_hex: hex::encode(input.prevout_txid()),
            prevout_index: *input.prevout_index(),
            value_zat: *input.value(),
            script_pubkey_hex: hex::encode(input.script_pubkey()),
        })
        .collect::<Vec<_>>();
    let outputs = pczt
        .transparent()
        .outputs()
        .iter()
        .map(|output| OutputSummary {
            value_zat: *output.value(),
            script_pubkey_hex: hex::encode(output.script_pubkey()),
            user_address: output.user_address().clone(),
        })
        .collect::<Vec<_>>();
    let input_total = inputs
        .iter()
        .map(|input| input.value_zat as u128)
        .sum::<u128>();
    let output_total = outputs
        .iter()
        .map(|output| output.value_zat as u128)
        .sum::<u128>();
    let fee = (input_total >= output_total).then_some((input_total - output_total) as u64);
    let branch_id = *pczt.global().consensus_branch_id();

    Summary {
        tx_version: *pczt.global().tx_version(),
        consensus_branch_id: branch_id,
        consensus_branch_id_hex: format!("{branch_id:08x}"),
        expiry_height: *pczt.global().expiry_height(),
        inputs,
        outputs,
        transparent_fee_zat: fee,
        shielded_data_present: has_shielded_data(pczt),
    }
}

fn validate_policy(pczt: &Pczt, policy: &Policy, secret_key: &SecretKey) -> Result<()> {
    ensure!(
        !has_shielded_data(pczt),
        "shielded inputs or outputs are outside this PoC's scope"
    );
    ensure!(
        !policy.inputs.is_empty(),
        "policy must authorize at least one input"
    );
    ensure!(
        !policy.outputs.is_empty(),
        "policy must authorize at least one output"
    );
    ensure!(
        pczt.transparent().inputs().len() == policy.inputs.len(),
        "transparent input count does not match policy"
    );
    ensure!(
        pczt.transparent().outputs().len() == policy.outputs.len(),
        "transparent output count does not match policy"
    );
    ensure!(
        *pczt.global().tx_version() == policy.tx_version,
        "transaction version does not match policy"
    );
    ensure!(
        *pczt.global().consensus_branch_id() == policy.consensus_branch_id,
        "consensus branch ID does not match policy"
    );
    ensure!(
        *pczt.global().expiry_height() == policy.expiry_height,
        "expiry height does not match policy"
    );

    let expected_key_script = p2pkh_script(secret_key);
    let mut input_total = 0u128;
    for (index, (input, expected)) in pczt
        .transparent()
        .inputs()
        .iter()
        .zip(&policy.inputs)
        .enumerate()
    {
        let txid = hex::decode(&expected.prevout_txid_raw_hex)
            .with_context(|| format!("policy input {index} has invalid txid hex"))?;
        let script = hex::decode(&expected.script_pubkey_hex)
            .with_context(|| format!("policy input {index} has invalid script hex"))?;
        ensure!(
            txid.len() == 32,
            "policy input {index} txid must be 32 bytes"
        );
        ensure!(
            input.prevout_txid().as_slice() == txid,
            "input {index} outpoint txid does not match policy"
        );
        ensure!(
            *input.prevout_index() == expected.prevout_index,
            "input {index} outpoint index does not match policy"
        );
        ensure!(
            *input.value() == expected.value_zat,
            "input {index} value does not match policy"
        );
        ensure!(
            input.script_pubkey().as_slice() == script,
            "input {index} script does not match policy"
        );
        ensure!(
            input.script_pubkey().as_slice() == expected_key_script,
            "input {index} is not a P2PKH output controlled by this PEM key"
        );
        input_total = input_total
            .checked_add(*input.value() as u128)
            .context("input value sum overflow")?;
    }

    let mut output_total = 0u128;
    for (index, (output, expected)) in pczt
        .transparent()
        .outputs()
        .iter()
        .zip(&policy.outputs)
        .enumerate()
    {
        let script = hex::decode(&expected.script_pubkey_hex)
            .with_context(|| format!("policy output {index} has invalid script hex"))?;
        ensure!(
            *output.value() == expected.value_zat,
            "output {index} amount does not match policy"
        );
        ensure!(
            output.script_pubkey().as_slice() == script,
            "output {index} script does not match policy"
        );
        output_total = output_total
            .checked_add(*output.value() as u128)
            .context("output value sum overflow")?;
    }

    ensure!(input_total >= output_total, "outputs exceed inputs");
    let fee = input_total - output_total;
    ensure!(
        fee <= policy.max_fee_zat as u128,
        "fee exceeds policy maximum"
    );
    Ok(())
}

fn has_shielded_data(pczt: &Pczt) -> bool {
    !pczt.sapling().spends().is_empty()
        || !pczt.sapling().outputs().is_empty()
        || !pczt.orchard().actions().is_empty()
        || !pczt.ironwood().actions().is_empty()
}

fn p2pkh_script(secret_key: &SecretKey) -> Vec<u8> {
    let public_key = PublicKey::from_secret_key(secret_key).serialize();
    let sha256 = Sha256::digest(public_key);
    let public_key_hash = Ripemd160::digest(sha256);
    let mut script = Vec::with_capacity(25);
    script.extend_from_slice(&[0x76, 0xa9, 0x14]);
    script.extend_from_slice(&public_key_hash);
    script.extend_from_slice(&[0x88, 0xac]);
    script
}

fn read_secp256k1_key(path: &PathBuf) -> Result<SecretKey> {
    let pem =
        fs::read_to_string(path).with_context(|| format!("reading key {}", path.display()))?;
    let key = if pem.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        let passphrase = Zeroizing::new(rpassword::prompt_password("PEM passphrase: ")?);
        K256SecretKey::from_pkcs8_encrypted_pem(&pem, passphrase.as_bytes())
            .context("decrypting PKCS#8 PEM; check the passphrase and key format")?
    } else if pem.contains("-----BEGIN PRIVATE KEY-----") {
        K256SecretKey::from_pkcs8_pem(&pem).context("parsing unencrypted PKCS#8 PEM")?
    } else {
        bail!("expected PKCS#8 PEM from `openssl genpkey` (PRIVATE KEY or ENCRYPTED PRIVATE KEY)");
    };
    let bytes: [u8; 32] = key.to_bytes().into();
    SecretKey::from_secret_bytes(bytes).context("converting secp256k1 key")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p2pkh_script_has_standard_shape() {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        let secret_key = SecretKey::from_secret_bytes(bytes).unwrap();
        let script = p2pkh_script(&secret_key);
        assert_eq!(script.len(), 25);
        assert_eq!(&script[..3], &[0x76, 0xa9, 0x14]);
        assert_eq!(&script[23..], &[0x88, 0xac]);
    }
}
