//! Runs the app's FROST account code (`zcash_frost`) as the coordinator from a
//! terminal, against the frost-zec test co-signer, to test it on the real chain
//! before the screens exist. It never touches the app's own data: it works in
//! the `--dir` folder given, with a throwaway seed kept there.
//!
//!   setup   --net test|main --dir DIR --via EXCHANGE
//!   sync    --net test|main --dir DIR
//!   balance --net test|main --dir DIR
//!   send    --net test|main --dir DIR --via EXCHANGE --to ADDRESS --amount ZATOSHIS [--memo TEXT]
//!
//! The co-signer side: `frost-zec qr setup --as cosigner --network test --via EXCHANGE`
//! then `frost-zec qr sign --as cosigner --via EXCHANGE`. Messages are the same
//! UR text files.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use frost_zec::wire;
use openpgp_wallet_core::zcash_frost::{self, Net};

fn option<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn required<'a>(args: &'a [String], name: &str) -> Result<&'a str> {
    option(args, name).ok_or_else(|| anyhow!("{name} is required"))
}

/// The throwaway seed of this test folder (never the app's).
fn seed(dir: &Path) -> Result<Vec<u8>> {
    let path = dir.join("example-seed.bin");
    if let Ok(seed) = std::fs::read(&path) {
        return Ok(seed);
    }
    let mut seed = vec![0u8; 64];
    getrandom::getrandom(&mut seed).map_err(|e| anyhow!("{e}"))?;
    std::fs::create_dir_all(dir)?;
    std::fs::write(&path, &seed)?;
    Ok(seed)
}

fn write(via: &Path, name: &str, payload: &[u8]) -> Result<()> {
    std::fs::create_dir_all(via)?;
    let temporary = via.join(format!(".{name}.tmp"));
    std::fs::write(&temporary, wire::single_part(payload)?)?;
    std::fs::rename(&temporary, via.join(name))?;
    println!("  → wrote {}", via.join(name).display());
    Ok(())
}

fn read(via: &Path, name: &str) -> Result<Vec<u8>> {
    let path = via.join(name);
    println!("  … waiting for {}", path.display());
    let deadline = Instant::now() + Duration::from_secs(3600);
    loop {
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(Some(payload)) = wire::Reader::default().receive(text.trim()) {
                let _ = std::fs::remove_file(&path);
                return Ok(payload);
            }
        }
        if Instant::now() > deadline {
            bail!("timed out waiting for {}", path.display());
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or_default();
    let net = Net::parse(required(&args, "--net")?)?;
    let dir = PathBuf::from(required(&args, "--dir")?);
    std::fs::create_dir_all(&dir)?;
    match command {
        "setup" => {
            let via = PathBuf::from(required(&args, "--via")?);
            let (step, payload) = zcash_frost::setup_start(&dir, net)?;
            write(&via, "1-pair-init.ur", &payload)?;
            let (step, payload, code) = zcash_frost::setup_response(step, &read(&via, "2-pair-response.ur")?)?;
            write(&via, "3-pair-confirm.ur", &payload)?;
            println!("  pairing code: {code} (compare it with the co-signer)");
            let step = zcash_frost::setup_code_confirmed(step)?;
            let keys = read(&via, "4-cosigner-keys.ur")?;
            let birthday = zcash_frost::chain_birthday(net)?;
            let (payload, step) = zcash_frost::setup_finish(&dir, step, &keys, &seed(&dir)?, &birthday)?;
            write(&via, "5-coordinator-keys.ur", &payload)?;
            let account = zcash_frost::setup_done(&dir, &step, &read(&via, "6-cosigner-done.ur")?)?;
            println!("  address:  {}\n  birthday: {}", account.address, account.birthday);
        }
        "sync" => {
            zcash_frost::sync(&dir, net)?;
            println!("  synced");
        }
        "balance" => {
            let balance = zcash_frost::balance(&dir, net)?;
            println!(
                "  spendable {} zat, pending {} zat, scanned to {:?} of {:?}",
                balance.spendable, balance.pending, balance.scanned_height, balance.chain_height
            );
        }
        "send" => {
            let via = PathBuf::from(required(&args, "--via")?);
            let to = required(&args, "--to")?;
            let amount: u64 = required(&args, "--amount")?.parse().context("--amount in zatoshis")?;
            let prepared = zcash_frost::send_prepare(&dir, net, to, amount, option(&args, "--memo"))?;
            println!(
                "  prepared: {} zat to {}, fee {} zat",
                prepared.summary.amount, prepared.summary.recipient, prepared.summary.fee
            );
            let (pending, payload, report) = zcash_frost::send_request(&dir, &prepared, &seed(&dir)?)?;
            for line in &report.lines {
                println!("  coordinator's check: {line}");
            }
            write(&via, "sign-1-request.ur", &payload)?;
            let reply = zcash_frost::read_reply(&pending, &read(&via, "sign-2-reply.ur")?)?;
            println!("  proving and broadcasting…");
            let txid = zcash_frost::send_finish(&dir, pending, &reply)?;
            println!("  broadcast: {txid}");
        }
        _ => bail!("usage: frost_coordinator <setup | sync | balance | send> --net test|main --dir DIR ..."),
    }
    Ok(())
}
