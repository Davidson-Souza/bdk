use bdk::blockchain::utreexo::UtreexoBlockchain;
use bdk::blockchain::utreexo::UtreexoError;

use bdk::database::MemoryDatabase;
use bdk::*;
use bitcoin::*;
use log::info;
use std::sync::Arc;

fn main() -> Result<(), UtreexoError> {
    env_logger::init();
    info!("start");

    let peers = vec!["127.0.0.1:38333"];
    let blockchain = UtreexoBlockchain::new(peers, Network::Signet);
    blockchain.sync_headers()?;
    // let descriptor = "wpkh(xpub6BetPhzxxFy1v3TnTJwkPAeMbNLn3vVTofpuR5Bx4qtrZiqgRSxoSH2zPhQadgHeiiHVbr4w3aryoLH29Fq5iSNpXCww7TEzHw5ccGwk3uj)";
    let  descriptor = "wpkh(tpubD6NzVbkrYhZ4X2yy78HWrr1M9NT8dKeWfzNiQqDdMqqa9UmmGztGGz6TaLFGsLfdft5iu32gxq1T4eMNxExNNWzVCpf9Y6JZi5TnqoC9wJq)";
    let database = MemoryDatabase::default();
    let wallet = Arc::new(Wallet::new(descriptor, None, Network::Signet, database).unwrap());

    let err = wallet.sync(&blockchain, SyncOptions::default());
    if err.is_err() {
        println!("Error: {:?}", err);
    } else {
        println!("done {:?}", wallet.get_balance());
    }

    Ok(())
}
