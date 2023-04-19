use pcap::{Capture, Device};
use std::error::Error;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let url_str = "https://hitomi.la";
    let client = reqwest::Client::builder()
        .tls_sni(false)
        .https_only(true)
        .user_agent("User-Agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36")
        .build()?;
    let res = client.get(url_str).send().await?;
    let res2 = res.text().await?;
    println!("{:#?}", client);
    println!("{:?}", res2); // good works. res status: 200 ok 

    // Todo: 패킷 sniff 하고, 해당 패킷의 sni 값을 변조해야함. 

    packet_sniff();
    Ok(())
}

fn packet_sniff() {
    let device = pcap::Device::lookup()
        .expect("device lookup failed")
        .expect("no device available");
    println!("Using device {}", device.name);

    // Setup Capture
    let mut cap = pcap::Capture::from_device(device)
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();
    // get a packet and print its bytes
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                println!("{:?}", cap.get_datalink());
            }
            Err(e) => {
                println!("Error: {}", e);
                break;
            }
        }
    }
    // println!("{:#?}", cap.stats());
}
