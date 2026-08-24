//! TypeBit example: parse every supported download link and verify content.
//!
//! Run with:  cargo run --example parse_links
//!
//! This shows the unified `parse_link` entry point — one function, ten
//! formats — plus `ContentId` cross-format verification.

use typebit::links::{parse_link, ContentFamily, ContentId, DownloadLink};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let links = [
        // BitTorrent magnet (BEP-9)
        "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=ubuntu.iso",
        // eD2k / eMule (MD4 file hash)
        "ed2k://|file|hello.bin|3|a448017aaf21d8525fc10ae87aa6729d|/",
        // Xunlei: base64(AA <url> ZZ)
        "thunder://QUFodHRwOi8vZXhhbXBsZS5jb20vZi5yYXJaWg==",
        // QQ Xuanfeng: base64(url)
        "qqdl://aHR0cDovL2V4YW1wbGUuY29tL2YucmFy",
        // FlashGet: [FLASHGET] base64(url) [/FLASHGET]
        "flashget://[FLASHGET]QUFodHRwOi8vZXhhbXBsZS5jb20vZi5yYXJaWg==[/FLASHGET]",
        // IPFS CIDv0
        "ipfs://QmNp5n7FFav5ZDaHAj6HzuhJ8LDbL1N6NRzAgT6piWS2Kx",
        // eMule Kad node
        "kad://00112233445566778899aabbccddeeff@127.0.0.1:4661",
        // Direct HTTPS link
        "https://cdn.example.com/data.bin",
        // Baidu Netdisk share (needs host cookies to actually fetch)
        "https://pan.baidu.com/s/1abcDEF123?pwd=uvw4",
        // Xunlei Netdisk share (same credential caveat)
        "https://pan.xunlei.com/s/AbCdEfGh?pwd=1234",
    ];

    for raw in links {
        match parse_link(raw) {
            Ok(link) => println!("[{:>10}] {raw}", link.kind()),
            Err(e) => println!("[{:>10}] {raw}  ->  error: {e:?}", "!!"),
        }
    }
    println!();

    let data = b"the quick brown fox jumps over the lazy dog";
    let id = ContentId::digest_of(ContentFamily::Sha256, data);
    println!("sha256(id)          = {}", hex(id.digest()));
    println!("verify(original)    = {}", id.verify(data));
    println!("verify(tampered)    = {}", id.verify(b"tampered"));
    println!("receipt root (32 B) = {}", hex(&id.to_root()));

    // Show what each variant looks like when you match on it.
    match parse_link(links[1]).unwrap() {
        DownloadLink::Ed2k(f) => {
            println!(
                "\ned2k file: {} ({} bytes), MD4 = {}",
                f.name,
                f.size,
                hex(&f.hash)
            );
        }
        other => println!("unexpected: {other:?}"),
    }
    Ok(())
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}
