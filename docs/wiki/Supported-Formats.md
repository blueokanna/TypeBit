# Supported Formats / 支持的格式

One entry point: `typebit::links::parse_link(&str) -> Result<DownloadLink>`.
Run `cargo run --example parse_links` to see all of them live.

## BitTorrent magnet（磁力）

```
magnet:?xt=urn:btih:<40-hex or 32-base32>&dn=...&tr=...&x.pe=...
```

Also accepts `urn:btmh:1220<64-hex>` (v2 multihash, BEP-53) and
`urn:sha1:<32-base32>` (web-seed magnet). Delegates to `typebit::magnet`.

## eD2k / eMule

```
ed2k://|file|<name>|<size>|<md4-hex>|/            single file
ed2k://|file|<name>|<size>|<md4-hex>|/|s=host:port|/   + servers
ed2k://|file|<name>|<size>|<md4-hex>|h=<aich-hex>|/    + AICH (SHA-1)
```

The file identity is MD4 (`crypto::md4`, RFC 1320 verified). TypeBit models
the file and can verify downloaded bytes; the eMule **transport** is a
roadmap item — real eD2k downloads need the eMule network.

## Xunlei（迅雷）

```
thunder://<base64(AA <real-url> ZZ)>
```

`crypto::base64` unwraps the `AA…ZZ` wrapper to the real HTTP/FTP URL.

## QQ Xuanfeng（QQ 旋风） & FlashGet

```
qqdl://<base64(url)>
flashget://[FLASHGET]<base64>[/FLASHGET]
```

Both decode to a plain URL.

## IPFS / IPNS

```
ipfs://<CIDv0|CIDv1>[/sub/path]
ipns://<name-or-CID>[/sub/path]
```

- CIDv0: `Qm…` base58, must be `0x12 0x20 + 32 bytes` (SHA-256)
- CIDv1: multibase `b`/`B` (base32) or `z` (base58), varint version/codec/multihash
- IPNS names may be CIDs or DNSLink domains (e.g. `docs.ipfs.tech`)

Content is fetched via an HTTP gateway: `IpfsLink::gateway_url("https://ipfs.io")`.
bitswap is not implemented yet.

## Kad node（eMule Kademlia 节点）

```
kad://<hex-or-base32-id>[@host:port]
kad://<id>|host:port
```

Numeric endpoints only (the core has no DNS); host names are rejected.

## Direct HTTP(S) / FTP（直链）

Any plain URL. Optionally content-addressed: pair it with a `ContentId`
(SHA-1 / MD4 / SHA-256 + size) and verify after download.

## Baidu / Xunlei Netdisk（百度 / 迅雷网盘）

```
https://pan.baidu.com/s/<code>?pwd=<extract>
https://pan.xunlei.com/s/<code>?pwd=<extract>
```

These are **authenticated services**. TypeBit parses and models them
(`DownloadLink::BaiduPan` / `XunleiPan`) so your UI can display and queue
them, but fetching requires a host-injected session (cookies) driving the
vendor API. There is no anonymous download path — anyone who claims
otherwise is lying.

## 下载格式一览 / Format matrix

| scheme | variant | needs credentials? |
|---|---|---|
| `magnet:` | `BitTorrent` | no |
| `ed2k://` | `Ed2k` | no (needs eMule net) |
| `thunder://` | `Thunder` | no |
| `qqdl://` | `Qqdl` | no |
| `flashget://` | `Flashget` | no |
| `ipfs://` `ipns://` | `Ipfs` | no (needs gateway) |
| `kad://` | `Kad` | no |
| `http(s)://` `ftp://` | `Url` | no |
| `pan.baidu.com` | `BaiduPan` | **yes** |
| `pan.xunlei.com` | `XunleiPan` | **yes** |
