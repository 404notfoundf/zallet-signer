# zallet-pczt-signer

最小 PoC signer：读取 Zallet 的 base64 PCZT，用单把外部 secp256k1 PEM 签名透明 P2PKH 输入。它不选币、不构造付款、不广播，也不支持 P2SH 或 shielded bundle。

> 仅用于 disposable regtest。当前实现没有连接节点独立核验 prevout；`policy.json` 必须来自独立可信的付款授权/链上核对流程。不要用于主网或真实资金。

## 当前命令

### 1. 从 Zallet 保存 PCZT

`pczt_create` 返回 PCZT 后，将 JSON-RPC 的 `result` 字符串内容原样保存到 `unsigned.pczt`。也可以保存完整 JSON 对象（包含字符串字段 `pczt`）。本工具接受这两种输入格式。

先解析并查看摘要：

```bash
cargo run --release -- inspect --pczt unsigned.pczt
```

工具显示交易版本、consensus branch ID、expiry height、透明输入 outpoint/金额/scriptPubKey、透明输出和手续费估算。输入 outpoint 中的 txid 是 PCZT 原始字节顺序；用于比对时不要自行反转。Zallet `pczt_inspect` 也应单独查看。

### 2. 写独立授权策略

按 `inspect` 的字段填写 `policy.json`。期望输出必须从付款请求/审批记录中独立取得，不能直接把 PCZT 自己报告的输出复制过去后就认为校验完成。

```json
{
  "tx_version": 5,
  "consensus_branch_id": 0,
  "expiry_height": 100,
  "inputs": [
    {
      "prevout_txid_raw_hex": "填写32字节小写hex",
      "prevout_index": 0,
      "value_zat": 100000,
      "script_pubkey_hex": "填写完整P2PKH scriptPubKey hex"
    }
  ],
  "outputs": [
    {
      "value_zat": 90000,
      "script_pubkey_hex": "填写收款和找零的实际scriptPubKey hex"
    }
  ],
  "max_fee_zat": 10000
}
```

上面所有值都是格式示例，必须换成你这笔交易的真实授权值；不能照抄这些数值。`outputs` 要按 PCZT 的顺序列出全部输出，包括找零。

### 3. 签名

```bash
cargo run --release -- sign \
  --pczt unsigned.pczt \
  --key "$HOME/zec-pczt/external-signer/poc-key.pem" \
  --policy policy.json \
  --output signed.pczt
```

如果 PEM 加密，程序会在终端交互读取密码；不会把密码作为命令行参数。输出文件已存在时命令会失败，不覆盖旧文件。`signed.pczt` 是 base64 签名 PCZT。

实现会检查：

- 交易版本、branch ID、expiry height 与策略一致；
- transparent 输入/输出数量和每项顺序、outpoint、金额、scriptPubKey 精确匹配；
- 没有 Sapling、Orchard 或 Ironwood 数据；
- 每个输入都是与 PEM 公钥匹配的 P2PKH；
- 输入减输出不为负，手续费不超过策略上限。

签名使用 `pczt::roles::signer::Signer::sign_transparent`，由固定版本 PCZT 库处理透明 sighash 和签名。Signer 不会因为解析成功就盲签。

### 4. 交回 Zallet 并广播

把 `signed.pczt` 文件内容（base64 字符串）传给 Zallet 的 `pczt_inspect`，确认签名状态及输入输出；再按当前 Zallet RPC help 调用 `pczt_extract`。将提取的 raw transaction 通过 Zebra `sendrawtransaction` 广播，并记录 txid、等待区块确认。

若 Zallet RPC CLI 要求 JSON 字符串参数，base64 参数需作为 JSON string 传入，例如：

```bash
zallet -d "$DATADIR" rpc pczt_inspect '"<signed.pczt中的base64内容>"'
```

先在你的 `zallet v0.1.0-beta.4` 环境用本机 `rpc help pczt_extract` 核对提取参数和返回格式。**签名成功不是广播成功；提取成功也不是节点接受。**

## Ubuntu 构建

在 Ubuntu/WSL 项目目录执行：

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev
cargo test --locked
cargo build --release --locked
./target/release/zallet-pczt-signer --help
```

Rust 版本要求 1.89 或更新。项目依赖 `pczt 0.10.0`，锁文件固定全部 crates 版本。

## 当前限制和下一步

- 本 PoC 只验证 signer 可以解析兼容 PCZT、校验策略并签一把 PEM 对应的 P2PKH 输入；当前测试只覆盖 P2PKH 脚本派生自检。
- 还没有用用户正在运行的 Zallet regtest PCZT 做真实签名、Zallet 提取、Zebra 广播和确认；这部分才是端到端通过标准。
- 策略内容必须通过独立可信来源核实。当前工具没有 RPC 客户端去 Zebra 查询 prevout，也没有验证交易地址编码与 `scriptPubKey` 的网络前缀对应关系；输出策略必须来自付款授权记录。
- 不支持 P2SH、多签、Sapling、Orchard、Ironwood、coinbase shielding、自动 UTXO reservation、重复支付账本、批量支付接口、HTTP API 或主网。
- 当前依赖 PCZT `0.10.0`；上线前必须确认与实际 Zallet 生成 PCZT 的格式和共识升级兼容，并做完整安全评审。