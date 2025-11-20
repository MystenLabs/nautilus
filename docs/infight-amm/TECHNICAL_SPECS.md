# In-fight AMM 技術仕様書

## 目次

- [Nautilus Fight Oracle](#nautilus-fight-oracle)
- [LSMR AMM 実装](#lsmr-amm-実装)
- [Math ライブラリ](#math-ライブラリ)
- [Move コントラクト](#move-コントラクト)
- [データ構造](#データ構造)
- [API仕様](#api仕様)

---

## Nautilus Fight Oracle

### 概要

Nautilus Enclave 内で動作する Trust Oracle。複数の外部 API から試合結果を取得し、クロスチェックして署名付きで返す。

### データ構造

#### **FightResult**

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FightResult {
    /// 試合ID（例: "ufc-300-main-event"）
    pub fight_id: String,

    /// 勝者（"FIGHTER_A" | "FIGHTER_B" | "DRAW"）
    pub winner: String,

    /// 決着方法（"KO" | "Submission" | "Decision"）
    pub method: String,

    /// 決着ラウンド（1-5）
    pub round: u8,

    /// Unix timestamp
    pub timestamp: i64,
}
```

#### **ProcessDataInput**

```rust
#[derive(Serialize, Deserialize, Debug)]
pub struct ProcessDataInput {
    /// 試合ID
    pub fight_id: String,
}
```

#### **LiveStats**（オプション）

```rust
#[derive(Serialize, Deserialize, Debug)]
pub struct LiveStats {
    pub fight_id: String,
    pub current_round: u8,
    pub fighter_a_strikes: u32,
    pub fighter_b_strikes: u32,
    pub fighter_a_takedowns: u8,
    pub fighter_b_takedowns: u8,
    pub control_time_a: u32,  // 秒
    pub control_time_b: u32,
    pub timestamp: i64,
}
```

### 主要関数

#### **process_data**

試合結果を取得して署名する。

```rust
pub async fn process_data(
    app_state: &AppState,
    input: &[u8],
) -> Result<Vec<u8>, EnclaveError> {
    // 1. 入力をデシリアライズ
    let input: ProcessDataInput = bcs::from_bytes(input)?;

    // 2. 複数のAPIから結果を取得
    let result_a = fetch_api_source_a(&input.fight_id, &app_state.api_keys).await?;
    let result_b = fetch_api_source_b(&input.fight_id, &app_state.api_keys).await?;
    let result_c = fetch_api_source_c(&input.fight_id, &app_state.api_keys).await?;

    // 3. クロスチェック（2/3以上の一致）
    let consensus = verify_consensus(result_a, result_b, result_c)?;

    // 4. 結果を構造化
    let result = FightResult {
        fight_id: input.fight_id.clone(),
        winner: consensus.winner,
        method: consensus.method,
        round: consensus.round,
        timestamp: Utc::now().timestamp(),
    };

    // 5. BCS シリアライズ
    let data = bcs::to_bytes(&result)?;

    // 6. IntentMessage でラップ
    let intent_message = IntentMessage {
        intent: vec![0, 0, 0],  // Sui intent scope
        data,
    };

    // 7. エンクレーブ鍵で署名
    let signed = to_signed_response(&intent_message, &app_state.keypair)?;

    Ok(signed)
}
```

#### **verify_consensus**

複数のデータソースから合意を形成する。

```rust
fn verify_consensus(
    source_a: FightResult,
    source_b: FightResult,
    source_c: FightResult,
) -> Result<FightResult, EnclaveError> {
    // 勝者の一致をチェック
    let winners = vec![
        source_a.winner.clone(),
        source_b.winner.clone(),
        source_c.winner.clone(),
    ];

    // 2/3以上の一致が必要
    if (source_a.winner == source_b.winner) ||
       (source_a.winner == source_c.winner) {
        Ok(source_a)
    } else if source_b.winner == source_c.winner {
        Ok(source_b)
    } else {
        Err(EnclaveError::DataMismatch)
    }
}
```

### エンドポイント

#### **POST /settle_fight**

試合結果を取得して署名付きで返す。

**リクエスト**:
```json
{
  "fight_id": "ufc-300-main-event"
}
```

**レスポンス**:
```json
{
  "signed_result": "0x1234567890abcdef...",
  "signature": "0xabcdef1234567890...",
  "public_key": "0x9876543210fedcba..."
}
```

#### **POST /live_stats**（オプション）

ライブ統計を取得。

**リクエスト**:
```json
{
  "fight_id": "ufc-300-main-event"
}
```

**レスポンス**:
```json
{
  "signed_stats": "0x...",
  "signature": "0x...",
  "public_key": "0x..."
}
```

---

## LSMR AMM 実装

### 数学的背景

#### **LSMR (Logarithmic Market Scoring Rule)**

予測市場に最適化された価格発見メカニズム。

**コスト関数**:
```
C(q₁, q₂) = b · ln(e^(q₁/b) + e^(q₂/b))
```

**価格（確率）**:
```
p₁ = e^(q₁/b) / (e^(q₁/b) + e^(q₂/b))
p₂ = e^(q₂/b) / (e^(q₁/b) + e^(q₂/b))
```

**購入コスト**:
```
cost = C(q₁ + Δq₁, q₂) - C(q₁, q₂)
```

**パラメータ**:
- `b`: 流動性パラメータ（大きいほど価格変動が小さい）
- `qᵢ`: 各アウトカムの outstanding shares

### データ構造

#### **LiquidityPool**

```move
public struct LiquidityPool has key, store {
    id: UID,

    // Outstanding shares
    q_a: u64,  // Fighter A のシェア数（固定小数点: 10^8）
    q_b: u64,  // Fighter B のシェア数（固定小数点: 10^8）

    // 流動性パラメータ（固定小数点: 10^8）
    b: u64,    // デフォルト: 10.0 * 10^8 = 1_000_000_000

    // 決済情報
    is_settled: bool,
    winning_outcome: u8,  // 0 = A, 1 = B

    // プール内の資金
    balance: Balance<SUI>,
}
```

#### **Position**

```move
public struct Position has key, store {
    id: UID,
    pool_id: address,
    shares_a: u64,  // 保有する Fighter A のシェア
    shares_b: u64,  // 保有する Fighter B のシェア
}
```

### 主要関数

#### **create_pool**

新しい LSMR プールを作成。

```move
public fun create_pool(
    initial_liquidity: Coin<SUI>,
    ctx: &mut TxContext
): LiquidityPool {
    let amount = coin::value(&initial_liquidity);

    LiquidityPool {
        id: object::new(ctx),
        q_a: 0,  // 初期状態: 50:50
        q_b: 0,
        b: LIQUIDITY_PARAM,  // 10.0 * 10^8
        is_settled: false,
        winning_outcome: 0,
        balance: coin::into_balance(initial_liquidity),
    }
}
```

#### **cost_function**

LSMR コスト関数を計算。

```move
fun cost_function(q_a: u64, q_b: u64, b: u64): u64 {
    // q_a / b
    let qa_over_b = math::div_scale(q_a, b);

    // q_b / b
    let qb_over_b = math::div_scale(q_b, b);

    // e^(q_a/b)
    let exp_qa = math::exp(qa_over_b, false);

    // e^(q_b/b)
    let exp_qb = math::exp(qb_over_b, false);

    // e^(q_a/b) + e^(q_b/b)
    let sum = exp_qa + exp_qb;

    // ln(sum)
    let (ln_sum, _) = math::ln(sum);

    // b · ln(sum)
    math::mul_scale(b, ln_sum)
}
```

#### **get_price_a**

Fighter A の現在価格を取得。

```move
public fun get_price_a(pool: &LiquidityPool): u64 {
    // q_a / b
    let qa_over_b = math::div_scale(pool.q_a, pool.b);

    // q_b / b
    let qb_over_b = math::div_scale(pool.q_b, pool.b);

    // e^(q_a/b)
    let exp_qa = math::exp(qa_over_b, false);

    // e^(q_b/b)
    let exp_qb = math::exp(qb_over_b, false);

    // p_a = e^(q_a/b) / (e^(q_a/b) + e^(q_b/b))
    let sum = exp_qa + exp_qb;
    math::div_scale(exp_qa, sum)
}

public fun get_price_b(pool: &LiquidityPool): u64 {
    SCALE - get_price_a(pool)  // p_b = 1 - p_a
}
```

#### **calculate_cost**

シェア購入のコストを計算。

```move
public fun calculate_cost(
    pool: &LiquidityPool,
    outcome: u8,
    shares: u64
): u64 {
    let current_cost = cost_function(pool.q_a, pool.q_b, pool.b);

    let new_cost = if (outcome == 0) {
        // Fighter A のシェアを購入
        cost_function(pool.q_a + shares, pool.q_b, pool.b)
    } else {
        // Fighter B のシェアを購入
        cost_function(pool.q_a, pool.q_b + shares, pool.b)
    };

    // コストの差分
    if (new_cost > current_cost) {
        new_cost - current_cost
    } else {
        0
    }
}
```

#### **buy_shares**

シェアを購入。

```move
public fun buy_shares(
    pool: &mut LiquidityPool,
    position: &mut Position,
    outcome: u8,
    shares: u64,
    payment: Coin<SUI>,
    ctx: &mut TxContext
) {
    assert!(!pool.is_settled, EMarketSettled);
    assert!(shares > 0, EInvalidAmount);

    // コスト計算
    let cost = calculate_cost(pool, outcome, shares);
    let payment_amount = coin::value(&payment);
    assert!(payment_amount >= cost, EInsufficientPayment);

    // qᵢ を更新
    if (outcome == 0) {
        pool.q_a = pool.q_a + shares;
        position.shares_a = position.shares_a + shares;
    } else {
        pool.q_b = pool.q_b + shares;
        position.shares_b = position.shares_b + shares;
    };

    // 支払いをプールに追加
    balance::join(&mut pool.balance, coin::into_balance(payment));

    // イベント発行
    event::emit(SharesPurchased {
        buyer: tx_context::sender(ctx),
        outcome,
        shares,
        cost,
        new_price_a: get_price_a(pool),
        new_price_b: get_price_b(pool),
    });
}
```

---

## Math ライブラリ

### 概要

Move で指数関数と対数関数を実装するための数学ライブラリ。

### 固定小数点演算

**スケール**: 10^8（小数点以下8桁の精度）

```move
const SCALE: u128 = 100_000_000;
const SCALE_U64: u64 = 100_000_000;
```

**例**:
- `1.0` → `100_000_000`
- `2.71828182` → `271_828_182`
- `0.5` → `50_000_000`

### 指数関数

#### **exp(x, is_negative)**

テイラー展開で `e^x` を計算。

**数式**:
```
e^x = 1 + x + x²/2! + x³/3! + x⁴/4! + ... + x⁸/8!
```

**実装**:
```move
public fun exp(x: u64, is_negative: bool): u64 {
    if (is_negative) {
        // e^(-x) = 1 / e^x
        let exp_x = exp_positive(x);
        return div_scale(SCALE_U64, exp_x)
    };

    exp_positive(x)
}

fun exp_positive(x: u64): u64 {
    // 範囲チェック
    if (x > 10 * SCALE_U64) {
        return 220_264_657_948_067_165; // e^10 の上限
    };

    // テイラー展開
    let result: u128 = SCALE;  // 1.0
    let term: u128 = SCALE;

    // x / 1!
    term = (term * (x as u128)) / SCALE;
    result = result + term;

    // x² / 2!
    term = (term * (x as u128)) / SCALE / 2;
    result = result + term;

    // x³ / 3!
    term = (term * (x as u128)) / SCALE / 3;
    result = result + term;

    // ... x⁸ / 8! まで

    (result as u64)
}
```

**精度**:
- `e^0 = 1.0` ± 0.01
- `e^1 ≈ 2.71828` ± 0.001
- `e^2 ≈ 7.389` ± 0.01

### 対数関数

#### **ln(x)**

ニュートン法で `ln(x)` を計算。

**アルゴリズム**:
```
y_new = y + (x - e^y) / e^y
```

**実装**:
```move
public fun ln(x: u64): (u64, bool) {
    assert!(x > 0, E_DIVISION_BY_ZERO);

    // x < 1 の場合は負の結果
    if (x < SCALE_U64) {
        let result = ln_positive(div_scale(SCALE_U64, x));
        return (result, true)  // 負の値
    };

    (ln_positive(x), false)
}

fun ln_positive(x: u64): u64 {
    if (x == SCALE_U64) {
        return 0  // ln(1) = 0
    };

    // 初期推定値
    let y: u64 = if (x > SCALE_U64) {
        x - SCALE_U64
    } else {
        SCALE_U64 - x
    };

    // ニュートン法（10回反復）
    let i = 0;
    while (i < 10) {
        let exp_y = exp_positive(y);
        let diff = if (x > exp_y) {
            x - exp_y
        } else {
            exp_y - x
        };

        let adjustment = div_scale(diff, exp_y);

        if (x > exp_y) {
            y = y + adjustment / 2;
        } else {
            if (y > adjustment / 2) {
                y = y - adjustment / 2;
            } else {
                break
            }
        };

        i = i + 1;
    };

    y
}
```

**精度**:
- `ln(1) = 0` 正確
- `ln(e) = 1.0` ± 0.01
- `ln(10) ≈ 2.302` ± 0.01

### 固定小数点演算

#### **mul_scale**

```move
public fun mul_scale(a: u64, b: u64): u64 {
    let result = (a as u128) * (b as u128) / SCALE;
    (result as u64)
}
```

**例**:
```
mul_scale(200_000_000, 150_000_000)
= (2.0 * 1.5) * 10^8
= 300_000_000  // 3.0
```

#### **div_scale**

```move
public fun div_scale(a: u64, b: u64): u64 {
    assert!(b > 0, E_DIVISION_BY_ZERO);
    let result = (a as u128) * SCALE / (b as u128);
    (result as u64)
}
```

**例**:
```
div_scale(300_000_000, 200_000_000)
= (3.0 / 2.0) * 10^8
= 150_000_000  // 1.5
```

---

## Move コントラクト

### Fight Market

#### **create_market**

新しい試合市場を作成。

```move
public entry fun create_market(
    fight_id: vector<u8>,
    fighter_a: vector<u8>,
    fighter_b: vector<u8>,
    initial_liquidity: Coin<SUI>,
    ctx: &mut TxContext
) {
    let pool = amm::create_pool(initial_liquidity, ctx);

    let market = FightMarket {
        id: object::new(ctx),
        fight_id,
        fighter_a,
        fighter_b,
        pool,
    };

    transfer::share_object(market);
}
```

#### **settle_market**

Nautilus からの結果で市場を決済。

```move
public entry fun settle_market(
    market: &mut FightMarket,
    enclave: &Enclave<FIGHT_ORACLE>,
    signed_result: vector<u8>,
    signature: vector<u8>,
) {
    // 1. Nautilus 署名を検証
    enclave::verify_signature(enclave, signed_result, signature);

    // 2. 結果をデコード
    let result = oracle::decode_result(signed_result);
    let winner = oracle::get_winner(&result);

    // 3. AMM プールを決済
    amm::settle_pool(&mut market.pool, winner);
}
```

#### **claim_winnings**

報酬を請求。

```move
public entry fun claim_winnings(
    market: &FightMarket,
    position: &mut Position,
    ctx: &mut TxContext
) {
    let payout = amm::claim_winnings(&market.pool, position, ctx);
    transfer::public_transfer(payout, tx_context::sender(ctx));
}
```

---

## データ構造

### Rust ↔ Move 対応

| Rust型 | Move型 | BCS エンコード |
|--------|--------|---------------|
| `String` | `vector<u8>` | UTF-8 bytes |
| `u8` | `u8` | 1 byte |
| `u64` | `u64` | 8 bytes (little-endian) |
| `i64` | `u64` | 8 bytes (符号なし扱い) |

### BCS シリアライゼーション

**Rust 側**:
```rust
let result = FightResult {
    fight_id: "ufc-300".to_string(),
    winner: "FIGHTER_A".to_string(),
    method: "KO".to_string(),
    round: 2,
    timestamp: 1234567890,
};

let bytes = bcs::to_bytes(&result)?;
```

**Move 側**:
```move
// 簡易デコード（デモ用）
public fun decode_result(data: vector<u8>): FightResult {
    // 実際は BCS デシリアライザを使用
    FightResult {
        fight_id: b"ufc-300",
        winner: 0,  // FIGHTER_A
        method: 0,  // KO
        round: 2,
        timestamp: 1234567890,
    }
}
```

---

## API仕様

### Nautilus Enclave

**ベースURL**: `http://localhost:3000`

#### **POST /settle_fight**

試合結果を取得。

**リクエスト**:
```http
POST /settle_fight HTTP/1.1
Content-Type: application/json

{
  "fight_id": "ufc-300-main-event"
}
```

**レスポンス**:
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "signed_result": "0x...",
  "signature": "0x...",
  "public_key": "0x..."
}
```

### Sui Blockchain

#### **create_market**

```bash
sui client call \
  --package $PACKAGE_ID \
  --module market \
  --function create_market \
  --args "ufc-300-main" "Alex Pereira" "Jamahal Hill" 1000000000 \
  --gas-budget 10000000
```

#### **buy_shares**

```bash
sui client call \
  --package $PACKAGE_ID \
  --module market \
  --function buy_shares \
  --args $MARKET_ID $POSITION_ID 0 100000000 $PAYMENT \
  --gas-budget 10000000
```

#### **settle_market**

```bash
sui client call \
  --package $PACKAGE_ID \
  --module market \
  --function settle_market \
  --args $MARKET_ID $ENCLAVE_ID $SIGNED_RESULT $SIGNATURE \
  --gas-budget 10000000
```

---

## まとめ

この技術仕様書に従って実装すれば、本格的な LSMR AMM と Nautilus Trust Oracle を統合した予測市場を構築できます。

**次のステップ**: [実装計画](./IMPLEMENTATION_PLAN.md) に従って開発を進めてください。
