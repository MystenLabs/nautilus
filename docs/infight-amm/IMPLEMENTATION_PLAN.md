# In-fight AMM 実装計画（2日間）

## 目次

- [実装概要](#実装概要)
- [Day 1: バックエンド実装](#day-1-バックエンド実装)
- [Day 2: 統合とデモ準備](#day-2-統合とデモ準備)
- [タスク一覧](#タスク一覧)
- [実装の優先順位](#実装の優先順位)
- [トラブルシューティング](#トラブルシューティング)

---

## 実装概要

### 実装する機能

**Must Have（絶対必要）**:
1. ✅ Nautilus Fight Oracle（自動決済）
2. ✅ LSMR AMM（指数関数）
3. ✅ Move コントラクト統合
4. ✅ フロントエンド（モック連携）

**Nice to Have（時間があれば）**:
5. ⭕ Nautilus Live Stats（ライブ統計）
6. ⭕ `sell_shares()` 実装
7. ⭕ 詳細なテストケース

**実装しない（将来計画）**:
- ❌ Walrus 統合
- ❌ SEAL 統合
- ❌ AWS デプロイ
- ❌ AI 予測モデル

### 時間配分

| Day | タスク | 時間 |
|-----|--------|------|
| Day 1 午前 | Nautilus Fight Oracle | 4時間 |
| Day 1 午後前半 | 署名検証（Move） | 1時間 |
| Day 1 午後後半 | LSMR AMM（Math + AMM） | 6時間 |
| Day 1 夜 | デバッグ | 1時間 |
| Day 2 午前 | 統合（Fight Market） | 2時間 |
| Day 2 午前後半 | 統合テスト | 2時間 |
| Day 2 午後 | デモ準備 | 5時間 |
| **合計** | | **21時間** |

---

## Day 1: バックエンド実装

### 🌅 午前（9:00-13:00, 4時間）

#### **Task 1: Nautilus Fight Oracle 実装**

**目標**: Rust で Fight Oracle を実装し、モックデータで動作確認

**ステップ**:

1. **プロジェクトセットアップ**（30分）
```bash
cd nautilus/src/nautilus-server/src/apps
cp -r weather-example fight-oracle
```

2. **mod.rs 実装**（2時間）
```rust
// src/nautilus-server/src/apps/fight-oracle/mod.rs

use crate::common::{to_signed_response, AppState, EnclaveError, IntentMessage};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct FightResult {
    pub fight_id: String,
    pub winner: String,      // "FIGHTER_A" or "FIGHTER_B"
    pub method: String,      // "KO", "Submission", "Decision"
    pub round: u8,
    pub timestamp: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProcessDataInput {
    pub fight_id: String,
}

pub async fn process_data(
    app_state: &AppState,
    input: &[u8],
) -> Result<Vec<u8>, EnclaveError> {
    let input: ProcessDataInput = bcs::from_bytes(input)?;

    // モックデータ（デモ用）
    let result = FightResult {
        fight_id: input.fight_id.clone(),
        winner: "FIGHTER_A".to_string(),
        method: "KO".to_string(),
        round: 2,
        timestamp: chrono::Utc::now().timestamp(),
    };

    // BCS シリアライズ
    let data = bcs::to_bytes(&result)?;

    // IntentMessage でラップ
    let intent_message = IntentMessage {
        intent: vec![0, 0, 0],
        data,
    };

    // エンクレーブ鍵で署名
    let signed = to_signed_response(&intent_message, &app_state.keypair)?;

    Ok(signed)
}

// （オプション）ライブ統計
#[derive(Serialize, Deserialize, Debug)]
pub struct LiveStats {
    pub fight_id: String,
    pub current_round: u8,
    pub fighter_a_strikes: u32,
    pub fighter_b_strikes: u32,
    pub timestamp: i64,
}

pub async fn get_live_stats(
    app_state: &AppState,
    fight_id: String,
) -> Result<Vec<u8>, EnclaveError> {
    // モックデータ
    let stats = LiveStats {
        fight_id,
        current_round: 2,
        fighter_a_strikes: 45,
        fighter_b_strikes: 28,
        timestamp: chrono::Utc::now().timestamp(),
    };

    let data = bcs::to_bytes(&stats)?;
    let intent_message = IntentMessage {
        intent: vec![0, 0, 0],
        data,
    };

    let signed = to_signed_response(&intent_message, &app_state.keypair)?;

    Ok(signed)
}
```

3. **main.rs にエンドポイント追加**（1時間）
```rust
// src/nautilus-server/src/main.rs

#[cfg(feature = "fight-oracle")]
use apps::fight_oracle;

#[cfg(feature = "fight-oracle")]
#[axum::debug_handler]
async fn settle_fight(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let fight_id = payload["fight_id"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "Missing fight_id".to_string()))?
        .to_string();

    let input = bcs::to_bytes(&fight_oracle::ProcessDataInput { fight_id })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let result = fight_oracle::process_data(&app_state, &input)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "signed_result": hex::encode(result)
    })))
}

// main 関数でルートに追加
#[cfg(feature = "fight-oracle")]
let app = app
    .route("/settle_fight", post(settle_fight));
```

4. **Cargo.toml 更新**（10分）
```toml
[features]
fight-oracle = []
```

5. **ビルドとテスト**（20分）
```bash
cargo build --features fight-oracle
cargo test --features fight-oracle
cargo run --features fight-oracle
```

**チェックポイント**:
- [ ] `cargo build` 成功
- [ ] `cargo test` 成功
- [ ] エンドポイント `/settle_fight` が応答する

---

### 🍱 昼休憩（13:00-14:00, 1時間）

---

### 🌆 午後前半（14:00-15:00, 1時間）

#### **Task 2: Move 署名検証（Oracle Module）**

**目標**: Rust 側のデータ構造に対応する Move モジュールを作成

**ステップ**:

1. **プロジェクトセットアップ**（10分）
```bash
mkdir -p move/fight-oracle/sources
```

2. **Move.toml 作成**（5分）
```toml
[package]
name = "fight_oracle"
version = "0.1.0"
edition = "2024.beta"

[dependencies]
Sui = { git = "https://github.com/MystenLabs/sui.git", subdir = "crates/sui-framework/packages/sui-framework", rev = "testnet" }

[addresses]
fight_oracle = "0x0"
```

3. **oracle.move 実装**（40分）
```move
module fight_oracle::oracle {
    use std::vector;

    // Fight結果の構造体（Rust側と一致）
    public struct FightResult has copy, drop, store {
        fight_id: vector<u8>,
        winner: u8,        // 0 = FIGHTER_A, 1 = FIGHTER_B, 2 = DRAW
        method: u8,        // 0 = KO, 1 = Submission, 2 = Decision
        round: u8,
        timestamp: u64,
    }

    // BCS デコード用（簡易版）
    public fun decode_result(data: vector<u8>): FightResult {
        // 実際の実装ではBCSでデコード
        // デモ用には固定値
        FightResult {
            fight_id: b"ufc-300-main",
            winner: 0,  // FIGHTER_A
            method: 0,  // KO
            round: 2,
            timestamp: 1234567890,
        }
    }

    public fun get_winner(result: &FightResult): u8 {
        result.winner
    }

    public fun get_method(result: &FightResult): u8 {
        result.method
    }

    public fun get_round(result: &FightResult): u8 {
        result.round
    }
}
```

4. **ビルド**（5分）
```bash
cd move/fight-oracle
sui move build
```

**チェックポイント**:
- [ ] `sui move build` 成功
- [ ] 構造体が Rust 側と一致している

---

### 🌇 午後後半（15:00-21:00, 6時間）

#### **Task 3: LSMR AMM 実装**

**目標**: 指数関数を使った本格的な LSMR AMM を実装

**3.1 Math Module（15:00-18:00, 3時間）**

1. **セットアップ**（10分）
```bash
mkdir -p move/lsmr-amm/sources
```

2. **Move.toml 作成**（5分）
```toml
[package]
name = "lsmr_amm"
version = "0.1.0"
edition = "2024.beta"

[dependencies]
Sui = { git = "https://github.com/MystenLabs/sui.git", subdir = "crates/sui-framework/packages/sui-framework", rev = "testnet" }

[addresses]
lsmr_amm = "0x0"
```

3. **math.move 実装**（2時間30分）

実装内容：
- 固定小数点演算（`mul_scale`, `div_scale`）
- 指数関数（`exp`, `exp_positive`）- テイラー展開8次まで
- 対数関数（`ln`, `ln_positive`）- ニュートン法10回反復
- ユーティリティ関数（`max`, `min`, `get_scale`）

詳細は [TECHNICAL_SPECS.md](./TECHNICAL_SPECS.md) を参照

4. **テスト**（15分）
```bash
sui move test
```

**チェックポイント**:
- [ ] `test_exp` 成功（e^0, e^1, e^2 の精度確認）
- [ ] `test_ln` 成功（ln(1), ln(e) の精度確認）

**3.2 AMM Module（18:00-21:00, 3時間）**

1. **amm.move 実装**（2時間30分）

実装内容：
- `LiquidityPool` 構造体
- `Position` 構造体
- `create_pool()` - プール作成
- `cost_function()` - LSMR コスト関数
- `calculate_cost()` - シェア購入コスト計算
- `get_price_a/b()` - 現在価格取得
- `buy_shares()` - シェア購入
- `sell_shares()` - シェア売却（時間があれば）
- `settle_pool()` - 市場決済
- `claim_winnings()` - 報酬請求

詳細は [TECHNICAL_SPECS.md](./TECHNICAL_SPECS.md) を参照

2. **テスト**（30分）
```move
#[test]
fun test_lsmr_pricing() {
    // 初期価格が50:50であることを確認
    // シェア購入後に価格が変動することを確認
}
```

**チェックポイント**:
- [ ] `sui move build` 成功
- [ ] `sui move test` 成功
- [ ] 価格計算が正しく動作する

---

### 🌙 夜（21:00-22:00, 1時間）

#### **デバッグとクリーンアップ**

- コンパイルエラーの修正
- テスト失敗の修正
- コードのリファクタリング
- コミット & プッシュ

---

## Day 2: 統合とデモ準備

### 🌅 午前（9:00-11:00, 2時間）

#### **Task 4: Fight Market 統合**

**目標**: すべてのモジュールを統合する市場管理コントラクトを作成

**ステップ**:

1. **セットアップ**（10分）
```bash
mkdir -p move/fight-market/sources
```

2. **Move.toml 作成**（5分）
```toml
[package]
name = "fight_market"
version = "0.1.0"
edition = "2024.beta"

[dependencies]
Sui = { git = "https://github.com/MystenLabs/sui.git", subdir = "crates/sui-framework/packages/sui-framework", rev = "testnet" }
Enclave = { local = "../enclave" }
FightOracle = { local = "../fight-oracle" }
LsmrAmm = { local = "../lsmr-amm" }

[addresses]
fight_market = "0x0"
```

3. **market.move 実装**（1時間30分）
```move
module fight_market::market {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::coin::Coin;
    use sui::sui::SUI;
    use enclave::enclave::{Self, Enclave};
    use fight_oracle::oracle::{Self, FightResult};
    use lsmr_amm::amm::{Self, LiquidityPool, Position};

    public struct FightMarket has key {
        id: UID,
        fight_id: vector<u8>,
        fighter_a: vector<u8>,
        fighter_b: vector<u8>,
        pool: LiquidityPool,
    }

    public struct FIGHT_ORACLE has drop {}

    // 市場作成
    public entry fun create_market(...)

    // シェア購入
    public entry fun buy_shares(...)

    // Nautilus 統合（自動決済）
    public entry fun settle_market(
        market: &mut FightMarket,
        enclave: &Enclave<FIGHT_ORACLE>,
        signed_result: vector<u8>,
        signature: vector<u8>,
    ) {
        // 1. 署名検証
        enclave::verify_signature(enclave, signed_result, signature);

        // 2. 結果デコード
        let result = oracle::decode_result(signed_result);
        let winner = oracle::get_winner(&result);

        // 3. プール決済
        amm::settle_pool(&mut market.pool, winner);
    }

    // 報酬請求
    public entry fun claim_winnings(...)
}
```

4. **ビルド**（15分）
```bash
sui move build
```

**チェックポイント**:
- [ ] すべての依存関係が解決されている
- [ ] `sui move build` 成功

---

### 🌆 午前後半（11:00-13:00, 2時間）

#### **Task 5: 統合テスト**

**目標**: エンドツーエンドのフローをテスト

**ステップ**:

1. **Nautilus を起動**（10分）
```bash
cd nautilus/src/nautilus-server
cargo run --features fight-oracle
```

2. **Move コントラクトをデプロイ（Testnet）**（30分）
```bash
sui client publish --gas-budget 100000000
```

3. **統合テストスクリプト作成**（1時間）
```bash
# test_integration.sh

# 1. 市場作成
sui client call \
  --package $PACKAGE_ID \
  --module market \
  --function create_market \
  --args "ufc-300-main" "Fighter A" "Fighter B" ...

# 2. シェア購入
sui client call \
  --package $PACKAGE_ID \
  --module market \
  --function buy_shares \
  --args ...

# 3. Nautilus から結果取得
RESULT=$(curl -X POST http://localhost:3000/settle_fight \
  -H "Content-Type: application/json" \
  -d '{"fight_id": "ufc-300-main"}')

# 4. 決済
sui client call \
  --package $PACKAGE_ID \
  --module market \
  --function settle_market \
  --args $MARKET_ID $ENCLAVE_ID $RESULT $SIGNATURE

# 5. 報酬請求
sui client call \
  --package $PACKAGE_ID \
  --module market \
  --function claim_winnings \
  --args ...
```

4. **テスト実行とデバッグ**（20分）

**チェックポイント**:
- [ ] 市場作成が成功
- [ ] シェア購入が成功
- [ ] Nautilus から結果取得
- [ ] 決済が成功
- [ ] 報酬請求が成功

---

### 🍱 昼休憩（13:00-14:00, 1時間）

---

### 🌇 午後（14:00-19:00, 5時間）

#### **Task 6: デモ準備**

**6.1 フロントエンド統合（14:00-15:00, 1時間）**

既存のフロントエンドに実際のエンドポイントを接続：

```typescript
// src/services/nautilus.ts
export async function settleFight(fightId: string) {
  const response = await fetch('http://localhost:3000/settle_fight', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fight_id: fightId })
  });

  return response.json();
}

// src/services/sui.ts
export async function settleMarket(
  marketId: string,
  enclaveId: string,
  signedResult: string,
  signature: string
) {
  // Sui SDK を使って settle_market を呼び出す
}
```

**6.2 デモ動画録画（15:00-16:00, 1時間）**

録画内容：
1. 市場作成画面（15秒）
2. ライブ統計表示（30秒）
3. シェア購入（価格変動を見せる）（30秒）
4. 試合終了 → 決済ボタンクリック（30秒）
5. 自動決済完了 → 報酬請求（30秒）
6. Nautilus の検証可能性を説明（30秒）

合計: 2-3分

**6.3 GitHub README 作成（16:00-17:00, 1時間）**

内容：
- プロジェクト概要
- アーキテクチャ図
- クイックスタート
- デモ動画リンク
- 技術スタック
- チーム情報

**6.4 ピッチスライド作成（17:00-19:00, 2時間）**

9枚のスライド：
1. タイトル
2. 問題提起
3. ソリューション
4. アーキテクチャ
5. Nautilus の強み
6. デモ動画
7. Provably Authentic Track
8. Future Roadmap
9. まとめ

詳細は [PITCH_GUIDE.md](./PITCH_GUIDE.md) を参照

---

### 🌙 夜（19:00-20:00, 1時間）

#### **最終チェック**

- [ ] すべてのコードがコミットされている
- [ ] README が完成している
- [ ] デモ動画がアップロードされている
- [ ] ピッチスライドが完成している
- [ ] 動作確認（エンドツーエンド）
- [ ] プレゼン練習

---

## タスク一覧

### Day 1

| 時間 | タスク | 担当 | 優先度 | ステータス |
|------|--------|------|--------|-----------|
| 09:00-13:00 | Nautilus Fight Oracle | - | 🔴 Must | ⬜ |
| 14:00-15:00 | Move 署名検証 | - | 🔴 Must | ⬜ |
| 15:00-18:00 | Math Module (指数・対数) | - | 🔴 Must | ⬜ |
| 18:00-21:00 | AMM Module (LSMR) | - | 🔴 Must | ⬜ |
| 21:00-22:00 | デバッグ | - | 🔴 Must | ⬜ |

### Day 2

| 時間 | タスク | 担当 | 優先度 | ステータス |
|------|--------|------|--------|-----------|
| 09:00-11:00 | Fight Market 統合 | - | 🔴 Must | ⬜ |
| 11:00-13:00 | 統合テスト | - | 🔴 Must | ⬜ |
| 14:00-15:00 | フロントエンド統合 | - | 🔴 Must | ⬜ |
| 15:00-16:00 | デモ動画録画 | - | 🔴 Must | ⬜ |
| 16:00-17:00 | GitHub README | - | 🔴 Must | ⬜ |
| 17:00-19:00 | ピッチスライド | - | 🔴 Must | ⬜ |
| 19:00-20:00 | 最終チェック | - | 🔴 Must | ⬜ |

---

## 実装の優先順位

### P0（絶対必要）
1. Nautilus Fight Oracle - 自動決済
2. LSMR AMM - 価格メカニズム
3. Math Module - 指数関数
4. Fight Market - 統合
5. 基本的な統合テスト

### P1（強く推奨）
6. デモ動画
7. ピッチスライド
8. GitHub README

### P2（時間があれば）
9. Nautilus Live Stats
10. `sell_shares()` 実装
11. 詳細なテストケース
12. エラーハンドリングの改善

### P3（将来計画）
13. Walrus 統合
14. SEAL 統合
15. AI 予測モデル

---

## トラブルシューティング

### よくある問題

#### **1. Cargo ビルドエラー**

```bash
error: failed to compile `nautilus-server`
```

**解決策**:
```bash
# 依存関係を更新
cargo clean
cargo update
cargo build --features fight-oracle
```

#### **2. Move ビルドエラー**

```bash
error: unresolved import
```

**解決策**:
- `Move.toml` の依存関係を確認
- パスが正しいか確認
- `sui move build --force` を実行

#### **3. 指数関数の精度が低い**

**症状**: `test_exp` が失敗する

**解決策**:
- テイラー展開の次数を増やす（現在8次）
- 範囲外の値は上限を設定（x > 10 の場合など）

#### **4. BCS デコードエラー**

```bash
error: BCS deserialization failed
```

**解決策**:
- Rust と Move の構造体が一致しているか確認
- フィールドの順序が同じか確認
- デバッグ用に固定値を返す

#### **5. Nautilus エンドポイントが応答しない**

**症状**: `curl` がタイムアウトする

**解決策**:
```bash
# ポートが使用中か確認
lsof -i :3000

# ログを確認
RUST_LOG=debug cargo run --features fight-oracle
```

---

## デバッグのヒント

### Rust デバッグ

```bash
# 詳細なログを有効化
RUST_LOG=debug cargo run --features fight-oracle

# 特定のモジュールのみ
RUST_LOG=fight_oracle=trace cargo run --features fight-oracle

# テストを詳細表示
cargo test --features fight-oracle -- --nocapture
```

### Move デバッグ

```bash
# ビルドログを詳細表示
sui move build --verbose

# テストを詳細表示
sui move test --verbose

# 特定のテストのみ実行
sui move test test_lsmr_pricing
```

### 統合デバッグ

```bash
# Nautilus のレスポンスを確認
curl -X POST http://localhost:3000/settle_fight \
  -H "Content-Type: application/json" \
  -d '{"fight_id": "test"}' | jq

# Sui トランザクションの詳細を確認
sui client call --help
sui client gas
sui client objects
```

---

## まとめ

この実装計画に従えば、2日間で In-fight AMM の MVP を完成できます。

**重要なポイント**:
- Day 1 は Nautilus と LSMR AMM に集中
- Day 2 は統合とデモ準備
- 優先順位を守る（P0 → P1 → P2）
- 詰まったらモックデータで進める

**次のステップ**: [技術仕様](./TECHNICAL_SPECS.md) で詳細な実装を確認してください。

---

**頑張ってください！🚀**
