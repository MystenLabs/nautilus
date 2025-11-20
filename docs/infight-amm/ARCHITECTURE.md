# In-fight AMM アーキテクチャ設計

## 目次

- [システム概要](#システム概要)
- [コンポーネント構成](#コンポーネント構成)
- [データフロー](#データフロー)
- [技術スタック](#技術スタック)
- [セキュリティモデル](#セキュリティモデル)
- [スケーラビリティ](#スケーラビリティ)

---

## システム概要

In-fight AMM は、Nautilus Trust Oracle を中心とした3層アーキテクチャで構成されています。

```
┌─────────────────────────────────────────────────────┐
│                  Sui Blockchain                      │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────┐ │
│  │ LSMR AMM     │  │ Market       │  │ Enclave   │ │
│  │ (Liquidity)  │  │ Settlement   │  │ Registry  │ │
│  └──────────────┘  └──────────────┘  └───────────┘ │
└─────────────────────────────────────────────────────┘
         ▲                  ▲                 ▲
         │                  │                 │
         │  Trades      Signed Results    Attestation
         │                  │                 │
┌────────┴──────────────────┴─────────────────┴───────┐
│         Nautilus Enclave (Trust Oracle)             │
│  ┌──────────────────────────────────────────────┐   │
│  │ Fight Oracle Service                         │   │
│  │  • Fetch results from multiple APIs         │   │
│  │  • Cross-validate data sources               │   │
│  │  • Sign results with enclave key             │   │
│  │  • Provide live stats feed                   │   │
│  └──────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────┐   │
│  │ SEAL Integration (Future)                    │   │
│  │  • Secure API key storage                    │   │
│  │  • Fraud detection parameters                │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
         ▲                              │
         │                              │
         │  API Calls               Signed Data
         │                              │
┌────────┴──────────────┐      ┌────────▼─────────────┐
│  External APIs        │      │  Walrus Storage      │
│  • UFC API            │      │  (Future)            │
│  • ESPN API           │      │  • Fight metadata    │
│  • Tapology           │      │  • Trading history   │
│  • Live stats feed    │      │  • Audit logs        │
└───────────────────────┘      └──────────────────────┘
                                         ▲
                                         │
                                    Store & Retrieve
                                         │
                              ┌──────────┴──────────┐
                              │  Frontend dApp      │
                              │  • Live streaming   │
                              │  • AMM interface    │
                              │  • Real-time charts │
                              └─────────────────────┘
```

---

## コンポーネント構成

### 1. Nautilus Enclave Layer（Trust Oracle）

#### **役割**
- 試合結果の取得と検証
- 複数データソースのクロスチェック
- Ed25519 署名による証明
- （オプション）ライブ統計のフィード

#### **主要モジュール**

**Fight Oracle Service** (`src/nautilus-server/src/apps/fight-oracle/`)
```rust
pub struct FightResult {
    fight_id: String,
    winner: String,      // "FIGHTER_A" or "FIGHTER_B"
    method: String,      // "KO", "Submission", "Decision"
    round: u8,
    timestamp: i64,
}

pub async fn process_data(input: &[u8]) -> Result<Vec<u8>>
pub async fn get_live_stats(fight_id: String) -> Result<Vec<u8>>
```

**主要エンドポイント**
- `POST /settle_fight` - 試合結果の取得と署名
- `POST /live_stats` - ライブ統計データ（オプション）
- `GET /get_attestation` - AWS Nitro 認証ドキュメント
- `GET /health_check` - ヘルスチェック

#### **データ取得フロー**
```
1. クライアントからリクエスト
   ↓
2. 複数のAPIから結果を取得
   - UFC Official API
   - ESPN Stats API
   - Tapology Database
   ↓
3. クロスチェック（2/3以上の一致）
   ↓
4. 結果を BCS シリアライズ
   ↓
5. エンクレーブ鍵で Ed25519 署名
   ↓
6. 署名付きデータを返却
```

---

### 2. Blockchain Layer（Sui Move）

#### **2.1 LSMR AMM Module**

**場所**: `move/lsmr-amm/`

**構造体**:
```move
public struct LiquidityPool {
    id: UID,
    q_a: u64,           // Outstanding shares for Fighter A
    q_b: u64,           // Outstanding shares for Fighter B
    b: u64,             // Liquidity parameter
    is_settled: bool,
    winning_outcome: u8,
    balance: Balance<SUI>,
}

public struct Position {
    id: UID,
    pool_id: address,
    shares_a: u64,
    shares_b: u64,
}
```

**価格計算**:
```move
// LSMR価格関数
// p_a = e^(q_a/b) / (e^(q_a/b) + e^(q_b/b))
public fun get_price_a(pool: &LiquidityPool): u64

// コスト計算
// cost = C(q_a + Δq_a, q_b) - C(q_a, q_b)
public fun calculate_cost(
    pool: &LiquidityPool,
    outcome: u8,
    shares: u64
): u64
```

**取引機能**:
```move
public fun buy_shares(...)   // シェア購入
public fun sell_shares(...)  // シェア売却
public fun settle_pool(...)  // 市場決済
public fun claim_winnings(...) // 報酬請求
```

#### **2.2 Math Module**

**場所**: `move/lsmr-amm/sources/math.move`

**指数関数（テイラー展開）**:
```move
// e^x = 1 + x + x²/2! + x³/3! + ... (8次まで)
public fun exp(x: u64, is_negative: bool): u64
```

**対数関数（ニュートン法）**:
```move
// ln(x) をニュートン法で計算（10回反復）
public fun ln(x: u64): (u64, bool)
```

**固定小数点演算**:
- スケール: 10^8
- 精度: 小数点以下8桁
- オーバーフロー対策済み

#### **2.3 Fight Oracle Module**

**場所**: `move/fight-oracle/`

```move
public struct FightResult {
    fight_id: vector<u8>,
    winner: u8,
    method: u8,
    round: u8,
    timestamp: u64,
}

public fun decode_result(data: vector<u8>): FightResult
```

#### **2.4 Fight Market Module**

**場所**: `move/fight-market/`

**統合コントラクト**:
```move
public struct FightMarket {
    id: UID,
    fight_id: vector<u8>,
    fighter_a: vector<u8>,
    fighter_b: vector<u8>,
    pool: LiquidityPool,
}

// 市場作成
public entry fun create_market(...)

// 取引
public entry fun buy_shares(...)

// Nautilus統合（自動決済）
public entry fun settle_market(
    market: &mut FightMarket,
    enclave: &Enclave<FIGHT_ORACLE>,
    signed_result: vector<u8>,
    signature: vector<u8>,
)

// 報酬請求
public entry fun claim_winnings(...)
```

---

### 3. Frontend Layer

#### **技術スタック**
- React 18+ / Next.js
- TypeScript
- Sui Wallet Adapter
- TailwindCSS
- Recharts（価格チャート）

#### **主要コンポーネント**

**FightMarket.tsx**
- 試合情報表示
- ライブ統計表示（Nautilus連携）
- AMM取引インターフェース
- 価格チャート

**WalletConnect.tsx**
- Sui ウォレット接続
- トランザクション署名

**LiveStats.tsx**
- リアルタイム統計更新
- Nautilus からのデータフィード

---

## データフロー

### Phase 1: 市場作成（試合開始前）

```
User
  ↓ (1) Create Market
Frontend
  ↓ (2) sui client call
Sui Blockchain
  ↓ (3) create_market()
FightMarket Contract
  ↓ (4) create_pool()
LSMR AMM
  ↓ (5) Emit MarketCreated event
Frontend
  ↓ (6) Listen to event
User (Market Ready)
```

### Phase 2: ライブトレーディング（試合中）

```
User
  ↓ (1) Buy Shares
Frontend
  ↓ (2) Calculate cost (get_price_a, calculate_cost)
Sui Blockchain
  ↓ (3) buy_shares()
LSMR AMM
  ↓ (4) Update q_a, q_b
  ↓ (5) Emit SharesPurchased event
Frontend
  ↓ (6) Update price chart
User (Position updated)

（並行して）

Nautilus Enclave
  ↓ (1) Fetch live stats (30秒間隔)
  ↓ (2) Sign stats
Frontend
  ↓ (3) Display live stats
User (View real-time data)
```

### Phase 3: 自動決済（試合終了後）

```
Fight Ends
  ↓
User
  ↓ (1) Click "Settle"
Frontend
  ↓ (2) POST /settle_fight
Nautilus Enclave
  ↓ (3) Fetch results from APIs
  ↓     - UFC API
  ↓     - ESPN API
  ↓     - Tapology
  ↓ (4) Cross-validate (2/3 consensus)
  ↓ (5) Sign result with Ed25519
  ↓ (6) Return signed data
Frontend
  ↓ (7) sui client call settle_market
Sui Blockchain
  ↓ (8) Verify signature (enclave::verify_signature)
  ↓ (9) Decode result (oracle::decode_result)
  ↓ (10) settle_pool(winner)
LSMR AMM
  ↓ (11) Mark is_settled = true
  ↓ (12) Emit PoolSettled event
Frontend
  ↓ (13) Enable "Claim Winnings"
User
  ↓ (14) claim_winnings()
  ↓ (15) Receive payout
```

---

## 技術スタック

### Backend (Nautilus Enclave)

| 技術 | バージョン | 用途 |
|------|-----------|------|
| Rust | 1.87 | エンクレーブサーバー |
| axum | 0.7 | HTTP フレームワーク |
| tokio | 1.43 | 非同期ランタイム |
| fastcrypto | latest | Ed25519 署名 |
| nsm_api | latest | AWS Nitro API |
| bcs | 0.1.6 | シリアライゼーション |
| reqwest | 0.11 | HTTP クライアント |

### Blockchain (Sui Move)

| 技術 | バージョン | 用途 |
|------|-----------|------|
| Sui Move | 2024.beta | スマートコントラクト |
| Sui Framework | testnet | 標準ライブラリ |
| BCS | - | データエンコーディング |

### Frontend

| 技術 | バージョン | 用途 |
|------|-----------|------|
| React | 18+ | UI フレームワーク |
| TypeScript | 5+ | 型安全性 |
| Sui SDK | latest | ブロックチェーン連携 |
| TailwindCSS | 3+ | スタイリング |

### Infrastructure

| 技術 | 用途 |
|------|------|
| AWS Nitro Enclaves | TEE 実行環境 |
| Docker | 再現可能なビルド |
| GitHub Actions | CI/CD |

---

## セキュリティモデル

### 信頼性の保証

#### 1. **Nautilus Trust Oracle**

**再現可能なビルド**:
```bash
# 誰でもビルドして PCR 値を検証可能
git clone https://github.com/team/infight-amm
cd nautilus
make ENCLAVE_APP=fight-oracle
cat output/pcr_values.json

# オンチェーンの PCR と比較
sui client call --function get_expected_pcrs ...
```

**PCR 値の検証**:
- PCR0: エンクレーブイメージのハッシュ
- PCR1: カーネルのハッシュ
- PCR2: アプリケーションのハッシュ

**署名検証**:
```move
// Sui Move での検証
enclave::verify_signature(
    enclave: &Enclave,
    signed_result: vector<u8>,
    signature: vector<u8>
)
```

#### 2. **データ整合性**

**複数ソースのクロスチェック**:
```rust
// 2/3以上の一致が必要
if (source_a.winner == source_b.winner) ||
   (source_a.winner == source_c.winner) ||
   (source_b.winner == source_c.winner) {
    // Consensus reached
} else {
    return Err(DataMismatch)
}
```

#### 3. **スマートコントラクト**

**アクセス制御**:
- 決済は Nautilus 署名がある場合のみ
- 報酬請求は決済後のみ
- 市場作成は誰でも可能

**リエントランシー対策**:
- Move の所有権システムで保護
- `&mut` による排他制御

---

## スケーラビリティ

### 現在の制限

| 項目 | 制限 | 備考 |
|------|------|------|
| 同時市場数 | 制限なし | Sui の並列実行 |
| トランザクション速度 | ~5秒 | Sui ブロックタイム |
| Nautilus 応答時間 | ~2秒 | API 呼び出し時間 |

### 将来の拡張

#### **Phase 2: Walrus 統合**
```
• 取引履歴の永続保存
• 監査証跡の記録
• 大規模データの分散保存
```

#### **Phase 3: SEAL 統合**
```
• API キーの安全管理
• センシティブパラメータの保護
• 鍵のローテーション
```

#### **Phase 4: マルチチェーン展開**
```
• 他のブロックチェーンへの展開
• クロスチェーンブリッジ
• より広範なユーザーベース
```

---

## デプロイメント

### 開発環境

```
Nautilus Enclave: ローカル実行（デバッグモード）
Sui Network: Testnet
Frontend: localhost:3000
```

### 本番環境（将来）

```
Nautilus Enclave: AWS Nitro Enclaves
Sui Network: Mainnet
Frontend: Vercel / Cloudflare Pages
Load Balancer: AWS ALB
Monitoring: CloudWatch
```

---

## パフォーマンス目標

| メトリクス | 目標 | 実績 |
|-----------|------|------|
| 決済時間 | < 10分 | TBD |
| API レスポンス | < 3秒 | TBD |
| トランザクション確認 | < 10秒 | TBD |
| フロントエンド読み込み | < 2秒 | TBD |
| 同時ユーザー数 | 1000+ | TBD |

---

## 監視とログ

### ログレベル

```rust
// Nautilus Enclave
RUST_LOG=info  // 本番環境
RUST_LOG=debug // 開発環境
```

### 監視項目

- Nautilus エンクレーブのヘルスチェック
- API 応答時間
- トランザクション成功率
- ガス消費量
- エラー率

---

## まとめ

In-fight AMM は、Nautilus Trust Oracle を中心とした堅牢なアーキテクチャで構築されています。各コンポーネントは独立しており、段階的な拡張が可能です。

**次のステップ**: [実装計画](./IMPLEMENTATION_PLAN.md) を参照してください。
