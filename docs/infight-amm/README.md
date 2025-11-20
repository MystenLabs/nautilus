# In-fight AMM

格闘技に特化した次世代予測市場 - Powered by Nautilus Trust Oracle

## 🥊 プロジェクト概要

**In-fight AMM** は、格闘技イベントのための革新的な予測市場プラットフォームです。Nautilus Trust Oracle を活用することで、従来の予測市場（Polymarket等）の課題を解決します。

### 主な特徴

- ⚡ **即座の決済**: 試合終了後10分以内でClaim可能（Polymarket: 数日〜数週間）
- 🎮 **ライブトレーディング**: 試合中もリアルタイムでポジション変更可能
- 🔒 **検証可能な信頼性**: Nautilus の再現可能なビルドで誰でも検証可能
- 📊 **本格的なLSMR AMM**: Polymarket初期と同じ指数関数ベースの価格メカニズム
- 🤖 **自動決済**: 複雑な紛争解決プロセス不要

## 🏆 Walrus Haulout Hackathon

### ターゲットトラック

**Provably Authentic (Truth Engine + Trust Oracle)** - メイントラック

- Nautilus Trust Oracle による検証可能な自動決済
- 複数データソースのクロスチェック
- 予測市場の精度向上

### 使用技術

- **Nautilus**: 自動決済システム（Trust Oracle）
- **Sui Move**: LSMR AMM スマートコントラクト
- **指数関数**: 本格的な価格発見メカニズム
- （将来計画）**Walrus**: 取引履歴の永続保存
- （将来計画）**SEAL**: API キーの安全管理

## 🚀 クイックスタート

### 必要な環境

- Rust 1.87+
- Sui CLI
- Node.js 18+
- Docker（オプション: Nautilus エンクレーブ用）

### セットアップ

```bash
# リポジトリをクローン
git clone https://github.com/your-team/infight-amm
cd infight-amm

# Nautilus Fight Oracle をビルド
cd nautilus/src/nautilus-server
cargo build --features fight-oracle

# Move コントラクトをビルド
cd ../../../move/lsmr-amm
sui move build

cd ../fight-market
sui move build

# フロントエンドをセットアップ
cd ../../frontend
npm install
npm run dev
```

## 📁 プロジェクト構造

```
infight-amm/
├── nautilus/                    # Nautilus エンクレーブ
│   └── src/nautilus-server/
│       └── src/apps/
│           └── fight-oracle/    # Fight Oracle 実装
├── move/                        # Sui Move コントラクト
│   ├── lsmr-amm/               # LSMR AMM 実装
│   │   ├── math.move           # 指数・対数関数
│   │   └── amm.move            # LSMR ロジック
│   ├── fight-oracle/           # Oracle データ構造
│   └── fight-market/           # 市場管理
├── frontend/                    # React フロントエンド
└── docs/                        # ドキュメント
    ├── ARCHITECTURE.md         # アーキテクチャ設計
    ├── IMPLEMENTATION_PLAN.md  # 実装計画
    ├── TECHNICAL_SPECS.md      # 技術仕様
    └── PITCH_GUIDE.md          # ピッチガイド
```

## 📚 ドキュメント

- [アーキテクチャ設計](./ARCHITECTURE.md) - システム全体の設計
- [実装計画](./IMPLEMENTATION_PLAN.md) - 2日間の詳細スケジュール
- [技術仕様](./TECHNICAL_SPECS.md) - Nautilus、LSMR AMM、Move の詳細
- [ピッチガイド](./PITCH_GUIDE.md) - ハッカソンプレゼン資料

## 🎯 主要コンポーネント

### 1. Nautilus Fight Oracle

試合結果を複数のAPIから取得し、クロスチェックして署名付きで返すTrust Oracle。

**エンドポイント**:
- `POST /settle_fight` - 試合結果の取得と署名
- `POST /live_stats` - ライブ統計データ（オプション）

### 2. LSMR AMM

Logarithmic Market Scoring Rule を実装した予測市場AMM。

**主要機能**:
- 指数関数ベースの価格計算
- 動的な流動性パラメータ
- Buy/Sell シェア機能

### 3. Fight Market Contract

Nautilus と LSMR AMM を統合する市場管理コントラクト。

**主要機能**:
- 市場作成
- 自動決済（Nautilus署名検証）
- 報酬請求

## 🔄 ワークフロー

### 試合前
```
1. 市場作成（試合情報 + 初期流動性）
2. 取引開始（選手入場時）
```

### 試合中
```
3. ライブトレーディング（リアルタイム価格変動）
4. （オプション）Nautilus からライブ統計取得
```

### 試合後
```
5. Nautilus が試合結果を取得・署名
6. オンチェーンで自動決済（署名検証）
7. ユーザーが報酬を Claim（即座）
```

## 📊 Polymarket との比較

| 項目 | Polymarket | In-fight AMM |
|------|-----------|--------------|
| 決済時間 | 数日〜数週間 | **10分以内** |
| オラクル | 人間投票（UMA） | **Nautilus自動** |
| 紛争解決 | 複雑な仕組み | **不要** |
| ライブ性 | 試合前のみ | **試合中も可能** |
| 価格メカニズム | LSMR → Orderbook | **LSMR** |
| 透明性 | ブラックボックス | **検証可能** |

## 🛠️ 開発ステータス

### Completed ✅
- [ ] Nautilus Fight Oracle 実装
- [ ] LSMR AMM（指数関数） 実装
- [ ] Move コントラクト統合
- [ ] フロントエンド（モック）

### In Progress 🚧
- [ ] エンドツーエンドテスト
- [ ] デモ動画作成
- [ ] ピッチ資料作成

### Future Roadmap 🔮
- [ ] Walrus 統合（取引履歴保存）
- [ ] SEAL 統合（API キー管理）
- [ ] AI 予測モデル
- [ ] モバイル対応

## 🤝 チーム

- **開発者**: [Your Name]
- **役割**: Nautilus / Move / Frontend
- **連絡先**: [Contact Info]

## 📄 ライセンス

Apache 2.0 License - 詳細は [LICENSE](../LICENSE) を参照

## 🔗 リンク

- [Nautilus Documentation](https://docs.sui.io/concepts/cryptography/nautilus)
- [Sui Developer Portal](https://sui.io/developers)
- [Walrus Haulout Hackathon](https://hackathon-link)
- [Demo Video](https://demo-link)

## 💬 サポート

質問や問題がある場合：
- GitHub Issues: [Issues Page]
- Discord: [Discord Link]
- Email: [Email]

---

**Built with ❤️ for Walrus Haulout Hackathon**
