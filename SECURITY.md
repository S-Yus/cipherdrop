# Security Policy

CipherDrop はゼロ知識設計の一時データ共有サービスです。脆弱性のご報告に感謝します。
This document is in Japanese; see the **[English summary](#english-summary)** at the bottom for the
essentials of responsible disclosure.

## 対応バージョン

本リポジトリは `main` ブランチの最新版のみをサポートします。タグ付きリリースを利用している場合は、
最新のマイナーバージョンにご対応ください。

## 脆弱性の報告方法（Responsible Disclosure）

脆弱性を発見された場合は、**GitHub の Issue やプルリクエスト、その他の公開の場では報告しないでください**。
以下の窓口までご連絡ください。

- **メール**: ［security@cipherdrop.io を発行後に記載］
- **暗号化連絡**: 上記アドレス宛の PGP 公開鍵を
  [`https://cipherdrop.io/.well-known/security.txt`](https://cipherdrop.io/.well-known/security.txt)
  （[RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) 準拠）に掲載します。機微な内容を含むご報告は、
  この鍵で暗号化した上での送付にご協力ください。鍵の指紋は運用開始までに本ファイルにも追記します。
- 可能であれば、次の情報を含めてください: 影響範囲・再現手順・想定される深刻度・関連するコミット/バージョン。

### 対応プロセスの目安

| 段階 | 目安期間 |
| --- | --- |
| 受領確認 | 3 営業日以内 |
| 一次トリアージ（深刻度の暫定評価） | 7 営業日以内 |
| 修正または軽減策の提供 | 深刻度に応じて個別に調整し、報告者と協議します |
| 公開（Advisory 公開・CVE 採番など） | 修正版のリリース後、報告者と合意のうえで実施します |

上記はベストエフォートの目安であり、契約上の SLA ではありません。

### Safe Harbor（善意の調査に対する免責の方針）

本ポリシーに沿った**善意（good faith）の調査・報告**については、当社として法的措置を取る意図はありません。
具体的には、次の行為は本ポリシーの対象として許容します。

- テストデータ（自ら作成したアカウント・自ら送信したペイロード）のみを用いた検証
- サービスの可用性を損なわない範囲（DoS を目的としない）での検証
- 発見した脆弱性を、修正が完了し当社と合意するまで非公開に保つこと

一方で、他のユーザーのデータへのアクセス、サービス妨害（DoS/DDoS）、ソーシャルエンジニアリング、
物理的な侵入は本ポリシーの対象外であり、許容されません。

## スコープ

**対象**:
- 本リポジトリのフロントエンド（`apps/frontend`）・バックエンド（`apps/backend`）の実装
- `Dockerfile` / `docker-compose.yml` / `deploy/` の配信構成
- `cipherdrop.io` 上で提供される本番サービス（運用中の場合）

**対象外**（本サービス自体の脆弱性ではないもの）:
- 第三者サービス（Cloudflare 等、インフラ上で連携するサービス自体の脆弱性）— 各サービスの窓口へ
- ソーシャルエンジニアリング、物理的アクセス
- 既に [信頼モデルと既知の制約](README.md#信頼モデルと既知の制約) に明記されている既知の設計上の制約
  （例: 配信される JavaScript 自体の改ざんは検知の範囲外であること、認証・レート制限が未実装であること）

## 脅威モデルの要約

詳細な脅威モデルは [`docs/SECURITY_WHITEPAPER.md`](docs/SECURITY_WHITEPAPER.md) と
[README「信頼モデルと既知の制約」](README.md#信頼モデルと既知の制約) に記載しています。要点は以下のとおりです。

- **守るもの**: 復号鍵・平文・ファイル名は、送信者と受信者以外（当社のサーバー運用者を含む）から
  読み取れないこと。データは 1 回の受信または期限切れで確実に削除されること。
- **信頼の前提**: ユーザーは、そのつどブラウザへ配信される JavaScript（暗号化・復号のコード）が
  改ざんされていないことを前提にしています。これはこのアーキテクチャに共通する既知の限界であり、
  ソース公開・再現可能ビルド等が根本的な対策になります（今後の課題）。
- **守らないもの（スコープ外）**: 受信者のデバイス・ブラウザの侵害、送信者・受信者間の伝送経路
  （URL の共有手段。例: メール自体が盗聴されている場合）、送信されたコンテンツ自体の適法性
  （[`TERMS.md`](TERMS.md) 参照）。

## 依存関係の脆弱性

`apps/backend` はランタイム依存パッケージ 0（`node:*` のみ）で構成されており、この点は
`tests/security-policy.test.ts` が機械的に強制しています。フロントエンドのビルド成果物にも
外部の npm パッケージは含まれません。開発・ビルド用ツールチェーンの既知の脆弱性は、
CI（`.github/workflows/ci.yml`）の `npm audit --audit-level=high` で push・PR のたびに検査しています。

---

## English Summary

CipherDrop is a zero-knowledge, one-time-read data sharing service. If you find a security
vulnerability, please **do not open a public GitHub issue**. Instead, email
［to be filled in once security@cipherdrop.io exists］ with a description, reproduction steps, and the
affected version/commit. A PGP key for encrypted reports will be published at
`https://cipherdrop.io/.well-known/security.txt` (RFC 9116). We aim to acknowledge reports within 3
business days and triage within 7. Good-faith research against your own test data, without degrading
service availability for others, is welcome under this policy; we will not pursue legal action for
reports made in good faith under these terms.
