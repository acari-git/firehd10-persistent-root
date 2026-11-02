# アーキテクチャ

> English: [architecture.md](architecture.md)

本システムは、上流 SnuSnuRoot の *一時的な* root を、正確に1つの
ファームウェアビルド上で *無人で永続化する* root へ変える。いかなる
パーティションにも書き込まない。毎回のブートで、同じメモリ内チェーンが
走る：アプリが試行を武装し、waiter チェーンが一時 root を再取得し、
Magisk が tmpfs から配置され、Enforcing が復帰し、署名付き証明が
ジャーナルを閉じる — そしてジャーナルだけが、次のブートを武装できる。

## ジャーナルが唯一の武装権限

`Stage4AttemptJournalV2` は二相のレコード
（`stage4-native-attempt-v2.state`、アプリのプライベートストレージ）を
保持する：

```
EMPTY ──genesis proof──▶ READY ──begin(boot)──▶ INFLIGHT ──signed proof──▶ READY
```

- ブートが root を試行できるのは、ジャーナルを READY → INFLIGHT へ
  遷移させる（`beginOneShot`）ことによってのみであり、そのブートの
  同一性に結び付けられる。
- 試行が完了するのは、INFLIGHT レコードと試行ごとの 256 ビット
  チャレンジに結び付けられた ECDSA 証明をアプリが検証したときに
  限る。それ以外 — 欠落、外部のもの、古いもの、矛盾するもの — は
  すべて拒否され、ブートは素の状態にとどまる。
- 他のいかなるコンポーネントもブートを武装できない。とりわけ、歴史的な
  ウォッチドッグのポーリング再武装パターンは意図的に採用していない：
  それは成功が判明する *前に* 再武装するものであり、まさにジャーナルが
  防ぐために存在するものだ。したがって、失敗したブートはシステムを
  武装解除の状態に残し（フェイルクローズ）、決して中途半端に武装した
  状態にはしない。

## ブート同一性（三層）

1. **署名者アンカー** — 端末内署名者は、自身の root コンテキストで
   `/proc/sys/kernel/random/boot_id` を読む。
2. **Waiter witness** — `snusnu-boot-witness.sh` は、waiter の
   Permissive 検出に組み込まれ、このブートの同一性主張（ブート UUID ＋
   `/proc/uptime`）をキャッシュの状態ディレクトリへ書き込む。アプリは
   それを `Stage4BootWitness` で解析する（厳密なパーサ、新鮮さのルール）。
   witness は証拠でしかなく、何も承認しない。
3. **ブートカウントラッチ** — リプレイ防止／同一ブートのガード。

ジャーナルの *begin* は Permissive の窓が存在する前に走るため、無人の
begin は通常、劣化した形式 `INFLIGHT:?` を使う。witness は完了時点の
主張と、古い witness のクリーンアップに役立つ。

## 証明と端末内署名者

- 証明は ECDSA P-256 / SHA256withECDSA で、ドメイン分離されている：
  通常の証明は `stage4-root-v1|…` に署名し、genesis 証明は
  `stage4-genesis-v1|…` に署名する。証明は INFLIGHT レコードと保留中の
  チャレンジに結び付けられる。チャレンジは検証の試行のたびに消費される
  （リプレイ防止）。
- 署名者（`signer/Stage4DeviceSigner.java`、依存関係のない単一クラスを
  dex にコンパイル）は、root シェルから `app_process` 経由で動く。
  秘密鍵は **端末内で** 生成され、`/data/snusnu_root/signer/proof-key.der`
  に置かれる（ディレクトリ `root:root 0700`、ファイル `0400`)。
  端末から決して出ない。
- 署名者は呼び出しのたびに自己検証を行い（同一性、保管状態、Enforcing
  状態）、いずれかのゲートが失敗すれば拒否する。署名された証明は、
  ファイルメールボックスを通じてアプリのプライベートな `proof-drop/`
  ディレクトリへ届けられ、アプリ自身のドメインで読めるよう、ドロップ
  にはアプリの SELinux ラベルがコピーされる。
- アプリは、APK にコンパイルされた **ピン留め公開鍵** で検証する
  （`Stage4PinnedProofKey`、ビルド時に再生成）。APK 自体の署名証明書は
  この信頼チェーンに何の役割も果たさない。

## ブートサイクル（武装ブート、操作者なし）

1. アプリが起動し（direct-boot / package-replaced トリガー）、ジャーナルを
   読む。以前のブートに結び付いた READY → `beginOneShot` → INFLIGHT。
   新しいチャレンジが発行される。
2. アプリは証明リクエストを書き、システムチャネル越しに **オンデマンド
   起動ヘルパー**（`snusnu-launch.sh`）を呼び出す。ヘルパーは姿勢を
   自ら再検証し（persist フラグがオン、両方の disable sentinel が不在、
   ブートごとの起動ラッチが利用可能、saved_time スロットが数値）、
   素の `time_update` トリガーを一時的に武装し、`ctl.start` でサービスを
   起動し、サービスの振る舞いから起動を確認し、スロットをバイト単位で
   復元する。アプリが Stage4 キャリアを送るのは `LAUNCH_RESULT OK` の
   ときだけだ。（ブートを跨ぐ武装は機能しえない：TimeService は毎回の
   ブートの数秒以内にスロットを NTP の値で上書きする — failure-modes
   を参照。）
3. waiter が root の窓で発火し、witness 書き込みがブート主張を記録し、
   `magisk_restore.sh` が Magisk を配置し（tmpfs)、`stage4-enforcing.sh`
   （参照のみ）が MagiskSU を生かしたまま（`uid=0`、`u:r:magisk:s0`)
   SELinux Enforcing を復帰させる。
4. **自動完了ワーカー**（`snusnu-completion.sh`、magisk ドメインで
   Magisk の `service.d` から起動）は、このブートの Enforcing 復帰
   マーカーに同期し、本番の署名者に保留中の証明リクエストへの署名を
   求め（試行は正確に1回）、アプリを再トリガーする
   （`am start-foreground-service`、明示的ブロードキャストがフォール
   バック）。このブートとチャレンジに既に結び付いたドロップが存在
   すれば、署名をスキップして再トリガーのみ行う。
5. アプリは証明を検証し、ジャーナルを完了させ（このブートに結び付いた
   READY、`proof_status=proof_completed_dps`)、persist フラグを
   **再武装** する（`rearmed_on_proof`)。完了の実行が2回目の試行へ
   すり抜けることは決してなく、同一ブートの READY レコードにより、
   以後のトリガーは静かに戻る。

受入端末でのエンドツーエンド実測：ブートから、完了し再武装した
ジャーナルまで約90秒。

## Genesis とロックアウト復旧

最初の READY レコードは通常の証明からは生まれえない（結び付ける対象の
INFLIGHT が存在しない）。genesis がそれを設置する：root を得たブートで、
署名者は — 現在のブート id を名指しする操作者トークンによる追加の
ゲートを受けて — ドメイン分離された genesis 証明に署名し、アプリは
それをピン留め鍵で検証して `READY` ＋ `genesis_installed` を書く。
同じ経路が **ロックアウト復旧** である：ジャーナルが INFLIGHT に
張り付いたら（例：失敗したブートの後）、root セッションが genesis を
再実行し、システムは再開する。genesis と復旧による完了は意図的に
再武装 **しない**。武装は通常の完了によってのみ得られる。`genesis.ja.md`
を参照。

## コンポーネント

| レイヤー | 構成要素 |
|---|---|
| アプリ（`app/`） | ジャーナル、genesis／証明の検証器、proof-drop パーサ、ブート同一性／witness、フォークした `PersistenceService` の統括 |
| 署名者（`signer/`） | 端末内 ECDSA 署名者＋ランチャ＋ビルド |
| 端末スクリプト（`device/`） | 起動ヘルパー、witness 書き込み、完了ワーカー＋ランチャ、システムチャネルのゲート、インストーラ、および実地投入された上流系譜の waiter/watchdog/restore/boot-entry |
| ホスト（`host-tests/`） | 実際のスクリプト／Java をサンドボックスのフィクスチャに対して実行する Python unittest ハーネス |
