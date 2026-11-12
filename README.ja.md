# AdaSMB

[English](README.md) | 日本語

AdaSMB は、GNAT の通常の Ada ランタイムだけを使って実装した、SMB
3.1.1 (dialect `0x0311`) と SMB 2.1 (`0x0210`) の同期型クライアント
ライブラリです。これは
SMB パケットを生成するだけのサンプルではなく、NTLMv2 認証、署名済み
セッション、ファイル I/O、ディレクトリ操作までを実装します。

## 対応範囲

* TCP 445（ポートは API で変更可能）上で、既定は SMB 3.1.1 のみ。
  `Connect (..., Dialects => SMB_311_Or_21)` は SMB 2.1 も提示しますが、
  その場合は能動的な攻撃者が要求から 3.1.1 を取り除いて 2.1 を強制でき
  ます。既定の `SMB_311_Only` では、2.1 を選んだサーバーを拒否します。
  結果は `Negotiated_Dialect` で分かります。3.1.1 のネゴシエーションは
  SHA-512 の preauth integrity hash で保護します。
* サーバーが cipher をネゴシエーションしたときは、SMB 3.1.1 の暗号化
  （AES-128-GCM または AES-128-CCM）を使います。認証後の要求は share の
  TREE_CONNECT も含めてすべて transform header に封入し、nonce は
  繰り返さないカウンターから取ります。応答はすべて封入されていて tag の
  検査に通らなければならず、そうでなければ接続を破棄します。
  `Is_Encrypted` で確認でき、`Connect (..., Require_Encryption => True)`
  は cipher をネゴシエーションしないサーバー（と 2.1）を拒否します。
  session や share の暗号化を求めるサーバーは、cipher があるときだけ
  受け入れます。CI では統合試験クライアントを、Samba と Windows ランナー
  自身の SMB サーバー（Windows Server 2025）を相手に暗号化して動かし、
  Windows では各 cipher を順に唯一の cipher にして試験します。
  `Negotiated_Cipher` で cipher が分かります。
* SPNEGO 内の NTLMv2 のみ。Unicode ユーザー名の完全な Windows
  大文字化表を持たないため、ユーザー名は ASCII に限定します。
  パスワード、ドメイン、ファイル名は UTF-8 から厳密に UTF-16LE に
  変換し、非 BMP 文字の surrogate pair も扱います。
* 最終 Session Setup 応答と認証後の通信に SMB signing を必須とします。
  SMB 3.1.1 は、セッション鍵とセッションの preauth integrity hash から
  導出（SP 800-108）した鍵の AES-128-CMAC で署名し、SMB 2.1 は
  セッション鍵の HMAC-SHA256 の先頭 16 byte を検証します。署名検証に失敗したフレーム
  や不正な相関番号は接続を破棄します。
  署名は改ざん検知であり、ファイル内容を隠すのは暗号化だけです。
* 1 接続につき 1 share、未完了の操作は 1 つだけです。接続・ハンドル
  はスレッドセーフではありません。異なる接続の `Connect` 呼び出しも、
  owner ID の割当てを共有するため外部で直列化してください。
  ハンドルには単調な整数 owner ID、
  epoch、open ticket を記録し、foreign/stale/closed handle はネットワーク
  I/O より前に拒否します。
* フレームは 1 MiB、単一要求の read/write は 64 KiB 以下に制限し、
  受信オフセット・長さ・加算の範囲を検査します。SMB1、SMB 3.0・3.0.2、
  AES-256 の cipher、compression、compound、Kerberos、guest/null fallback、
  large-MTU negotiation は実装していません。
* スタック使用量は証明の対象外です。フレーム・転送・要求・ディレクトリ
  一覧のバッファはヒープに置き、ソケットは 16 KiB 単位で読みます。応答の
  署名検証と NTLM 認証は HMAC-SHA256 / HMAC-MD5 を 64 byte のブロック単位で
  逐次計算し、相手が長さを決めるデータをスタックにコピーしません。
  `make stack-check` は公開 API ごとの最悪スタック量（GNAT ランタイムを除く
  静的見積り）が 256 KiB 以内であることを検査します（最大は `Authenticate`
  の約 230 KiB）。1 MiB 以上のスタックを持つスレッドやタスクから呼び出して
  ください。

公開 API は同期型で、一度に 1 要求だけを送信します。認証後の
LOGOFF、TREE_DISCONNECT、CREATE、CLOSE、READ、WRITE、QUERY_DIRECTORY、
SET_INFO では SMB 2.x の `STATUS_PENDING` interim と対応する async final
response を扱います。interim は仕様に従って署名検証を行わず、要求との
相関、非ゼロ AsyncId、ERROR 本文の必須フィールドだけを確認します。interim は成功、
認証済みデータ、NTSTATUS として扱いません。最終応答は受信した元の
バイト列に対して通常どおり署名検証します。暗号化したセッションでは interim
も最終応答も暗号化されていなければならず、署名の代わりにそれぞれの tag を
検査します。
公式仕様への参照と検証結果は
[proof report](docs/proof-report.md#smb-21-asynchronous-interim-responses) に記載しています。

クレジット管理は既存の単一要求プロファイルのままです。最初の interim
には正の CreditResponse が必要で、AsyncId を保持した後の interim は
ゼロを許し、async final はゼロ、同期応答は正のクレジットを要求します。
interim ごとに待機時間を延長せず、要求ごとに一度だけ設定した絶対受信
deadline を適用します。NEGOTIATE、SESSION_SETUP、TREE_CONNECT の async
応答、SMB3、compound、cancel、並行要求、完全な credit-window 管理は
対応範囲外です。

「Pure Ada」は、実装が Ada であり C の暗号ライブラリや
`libsmbclient` をリンクしない、という意味です。`pragma Pure` という
Ada パッケージ属性を意味しません。GNAT.Sockets、Ada Stream_IO、
GNAT の通常ランタイムに依存します。既定のエントロピー源は Unix の
`/dev/urandom`、Windows の `BCryptGenRandom` (OS標準CSPRNG) です。
Windows版だけがOS乱数取得のために `bcrypt` をリンクし、AdaのOSアダプターで
直接呼び出します。ハッシュ・HMAC・NTLM・SMB署名は引き続きPure Adaです。
`Connect` の既存entropy callbackも利用できます。CSPRNG失敗時は代替せず
fail closedします。プロジェクトは実験的な段階です。

Windowsでは `OS=Windows_NT` からアダプターを自動選択します。
クロスビルドではコンパイラのtarget指定に加え `-XADASMB_OS=Windows_NT` または
`-XADASMB_OS=Unix` を明示してください。

未署名の最終認証失敗も拒否・切断しますが、要求対応と構造が正しいエラーは
`Last_Unverified_Authentication_Status` と例外メッセージで診断できます。
これは**未認証の相手による主張**です。`Last_NT_Status`には混ぜず、認証成功や
自動再試行の判断に使いません。値0は診断なし、Connect/Disconnectで消去します。

## SPARK による保証範囲

公開 API が実際に使う暗号計算、UTF 変換、NTLMv2/SPNEGO 認証、SMB
ヘッダー・操作本文・フレームの解析／生成、転送の進捗計算、状態・ハンドル
管理を SPARK コアに置いています。別途作ったモデルだけの証明ではありません。
証明対象は実行時エラー不在と明記した境界・状態契約です。

CREATE/CLOSE と READ/WRITE の実際の `SMB.Client` 経路は、
`SMB.Core_Client` の型付きコーディネータを通ります。コアが Engine の
要求期待値から完全なパケットを構築・署名し、送信確認後だけ応答を受け付けます。
転送状態は最大 1 MiB を保持し、各 READ/WRITE 要求は最大 64 KiB です。
WRITE は開始時に入力を private snapshot へ一度だけコピーし、部分書込みは
検証済み count だけ進めます。READ は検証済みデータを状態内へ蓄積し、
最終結果もコアの境界付きコピーで抽出します。不確かな送受信や不正応答では
再試行せず Engine を無効化し、ファサードが Channel を閉じます。ソケット I/O、
返却スライスの転送、割当て、例外処理、コンテナ寿命は信頼境界です。
認証、ディレクトリ列挙、DISPOSITION／RENAME も型付きコアを通り、
接続・共有接続・切断は `SMB.Core_Connection` が要求と応答に基づく
状態更新を管理します。

ソケット経路は `SMB.Core_Transport` を使い、実際に送るネイティブ配列の
フレーム全バイト、部分受信のコピーと既存データの保持、部分送信の
残りスライスと進捗を証明対象にしています。OS が返すバイト数の意味、
ソケットループ、待機期限、割当て・初期化・例外処理は未証明です。

認証に渡す FILETIME の暦計算と 100ns 単位への切捨ては
`SMB.Core_Clock` で証明します。OS 時刻の取得・UTC 分解は信頼境界です。

相対パスと共有名は、文字列上の拒否規則・成功時の正確な区切り文字変換・
失敗時の出力消去も契約化しています。サーバー側のリンク解決や Unicode
正規化によるパスの意味まで証明するものではありません。

ただし公開 `SMB.Client` の呼び出し順序・バッファ割当て・例外処理、
ソケット、OS 乱数・時計、ランタイム、メモリ確保は信頼境界に残ります。
**公開 API 全体の無条件な安全性、暗号学的安全性、完全な SMB 準拠を証明した
という意味ではありません。** 証明結果・再現コマンドは
[`docs/proof-report.md`](docs/proof-report.md)、全ての非 SPARK 部分と前提は
[`docs/assurance.md`](docs/assurance.md) に記載します。

## API とビルド

主要 API は `SMB.Client` の `Connect`、`Authenticate`、
`Connect_Share`、`Open_File`、`Read`、`Write`、`Close`、
`List_Directory`、`Make_Directory`、`Remove_File`、
`Remove_Directory`、`Rename`、`Disconnect` です。パスは share 相対で、
絶対パス・`..` の脱出・組み込み NUL は拒否されます。

必要なものは GNAT、GPRbuild、GNU Make です。時刻変換は GNAT の
1ns 刻みの `Duration` を要求し、異なる精度のランタイムはコンパイル時に拒否します。

```sh
make build                  # 静的ライブラリ build/lib/libsmb.a
make test                   # 暗号、wire、UTF-8/UTF-16、SPNEGO のテスト
make unicode-test           # Python 標準 codec との Unicode 全スカラー差分試験
make ntlm-test              # NTLM challenge と認証出力の差分試験
make crypto-test            # OpenSSL / Python と hash・HMAC の差分試験
make aes-test               # Python の cryptography と AES-128・AES-256 の差分試験
make cmac-test              # Python の cryptography と AES-128-CMAC の差分試験
make ccm-test               # Python の cryptography と AES-CCM（128・256 ビット鍵）の差分試験
make gcm-test               # Python の cryptography と AES-GCM（128・256 ビット鍵）の差分試験
make kdf-test               # Python の cryptography と SMB 3.1.1 の鍵導出の差分試験
make signing-test           # SMB 2.1・3.1.1 の署名の組立て・改ざん拒否を Python と照合
make clock-test             # FILETIME の全暦日・秒・100ns 端数を Python と照合
make check                  # warnings-as-errors と依存関係検査（stack-check を含む）
make stack-check            # 公開 API ごとの最悪スタック使用量を GCC の呼び出しグラフで検査
make example                # build/bin/smb_example
make prove                  # GNATprove + cvc5/z3/alt-ergo が必要。未証明があれば失敗
make transport-test         # TCP 断片化、送受信 timeout、途中切断・復旧試験
make integration            # 明示的にローカル Samba を起動する opt-in テスト
make mutation               # src/*.adb 全体に対する試験のミューテーションテスト（AdaMutant が必要）
make mutation-diff          # 同じことを origin/main から変わった行だけに行う
```

試験プログラムは、ライブラリも含めて `pragma Initialize_Scalars` と妥当性検査
（`-gnatVa`）付きでビルドします。出力を設定し忘れたサブプログラムは、古い値が
たまたま期待値と一致して通ることがなく、どのプラットフォームでも試験に失敗
します。

`make mutation` は [AdaMutant](https://github.com/gomurin0428/AdaMutant) で
試験そのものを検査します。AdaMutant は `PATH` に置くか `ADAMUTANT=` で
指定します。ライブラリのソースに一度に一つだけ小さな変更（演算子、
リテラル、条件、代入や呼び出し一つを `null` に置換）を加え、`test_suite` を
作り直して実行します。試験が気づかなかった変更が生き残ったミュータント
です。照合試験が対象にしている単位（NTLM、ハッシュ・AES・AES-CMAC・AES-CCM・AES-GCM・
鍵導出と署名、UTF 変換、時刻）のミュータントを `test_suite` が見逃したときは、
[`tests/mutant_tests.py`](tests/mutant_tests.py) がその照合試験も実行するので、
該当するすべての試験が見逃したミュータントだけが生き残ります。変更前の
ベースラインではすべての照合試験を実行するため、`make mutation` と
`make mutation-diff` にはそれらの試験が必要とするもの（Python の
`cryptography` パッケージを含む）が必要です。契約・
pragma・ghost コードは GNATprove が検査するので変更しません。
`src/smb-client.adb` と `src/smb-transport.adb` は対象外です。動作中の
サーバーが必要で、統合試験（Samba と Windows）と転送試験でしか動かせず、それらを
ミュータントごとに実行するには時間がかかりすぎるためです。設定は
[`adamutant.toml`](adamutant.toml) にあり、HTML と JSON のレポートは
`.adamutant/reports` に出ます。
[`tests/mutation_survivors.py`](tests/mutation_survivors.py) はどの試験も
検出しなかったミュータントを一覧にし、`make mutation-diff` はそれが一つでも
あると失敗します。振る舞いを変えようのないミュータントや、どの入力でも
到達しない防御的な分岐にあるミュータントは、理由を書いた
`adamutant:disable-next-line` コメントでソース上で無効化します。

`make unicode-test` は Python 3 の標準 codec を独立した比較対象として、
NUL を除く全 1,112,063 Unicode スカラー、短いバイト列の全組合せ、
複合文字列・固定 seed の入力を検査します。NUL は SMB の方針で拒否します。
この差分試験は Unicode の意味的な形式証明ではありません。Python は
試験専用であり、ライブラリの実行時依存には追加されません。

`make crypto-test` は Python 3 と OpenSSL 3 の legacy provider が必要です。
MD4 は OpenSSL、MD5/SHA-256/SHA-512 と HMAC は Python の `hashlib`/`hmac` と比較し、
ブロック境界・長い鍵・最大入力長・配列下限の違いを検査します。これらは
試験専用の依存です。暗号学的強度や定時間性の証明ではなく、MD4/MD5 を
NTLM 互換用途以外の新しい設計に推奨するものでもありません。

`make aes-test` は Python の `cryptography` パッケージ（これも試験専用）が
必要です。SMB 3.1.1 対応のための AES-128 と AES-256 の暗号化を、FIPS 197 の例と
SP 800-38A の AES-256 の例、さらに鍵長ごとに 1 ビットだけを立てたすべての鍵と
平文、すべての S-box 入力、シード固定の乱数ブロックで比較します。S-box は表引きではなく計算で求め、秘密データに依存する表の添字を
使いません。これはコーディング規則であり、試験や証明で確かめた性質では
ありません。

`make cmac-test` は SMB 3.1.1 の署名 MAC である AES-128-CMAC を同じ
パッケージと比較します。RFC 4493 と NIST の例、サブ鍵の倍算のすべての経路を
通る鍵での 5 ブロックまでのすべての長さと 4 KiB までの大きなブロック境界前後の
長さ、64 KiB とフレーム上限前後の長さ、パディングでしか区別できない
メッセージ、シード固定の乱数メッセージを、一括と分割入力の両方で検査します。

`make ccm-test` は SMB 3.x のメッセージ暗号である AES-128-CCM を同じ
パッケージの `AESCCM` と、常に SMB の 11 バイト nonce と 16 バイト tag で
比較します。Microsoft の SMB 3.1.1 暗号化の例にある 4 つのメッセージ、
5 ブロックまでのすべてのデータ長と大きなブロック境界前後の長さ、フレーム
上限までのカウンターと長さフィールドが桁上がりする長さ、0 から 65,279
バイトまでの関連データ、1 ビットの変更、シード固定の乱数メッセージを
検査します。SMB の例が公開されていない AES-256-CCM は、同じ種類のメッセージを
数を減らして 32 バイト鍵で検査します。各メッセージを複数の配列境界で暗号化・復号し、tag や暗号文を
変えたものは拒否してデータをゼロにすることも確かめます。

`make gcm-test` は SMB 3.1.1 のメッセージ暗号である AES-128-GCM を同じ
パッケージの `AESGCM` と、常に SMB の 12 バイト nonce と 16 バイト tag で
比較します。Microsoft の SMB 3.1.1 暗号化の例にある 4 つのメッセージ、
5 ブロックまでのすべてのデータ長と大きなブロック境界前後の長さ、フレーム
上限までのカウンターが桁上がりする長さ、3 ブロックまでのすべての長さと
いくつかの長い関連データ、1 ビットの変更、シード固定の乱数メッセージを
検査します。AES-256-GCM は GCM 仕様の試験ケース 13〜16 と、同じ種類の
メッセージを数を減らして 32 バイト鍵で検査します。各メッセージを複数の
配列境界で暗号化・復号し、tag や暗号文を変えたものは拒否してデータを
ゼロにすることも確かめます。

`make kdf-test` は SMB 3.1.1 の鍵導出（HMAC-SHA256 を使うカウンターモードの
SP 800-108）を同じパッケージの `KBKDFHMAC` と比較します。Microsoft が公開して
いる 3.1.1 の署名鍵・暗号化鍵・復号鍵 12 個、全ビット 0 と全ビット 1 の入力、
シード固定の乱数のセッション鍵と preauth ハッシュを、3 つのラベルすべてで、
16 バイト鍵と AES-256 用の 32 バイト鍵の両方について検査します。

example はホスト、share、パスを引数に取れますが、パスワードを引数に
取りません。`SMB_USER`、`SMB_DOMAIN`、`SMB_PASSWORD` 環境変数を使います。
環境変数はプロセス環境から参照可能な場合があるため、共有ホスト上で
使う場合は注意してください。

```sh
SMB_USER=alice SMB_PASSWORD='...' SMB_DOMAIN=WORKGROUP \
  build/bin/smb_example 127.0.0.1 public README.txt
```

`make integration` は root 権限があるローカル Linux でだけ実行して
ください。専用の一時 Samba 設定、共有、`ada_smb_test_only` ユーザー
（テスト専用の既知のパスワード）を作り、終了時に削除します。リモート
ホストへ接続するテストではありません。
`smbd`、`smbpasswd`、Python 3 が必要です。

[`tests/windows_integration.py`](tests/windows_integration.py) は、同じ統合
試験クライアントを、実行したマシン自身の Windows SMB サーバーに対して動かし
ます。CI ランナーのように管理者として動く使い捨ての Windows マシン向けで、
`ADASMB_WINDOWS_SERVER=1` がなければ起動しません。自分で生成して表示しない
ランダムなパスワードを持つ `adasmb_test_only` ローカルアカウントと共有を
作り、試験のあいだサーバーの暗号化設定を変え、最後にアカウントと共有を削除
して設定を元に戻します。

## CI

GitHub Actions（`.github/workflows`）で次を実行します。ツールチェーンは
Alire 2.1.1 で GNAT 16.1.0・gprbuild 26.0.1・gnatprove 16.1.0 を導入します
（`alr` はリリースの SHA-256 を照合し、導入結果はキャッシュします）。

* `ci.yml`（main への push、pull request、手動実行。文書だけの変更では
  動きません）
  * Linux: `make check`（`stack-check` を含む）、`make test`、各照合試験、
    `make transport-test`、使い捨ての VM 上での Samba 統合試験
  * Windows: 警告をエラー扱いにしたビルド、ソース・スタック検査、単体試験、
    ランナー自身の SMB サーバーに対する統合試験（cipher をネゴシエーション
    した SMB 3.1.1、続いて AES-128-GCM と AES-128-CCM それぞれで暗号化を
    必須にした場合）、各照合試験、TCP 転送試験
  * macOS（ARM64）: 警告をエラー扱いにしたビルド
  * pull request のみ: その pull request が変えた `src/*.adb` の行に対する
    ミューテーションテスト（`make mutation-diff`）。どの試験も検出しなかった
    ミュータントがあると失敗します。
* `mutation.yml`（毎週日曜 03:00 JST と手動実行）: `src/*.adb` 全体の
  ミューテーションテスト。ミュータント数がほぼ等しい 8 つのジョブに分けて
  実行し、レポートを成果物として残します。
* `proof.yml`（毎週月曜 03:00 JST と手動実行）: `make prove` による全体証明。
  GitHub は、60 日間活動のないリポジトリでは定期実行を止めます。

## プロトコル根拠

署名計算は [MS-SMB2 signing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a3e9ea1e-53c8-4cff-94bd-d98fb20417c0)
に従い、ゼロ化した signature field を含む SMB2 message 全体に
HMAC-SHA256 を適用します。NTLMv2 の NTOWFv2、response、session base
key は
[MS-NLMP NTOWFv2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3)
を、timestamp、zero LM response、MIC/AV flags は
[MS-NLMP timestamp and MIC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/c0250a97-2940-40c7-82fb-20d208c71e96)
を参照しています。各リンクは実装可能な対応範囲を広げるものではなく、
上記の 2.1/NTLMv2 限定プロファイルを維持します。

詳細な状態遷移、拒否する入力、制限事項は
[`docs/protocol.md`](docs/protocol.md) を参照してください。
SPARK の対象範囲と未証明部分は
[`docs/assurance.md`](docs/assurance.md) を参照してください。

Ada クライアントを使うプロジェクトは、GPR project からライブラリを
参照します。

```gpr
with "/path/to/AdaSMB/smb.gpr";
project Example is
   for Source_Dirs use ("src");
   for Main use ("client.adb");
end Example;
```

## Alire

Alire のクレート名は `smb` です（[`alire.toml`](alire.toml)）。Alire の
コミュニティインデックスに登録済みで、次のように依存関係へ追加できます。

```sh
alr with smb
```

Alire 経由のビルドでは GNAT 14 以上を要求し、`ADASMB_OS` を OS に応じて
`Windows_NT` または `Unix` に設定します。Alire のクレート設定ファイル
（`config/`）は生成しません。

## ライセンス

`MIT OR Apache-2.0` のデュアルライセンスです。利用者はどちらか一方を選んで
利用できます。本文は [`LICENSE-MIT`](LICENSE-MIT) と
[`LICENSE-APACHE`](LICENSE-APACHE) を参照してください。
