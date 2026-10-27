# AdaSMB

AdaSMB は、GNAT の通常の Ada ランタイムだけを使って実装した、SMB
2.1 (dialect `0x0210`) の同期型クライアントライブラリです。これは
SMB パケットを生成するだけのサンプルではなく、NTLMv2 認証、署名済み
セッション、ファイル I/O、ディレクトリ操作までを実装します。

## 対応範囲

* Linux の TCP 445（ポートは API で変更可能）上の SMB 2.1 のみ。
* SPNEGO 内の NTLMv2 のみ。Unicode ユーザー名の完全な Windows
  大文字化表を持たないため、ユーザー名は ASCII に限定します。
  パスワード、ドメイン、ファイル名は UTF-8 から厳密に UTF-16LE に
  変換し、非 BMP 文字の surrogate pair も扱います。
* 最終 Session Setup 応答と認証後の通信に SMB signing を必須とし、SMB 2.1 の
  HMAC-SHA256 の先頭 16 byte を検証します。署名検証に失敗したフレーム
  や不正な相関番号は接続を破棄します。
  署名は改ざん検知であり、ファイル内容を暗号化するものではありません。
* 1 接続につき 1 share、未完了の操作は 1 つだけです。接続・ハンドル
  はスレッドセーフではありません。異なる接続の `Connect` 呼び出しも、
  owner ID の割当てを共有するため外部で直列化してください。
  ハンドルには単調な整数 owner ID、
  epoch、open ticket を記録し、foreign/stale/closed handle はネットワーク
  I/O より前に拒否します。
* フレームは 1 MiB、単一要求の read/write は 64 KiB 以下に制限し、
  受信オフセット・長さ・加算の範囲を検査します。SMB1、SMB3、
  encryption、compression、compound、async、Kerberos、guest/null
  fallback、large-MTU negotiation は実装していません。

「Pure Ada」は、実装が Ada であり C の暗号ライブラリや
`libsmbclient` をリンクしない、という意味です。`pragma Pure` という
Ada パッケージ属性を意味しません。GNAT.Sockets、Ada Stream_IO、
GNAT の通常ランタイムに依存します。既定のエントロピー源は Linux の
`/dev/urandom` で、`Connect` に callback を渡せば別 OS の呼び出し元が
OS 固有の CSPRNG を注入できます。CSPRNG が使えない場合は fail closed
します。プロジェクトは実験的な段階です。

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
make check                  # warnings-as-errors と依存関係検査
make example                # build/bin/smb_example
make prove                  # GNATprove + cvc5/z3 が必要。未証明があれば失敗
make transport-test         # TCP 断片化、送受信 timeout、途中切断・復旧試験
make integration            # 明示的にローカル Samba を起動する opt-in テスト
```

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
`smbd`、`smbpasswd`、Python 3 が必要です。CI の自動実行は設定していません。

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
