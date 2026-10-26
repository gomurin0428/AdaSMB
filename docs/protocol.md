# AdaSMB プロトコル設計メモ

この文書は、`src/` の実装が受け入れる wire profile と、意図的に
受け入れない入力を記録します。

## 接続状態

`Disconnected` から TCP 接続、SMB2.1 negotiate、NTLMv2 session setup、
tree connect の順に遷移します。ネゴシエーションで dialect が `0x0210`
でない、signing が有効でない、I/O 最大値が 0、または暗号化 share を
要求された場合は遷移を完了しません。セッション setup の成功応答にも
署名を要求し、guest、null、session encryption を拒否します。

各 request は単調な message id と 1 credit で送信します。応答の magic、
structure size、command、message id、session/tree id、zero credit、
response flag、async flag、`NextCommand` を検査します。SMB 2 transform
header、compression、compound response、未実装の async 応答は、状態を
破棄して `SMB.Protocol_Error` になります。認証後の NTSTATUS は署名を検証した
後に限り `SMB.NT_Status_Error` として呼び出し元へ渡します。
ネゴシエーションと最初の challenge 応答は署名鍵確立前なので unsigned
です。これだけで認証済み状態へ進むことはできません。

## 署名

session base key の 16 byte を signing key とし、SMB2 header の
signature field をゼロ化して HMAC-SHA256(message) を計算し、先頭 16
byte を格納・比較します。認証後の request は全て署名し、期待する
response も全て署名されている必要があります。比較は
`SMB.Crypto.Constant_Time_Equal` を使います。署名の不一致、相関不一致、
パケット bounds 不正は socket を閉じます。

公式仕様:

* [MS-SMB2 3.1.4.1 Signing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a3e9ea1e-53c8-4cff-94bd-d98fb20417c0)

## NTLMv2/SPNEGO

クライアントが出す SPNEGO は NTLM OID だけを含みます。応答は DER の
長さと nesting を検査し、GSS wrapper または NegTokenResp を認識します。
supportedMech が NTLM でない場合、duplicate/out-of-order field、nonminimal
DER、unexpected negState を拒否します。challenge では accept-incomplete
または request-mic、final success では accept-completed を受け入れます。
Type 3 には client-to-server の `mechListMIC` を添え、最終応答では
server-to-client の `mechListMIC` を必須として検証します。これは NTLM
メッセージ自体の MIC とは別の検査です。文字列中の
`NTLMSSP` を検索して認証することはしません。

Type 2 の security buffer と AV pairs を全て bounds-check し、Unicode、
NTLM、ESS、signing、target-info を要求します。server timestamp を
優先して NTLMv2 blob に使い、その AV がある場合は LM response を全
zero にします。timestamp がない場合だけ現在の FILETIME と callback
nonce を使います。MsvAvFlags の MIC-present bit を保持/追加し、Type 1、
Type 2、zero-MIC Type 3 全体で MIC を計算します。channel binding が
非 zero の場合、値を捏造せず拒否します。KEY_EXCH/RC4、NTLMv1、LM 認証
は提供しません。

公式仕様:

* [MS-NLMP NTOWFv2 and session base key](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3)
* [MS-NLMP timestamp, LM response and MIC AV flag](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/c0250a97-2940-40c7-82fb-20d208c71e96)

## 暗号と入力制限

MD4、MD5、SHA-256、HMAC-MD5、HMAC-SHA256 は Ada の整数演算だけで
実装しています。既定エントロピーは `/dev/urandom` を短く読めなかった
場合も成功扱いにしません。UTF-8 の overlong、surrogate、範囲外 scalar、
embedded NUL、UTF-16 の奇数長・不正 surrogate は拒否します。

フレーム最大値は 1 MiB、read/write の単一 credit chunk は 64 KiB
です。TCP の header と payload は一つの deadline で完全送受信し、
dribble peer が無期限に socket を占有できないようにします。絶対、
UNC、drive-qualified、空 component、`..` escape の share-relative path
は API 境界で拒否します。
名前解決はソケット接続前に同期的に行われ、接続・I/O deadline の対象外
です。socket deadline は名前解決後の TCP 接続と各 SMB frame の完全な
読み書きに適用されます。

この文書とライブラリは、FIPS 等の認証、攻撃耐性の保証、Windows native
サポートを宣言しません。別 OS では entropy callback と GNAT socket
環境を呼び出し元が用意する必要があります。
