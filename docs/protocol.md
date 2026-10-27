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

## 応答の予約領域

SMB 2.1 の READ 応答にある `Reserved`（1 byte）と `Reserved2`
（4 byte）は、仕様の受信側の規則に従い、ゼロ以外でも無視します。
送信側にはゼロを設定する義務がありますが、受信側が値を理由に拒否する
規則ではありません。後者を flags として解釈する SMB 3.1.1 は対象外です。
structure size、DataOffset（1 byte）、DataLength、要求との対応は引き続き
検査し、予約領域を含むメッセージ全体の署名検証も維持します。

公式仕様:

* [MS-SMB2 2.2.20 READ Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3e3d2f2c-0e2f-41ea-ad07-fbca6ffdfd90)

ERROR 応答でも `Reserved`（1 byte）を無視します。隣接する
`ErrorContextCount` は別のフィールドで、SMB 3.1.1 のエラーコンテキストは
対象外のため、ゼロ以外は引き続き拒否します。エラー本文の structure size
と ByteCount の境界、署名、要求との対応を検査したうえで、受信した
NTSTATUS を呼び出し元へ返します。

* [MS-SMB2 2.2.2 ERROR Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d4da8b67-c180-47e3-ba7a-d24214ac4aaa)

CLOSE の予約 DWORD、TREE_DISCONNECT／LOGOFF の予約 WORD も受信時に
無視します。CLOSE の flags（0 または POSTQUERY_ATTRIB）、各応答の
最小長・structure size、署名と要求の対応は引き続き検査します。
予約領域だけを理由に、正常な終了応答をプロトコルエラーへ変換しません。

* [MS-SMB2 2.2.16 CLOSE Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c0c15c57-3f3e-452b-b51c-9cc650a13f7b)
* [MS-SMB2 2.2.12 TREE_DISCONNECT Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/aeac92de-8db3-48f8-a8b7-bfee28b9fd9e)
* [MS-SMB2 2.2.8 LOGOFF Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/7539feb4-6fbb-4996-81ac-06863bb1a89e)

NEGOTIATE の `NegotiateContextCount/Reserved` と `NegotiateContextOffset/Reserved2`、
TREE_CONNECT の `Reserved` も受信時に無視します。方言は 0x0210 だけを受理するため、
SMB 3.1.1 のコンテキストとして解釈しません。署名有効、セキュリティバッファの境界、
共有種別、TreeId、暗号化要求の拒否は引き続き検査します。

* [MS-SMB2 2.2.4 NEGOTIATE Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/63abf97c-0d09-47e2-88d6-6bfa552949a5)
* [MS-SMB2 2.2.10 TREE_CONNECT Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/dd34e26c-a75e-47fa-aab2-6efc27502e96)

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
実装しています。既定エントロピーはUnixで `/dev/urandom`、Windowsで
`BCryptGenRandom(NULL, buffer, length, BCRYPT_USE_SYSTEM_PREFERRED_RNG)`です。
短い読み取りやOS API失敗を成功扱いにせず、疑似乱数にフォールバックしません。UTF-8 の overlong、surrogate、範囲外 scalar、
embedded NUL、UTF-16 の奇数長・不正 surrogate は拒否します。

フレーム最大値は 1 MiB、read/write の単一 credit chunk は 64 KiB
です。TCP の header と payload は一つの deadline で完全送受信し、
dribble peer が無期限に socket を占有できないようにします。絶対、
UNC、drive-qualified、空 component、`..` escape の share-relative path
は API 境界で拒否します。
名前解決はソケット接続前に同期的に行われ、接続・I/O deadline の対象外
です。socket deadline は名前解決後の TCP 接続と各 SMB frame の完全な
読み書きに適用されます。

この文書とライブラリは、FIPS 等の認証や攻撃耐性を保証しません。
OS乱数・GNAT socket環境は信頼境界です。Windows既定乱数はOS標準APIを使う
Adaアダプターだけに分離し、他の暗号処理には利用しません。

最終SESSION_SETUPの未署名エラーは引き続き認証失敗として切断します。
要求ID・SessionId・TreeId・コマンド・エラー構造を検査したうえで、error severityの
NTSTATUSだけを `Last_Unverified_Authentication_Status` に診断用として残します。
この値の真正性は保証せず、署名済み応答の `Last_NT_Status` と分離します。
成功・継続要求・壊れた署名・相関不一致・不正構造を診断値として採用しません。

* [BCryptGenRandom](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom)
* [MS-SMB2 3.2.5.1.3 Verifying the Signature](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/36172e53-ac81-48fb-b2e3-caa3761b9157)
