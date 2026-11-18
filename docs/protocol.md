# AdaSMB プロトコル設計メモ

この文書は、`src/` の実装が受け入れる wire profile と、意図的に
受け入れない入力を記録します。

## 接続状態

`Disconnected` から TCP 接続、negotiate、NTLMv2 session setup、
tree connect の順に遷移します。negotiate は SMB 3.1.1 を提示し、
`Dialects => SMB_311_Or_21` のときだけ SMB 2.1 も提示します。dialect が
提示したものでない、3.1.1 の negotiate context が不正（
`SMB.Core_Negotiate.Check_Response_Contexts`）、signing が有効でない、
I/O 最大値が 0、または cipher がないのに暗号化 share を要求された場合は
遷移を完了しません。
3.1.1 では NEGOTIATE と SESSION_SETUP の要求・応答（最終の成功応答を除く）
を SHA-512 の preauth integrity hash に入れ、その値とセッション鍵から
署名鍵を導出して、最終応答以降を AES-128-GMAC か AES-128-CMAC（後述）で署名・検証します。セッション setup の成功応答にも
署名を要求し、guest と null を拒否します。session encryption の要求は
cipher があるときだけ受け入れます。Windows Server 2025 は鍵を導出する前の
challenge 応答ですでにこの flag を立てるので、判定は鍵ではなく cipher の
有無で行います。

cipher をネゴシエーションした 3.1.1 セッションは、同じ preauth hash から
暗号化鍵・復号鍵も導出し、認証後のすべての要求を
SMB2 TRANSFORM_HEADER に封入します（`SMB.Core_Transform`、
`SMB.Engine.Seal_Request`）。nonce は先頭 8 byte がセッションごとに 1 から
始まるカウンター、残りが 0 で、カウンターが尽きると封入を拒否します。
封入した要求の中身も署名したままです（MS-SMB2 3.2.4.1.1 は
session と share の両方が暗号化されている場合を除いて署名を必須とし、その
場合も署名を禁じていません。サーバーは暗号化された要求の署名を検証
しません）。暗号化中の応答は `SMB.Engine.Unwrap_Response` を通ったものだけ
を受け入れます。transform header の長さ、ProtocolId、Flags、
OriginalMessageSize、SessionId、tag、復号後の SMB2 ProtocolId と SessionId
のどれかが合わない場合や、平文の応答が来た場合は状態を破棄します。復号した
応答は tag で認証済みなので、中の署名は要求も検証もしません。SIGNED flag も
問いません（Windows は暗号化した応答で flag を下ろし、Samba は要求の flag を
そのまま写します）。CI では Samba と Windows Server 2025 の SMB サーバーを
相手に暗号化を試験します。Samba では AES-256-GCM と AES-256-CCM を、
Windows では 4 つの cipher をそれぞれ唯一の cipher にし、暗号化を必須にした
うえで、クライアントがその cipher をネゴシエーションしたことも確かめます。

クライアントは AES-128-GCM、AES-128-CCM、AES-256-GCM、AES-256-CCM の順に
提示し（Windows クライアントの既定と同じ順です）、サーバーが選びます。
AES-256 の cipher では暗号化鍵・復号鍵を L = 256 で 32 byte 導出し
（`SMB.KDF.Derive_256`）、署名鍵はどの cipher でも L = 128 の 16 byte
です。Samba も同じ導出をします。

署名アルゴリズムは SIGNING_CAPABILITIES コンテキストで AES-GMAC、AES-CMAC の
順に提示し、サーバーが選びます。応答の署名コンテキストは、アルゴリズムが
1 つで、こちらが提示したものでなければなりません（HMAC-SHA256 や未知の ID は
接続を失敗させます）。署名コンテキストがなければ AES-CMAC です
（MS-SMB2 3.1.4.1）。AES-GMAC は平文なしの GCM で、Signature field をゼロにした
メッセージ全体を関連データとし、16 byte の署名鍵で tag を計算します。nonce は
12 byte で、header の MessageId 8 byte のあとに、サーバーが送るメッセージなら
bit 0、CANCEL 要求なら bit 1 を立てた 4 byte が続きます。bit 0 は Samba と同じく
header の SMB2_FLAGS_SERVER_TO_REDIR から取ります。`Negotiated_Signing` で
アルゴリズムが分かります。CI では Samba をそれぞれ唯一のアルゴリズムにして
試験し、Windows Server 2025 が AES-GMAC を選ぶことも確かめます。

各 request は単調な message id で送信し、READ 以外は 1 credit です。
NEGOTIATE では SMB2_GLOBAL_CAP_LARGE_MTU を提示し、サーバーも返したときだけ、
READ に 64 KiB ごとに 1 つ（最大 15）のクレジットを課します（CreditCharge）。
エンジンは接続時の 1 から始めて、要求ごとに CreditCharge を引き、応答
（interim を含む）ごとに CreditResponse を足し（上限 8,192）、手元にない
クレジットを要する READ は送りません。message id は CreditCharge だけ進めます。
LARGE_MTU のときの CreditRequest は、CreditCharge に、残りを 32 に戻す分を
足した値です（それ以外は 1）。応答の magic、
structure size、command、message id、session/tree id、zero credit、
response flag、async flag、`NextCommand` を検査します。暗号化していない
ときの SMB 2 transform header、compression、compound response、未実装の
async 応答は、状態を破棄して `SMB.Protocol_Error` になります。認証後の NTSTATUS は署名を検証した
後に限り `SMB.NT_Status_Error` として呼び出し元へ渡します。
ネゴシエーションと最初の challenge 応答は署名鍵確立前なので unsigned
です。これだけで認証済み状態へ進むことはできません。

## 署名

session base key の 16 byte を signing key とし、SMB2 header の
signature field をゼロ化して HMAC-SHA256(message) を計算し、先頭 16
byte を格納・比較します（SMB 2.1）。SMB 3.1.1 は上記のとおり導出した鍵の
AES-128-GMAC か AES-128-CMAC の 16 byte です。認証後の request は全て署名し、期待する
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

2.1 の NEGOTIATE 応答では `NegotiateContextCount/Reserved` と
`NegotiateContextOffset/Reserved2` を無視し、3.1.1 の応答ではそれらを
negotiate context の位置として検査します。TREE_CONNECT の `Reserved` も
受信時に無視します。2.1 の応答が SMB 3 の capability（multichannel、
persistent handle、directory leasing、encryption）を主張すると拒否し、
3.1.1 の応答では使わないだけで受け入れます。署名有効、セキュリティバッファの境界、
共有種別、TreeId、cipher がない場合の暗号化要求の拒否は引き続き検査します。

* [MS-SMB2 2.2.4 NEGOTIATE Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/63abf97c-0d09-47e2-88d6-6bfa552949a5)
* [MS-SMB2 2.2.10 TREE_CONNECT Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/dd34e26c-a75e-47fa-aab2-6efc27502e96)

## ファイル情報

`Query_Information` は開いたハンドルに QUERY_INFO を 1 つ送り、
FileNetworkOpenInformation（class 34）をちょうど 56 byte 要求します。
要求本文は StructureSize 41 で、OutputBufferLength は 56、InputBuffer は
なく（InputBufferOffset と InputBufferLength は 0）、StructureSize が数える
1 byte の Buffer はゼロです。クライアントが開くハンドルはどのアクセス
モードでも FILE_READ_ATTRIBUTES を含むので、読み取り専用でも書き込み専用でも
問い合わせられます。

応答は QUERY_DIRECTORY と同じ形（StructureSize 9、OutputBufferOffset、
OutputBufferLength）で、長さが 0 でなければ offset は固定部の後（72 以上）、
データはパケット内に収まっていなければなりません。成功応答の長さが 56 byte
でなければ、要求した構造ではないので接続を破棄します。Reserved の 4 byte は
読みません。STATUS_ACCESS_DENIED などのエラー応答は、署名と構造を検査した
うえで NTSTATUS として呼び出し元へ返し、接続は保ちます。

時刻はサーバーが送る FILETIME（1601-01-01 UTC からの 100ns 単位）のまま
返します。`List_Directory` の各項目も、FileIdBothDirectoryInformation の
同じ 4 つの時刻を返します。`To_Time` は Ada.Calendar の範囲（1901〜2399 年）
で `Ada.Calendar.Time` に変換し、範囲外は `Ada.Calendar.Time_Error` にします。
時刻を持たないサーバーが送る 0 も範囲外です。

`Set_Size` は書き込み可能なハンドル（`Write_Only` か `Read_Write`）に
SET_INFO を 1 つ送り、FileEndOfFileInformation（class 20）の 8 byte の
EndOfFile を設定します。要求本文は StructureSize 33、BufferLength 8、
BufferOffset 96 です。EndOfFile は符号付き 64 bit なので 2**63 - 1 を超える
サイズは送らず、読み取り専用のハンドルとともに送信前に拒否します。応答は
StructureSize 2 の SET_INFO 応答で、エラーは NTSTATUS として返し、接続は
保ちます。伸ばした部分は、Windows でも Samba でもゼロとして読めます。

公式仕様:

* [MS-SMB2 2.2.37 QUERY_INFO Request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d623b2f7-a5cd-4639-8cc9-71fa7d9f9ba9)
* [MS-SMB2 2.2.38 QUERY_INFO Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3b1b3598-a898-44ca-bfac-2dcae065247f)
* [MS-FSCC FileNetworkOpenInformation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/26d261db-58d1-4513-a548-074448cbb146)
* [MS-SMB2 2.2.39 SET_INFO Request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ee9614c4-be54-4a3c-98f1-769a7032a0e4)
* [MS-SMB2 2.2.40 SET_INFO Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c4318eb4-bdab-49b7-9352-abd7005c7f19)
* [MS-FSCC FileEndOfFileInformation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/75241cca-3167-472f-8058-a52d77c6bb17)

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

Type 2 の有効な security buffer と AV pairs を bounds-check し、Unicode、
NTLM、ESS、signing、target-info を要求します。server timestamp を
優先して NTLMv2 blob に使い、その AV がある場合は LM response を全
zero にします。timestamp がない場合だけ現在の FILETIME と callback
nonce を使います。MsvAvFlags の MIC-present bit を保持/追加し、Type 1、
Type 2、zero-MIC Type 3 全体で MIC を計算します。channel binding が
非 zero の場合、値を捏造せず拒否します。KEY_EXCH/RC4、NTLMv1、LM 認証
は提供しません。

`NTLMSSP_REQUEST_TARGET` が解除されている場合、TargetName の長さ・最大長・
オフセットは仕様に従って無視し、名前を読み取りません。設定されている場合は
既存の境界・UTF-16 検査を行います。TargetInfo とその必須 AV 名の検査は
維持し、無視するフィールドも含めて Type 2 全体を MIC 計算の対象にします。

公式仕様:

* [MS-NLMP NTOWFv2 and session base key](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3)
* [MS-NLMP timestamp, LM response and MIC AV flag](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/c0250a97-2940-40c7-82fb-20d208c71e96)
* [MS-NLMP CHALLENGE_MESSAGE fields](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786)

## 暗号と入力制限

MD4、MD5、SHA-256、SHA-512、HMAC-MD5、HMAC-SHA256、AES-128 と AES-256
（暗号化方向のみ）、AES-128-CMAC、AES-CCM、AES-GCM（GMAC を含む）、SMB 3.1.1 の鍵導出
（SP 800-108）は
Ada の整数演算だけで実装しています。既定エントロピーはUnixで `/dev/urandom`、Windowsで
`BCryptGenRandom(NULL, buffer, length, BCRYPT_USE_SYSTEM_PREFERRED_RNG)`です。
短い読み取りやOS API失敗を成功扱いにせず、疑似乱数にフォールバックしません。UTF-8 の overlong、surrogate、範囲外 scalar、
embedded NUL、UTF-16 の奇数長・不正 surrogate は拒否します。

フレーム最大値は 1 MiB です。READ と WRITE は LARGE_MTU のとき 1 要求最大
960 KiB（15 クレジット、READ 応答と WRITE 要求が header・transform header
込みで 1 MiB のフレームに収まる大きさ）、それ以外は 64 KiB です。TCP の header と payload は一つの deadline で完全送受信し、
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
