with SMB.AES;
with SMB.Core_Negotiate;
with SMB.Core_Preauth;
with SMB.Core_Transform;
with SMB.Core_Wire;
with SMB.Core_Protocol;
with SMB.KDF;
with SMB.Core_NTLM;
with SMB.Crypto;

package SMB.Engine
  with SPARK_Mode,
       Abstract_State => Identity_Registry,
       Initializes => Identity_Registry
is
   use type SMB.Byte;
   use type SMB.Word;
   use type SMB.Core_Negotiate.Cipher_Id;
   use type SMB.Core_Wire.Command_Code;
   use type SMB.DWord;
   use type SMB.QWord;
   pragma Unevaluated_Use_Of_Old (Allow);

   Maximum_Handles : constant := 256;

   type Phase is
     (Disconnected, Transport_Connected, Negotiated, Authenticated,
      Share_Connected);
   type Access_Kind is (Read_Only, Write_Only, Read_Write);

   type Handle_Token is record
      Owner : SMB.QWord := 0;
      Epoch : SMB.QWord := 0;
      Ticket : SMB.QWord := 0;
   end record;

   type Request_Expectation is record
      Command : SMB.Core_Wire.Command_Code := 0;
      Message_Id : SMB.QWord := 0;
      Tree_Id : SMB.DWord := 0;
      Session_Id : SMB.QWord := 0;
      Match_Tree : Boolean := False;
      Match_Session : Boolean := False;
      Request_Signed : Boolean := False;
      Signed : Boolean := False;
      Request_Amount : Natural := 0;
      Close_Token : Handle_Token := (others => 0);
   end record;

   type Engine_State is private;

   function Handle_Table_Equivalent
     (Left, Right : Engine_State) return Boolean
   with Ghost;

   function Other_Handles_Preserved
     (Left, Right : Engine_State;
      Except_Ticket : SMB.QWord := 0) return Boolean
   with Ghost;

   procedure Lemma_Handle_Table_Transitive
     (First, Middle, Last : Engine_State)
   with Ghost,
     Pre => Handle_Table_Equivalent (First, Middle)
       and then Handle_Table_Equivalent (Middle, Last),
     Post => Handle_Table_Equivalent (First, Last);

   function Current_Phase (State : Engine_State) return Phase;
   function Current_Session_Id (State : Engine_State) return SMB.QWord;
   function Current_Tree_Id (State : Engine_State) return SMB.DWord;
   function Current_Max_Read (State : Engine_State) return Natural;
   function Current_Max_Write (State : Engine_State) return Natural;
   function Current_Async_Id (State : Engine_State) return SMB.QWord;
   function Has_Open_Handles (State : Engine_State) return Boolean;
   function Has_Pending_Request (State : Engine_State) return Boolean;
   function Has_Signing_Key (State : Engine_State) return Boolean;
   function Current_Response_Info (State : Engine_State)
     return SMB.Core_Protocol.Response_Info;
   function Signing_Key_Is_Zero (State : Engine_State) return Boolean;
   --  The dialect and cipher that negotiation chose (0 and No_Cipher before
   --  it), and the connection's preauth integrity hash after the NEGOTIATE
   --  exchange, which a 3.1.1 session continues.
   function Current_Dialect (State : Engine_State) return SMB.Word;
   function Current_Cipher
     (State : Engine_State) return SMB.Core_Negotiate.Cipher_Id;
   function Current_Preauth
     (State : Engine_State) return SMB.Core_Preauth.Hash_Value;
   --  A 3.1.1 session signs with a key derived from the session key, which
   --  Current_Signing_Key holds as for 2.1 and which still keys the SPNEGO
   --  mechListMIC.
   function Has_SMB3_Signing_Key (State : Engine_State) return Boolean;
   function Current_SMB3_Signing_Key
     (State : Engine_State) return SMB.AES.Key_128;
   --  With a cipher, a 3.1.1 session also derives the keys that encrypt
   --  requests and decrypt responses, as Cipher_Key gives them. Encryption
   --  starts once the session is authenticated; from then on every request
   --  is sealed with the next nonce, and only a response that
   --  Unwrap_Response decrypted is accepted.
   function Has_Cipher_Keys (State : Engine_State) return Boolean;
   function Current_Encryption_Key
     (State : Engine_State) return SMB.AES.Key_256;
   function Current_Decryption_Key
     (State : Engine_State) return SMB.AES.Key_256;

   --  The cipher key a 3.1.1 session derives for Purpose under Cipher, in
   --  32 bytes: SMB.KDF.Derive_256 (L = 256) for AES-256-CCM and
   --  AES-256-GCM, and otherwise SMB.KDF.Derive (L = 128) followed by 16
   --  zero bytes. Seal_Request and Unwrap_Response use the first
   --  SMB.Core_Transform.Key_Length (Cipher) bytes. The signing key is
   --  SMB.KDF.Derive (L = 128) under every cipher, since 3.1.1 signs with
   --  AES-128-CMAC; Samba derives it the same way.
   function Cipher_Key
     (Session_Key : SMB.Crypto.Digest_128;
      Purpose : SMB.KDF.Key_Purpose;
      Preauth : SMB.Core_Preauth.Hash_Value;
      Cipher : SMB.Core_Negotiate.Cipher_Id) return SMB.AES.Key_256 is
     (if Cipher in SMB.Core_Negotiate.AES_256_CCM
                 | SMB.Core_Negotiate.AES_256_GCM
      then SMB.KDF.Derive_256 (Session_Key, Purpose, Preauth)
      else SMB.KDF.Derive (Session_Key, Purpose, Preauth)
           & SMB.Crypto.Digest_128'(others => 0));
   function Is_Encrypting (State : Engine_State) return Boolean;
   function Next_Nonce (State : Engine_State) return SMB.QWord;
   function Holds_Decrypted_Response (State : Engine_State) return Boolean;
   function Current_Owner_Id (State : Engine_State) return SMB.QWord;
   function Current_Epoch (State : Engine_State) return SMB.QWord;
   function Connection_Context_Equivalent
     (Left, Right : Engine_State) return Boolean
   with Ghost,
     Post => Connection_Context_Equivalent'Result =
       (Current_Phase (Left) = Current_Phase (Right)
        and then Current_Owner_Id (Left) = Current_Owner_Id (Right)
        and then Current_Epoch (Left) = Current_Epoch (Right)
        and then Current_Session_Id (Left) = Current_Session_Id (Right)
        and then Current_Tree_Id (Left) = Current_Tree_Id (Right)
        and then Current_Max_Read (Left) = Current_Max_Read (Right)
        and then Current_Max_Write (Left) = Current_Max_Write (Right)
        and then Has_Signing_Key (Left) = Has_Signing_Key (Right)
        and then Current_Signing_Key (Left) = Current_Signing_Key (Right)
        and then Handle_Table_Equivalent (Left, Right));
   function Interim_Context_Equivalent
     (Left, Right : Engine_State) return Boolean
   with Ghost;
   procedure Lemma_Connection_Context_Transitive
     (First, Middle, Last : Engine_State)
   with Ghost,
     Pre => Connection_Context_Equivalent (First, Middle)
       and then Connection_Context_Equivalent (Middle, Last),
     Post => Connection_Context_Equivalent (First, Last);

   function Valid_Handle
     (State : Engine_State;
      Token : Handle_Token;
      Need_Read, Need_Write : Boolean) return Boolean
   with Ghost;
   function Handle_Matches
     (State : Engine_State;
      Token : Handle_Token;
      File_Id : SMB.Bytes;
      Access_Mode : Access_Kind;
      Is_Directory : Boolean) return Boolean
   with Ghost;
   function Handle_Matches_In_States
     (Before, After : Engine_State;
      Token : Handle_Token;
      File_Id : SMB.Bytes;
      Access_Mode : Access_Kind;
      Is_Directory : Boolean) return Boolean
   with
     Ghost,
     Pre => File_Id'Length = 16,
     Post =>
       Handle_Matches_In_States'Result =
         (Handle_Table_Equivalent (Before, After)
          and then Current_Phase (Before) = Current_Phase (After)
          and then Current_Owner_Id (Before) = Current_Owner_Id (After)
          and then Current_Epoch (Before) = Current_Epoch (After))
       and then
         (if Handle_Matches_In_States'Result then
            Handle_Matches
              (Before, Token, File_Id, Access_Mode, Is_Directory) =
            Handle_Matches
              (After, Token, File_Id, Access_Mode, Is_Directory));
   function Handle_Matches_Equivalent
     (State : Engine_State;
      Token : Handle_Token;
      Left_File_Id, Right_File_Id : SMB.Bytes;
      Access_Mode : Access_Kind;
      Is_Directory : Boolean) return Boolean
   with
     Ghost,
     Pre =>
       Left_File_Id'Length = 16
       and then Right_File_Id'Length = 16
       and then
         (for all Index in 0 .. 15 =>
            Left_File_Id (Left_File_Id'First + Index) =
              Right_File_Id (Right_File_Id'First + Index)),
     Post =>
       Handle_Matches_Equivalent'Result
       and then Handle_Matches
         (State, Token, Left_File_Id, Access_Mode, Is_Directory) =
       Handle_Matches
         (State, Token, Right_File_Id, Access_Mode, Is_Directory);
   function Has_Validated_Response (State : Engine_State) return Boolean;
   function Response_Receipt_Matches
     (State : Engine_State;
      Command : SMB.Core_Wire.Command_Code;
      Nt_Status : SMB.DWord;
      Signed, MIC_Valid : Boolean) return Boolean;
   function Pending_Command
     (State : Engine_State) return SMB.Core_Wire.Command_Code
   with Ghost;
   function Pending_Response_Is_Signed
     (State : Engine_State) return Boolean
   with Ghost;
   function Response_Header_Matches_Request
     (State : Engine_State; Packet : SMB.Bytes; Interim : Boolean)
      return Boolean
   with Ghost;
   function Pending_Request_Matches
     (State : Engine_State;
      Expected : Request_Expectation) return Boolean
   with Post =>
     (if Pending_Request_Matches'Result then
        Pending_Command (State) = Expected.Command
        and then Pending_Response_Is_Signed (State) = Expected.Signed);
   function Create_Receipt_Matches_File_Id
     (State : Engine_State;
      File_Id : SMB.Bytes) return Boolean
   with Ghost;
   function Close_Receipt_Matches
     (State : Engine_State;
      Token : Handle_Token) return Boolean
   with Ghost;

   function Last_Allocated_Owner_Id return SMB.QWord
   with Ghost, Global => (Input => Identity_Registry);

   function Next_Request_Id (State : Engine_State) return SMB.QWord
   with Ghost;

   function Last_Allocated_Handle_Ticket (State : Engine_State) return SMB.QWord
   with Ghost;

   procedure Initialize
     (State : in out Engine_State;
      Status : out SMB.Core_Status)
   with
     Global => (In_Out => Identity_Registry),
     Post =>
       Last_Allocated_Owner_Id = Last_Allocated_Owner_Id'Old
         + (if Status = SMB.Ok then 1 else 0)
       and (Status /= SMB.Ok
            or Last_Allocated_Owner_Id'Old < SMB.QWord'Last)
       and (Status /= SMB.Counter_Exhausted
            or Last_Allocated_Owner_Id'Old = SMB.QWord'Last)
       and
       (if Status = SMB.Ok then
          Current_Phase (State)'Old = Disconnected
          and not Has_Pending_Request (State)'Old
          and not Has_Signing_Key (State)'Old
          and not Has_Validated_Response (State)'Old
          and not Has_Open_Handles (State)'Old
          and Current_Phase (State) = Disconnected
          and Current_Owner_Id (State) = Last_Allocated_Owner_Id
          and Current_Owner_Id (State) /= 0
          and Current_Epoch (State) = 0
          and Next_Request_Id (State) = 0
          and Last_Allocated_Handle_Ticket (State) = 0
          and Current_Session_Id (State) = 0
          and Current_Tree_Id (State) = 0
          and Current_Max_Read (State) = 0
          and Current_Max_Write (State) = 0
          and not Has_Open_Handles (State)
          and not Has_Pending_Request (State)
          and not Has_Validated_Response (State)
          and not Has_Signing_Key (State)
          and Current_Async_Id (State) = 0
          and Signing_Key_Is_Zero (State)
          and not Has_Cipher_Keys (State)
          and Current_Encryption_Key (State) = SMB.AES.Key_256'(others => 0)
          and Current_Decryption_Key (State) = SMB.AES.Key_256'(others => 0)
          and Next_Nonce (State) = 0
          and not Is_Encrypting (State)
          and not Holds_Decrypted_Response (State)
        else State = State'Old
          and (if Current_Phase (State)'Old /= Disconnected
                 or else Has_Pending_Request (State)'Old
                 or else Has_Signing_Key (State)'Old
                 or else Has_Validated_Response (State)'Old
                 or else Has_Open_Handles (State)'Old
               then Status = SMB.Invalid_State_Status
               else Status = SMB.Counter_Exhausted));

   procedure Mark_Connected
     (State : in out Engine_State;
      Status : out SMB.Core_Status)
   with
     Post =>
       Next_Request_Id (State) = Next_Request_Id (State)'Old
       and then
       Last_Allocated_Handle_Ticket (State) = Last_Allocated_Handle_Ticket (State)'Old
       and then
       (if Status = SMB.Ok then
          Current_Phase (State)'Old = Disconnected
          and Current_Owner_Id (State)'Old /= 0
          and Current_Phase (State) = Transport_Connected
          and Current_Owner_Id (State) = Current_Owner_Id (State)'Old
          and Current_Epoch (State) = Current_Epoch (State)'Old
          and Current_Session_Id (State) = Current_Session_Id (State)'Old
          and Current_Tree_Id (State) = Current_Tree_Id (State)'Old
          and Current_Max_Read (State) = Current_Max_Read (State)'Old
          and Current_Max_Write (State) = Current_Max_Write (State)'Old
          and Has_Signing_Key (State) = Has_Signing_Key (State)'Old
          and Current_Signing_Key (State) = Current_Signing_Key (State)'Old
          and Handle_Table_Equivalent (State'Old, State)
          and Has_Pending_Request (State) = Has_Pending_Request (State)'Old
          and Has_Validated_Response (State) =
            Has_Validated_Response (State)'Old
        else State = State'Old and Status = SMB.Invalid_State_Status);

   --  Cipher and Preauth are those of a 3.1.1 response; a 2.1 response has
   --  neither, and gets No_Cipher.
   procedure Mark_Negotiated
     (State : in out Engine_State;
      Maximum_Read, Maximum_Write : Natural;
      Cipher : SMB.Core_Negotiate.Cipher_Id;
      Preauth : SMB.Core_Preauth.Hash_Value;
      Status : out SMB.Core_Status)
   with
     Post =>
       Next_Request_Id (State) = Next_Request_Id (State)'Old
       and then
       Last_Allocated_Handle_Ticket (State) = Last_Allocated_Handle_Ticket (State)'Old
       and then
       Status =
         (if Current_Phase (State)'Old = Transport_Connected
             and then not Has_Pending_Request (State)'Old
             and then Response_Receipt_Matches
               (State, 0, SMB.Success, False, False)'Old
             and then Maximum_Read in 1 .. SMB.Maximum_Frame_Size
             and then Maximum_Write in 1 .. SMB.Maximum_Frame_Size
             and then Current_Response_Info (State)'Old.Max_Read = Maximum_Read
             and then Current_Response_Info (State)'Old.Max_Write = Maximum_Write
          then SMB.Ok else SMB.Invalid_Value)
       and then
       (if Status = SMB.Ok then
          Current_Phase (State)'Old = Transport_Connected
          and not Has_Pending_Request (State)'Old
          and Response_Receipt_Matches
            (State, 0, SMB.Success, False, False)'Old
          and Current_Response_Info (State)'Old.Max_Read = Maximum_Read
          and Current_Response_Info (State)'Old.Max_Write = Maximum_Write
          and
          Current_Phase (State) = Negotiated
          and Current_Owner_Id (State) = Current_Owner_Id (State)'Old
          and Current_Epoch (State) = Current_Epoch (State)'Old
          and Current_Tree_Id (State) = Current_Tree_Id (State)'Old
          and Current_Signing_Key (State) = Current_Signing_Key (State)'Old
          and Has_Signing_Key (State) = Has_Signing_Key (State)'Old
          and Handle_Table_Equivalent (State'Old, State)
          and Current_Max_Read (State) = Maximum_Read
          and Current_Max_Write (State) = Maximum_Write
          and Current_Session_Id (State) = 0
          and Current_Dialect (State) =
            Current_Response_Info (State)'Old.Dialect
          and Current_Cipher (State) =
            (if Current_Dialect (State) = SMB.SMB2_Dialect_0311 then Cipher
             else SMB.Core_Negotiate.No_Cipher)
          and Current_Preauth (State) = Preauth
          and not Has_SMB3_Signing_Key (State)
          and not Has_Validated_Response (State)
          and not Has_Pending_Request (State)
        else State = State'Old);

   --  True when After differs from Before at most in the 3.1.1 signing key.
   function Only_SMB3_Keys_Changed (Before, After : Engine_State) return Boolean
   with Ghost;

   --  Derives the 3.1.1 signing key from the session key and Preauth, the
   --  session's final preauth integrity hash, once the last SESSION_SETUP
   --  request that enters it is built (MS-SMB2 3.2.5.3.1). The final
   --  response is verified with it. With a cipher it also derives the
   --  encryption and decryption keys and starts the nonce counter at 1.
   procedure Derive_SMB3_Keys
     (State : in out Engine_State;
      Preauth : SMB.Core_Preauth.Hash_Value;
      Status : out SMB.Core_Status)
   with
     Post =>
       (if Status = SMB.Ok then
          Current_Dialect (State)'Old = SMB.SMB2_Dialect_0311
          and Has_Signing_Key (State)'Old
          and not Has_SMB3_Signing_Key (State)'Old
          and not Has_Cipher_Keys (State)'Old
          and Only_SMB3_Keys_Changed (State'Old, State)
          and Next_Request_Id (State) = Next_Request_Id (State)'Old
          and Last_Allocated_Handle_Ticket (State) =
            Last_Allocated_Handle_Ticket (State)'Old
          and Current_Phase (State) = Current_Phase (State)'Old
          and Current_Owner_Id (State) = Current_Owner_Id (State)'Old
          and Current_Epoch (State) = Current_Epoch (State)'Old
          and Current_Session_Id (State) = Current_Session_Id (State)'Old
          and Current_Tree_Id (State) = Current_Tree_Id (State)'Old
          and Current_Max_Read (State) = Current_Max_Read (State)'Old
          and Current_Max_Write (State) = Current_Max_Write (State)'Old
          and Current_Signing_Key (State) = Current_Signing_Key (State)'Old
          and Has_Signing_Key (State) = Has_Signing_Key (State)'Old
          and Signing_Key_Is_Zero (State) = Signing_Key_Is_Zero (State)'Old
          and Has_Pending_Request (State) = Has_Pending_Request (State)'Old
          and Has_Validated_Response (State) =
            Has_Validated_Response (State)'Old
          and SMB.Core_Protocol."="
            (Current_Response_Info (State), Current_Response_Info (State)'Old)
          and Handle_Table_Equivalent (State'Old, State)
          and Current_Dialect (State) = Current_Dialect (State)'Old
          and Current_Cipher (State) = Current_Cipher (State)'Old
          and Current_Preauth (State) = Current_Preauth (State)'Old
          and Has_SMB3_Signing_Key (State)
          and Current_SMB3_Signing_Key (State) =
            SMB.KDF.Derive
              (Current_Signing_Key (State), SMB.KDF.Signing, Preauth)
          and Is_Encrypting (State) = Is_Encrypting (State)'Old
          and Holds_Decrypted_Response (State) =
            Holds_Decrypted_Response (State)'Old
          and
            (if Current_Cipher (State) = SMB.Core_Negotiate.No_Cipher then
               not Has_Cipher_Keys (State)
               and Current_Encryption_Key (State) =
                 Current_Encryption_Key (State)'Old
               and Current_Decryption_Key (State) =
                 Current_Decryption_Key (State)'Old
               and Next_Nonce (State) = Next_Nonce (State)'Old
             else
               Has_Cipher_Keys (State)
               and Current_Encryption_Key (State) =
                 Cipher_Key
                   (Current_Signing_Key (State), SMB.KDF.Encryption,
                    Preauth, Current_Cipher (State))
               and Current_Decryption_Key (State) =
                 Cipher_Key
                   (Current_Signing_Key (State), SMB.KDF.Decryption,
                    Preauth, Current_Cipher (State))
               and Next_Nonce (State) = 1)
        else State = State'Old and Status = SMB.Invalid_State_Status);

   procedure Install_Session_Key
     (State : in out Engine_State;
      Session_Id : SMB.QWord;
      Key : SMB.Bytes;
      Status : out SMB.Core_Status)
   with
     Post =>
       Next_Request_Id (State) = Next_Request_Id (State)'Old
       and then
       Last_Allocated_Handle_Ticket (State) = Last_Allocated_Handle_Ticket (State)'Old
       and then
       (if Status = SMB.Ok then
          Current_Owner_Id (State) = Current_Owner_Id (State)'Old
          and Current_Epoch (State) = Current_Epoch (State)'Old
          and Current_Phase (State)'Old = Negotiated
          and not Has_Pending_Request (State)'Old
          and Response_Receipt_Matches
            (State, 1, SMB.Status_More_Processing_Required, False, False)'Old
          and Current_Response_Info (State)'Old.Session_Id = Session_Id
          and not Has_Signing_Key (State)'Old
          and not Has_Pending_Request (State)'Old
          and Session_Id /= 0
          and Key'Length = 16
          and
          Current_Phase (State) = Negotiated
          and
          Has_Signing_Key (State)
          and Current_Session_Id (State) = Session_Id
          and Current_Signing_Key (State) = Key
          and not Has_Validated_Response (State)
        else State = State'Old and Status = SMB.Invalid_Value);

   procedure Mark_Authenticated
     (State : in out Engine_State;
      Status : out SMB.Core_Status)
   with
     Post =>
       Next_Request_Id (State) = Next_Request_Id (State)'Old
       and then
       Last_Allocated_Handle_Ticket (State) = Last_Allocated_Handle_Ticket (State)'Old
       and then
       (if Status = SMB.Ok then
          Current_Owner_Id (State) = Current_Owner_Id (State)'Old
          and Current_Epoch (State) = Current_Epoch (State)'Old
          and Current_Phase (State)'Old = Negotiated
          and Has_Signing_Key (State)'Old
          and not Has_Pending_Request (State)'Old
          and Response_Receipt_Matches (State, 1, SMB.Success, True, True)'Old
          and Current_Response_Info (State)'Old.Session_Id =
            Current_Session_Id (State)'Old
          and
          Current_Phase (State) = Authenticated
          and Current_Session_Id (State) = Current_Session_Id (State)'Old
          and Has_Signing_Key (State)
          and Current_Signing_Key (State) = Current_Signing_Key (State)'Old
          and SMB.Core_Protocol."="
            (Current_Response_Info (State), Current_Response_Info (State)'Old)
          and SMB.Core_NTLM.Mechanism_List_MIC
            (SMB.Crypto.Digest_128 (Current_Signing_Key (State)), True) =
            SMB.Core_NTLM.Mechanism_List_MIC
              (SMB.Crypto.Digest_128 (Current_Signing_Key (State)'Old), True)
          and not Has_Validated_Response (State)
          and not Has_Pending_Request (State)
          --  Encryption starts with the first request after authentication.
          and Is_Encrypting (State) = Has_Cipher_Keys (State)'Old
        else State = State'Old and Status = SMB.Invalid_State_Status);

   procedure Mark_Share_Connected
     (State : in out Engine_State;
      Tree_Id : SMB.DWord;
      Status : out SMB.Core_Status)
   with
     Post =>
       Next_Request_Id (State) = Next_Request_Id (State)'Old
       and then
       Last_Allocated_Handle_Ticket (State) = Last_Allocated_Handle_Ticket (State)'Old
       and then
       Status =
         (if Current_Phase (State)'Old = Authenticated
             and then not Has_Pending_Request (State)'Old
             and then Tree_Id /= 0
             and then Response_Receipt_Matches
               (State, 3, SMB.Success, True, False)'Old
             and then Current_Response_Info (State)'Old.Tree_Id = Tree_Id
          then SMB.Ok else SMB.Invalid_State_Status)
       and then
       (if Status = SMB.Ok then
          Current_Phase (State)'Old = Authenticated
          and not Has_Pending_Request (State)'Old
          and Tree_Id /= 0
          and Response_Receipt_Matches (State, 3, SMB.Success, True, False)'Old
          and Current_Response_Info (State)'Old.Tree_Id = Tree_Id
          and
          Current_Phase (State) = Share_Connected
          and Current_Owner_Id (State) = Current_Owner_Id (State)'Old
          and Current_Epoch (State) = Current_Epoch (State)'Old
          and Current_Session_Id (State) = Current_Session_Id (State)'Old
          and Current_Signing_Key (State) = Current_Signing_Key (State)'Old
          and Has_Signing_Key (State) = Has_Signing_Key (State)'Old
          and Handle_Table_Equivalent (State'Old, State)
          and Current_Tree_Id (State) = Tree_Id
          and Current_Max_Read (State) = Current_Max_Read (State)'Old
          and Current_Max_Write (State) = Current_Max_Write (State)'Old
          and not Has_Validated_Response (State)
          and not Has_Pending_Request (State)
        else State = State'Old);

   procedure Begin_Request
     (State : in out Engine_State;
      Command : SMB.Core_Wire.Command_Code;
      Request_Signed : Boolean;
      Response_Signed : Boolean;
      Message_Id : out SMB.QWord;
      Expected : out Request_Expectation;
      Status : out SMB.Core_Status;
      Request_Amount : Natural := 0;
      Close_Token : Handle_Token := (others => 0))
   with
     Post =>
       Last_Allocated_Handle_Ticket (State) = Last_Allocated_Handle_Ticket (State)'Old
       and then
       Connection_Context_Equivalent (State'Old, State)
       and then
       Current_Owner_Id (State) = Current_Owner_Id (State)'Old
       and then Current_Epoch (State) = Current_Epoch (State)'Old
       and then
         (if Status /= SMB.Ok then State = State'Old)
       and then
         (if not Has_Pending_Request (State)'Old
             and then Next_Request_Id (State)'Old = SMB.QWord'Last
          then Status = SMB.Counter_Exhausted)
       and then
         (if not Has_Pending_Request (State)'Old
             and then Current_Phase (State)'Old = Share_Connected
             and then Command = 5 and then Request_Signed and then Response_Signed
             and then Last_Allocated_Handle_Ticket (State)'Old = SMB.QWord'Last
          then Status = SMB.Counter_Exhausted)
       and then
       (if Status = SMB.Ok then
          Has_Pending_Request (State)
          and Next_Request_Id (State)'Old < SMB.QWord'Last
          and Message_Id = Next_Request_Id (State)'Old
          and Next_Request_Id (State) = Next_Request_Id (State)'Old + 1
          and not Has_Validated_Response (State)
          and Current_Async_Id (State) = 0
          and (if Command = 5 then Last_Allocated_Handle_Ticket (State) < SMB.QWord'Last)
          and Expected.Command = Command
          and Message_Id = Expected.Message_Id
          and Expected.Request_Signed = Request_Signed
          and Expected.Signed = Response_Signed
          and Expected.Request_Amount = Request_Amount
          and Expected.Close_Token = Close_Token
          and Expected.Match_Tree =
            (Current_Phase (State) = Share_Connected and then Command /= 2)
          and Expected.Match_Session =
            (Current_Phase (State) = Authenticated
             or else Current_Phase (State) = Share_Connected
             or else (Command = 1 and then Has_Signing_Key (State)))
          and Expected.Session_Id = Current_Session_Id (State)
          and Expected.Tree_Id =
            (if Command = 0 or else Command = 2 or else Command = 3
             then 0 else Current_Tree_Id (State))
          and Current_Session_Id (State) = Current_Session_Id (State)'Old
          and Current_Phase (State) = Current_Phase (State)'Old
          and Has_Signing_Key (State) = Has_Signing_Key (State)'Old
          and Handle_Table_Equivalent (State'Old, State)
          and Pending_Request_Matches (State, Expected)
        else Message_Id = 0 and Expected = Request_Expectation'(others => <>));

   procedure Inspect_Interim_Response
     (State : in out Engine_State;
      Packet : SMB.Bytes;
      Is_Interim : out Boolean;
      Status : out SMB.Core_Status)
   with
     Pre => Packet'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Next_Request_Id (State) =
         (if Status = SMB.Ok then Next_Request_Id (State)'Old else 0)
       and then
       Last_Allocated_Handle_Ticket (State) =
         (if Status = SMB.Ok then Last_Allocated_Handle_Ticket (State)'Old else 0)
       and then
       (if Status = SMB.Ok then
          (if Is_Interim then
             Interim_Context_Equivalent (State'Old, State)
             and then Has_Pending_Request (State)'Old
             and then Has_Pending_Request (State)
             and then not Has_Validated_Response (State)
             and then Current_Async_Id (State) /= 0
             and then Packet'Length >= 72
             and then Current_Async_Id (State) =
               SMB.Core_Wire.Encoded_U64 (Packet, 32)
             and then Response_Header_Matches_Request
               (State, Packet, True)'Old
             and then
               (if Current_Async_Id (State)'Old /= 0 then
                  Current_Async_Id (State) = Current_Async_Id (State)'Old)
           else State = State'Old)
        else
          not Is_Interim
          and then Current_Phase (State) = Disconnected
          and then not Has_Signing_Key (State)
          and then Current_Session_Id (State) = 0
          and then Current_Tree_Id (State) = 0
          and then Current_Async_Id (State) = 0
          and then not Has_Pending_Request (State)
          and then not Has_Validated_Response (State)
          and then not Has_Open_Handles (State)
          and then Signing_Key_Is_Zero (State))
       --  While encrypting, an interim response must have been decrypted,
       --  and the final one is decrypted on its own.
       and then
         (if Status = SMB.Ok and then Is_Interim then
            (if Is_Encrypting (State)'Old then
               Holds_Decrypted_Response (State)'Old)
            and then not Holds_Decrypted_Response (State)
            and then Is_Encrypting (State) = Is_Encrypting (State)'Old
            and then Next_Nonce (State) = Next_Nonce (State)'Old);

   function Only_Nonce_Advanced (Before, After : Engine_State) return Boolean
   with Ghost;
   function Only_Decryption_Recorded
     (Before, After : Engine_State) return Boolean
   with Ghost;

   --  Seals Message, a request ready to send, into a transform header with
   --  the encryption key and the next nonce (MS-SMB2 3.1.4.3), and advances
   --  the counter, so no nonce is used twice under a key. It fails when
   --  encryption is off, and with Counter_Exhausted rather than wrap.
   procedure Seal_Request
     (State : in out Engine_State;
      Message : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with
     Pre => Message'Length in 1 .. SMB.Core_Transform.Maximum_Message_Size
       and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Status in SMB.Ok | SMB.Invalid_State_Status | SMB.Counter_Exhausted
                | SMB.Invalid_Length
       and then
         (if Status = SMB.Ok then
            Is_Encrypting (State)'Old
            and then Next_Nonce (State)'Old < SMB.QWord'Last
            and then Next_Nonce (State) = Next_Nonce (State)'Old + 1
            and then Only_Nonce_Advanced (State'Old, State)
            and then Used = SMB.Core_Transform.Header_Size + Message'Length
            and then Used <= Output'Length
            and then SMB.Core_Transform.Is_Transformed (Output)
            and then
              (for all Index in SMB.Core_Transform.Nonce_Field'Range =>
                 Output (Output'First + 20 + Index) =
                   SMB.Core_Transform.Counter_Nonce
                     (Next_Nonce (State)'Old) (Index))
            and then SMB.Core_Wire.Encoded_U64 (Output, 44) =
              Current_Session_Id (State)
          else State = State'Old and then Used = 0);

   --  Checks and decrypts Packet, a whole received frame, in place with the
   --  decryption key (SMB.Core_Transform.Unwrap), for the pending request:
   --  on Ok the message after the transform header is what Accept_Response
   --  or Inspect_Interim_Response may take, without a signature. It needs
   --  encryption on, a pending request and no decrypted response held; any
   --  failure, a plaintext frame included, invalidates the engine and leaves
   --  no bytes after the transform header.
   procedure Unwrap_Response
     (State : in out Engine_State;
      Packet : in out SMB.Bytes;
      Status : out SMB.Core_Status)
   with
     Pre => Packet'Length <= SMB.Maximum_Frame_Size,
     Post =>
       (if Status = SMB.Ok then
          Is_Encrypting (State)'Old
          and then Has_Pending_Request (State)'Old
          and then not Holds_Decrypted_Response (State)'Old
          and then Holds_Decrypted_Response (State)
          and then Only_Decryption_Recorded (State'Old, State)
          and then Packet'Length - SMB.Core_Transform.Header_Size >=
            SMB.Core_Transform.SMB2_Header_Size
          and then SMB.Core_Wire.Encoded_U64
            (Packet, SMB.Core_Transform.Header_Size + 40) =
              Current_Session_Id (State)
        else
          Current_Phase (State) = Disconnected
          and then not Has_Pending_Request (State)
          and then not Has_Validated_Response (State)
          and then not Has_Signing_Key (State)
          and then not Is_Encrypting (State)
          and then not Holds_Decrypted_Response (State)
          and then
            (for all Index in Packet'Range =>
               (if Index - Packet'First >= SMB.Core_Transform.Header_Size
                then Packet (Index) = 0)));

   function Final_Token_MIC_Matches
     (Packet : SMB.Bytes;
      Info : SMB.Core_Protocol.Response_Info;
      Expected_MIC : SMB.Crypto.Digest_128) return Boolean
   is
     (Packet'Length <= SMB.Maximum_Frame_Size
      and then Info.Data_Length >= 16
      and then Info.Data_Offset <= Packet'Length
      and then Info.Data_Length <= Packet'Length - Info.Data_Offset
      and then Packet
        (Packet'Last
         - (Packet'Length - Info.Data_Offset - Info.Data_Length) - 15
         .. Packet'Last
            - (Packet'Length - Info.Data_Offset - Info.Data_Length)) =
        Expected_MIC)
   with Ghost,
     Annotate => (GNATprove, Inline_For_Proof);

   procedure Lemma_Final_Token_MIC_Transfer
     (Packet : SMB.Bytes;
      Left_Info, Right_Info : SMB.Core_Protocol.Response_Info;
      Left_MIC, Right_MIC : SMB.Crypto.Digest_128)
   with Ghost,
     Pre =>
       Final_Token_MIC_Matches (Packet, Left_Info, Left_MIC)
       and then SMB.Core_Protocol."=" (Left_Info, Right_Info)
       and then Left_MIC = Right_MIC,
     Post => Final_Token_MIC_Matches (Packet, Right_Info, Right_MIC);

   procedure Accept_Response
     (State : in out Engine_State;
      Packet : SMB.Bytes;
      Nt_Status : out SMB.DWord;
      Status : out SMB.Core_Status)
   with
     Pre => Packet'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Next_Request_Id (State) =
         (if Status /= SMB.Ok
             or else (Pending_Command (State)'Old = 2 and then Nt_Status = SMB.Success)
          then 0 else Next_Request_Id (State)'Old)
       and then
       Last_Allocated_Handle_Ticket (State) =
         (if Status /= SMB.Ok
             or else (Pending_Command (State)'Old = 2 and then Nt_Status = SMB.Success)
          then 0 else Last_Allocated_Handle_Ticket (State)'Old)
       and then
       (if Status /= SMB.Ok then
          Current_Phase (State) = Disconnected
          and not Has_Signing_Key (State)
          and Current_Session_Id (State) = 0
          and Current_Tree_Id (State) = 0
          and Current_Async_Id (State) = 0
          and Nt_Status = 0
          and not Has_Pending_Request (State)
          and not Has_Validated_Response (State)
          and not Has_Open_Handles (State)
          and Signing_Key_Is_Zero (State)
        else
          Packet'Length >= SMB.Core_Wire.Header_Size
          and then Response_Header_Matches_Request (State, Packet, False)'Old
          and then Nt_Status = SMB.Core_Wire.Header_Nt_Status (Packet)
          and then
          (if Pending_Command (State)'Old = 2
                and then Nt_Status = SMB.Success
           then True
           else Current_Owner_Id (State) = Current_Owner_Id (State)'Old
             and then Current_Epoch (State) = Current_Epoch (State)'Old)
          and then
          not Has_Pending_Request (State)
          and then Current_Async_Id (State) = 0
          and then
            (if Pending_Command (State)'Old = 4
               and then Nt_Status = SMB.Success
             then Current_Phase (State) = Authenticated
               and Current_Tree_Id (State) = 0
               and Current_Session_Id (State) = Current_Session_Id (State)'Old
               and Current_Signing_Key (State) = Current_Signing_Key (State)'Old
               and Has_Signing_Key (State) = Has_Signing_Key (State)'Old
               and not Has_Open_Handles (State)
               and not Has_Validated_Response (State)
             elsif Pending_Command (State)'Old = 2
               and then Nt_Status = SMB.Success
             then Current_Phase (State) = Disconnected
               and Signing_Key_Is_Zero (State)
               and not Has_Signing_Key (State)
               and Current_Session_Id (State) = 0
               and Current_Tree_Id (State) = 0
               and not Has_Open_Handles (State)
               and not Has_Validated_Response (State)
             else Connection_Context_Equivalent (State'Old, State)
               and then Response_Receipt_Matches
               (State, Pending_Command (State)'Old, Nt_Status,
                Pending_Response_Is_Signed (State)'Old,
                Pending_Command (State)'Old = 1
                  and then Nt_Status = SMB.Success)
               and then
                 (if Pending_Command (State)'Old = 1
                    and then Nt_Status = SMB.Success
                  then Final_Token_MIC_Matches
                    (Packet, Current_Response_Info (State),
                     SMB.Core_NTLM.Mechanism_List_MIC
                       (SMB.Crypto.Digest_128 (Current_Signing_Key (State)),
                        True)))
               and then
                 (if Pending_Command (State)'Old = 0
                    and then Nt_Status = SMB.Success
                  then Packet'Length >= 128
                    and then Current_Response_Info (State).Dialect in
                      SMB.SMB2_Dialect_0210 | SMB.SMB2_Dialect_0311
                    and then Current_Response_Info (State).Max_Read in
                      1 .. SMB.Core_Protocol.Maximum_IO_Chunk
                    and then Current_Response_Info (State).Max_Write in
                      1 .. SMB.Core_Protocol.Maximum_IO_Chunk
                    and then Current_Response_Info (State).Max_Read =
                      Natural (SMB.DWord'Min
                        (SMB.Core_Protocol.Maximum_IO_Chunk,
                         SMB.Core_Wire.Encoded_U32 (Packet, 96)))
                    and then Current_Response_Info (State).Max_Write =
                      Natural (SMB.DWord'Min
                        (SMB.Core_Protocol.Maximum_IO_Chunk,
                         SMB.Core_Wire.Encoded_U32 (Packet, 100)))
                  elsif Pending_Command (State)'Old = 3
                    and then Nt_Status = SMB.Success
                  then Packet'Length >= 80
                    and then Current_Response_Info (State).Tree_Id /= 0
                    and then Current_Response_Info (State).Tree_Id =
                      SMB.Core_Wire.Encoded_U32 (Packet, 36))
               and then
                 (if Pending_Command (State)'Old = 1
                    and then Nt_Status =
                      SMB.Status_More_Processing_Required
                  then Packet'Length >= 72
                    and then Current_Response_Info (State).Data_Offset =
                      Natural (SMB.Core_Wire.Encoded_U16 (Packet, 68))
                    and then Current_Response_Info (State).Data_Length =
                      Natural (SMB.Core_Wire.Encoded_U16 (Packet, 70)))
               and then
                 (if Pending_Command (State)'Old = 8
                    and then Nt_Status = SMB.Success
                  then Packet'Length >= 80
                    and then Current_Response_Info (State).Data_Offset =
                      Natural (Packet (Packet'First + 66))
                    and then SMB.Core_Wire.Encoded_U32 (Packet, 68) <=
                      SMB.DWord (SMB.Core_Protocol.Maximum_IO_Chunk)
                    and then Current_Response_Info (State).Data_Length =
                      Natural (SMB.Core_Wire.Encoded_U32 (Packet, 68))
                  elsif Pending_Command (State)'Old = 9
                    and then Nt_Status = SMB.Success
                  then Packet'Length >= 80
                    and then SMB.Core_Wire.Encoded_U32 (Packet, 68) <=
                      SMB.DWord (SMB.Core_Protocol.Maximum_IO_Chunk)
                    and then Current_Response_Info (State).Count =
                      Natural (SMB.Core_Wire.Encoded_U32 (Packet, 68))
                  elsif Pending_Command (State)'Old = 14
                    and then Nt_Status = SMB.Success
                  then Packet'Length >= 72
                    and then SMB.Core_Wire.Encoded_U32 (Packet, 68) <=
                      SMB.DWord (SMB.Core_Protocol.Maximum_IO_Chunk)
                    and then Current_Response_Info (State).Data_Offset =
                      Natural (SMB.Core_Wire.Encoded_U16 (Packet, 66))
                    and then Current_Response_Info (State).Data_Length <=
                      SMB.Core_Protocol.Maximum_IO_Chunk
                    and then Current_Response_Info (State).Data_Length =
                      Natural (SMB.Core_Wire.Encoded_U32 (Packet, 68))
                    and then
                      (Current_Response_Info (State).Data_Length = 0
                       or else Current_Response_Info (State).Data_Offset >= 72)
                    and then Current_Response_Info (State).Data_Offset <=
                      Packet'Length
                    and then Current_Response_Info (State).Data_Length <=
                      Packet'Length -
                        Current_Response_Info (State).Data_Offset
                    ))
               and then
                 (if Pending_Command (State)'Old = 17 then
                    Current_Phase (State) = Current_Phase (State)'Old
                    and then Handle_Table_Equivalent (State'Old, State)))
       --  While encrypting, only a decrypted response is taken; the flag is
       --  consumed either way, and only a successful LOGOFF, which ends the
       --  session, stops encryption or moves the nonce counter.
       and then not Holds_Decrypted_Response (State)
       and then
         (if Status = SMB.Ok then
            (if Is_Encrypting (State)'Old then
               Holds_Decrypted_Response (State)'Old)
            and then
              (if not (Pending_Command (State)'Old = 2
                       and then Nt_Status = SMB.Success)
               then Is_Encrypting (State) = Is_Encrypting (State)'Old
                 and then Next_Nonce (State) = Next_Nonce (State)'Old));
   --  A failed wire/signature check invalidates the session and all handles.

   procedure Register_Handle
     (State : in out Engine_State;
      File_Id : SMB.Bytes;
      Access_Mode : Access_Kind;
      Is_Directory : Boolean;
      Token : out Handle_Token;
      Status : out SMB.Core_Status)
   with
      Post =>
       Next_Request_Id (State) = Next_Request_Id (State)'Old
       and then
       (if Status = SMB.Counter_Exhausted then
          Last_Allocated_Handle_Ticket (State) = SMB.QWord'Last)
       and then
       (if Status = SMB.Ok then
          Last_Allocated_Handle_Ticket (State)'Old < SMB.QWord'Last
          and Last_Allocated_Handle_Ticket (State) =
            Last_Allocated_Handle_Ticket (State)'Old + 1
          and Token.Ticket = Last_Allocated_Handle_Ticket (State)
          and
          Current_Phase (State)'Old = Share_Connected
          and not Has_Pending_Request (State)'Old
          and Create_Receipt_Matches_File_Id (State, File_Id)'Old
          and
          Handle_Matches (State, Token, File_Id, Access_Mode, Is_Directory)
          and Other_Handles_Preserved (State'Old, State)
          and not Has_Validated_Response (State)
        else State = State'Old
          and Token.Owner = 0 and Token.Epoch = 0 and Token.Ticket = 0);

   procedure Validate_Handle
     (State : Engine_State;
      Token : Handle_Token;
      Need_Read, Need_Write : Boolean;
      File_Id : out SMB.Bytes;
      Access_Mode : out Access_Kind;
      Is_Directory : out Boolean;
      Status : out SMB.Core_Status)
   with
     Post =>
       (if File_Id'Length = 16 then
          (Status = SMB.Ok) =
            Valid_Handle (State, Token, Need_Read, Need_Write)
          and then
            (if Status = SMB.Ok then
               Handle_Matches (State, Token, File_Id, Access_Mode, Is_Directory)
             else Status = SMB.Invalid_Handle_Status)
        else Status = SMB.Invalid_Length)
       and then
         (if Status /= SMB.Ok then
            (for all Index in File_Id'Range => File_Id (Index) = 0)
            and then Access_Mode = Read_Only
            and then not Is_Directory);

   procedure Discard_Response_Receipt
     (State : in out Engine_State;
      Status : out SMB.Core_Status)
   with
     Post =>
       Next_Request_Id (State) = Next_Request_Id (State)'Old
       and then
       Last_Allocated_Handle_Ticket (State) = Last_Allocated_Handle_Ticket (State)'Old
       and then
       Status =
         (if Has_Pending_Request (State)'Old
          then SMB.Invalid_State_Status else SMB.Ok)
       and then Connection_Context_Equivalent (State'Old, State)
       and then Current_Phase (State) = Current_Phase (State)'Old
       and then Current_Owner_Id (State) = Current_Owner_Id (State)'Old
       and then Current_Epoch (State) = Current_Epoch (State)'Old
       and then Current_Session_Id (State) =
         Current_Session_Id (State)'Old
       and then Current_Tree_Id (State) = Current_Tree_Id (State)'Old
       and then Current_Max_Read (State) = Current_Max_Read (State)'Old
       and then Current_Max_Write (State) = Current_Max_Write (State)'Old
       and then Has_Signing_Key (State) = Has_Signing_Key (State)'Old
       and then Current_Signing_Key (State) =
         Current_Signing_Key (State)'Old
       and then Handle_Table_Equivalent (State'Old, State)
       and then (if Status = SMB.Ok then
          not Has_Validated_Response (State)
          and not Has_Pending_Request (State)
          and SMB.Core_Protocol."="
            (Current_Response_Info (State),
             SMB.Core_Protocol.Response_Info'(others => <>))
        else State = State'Old);

   procedure Close_Handle
     (State : in out Engine_State;
      Token : Handle_Token;
      Status : out SMB.Core_Status;
      Close_Token : Handle_Token := (others => 0))
   with
     Post =>
       Next_Request_Id (State) = Next_Request_Id (State)'Old
       and then
       Last_Allocated_Handle_Ticket (State) = Last_Allocated_Handle_Ticket (State)'Old
       and then
       (if Status = SMB.Ok then
          Current_Phase (State)'Old = Share_Connected
          and not Has_Pending_Request (State)'Old
          and Valid_Handle (State, Token, False, False)'Old
          and Close_Receipt_Matches (State, Token)'Old
          and Close_Token.Owner = Token.Owner
          and Close_Token.Epoch = Token.Epoch
          and Close_Token.Ticket = Token.Ticket
          and
          not Valid_Handle (State, Token, False, False)
          and Other_Handles_Preserved (State'Old, State, Token.Ticket)
          and not Has_Validated_Response (State)
        else State = State'Old and Status = SMB.Invalid_Handle_Status);

   procedure Invalidate
     (State : in out Engine_State;
      Status : out SMB.Core_Status)
   with
     Post =>
       Current_Phase (State) = Disconnected
       and not Has_Open_Handles (State)
       and not Has_Pending_Request (State)
       and not Has_Validated_Response (State)
       and Signing_Key_Is_Zero (State)
       and not Has_Signing_Key (State)
       and Current_Session_Id (State) = 0
       and Current_Tree_Id (State) = 0
       and Current_Async_Id (State) = 0
       and Current_Max_Read (State) = 0
       and Current_Max_Write (State) = 0
       and Next_Request_Id (State) = 0
       and Last_Allocated_Handle_Ticket (State) = 0
       and not Has_Cipher_Keys (State)
       and Current_Encryption_Key (State) = SMB.AES.Key_256'(others => 0)
       and Current_Decryption_Key (State) = SMB.AES.Key_256'(others => 0)
       and Next_Nonce (State) = 0
       and not Is_Encrypting (State)
       and not Holds_Decrypted_Response (State)
       and SMB.Core_Protocol."="
         (Current_Response_Info (State),
          SMB.Core_Protocol.Response_Info'(others => <>))
       and Status =
         (if Current_Epoch (State)'Old = SMB.QWord'Last
          then SMB.Counter_Exhausted
          else SMB.Ok)
       and
         (if Status = SMB.Ok then
            Current_Owner_Id (State) = Current_Owner_Id (State)'Old
            and Current_Epoch (State)'Old < SMB.QWord'Last
            and Current_Epoch (State) = Current_Epoch (State)'Old + 1
          else
            Current_Owner_Id (State) = 0
            and Current_Epoch (State) = Current_Epoch (State)'Old);

   function Current_Signing_Key (State : Engine_State) return SMB.Bytes
   with Post => Current_Signing_Key'Result'Length = 16;

private

   type Handle_Record is record
      Active : Boolean := False;
      Ticket : SMB.QWord := 0;
      File_Id : SMB.Bytes (0 .. 15) := (others => 0);
      Access_Mode : Access_Kind := Read_Only;
      Is_Directory : Boolean := False;
   end record;

   subtype Handle_Slot is Natural range 0 .. Maximum_Handles - 1;
   type Handle_Table is array (Handle_Slot)
      of Handle_Record;

   type Engine_State is record
      Current : Phase := Disconnected;
      Owner_Id : SMB.QWord := 0;
      Epoch : SMB.QWord := 0;
      Next_Message_Id : SMB.QWord := 0;
      Next_Ticket : SMB.QWord := 0;
      Session_Id : SMB.QWord := 0;
      Tree_Id : SMB.DWord := 0;
      Max_Read : Natural := 0;
      Max_Write : Natural := 0;
      Signing_Key : SMB.Bytes (0 .. 15) := (others => 0);
      Has_Key : Boolean := False;
      SMB3_Key : SMB.AES.Key_128 := (others => 0);
      Has_SMB3_Key : Boolean := False;
      Encryption_Key : SMB.AES.Key_256 := (others => 0);
      Decryption_Key : SMB.AES.Key_256 := (others => 0);
      Has_Cipher_Keys : Boolean := False;
      Encrypting : Boolean := False;
      Decrypted : Boolean := False;
      Nonce_Counter : SMB.QWord := 0;
      Dialect : SMB.Word := 0;
      Cipher : SMB.Core_Negotiate.Cipher_Id := SMB.Core_Negotiate.No_Cipher;
      Preauth : SMB.Core_Preauth.Hash_Value := SMB.Core_Preauth.Initial;
      Pending : Boolean := False;
      Pending_Async_Id : SMB.QWord := 0;
      Pending_Expected : Request_Expectation;
      Receipt_Valid : Boolean := False;
      Receipt_Command : SMB.Core_Wire.Command_Code := 0;
      Receipt_Status : SMB.DWord := 0;
      Receipt_Signed : Boolean := False;
      Receipt_MIC_Valid : Boolean := False;
      Receipt_Close_Token : Handle_Token := (others => 0);
      Receipt_Info : SMB.Core_Protocol.Response_Info;
      Handles : Handle_Table;
   end record;

   function Only_SMB3_Keys_Changed (Before, After : Engine_State) return Boolean
   is (After.Current = Before.Current
       and then After.Owner_Id = Before.Owner_Id
       and then After.Epoch = Before.Epoch
       and then After.Next_Message_Id = Before.Next_Message_Id
       and then After.Next_Ticket = Before.Next_Ticket
       and then After.Session_Id = Before.Session_Id
       and then After.Tree_Id = Before.Tree_Id
       and then After.Max_Read = Before.Max_Read
       and then After.Max_Write = Before.Max_Write
       and then After.Signing_Key = Before.Signing_Key
       and then After.Has_Key = Before.Has_Key
       and then After.Dialect = Before.Dialect
       and then After.Cipher = Before.Cipher
       and then After.Preauth = Before.Preauth
       and then After.Pending = Before.Pending
       and then After.Pending_Async_Id = Before.Pending_Async_Id
       and then After.Pending_Expected = Before.Pending_Expected
       and then After.Receipt_Valid = Before.Receipt_Valid
       and then After.Receipt_Command = Before.Receipt_Command
       and then After.Receipt_Status = Before.Receipt_Status
       and then After.Receipt_Signed = Before.Receipt_Signed
       and then After.Receipt_MIC_Valid = Before.Receipt_MIC_Valid
       and then After.Receipt_Close_Token = Before.Receipt_Close_Token
       and then SMB.Core_Protocol."=" (After.Receipt_Info, Before.Receipt_Info)
       and then After.Handles = Before.Handles
       and then After.Encrypting = Before.Encrypting
       and then After.Decrypted = Before.Decrypted);

   --  Every field but the nonce counter.
   function Only_Nonce_Advanced (Before, After : Engine_State) return Boolean
   is (After.Current = Before.Current
       and then After.Owner_Id = Before.Owner_Id
       and then After.Epoch = Before.Epoch
       and then After.Next_Message_Id = Before.Next_Message_Id
       and then After.Next_Ticket = Before.Next_Ticket
       and then After.Session_Id = Before.Session_Id
       and then After.Tree_Id = Before.Tree_Id
       and then After.Max_Read = Before.Max_Read
       and then After.Max_Write = Before.Max_Write
       and then After.Signing_Key = Before.Signing_Key
       and then After.Has_Key = Before.Has_Key
       and then After.SMB3_Key = Before.SMB3_Key
       and then After.Has_SMB3_Key = Before.Has_SMB3_Key
       and then After.Encryption_Key = Before.Encryption_Key
       and then After.Decryption_Key = Before.Decryption_Key
       and then After.Has_Cipher_Keys = Before.Has_Cipher_Keys
       and then After.Encrypting = Before.Encrypting
       and then After.Decrypted = Before.Decrypted
       and then After.Dialect = Before.Dialect
       and then After.Cipher = Before.Cipher
       and then After.Preauth = Before.Preauth
       and then After.Pending = Before.Pending
       and then After.Pending_Async_Id = Before.Pending_Async_Id
       and then After.Pending_Expected = Before.Pending_Expected
       and then After.Receipt_Valid = Before.Receipt_Valid
       and then After.Receipt_Command = Before.Receipt_Command
       and then After.Receipt_Status = Before.Receipt_Status
       and then After.Receipt_Signed = Before.Receipt_Signed
       and then After.Receipt_MIC_Valid = Before.Receipt_MIC_Valid
       and then After.Receipt_Close_Token = Before.Receipt_Close_Token
       and then SMB.Core_Protocol."=" (After.Receipt_Info, Before.Receipt_Info)
       and then After.Handles = Before.Handles);

   --  Every field but the decrypted-response flag.
   function Only_Decryption_Recorded
     (Before, After : Engine_State) return Boolean
   is (After.Current = Before.Current
       and then After.Owner_Id = Before.Owner_Id
       and then After.Epoch = Before.Epoch
       and then After.Next_Message_Id = Before.Next_Message_Id
       and then After.Next_Ticket = Before.Next_Ticket
       and then After.Session_Id = Before.Session_Id
       and then After.Tree_Id = Before.Tree_Id
       and then After.Max_Read = Before.Max_Read
       and then After.Max_Write = Before.Max_Write
       and then After.Signing_Key = Before.Signing_Key
       and then After.Has_Key = Before.Has_Key
       and then After.SMB3_Key = Before.SMB3_Key
       and then After.Has_SMB3_Key = Before.Has_SMB3_Key
       and then After.Encryption_Key = Before.Encryption_Key
       and then After.Decryption_Key = Before.Decryption_Key
       and then After.Has_Cipher_Keys = Before.Has_Cipher_Keys
       and then After.Encrypting = Before.Encrypting
       and then After.Nonce_Counter = Before.Nonce_Counter
       and then After.Dialect = Before.Dialect
       and then After.Cipher = Before.Cipher
       and then After.Preauth = Before.Preauth
       and then After.Pending = Before.Pending
       and then After.Pending_Async_Id = Before.Pending_Async_Id
       and then After.Pending_Expected = Before.Pending_Expected
       and then After.Receipt_Valid = Before.Receipt_Valid
       and then After.Receipt_Command = Before.Receipt_Command
       and then After.Receipt_Status = Before.Receipt_Status
       and then After.Receipt_Signed = Before.Receipt_Signed
       and then After.Receipt_MIC_Valid = Before.Receipt_MIC_Valid
       and then After.Receipt_Close_Token = Before.Receipt_Close_Token
       and then SMB.Core_Protocol."=" (After.Receipt_Info, Before.Receipt_Info)
       and then After.Handles = Before.Handles);

   function Has_Pending_Request (State : Engine_State) return Boolean is
     (State.Pending);

   function Has_Validated_Response (State : Engine_State) return Boolean is
     (State.Receipt_Valid);

   function Response_Receipt_Matches
     (State : Engine_State;
      Command : SMB.Core_Wire.Command_Code;
      Nt_Status : SMB.DWord;
      Signed, MIC_Valid : Boolean) return Boolean is
     (State.Receipt_Valid
      and then State.Receipt_Command = Command
      and then State.Receipt_Status = Nt_Status
      and then State.Receipt_Signed = Signed
      and then State.Receipt_MIC_Valid = MIC_Valid);

   function Pending_Request_Matches
     (State : Engine_State;
     Expected : Request_Expectation) return Boolean is
     (State.Pending
      and then State.Pending_Expected = Expected);

   function Pending_Command
     (State : Engine_State) return SMB.Core_Wire.Command_Code is
     (State.Pending_Expected.Command);

   function Pending_Response_Is_Signed
     (State : Engine_State) return Boolean is
     (State.Pending_Expected.Signed);

   function Response_Header_Matches_Request
     (State : Engine_State; Packet : SMB.Bytes; Interim : Boolean)
      return Boolean is
     (State.Pending
      and then Packet'Length >= SMB.Core_Wire.Header_Size
      and then Packet'Length <= SMB.Maximum_Frame_Size
      and then SMB.Core_Wire.Encoded_U16 (Packet, 12) =
        SMB.Word (State.Pending_Expected.Command)
      and then SMB.Core_Wire.Encoded_U64 (Packet, 24) =
        State.Pending_Expected.Message_Id
      and then
        (if State.Pending_Expected.Match_Session then
           SMB.Core_Wire.Encoded_U64 (Packet, 40) =
             State.Pending_Expected.Session_Id)
      and then
        (if State.Pending_Expected.Match_Tree
           and not Interim and State.Pending_Async_Id = 0
         then
           SMB.Core_Wire.Encoded_U32 (Packet, 36) =
             State.Pending_Expected.Tree_Id)
      and then (SMB.Core_Wire.Encoded_U32 (Packet, 16) and 1) /= 0
      and then ((SMB.Core_Wire.Encoded_U32 (Packet, 16) and 2) /= 0) =
        (Interim or State.Pending_Async_Id /= 0)
      and then (SMB.Core_Wire.Header_Nt_Status (Packet) = SMB.Status_Pending) =
        Interim
      and then
        (if Interim or State.Pending_Async_Id /= 0 then
           SMB.Core_Wire.Encoded_U64 (Packet, 32) /= 0
           and then
             (if State.Pending_Async_Id /= 0 then
                SMB.Core_Wire.Encoded_U64 (Packet, 32) = State.Pending_Async_Id))
      --  A decrypted response may carry the SIGNED flag or not.
      and then
        (if not Interim and not State.Decrypted then
           ((SMB.Core_Wire.Encoded_U32 (Packet, 16) and 8) /= 0) =
             State.Pending_Expected.Signed));

end SMB.Engine;
