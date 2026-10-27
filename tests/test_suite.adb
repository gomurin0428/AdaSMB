with Ada.Text_IO;
with SMB;
with SMB.Core_Auth;
with SMB.Core_Client;
with SMB.Core_Framing;
with SMB.Core_NTLM;
with SMB.Core_Protocol;
with SMB.Core_Wire;
with SMB.Crypto;
with SMB.Engine;
with SMB.NTLM;
with SMB.Text;
with SMB.Wire;

procedure Test_Suite is
   use type SMB.Core_Status;
   use type SMB.Engine.Access_Kind;
   use type SMB.Engine.Phase;
   use type SMB.Core_Client.Transfer_Stage;
   use type SMB.Core_Client.Authentication_Stage;
   use type SMB.Bytes;

   use type SMB.Byte;
   use type SMB.DWord;
   use type SMB.QWord;
   use type SMB.Word;

   procedure Assert (Condition : Boolean; Message : String) is
   begin
      if not Condition then
         raise Program_Error with Message;
      end if;
   end Assert;

   procedure Test_Framing is
      Sizes : constant array (Positive range 1 .. 2) of Natural :=
        (64, SMB.Maximum_Frame_Size);
      Header : SMB.Core_Framing.Frame_Header;
      Length : Natural;
      Status : SMB.Core_Status;
   begin
      for Size of Sizes loop
         SMB.Core_Framing.Encode (Size, Header, Status);
         Assert (Status = SMB.Ok, "valid frame encoding");
         SMB.Core_Framing.Decode (Header, Length, Status);
         Assert (Status = SMB.Ok and then Length = Size, "frame round trip");
      end loop;
      SMB.Core_Framing.Encode (63, Header, Status);
      Assert (Status = SMB.Invalid_Length, "short frame encoded");
      SMB.Core_Framing.Encode (SMB.Maximum_Frame_Size + 1, Header, Status);
      Assert (Status = SMB.Invalid_Length, "oversized frame encoded");
      Header := (0, 16#FF#, 16#FF#, 16#FF#);
      SMB.Core_Framing.Decode (Header, Length, Status);
      Assert (Status = SMB.Invalid_Length and then Length = 0,
              "oversized frame decoded");
      Header := (1, 0, 0, 64);
      SMB.Core_Framing.Decode (Header, Length, Status);
      Assert (Status = SMB.Unsupported_Feature and then Length = 0,
              "unsupported NetBIOS frame decoded");
   end Test_Framing;

   procedure Test_Core_Wire is
      Data : SMB.Bytes (10 .. 25) := (others => 16#A5#);
      Empty : SMB.Bytes (1 .. 0) := (others => 0);
      Signed : SMB.Bytes (100 .. 179) := (others => 16#A5#);
      Key : constant SMB.Bytes (0 .. 15) := (others => 0);
      Value_16 : SMB.Word;
      Value_32 : SMB.DWord;
      Status : SMB.Core_Status;
   begin
      SMB.Core_Wire.Write_U32
        (Data, 4, 16#7856_3412#, Status);
      Assert (Status = SMB.Ok, "nonzero-bound U32 write");
      Assert
        (Data (10) = 16#A5# and then Data (25) = 16#A5#
         and then Data (14) = 16#12# and then Data (17) = 16#78#,
         "U32 write preserved outside range");
      SMB.Core_Wire.Read_U32 (Data, 4, Value_32, Status);
      Assert (Status = SMB.Ok and then Value_32 = 16#7856_3412#,
              "nonzero-bound U32 round trip");
      SMB.Core_Wire.Write_U16 (Data, 9, 16#BEEF#, Status);
      Assert (Status = SMB.Ok, "nonzero-bound U16 write");
      SMB.Core_Wire.Read_U16 (Data, 9, Value_16, Status);
      Assert (Status = SMB.Ok and then Value_16 = 16#BEEF#,
              "nonzero-bound U16 round trip");
      SMB.Core_Wire.Write_U32 (Empty, 0, 0, Status);
      Assert (Status /= SMB.Ok, "empty U32 write accepted");
      SMB.Core_Wire.Sign (Signed, Key, Status);
      Assert
        (Status = SMB.Ok and then Signed (100) = 16#A5#
         and then Signed (164) = 16#A5#,
         "signature preserved bytes outside signature field");
      Signed := (others => 16#A5#);
      SMB.Core_Wire.Initialize_Header
        (Signed, 8, 123, 0, 0, 1, Status);
      Assert
        (Status = SMB.Ok
         and then (for all Index in 164 .. 179 => Signed (Index) = 16#A5#),
         "core header initialization must preserve an assembled body");
      SMB.Wire.Initialize_Header (Signed, SMB.Wire.Read_Command, 124);
      Assert
        (SMB.Wire.U64 (Signed, 24) = 124
         and then (for all Index in 164 .. 179 => Signed (Index) = 0),
         "public header initialization must clear a reused packet body");
   end Test_Core_Wire;

   function ASCII (Value : String) return SMB.Bytes is
   begin
      if Value'Length = 0 then
         return SMB.Bytes'(1 .. 0 => 0);
      end if;
      declare
         Result : SMB.Bytes (0 .. Value'Length - 1);
      begin
      for I in Value'Range loop
         Result (I - Value'First) := SMB.Byte (Character'Pos (Value (I)));
      end loop;
      return Result;
      end;
   end ASCII;

   function Hex (Value : String) return SMB.Bytes is
      Result : SMB.Bytes (0 .. Value'Length / 2 - 1);
      function Nibble (C : Character) return SMB.Byte is
      begin
         if C in '0' .. '9' then
            return SMB.Byte (Character'Pos (C) - Character'Pos ('0'));
         elsif C in 'a' .. 'f' then
            return SMB.Byte (10 + Character'Pos (C) - Character'Pos ('a'));
         elsif C in 'A' .. 'F' then
            return SMB.Byte (10 + Character'Pos (C) - Character'Pos ('A'));
         end if;
         raise Program_Error with "invalid hexadecimal test vector";
      end Nibble;
   begin
      Assert (Value'Length mod 2 = 0, "odd hexadecimal vector");
      for I in Result'Range loop
         Result (I) := Nibble (Value (Value'First + I * 2)) * 16
           + Nibble (Value (Value'First + I * 2 + 1));
      end loop;
      return Result;
   end Hex;

   procedure Assert_Equal (Actual, Expected : SMB.Bytes; Message : String) is
   begin
      Assert (SMB.Crypto.Constant_Time_Equal (Actual, Expected), Message);
   end Assert_Equal;

   procedure Test_Crypto is
      Empty : constant SMB.Bytes := ASCII ("");
      ABC : constant SMB.Bytes := ASCII ("abc");
      HMAC_Message : constant SMB.Bytes :=
        ASCII ("what do ya want for nothing?");
      Long_HMAC_Message : constant SMB.Bytes :=
        ASCII ("Test Using Larger Than Block-Size Key - Hash Key First");
      Long_HMAC_Key : constant SMB.Bytes (0 .. 130) := (others => 16#AA#);
      Boundary_Lengths : constant array (Positive range 1 .. 4) of Natural :=
        (55, 56, 63, 64);
      NT_Hash : constant SMB.Bytes :=
        SMB.Crypto.MD4 (SMB.Text.To_UTF16LE ("Password"));
      NTLMv2_Key : constant SMB.Bytes := SMB.Crypto.HMAC_MD5
        (NT_Hash,
         SMB.Text.To_UTF16LE (SMB.Text.NTLM_Username ("User") & "Domain"));
   begin
      Assert_Equal
        (SMB.Crypto.MD4 (Empty),
         Hex ("31d6cfe0d16ae931b73c59d7e0c089c0"), "MD4 empty");
      Assert_Equal
        (SMB.Crypto.MD4 (ABC),
         Hex ("a448017aaf21d8525fc10ae87aa6729d"), "MD4 abc");
      Assert_Equal
        (SMB.Crypto.MD5 (Empty),
         Hex ("d41d8cd98f00b204e9800998ecf8427e"), "MD5 empty");
      Assert_Equal
        (SMB.Crypto.MD5 (ABC),
         Hex ("900150983cd24fb0d6963f7d28e17f72"), "MD5 abc");
      Assert_Equal
        (SMB.Crypto.SHA256 (Empty),
         Hex
           ("e3b0c44298fc1c149afbf4c8996fb924"
            & "27ae41e4649b934ca495991b7852b855"),
         "SHA-256 empty");
      Assert_Equal
        (SMB.Crypto.SHA256 (ABC),
         Hex
           ("ba7816bf8f01cfea414140de5dae2223"
            & "b00361a396177a9cb410ff61f20015ad"),
         "SHA-256 abc");
      Assert_Equal
        (SMB.Crypto.HMAC_MD5 (ASCII ("Jefe"), HMAC_Message),
         Hex ("750c783e6ab0b503eaa86e310a5db738"), "HMAC-MD5 RFC 2202");
      Assert_Equal
        (NTLMv2_Key, Hex ("0c868a403bfd7a93a3001ef22ef02e3f"),
         "NTLMv2 response-key known answer");
      Assert_Equal
        (SMB.Crypto.HMAC_SHA256 (ASCII ("Jefe"), HMAC_Message),
         Hex
           ("5bdcc146bf60754e6a042426089575c7"
            & "5a003f089d2739839dec58b964ec3843"),
         "HMAC-SHA256 RFC 4231");
      Assert_Equal
        (SMB.Crypto.HMAC_SHA256 (Long_HMAC_Key, Long_HMAC_Message),
         Hex ("60e431591ee0b67f0d8a26aacbf5b77f"
              & "8e0bc6213728c5140546040f0ee37f54"),
         "HMAC-SHA256 RFC 4231 long-key vector");
      for Vector_Index in Boundary_Lengths'Range loop
         declare
            Length : constant Natural := Boundary_Lengths (Vector_Index);
            Input : constant SMB.Bytes (0 .. Length - 1) :=
              (others => SMB.Byte (Character'Pos ('a')));
         begin
            case Length is
               when 55 =>
                  Assert_Equal
                    (SMB.Crypto.MD5 (Input),
                     Hex ("ef1772b6dff9a122358552954ad0df65"),
                     "MD5 padding vector, 55 bytes");
                  Assert_Equal
                    (SMB.Crypto.SHA256 (Input),
                     Hex ("9f4390f8d30c2dd92ec9f095b65e2b9a"
                          & "e9b0a925a5258e241c9f1e910f734318"),
                     "SHA-256 padding vector, 55 bytes");
               when 56 =>
                  Assert_Equal
                    (SMB.Crypto.MD5 (Input),
                     Hex ("3b0c8ac703f828b04c6c197006d17218"),
                     "MD5 padding vector, 56 bytes");
                  Assert_Equal
                    (SMB.Crypto.SHA256 (Input),
                     Hex ("b35439a4ac6f0948b6d6f9e3c6af0f5f"
                          & "590ce20f1bde7090ef7970686ec6738a"),
                     "SHA-256 padding vector, 56 bytes");
               when 63 =>
                  Assert_Equal
                    (SMB.Crypto.MD5 (Input),
                     Hex ("b06521f39153d618550606be297466d5"),
                     "MD5 padding vector, 63 bytes");
                  Assert_Equal
                    (SMB.Crypto.SHA256 (Input),
                     Hex ("7d3e74a05d7db15bce4ad9ec0658ea98"
                          & "e3f06eeecf16b4c6fff2da457ddc2f34"),
                     "SHA-256 padding vector, 63 bytes");
               when 64 =>
                  Assert_Equal
                    (SMB.Crypto.MD5 (Input),
                     Hex ("014842d480b571495a4a0363793f7367"),
                     "MD5 padding vector, 64 bytes");
                  Assert_Equal
                    (SMB.Crypto.SHA256 (Input),
                     Hex ("ffe054fe7ae0cb6dc65c3af9b61d5209"
                          & "f439851db43d0ba5997337df154668eb"),
                     "SHA-256 padding vector, 64 bytes");
               when others =>
                  raise Program_Error with "unexpected hash vector length";
            end case;
         end;
      end loop;
   end Test_Crypto;

   procedure Test_NTLM_Authenticate is
      Challenge : constant SMB.Bytes := Hex
        ("a1818e30818ba0030a0101a10c060a2b06010401823702020aa27604744e544c"
         & "4d53535000020000000c000c0030000000158288200123456789abcdef000000"
         & "0000000000380038003c00000044006f006d00610069006e0001000c00530065"
         & "00720076006500720002000c0044006f006d00610069006e0007000800080706"
         & "0504030201060004000200000000000000");
      Expected : constant SMB.Bytes := Hex
        ("a182010a30820106a281ef0481ec4e544c4d5353500003000000180018005800"
         & "000068006800700000000c000c00d800000008000800e400000000000000ec00"
         & "000000000000ec0000001582882000000000000000003909823c8592086081bb"
         & "35de5f578366000000000000000000000000000000000000000000000000a3e8"
         & "7cafaf3a8c12a0bec29d2d579a5101010000000000000807060504030201ffff"
         & "ff00112233440000000001000c0053006500720076006500720002000c004400"
         & "6f006d00610069006e0007000800080706050403020106000400020000000000"
         & "00000000000044006f006d00610069006e005500530045005200a31204100100"
         & "0000dc73cbb3b8b19e6200000000");
      Auth : constant SMB.NTLM.Authentication_Result :=
        SMB.NTLM.Authenticate
          ("User", "Password", "Domain", Hex ("ffffff0011223344"), Challenge);
   begin
      Assert_Equal
        (Auth.Security_Token, Expected, "NTLM Type3 and SPNEGO MIC vector");
      Assert_Equal
        (Auth.Session_Key, Hex ("e711de05352dfa50de477e818cffec55"),
         "NTLM session base key vector");
      declare
         Nonce : constant SMB.Bytes (0 .. 7) :=
           (16#FF#, 16#FF#, 16#FF#, 0, 16#11#, 16#22#, 16#33#, 16#44#);
         Type2_Offset, Type2_Length : Natural := 0;
         Extract_Status : SMB.Core_Status;
         Wire_Status : SMB.Core_Status;
         Info_Offset : SMB.DWord := 0;
         Bad_Offset : SMB.Bytes := Challenge;
         Duplicate_AV : SMB.Bytes := Challenge;
         Nonminimal : SMB.Bytes (0 .. Challenge'Length) := (others => 0);
         Small_Output : SMB.Bytes (0 .. 0) := (others => 0);
         Small_Used : Natural := 1;
         Small_Status : SMB.Core_Status;
         Small_Auth_Output : SMB.Bytes (0 .. 0) := (others => 0);
         Small_Auth_Used : Natural := 1;
         Small_Auth_Key : SMB.Crypto.Digest_128 := (others => 0);
         Small_Auth_Status : SMB.Core_Status;
         procedure Assert_Protocol_Rejected (Token : SMB.Bytes) is
         begin
            declare
               Rejected : constant SMB.NTLM.Authentication_Result :=
                 SMB.NTLM.Authenticate
                   ("User", "Password", "Domain", Nonce, Token);
            begin
               Assert
                 (Rejected.Security_Token'Length = 0,
                  "malformed NTLM challenge unexpectedly returned a token");
            end;
            raise Program_Error with "malformed NTLM challenge was accepted";
         exception
            when SMB.Protocol_Error => null;
         end Assert_Protocol_Rejected;
      begin
         SMB.Core_NTLM.Extract_Challenge
           (Challenge, Type2_Offset, Type2_Length, Extract_Status);
         Assert
           (Extract_Status = SMB.Ok and then Type2_Length >= 48,
            "SPNEGO challenge extraction");
         Bad_Offset
           (Type2_Offset + 16 .. Type2_Offset + 19) :=
             (16#FF#, 16#FF#, 16#FF#, 16#FF#);
         Assert_Protocol_Rejected (Bad_Offset);

         declare
            Type2_Data : SMB.Bytes (0 .. Type2_Length - 1) :=
              Challenge
                (Type2_Offset .. Type2_Offset + Type2_Length - 1);
         begin
            SMB.Core_Wire.Read_U32
              (Type2_Data, 44, Info_Offset, Wire_Status);
            Assert (Wire_Status = SMB.Ok, "fixture TargetInfo offset");
            Assert
              (Info_Offset <= SMB.DWord (Type2_Length)
               and then Natural (Info_Offset) + 20 <= Type2_Length,
               "fixture TargetInfo bounds");
            Type2_Data (Natural (Info_Offset) + 16) := 1;
            Duplicate_AV
              (Type2_Offset .. Type2_Offset + Type2_Length - 1) := Type2_Data;
            Assert_Protocol_Rejected (Duplicate_AV);
         end;

         Nonminimal (0) := Challenge (0);
         Nonminimal (1) := 16#82#;
         Nonminimal (2) := 0;
         Nonminimal (3) := Challenge (2);
         Nonminimal (4 .. Nonminimal'Last) :=
           Challenge (3 .. Challenge'Last);
         SMB.Core_NTLM.Extract_Challenge
           (Nonminimal, Type2_Offset, Type2_Length, Extract_Status);
         Assert (Extract_Status /= SMB.Ok, "nonminimal challenge DER accepted");

         SMB.Core_Auth.Build_Negotiate_Token
           (Small_Output, Small_Used, Small_Status);
         Assert
           (Small_Status = SMB.Resource_Limit and then Small_Used = 0,
            "short negotiate output buffer was accepted");
         SMB.Core_Auth.Authenticate
           ("User", "Password", "Domain", Nonce, Challenge, 0,
            Small_Auth_Output, Small_Auth_Used, Small_Auth_Key,
            Small_Auth_Status);
         Assert
           (Small_Auth_Status = SMB.Resource_Limit
            and then Small_Auth_Used = 0
            and then Small_Auth_Key = (Small_Auth_Key'Range => 0),
            "short authentication output buffer was accepted");
      end;
   end Test_NTLM_Authenticate;

   procedure Test_Core_Client_Authentication is
      Challenge : constant SMB.Bytes := Hex
        ("a1818e30818ba0030a0101a10c060a2b06010401823702020aa27604744e544c"
         & "4d53535000020000000c000c0030000000158288200123456789abcdef000000"
         & "0000000000380038003c00000044006f006d00610069006e0001000c00530065"
         & "00720076006500720002000c0044006f006d00610069006e0007000800080706"
         & "0504030201060004000200000000000000");
      Expected_Token : constant SMB.Bytes := Hex
        ("a182010a30820106a281ef0481ec4e544c4d5353500003000000180018005800"
         & "000068006800700000000c000c00d800000008000800e400000000000000ec00"
         & "000000000000ec0000001582882000000000000000003909823c8592086081bb"
         & "35de5f578366000000000000000000000000000000000000000000000000a3e8"
         & "7cafaf3a8c12a0bec29d2d579a5101010000000000000807060504030201ffff"
         & "ff00112233440000000001000c0053006500720076006500720002000c004400"
         & "6f006d00610069006e0007000800080706050403020106000400020000000000"
         & "00000000000044006f006d00610069006e005500530045005200a31204100100"
         & "0000dc73cbb3b8b19e6200000000");
      Session_Key : constant SMB.Bytes :=
        Hex ("e711de05352dfa50de477e818cffec55");
      Nonce : constant SMB.Bytes (0 .. 7) :=
        (16#FF#, 16#FF#, 16#FF#, 0, 16#11#, 16#22#, 16#33#, 16#44#);
      Session_Id : constant SMB.QWord := 16#1234#;

      procedure Prepare_Negotiated (State : in out SMB.Engine.Engine_State) is
         Status : SMB.Core_Status;
         Nt_Status : SMB.DWord;
         Message_Id : SMB.QWord;
         Expected : SMB.Engine.Request_Expectation;
         Response : SMB.Bytes (0 .. 127) := (others => 0);
      begin
         SMB.Engine.Initialize (State, Status);
         Assert (Status = SMB.Ok, "authentication engine initialize");
         SMB.Engine.Mark_Connected (State, Status);
         Assert (Status = SMB.Ok, "authentication transport connect");
         SMB.Engine.Begin_Request
           (State, 0, False, False, Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "authentication negotiate reservation");
         SMB.Wire.Initialize_Header (Response, 0, Message_Id, 0, 0);
         SMB.Wire.Put_U32 (Response, 16, 1);
         Response (64) := 65;
         Response (66) := 1;
         Response (68) := 16#10#;
         Response (69) := 2;
         Response (98) := 1;
         Response (102) := 1;
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert (Status = SMB.Ok, "authentication negotiate response");
         SMB.Engine.Mark_Negotiated (State, 65_536, 65_536, Status);
         Assert (Status = SMB.Ok, "authentication negotiated state");
      end Prepare_Negotiated;

      function Challenge_Response
        (Message_Id : SMB.QWord;
         Reply_Status : SMB.DWord;
         Token : SMB.Bytes) return SMB.Bytes
      is
         Packet : SMB.Bytes (0 .. 71 + Token'Length) := (others => 0);
      begin
         SMB.Wire.Initialize_Header
           (Packet, 1, Message_Id, 0, Session_Id);
         SMB.Wire.Put_U32 (Packet, 8, Reply_Status);
         SMB.Wire.Put_U32 (Packet, 16, 1);
         SMB.Wire.Put_U16 (Packet, 64, 9);
         SMB.Wire.Put_U16 (Packet, 68, 72);
         SMB.Wire.Put_U16 (Packet, 70, SMB.Word (Token'Length));
         if Token'Length > 0 then
            Packet (72 .. 71 + Token'Length) := Token;
         end if;
         return Packet;
      end Challenge_Response;

      function Final_Response
        (Message_Id : SMB.QWord;
         Reply_Status : SMB.DWord;
         Tamper_Signature, Tamper_MIC : Boolean) return SMB.Bytes
      is
         Packet : SMB.Bytes (0 .. 100) := (others => 0);
         Final_Token : SMB.Bytes (0 .. 28) :=
           (16#A1#, 16#1B#, 16#30#, 16#19#,
            16#A0#, 16#03#, 16#0A#, 16#01#, 0,
            16#A3#, 16#12#, 16#04#, 16#10#,
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
         Server_MIC : constant SMB.Bytes :=
           SMB.Core_NTLM.Mechanism_List_MIC (Session_Key, True);
      begin
         for Index in 0 .. 15 loop
            Final_Token (13 + Index) := Server_MIC (Index);
         end loop;
         if Tamper_MIC then
            Final_Token (17) := Final_Token (17) xor 1;
         end if;
         SMB.Wire.Initialize_Header
           (Packet, 1, Message_Id, 0, Session_Id);
         SMB.Wire.Put_U32 (Packet, 8, Reply_Status);
         SMB.Wire.Put_U32 (Packet, 16, 9);
         SMB.Wire.Put_U16 (Packet, 64, 9);
         if Reply_Status = SMB.Success then
            SMB.Wire.Put_U16 (Packet, 68, 72);
            SMB.Wire.Put_U16 (Packet, 70, SMB.Word (Final_Token'Length));
            Packet (72 .. 100) := Final_Token;
         else
            SMB.Wire.Put_U32 (Packet, 68, 0);
         end if;
         SMB.Wire.Sign (Packet, Session_Key);
         if Tamper_Signature then
            Packet (48) := Packet (48) xor 1;
         end if;
         return Packet;
      end Final_Response;

      procedure Prepare_Final_Request
        (State : in out SMB.Engine.Engine_State;
         Value : in out SMB.Core_Client.Authentication;
         Output : in out SMB.Bytes;
         Used : out Natural) is
         Status : SMB.Core_Status;
         Nt_Status : SMB.DWord;
         Message_Id : SMB.QWord;
      begin
         SMB.Core_Client.Prepare_Negotiate
           (Value, State, Output, Used, Status);
         Assert (Status = SMB.Ok, "prepare coordinator negotiate");
         Message_Id := SMB.Wire.U64 (Output, 24);
         SMB.Core_Client.Authentication_Send_Succeeded (Value, State, Status);
         Assert (Status = SMB.Ok, "acknowledge coordinator negotiate");
         declare
            Response : constant SMB.Bytes := Challenge_Response
              (Message_Id, SMB.Status_More_Processing_Required, Challenge);
         begin
            SMB.Core_Client.Complete_Challenge
              (Value, State, Response, Nt_Status, Status);
            Assert
              (Status = SMB.Ok and then Nt_Status =
                 SMB.Status_More_Processing_Required,
               "complete coordinator challenge");
         end;
         SMB.Core_Client.Prepare_Authenticate
           (Value, State, "User", "Password", "Domain", Nonce, 0,
            Output, Used, Status);
         Assert (Status = SMB.Ok, "prepare coordinator authenticate");
         SMB.Core_Client.Authentication_Send_Succeeded (Value, State, Status);
         Assert (Status = SMB.Ok, "acknowledge coordinator authenticate");
      end Prepare_Final_Request;

      State : SMB.Engine.Engine_State;
      Value : SMB.Core_Client.Authentication;
      Request : SMB.Bytes
        (0 .. SMB.Core_Client.Authentication_Request_Size - 1) :=
          (others => 0);
      Response : SMB.Bytes (0 .. 100) := (others => 0);
      Status : SMB.Core_Status;
      Nt_Status : SMB.DWord;
      Used : Natural;
      Message_Id : SMB.QWord;
   begin
      Prepare_Negotiated (State);
      SMB.Core_Client.Prepare_Negotiate
        (Value, State, Request, Used, Status);
      Assert (Status = SMB.Ok, "prepare authentication negotiate");
      Message_Id := SMB.Wire.U64 (Request, 24);
      declare
         Response : constant SMB.Bytes := Challenge_Response
           (Message_Id, SMB.Status_More_Processing_Required, Challenge);
      begin
         SMB.Core_Client.Complete_Challenge
           (Value, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Core_Client.Authentication_Stage_Of (Value) =
              SMB.Core_Client.Negotiate_Prepared,
            "challenge completed before send acknowledgement");
      end;
      SMB.Core_Client.Authentication_Send_Succeeded (Value, State, Status);
      Assert (Status = SMB.Ok, "authentication negotiate acknowledgement");
      declare
         Response : constant SMB.Bytes := Challenge_Response
           (Message_Id, SMB.Status_More_Processing_Required, Challenge);
      begin
         SMB.Core_Client.Complete_Challenge
           (Value, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status =
              SMB.Status_More_Processing_Required
            and then SMB.Core_Client.Authentication_Challenge_Length_Of (Value) =
              Challenge'Length,
            "coordinator challenge accepted");
         SMB.Core_Client.Complete_Challenge
           (Value, State, Response, Nt_Status, Status);
      end;
      Assert
        (Status = SMB.Invalid_State_Status
         and then SMB.Core_Client.Authentication_Stage_Of (Value) =
           SMB.Core_Client.Challenge_Received,
         "duplicate challenge completion advanced authentication");
      SMB.Core_Client.Prepare_Authenticate
        (Value, State, "User", "Password", "Domain", Nonce, 0,
         Request, Used, Status);
      Assert (Status = SMB.Ok, "prepare authentication token");
      Assert
        (Used = 64 + 24 + Expected_Token'Length
         and then Request (88 .. Used - 1) = Expected_Token,
         "coordinator produced the expected NTLM Type 3 token");
      Message_Id := SMB.Wire.U64 (Request, 24);
      Response := Final_Response (Message_Id, SMB.Success, False, False);
      SMB.Core_Client.Complete_Authenticate
        (Value, State, Response, Nt_Status, Status);
      Assert
        (Status = SMB.Invalid_State_Status
         and then Nt_Status = 0
         and then SMB.Core_Client.Authentication_Stage_Of (Value) =
           SMB.Core_Client.Authenticate_Prepared
         and then SMB.Engine.Has_Pending_Request (State)
         and then SMB.Engine.Has_Signing_Key (State),
         "final authentication completed before send acknowledgement");
      SMB.Core_Client.Authentication_Send_Succeeded (Value, State, Status);
      Assert (Status = SMB.Ok, "authentication token acknowledgement");
      SMB.Core_Client.Complete_Authenticate
        (Value, State, Response, Nt_Status, Status);
      Assert
        (Status = SMB.Ok and then Nt_Status = SMB.Success
         and then SMB.Engine.Current_Phase (State) = SMB.Engine.Authenticated
         and then SMB.Core_Client.Authentication_Stage_Of (Value) =
           SMB.Core_Client.Authentication_Finished,
         "coordinator completed signed authentication");

      declare
         State_A, State_B : SMB.Engine.Engine_State;
         Value_A, Value_B : SMB.Core_Client.Authentication;
         Request_A, Request_B : SMB.Bytes
           (0 .. SMB.Core_Client.Authentication_Request_Size - 1) :=
             (others => 0);
         Response_A, Response_B : SMB.Bytes
           (0 .. 71 + Challenge'Length) := (others => 0);
         Final_A, Final_B : SMB.Bytes (0 .. 100) := (others => 0);
         Used_A, Used_B : Natural;
         Message_A, Message_B : SMB.QWord;
         Fresh_Value : SMB.Core_Client.Authentication;
         Fresh_Request : SMB.Bytes
           (0 .. SMB.Core_Client.Authentication_Request_Size - 1) :=
             (others => 0);
         Fresh_Used : Natural;
         Stale_State : SMB.Engine.Engine_State;
         Stale_Value : SMB.Core_Client.Authentication;
         Stale_Request : SMB.Bytes
           (0 .. SMB.Core_Client.Authentication_Request_Size - 1) :=
             (others => 0);
         Stale_Used : Natural;
         Stale_Response : SMB.Bytes
           (0 .. 71 + Challenge'Length) := (others => 0);
         Stale_Message : SMB.QWord;
      begin
         Prepare_Negotiated (State_A);
         Prepare_Negotiated (State_B);
         SMB.Core_Client.Prepare_Negotiate
           (Value_A, State_A, Request_A, Used_A, Status);
         Assert (Status = SMB.Ok, "prepare owner A negotiate");
         SMB.Core_Client.Prepare_Negotiate
           (Value_B, State_B, Request_B, Used_B, Status);
         Assert (Status = SMB.Ok, "prepare owner B negotiate");
         Message_A := SMB.Wire.U64 (Request_A, 24);
         Message_B := SMB.Wire.U64 (Request_B, 24);
         Assert (Message_A = Message_B, "owner context message collision");
         SMB.Core_Client.Authentication_Send_Succeeded
           (Value_A, State_A, Status);
         Assert (Status = SMB.Ok, "acknowledge owner A negotiate");
         SMB.Core_Client.Authentication_Send_Succeeded
           (Value_B, State_B, Status);
         Assert (Status = SMB.Ok, "acknowledge owner B negotiate");
         Response_A := Challenge_Response
           (Message_A, SMB.Status_More_Processing_Required, Challenge);
         Response_B := Challenge_Response
           (Message_B, SMB.Status_More_Processing_Required, Challenge);
         SMB.Core_Client.Complete_Challenge
           (Value_A, State_B, Response_A, Nt_Status, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Core_Client.Authentication_Stage_Of (Value_A) =
              SMB.Core_Client.Negotiate_Sent
            and then SMB.Engine.Has_Pending_Request (State_B),
           "foreign challenge consumed another engine");
         SMB.Core_Client.Complete_Challenge
           (Value_A, State_A, Response_A, Nt_Status, Status);
         Assert (Status = SMB.Ok, "complete owner A challenge");
         SMB.Core_Client.Complete_Challenge
           (Value_B, State_B, Response_B, Nt_Status, Status);
         Assert (Status = SMB.Ok, "complete owner B challenge");
         SMB.Core_Client.Prepare_Negotiate
           (Fresh_Value, State_A, Fresh_Request, Fresh_Used, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Core_Client.Authentication_Stage_Of (Fresh_Value) =
              SMB.Core_Client.Authentication_Ready
            and then SMB.Engine.Has_Validated_Response (State_A),
           "second authentication consumed challenge receipt");
         SMB.Core_Client.Prepare_Authenticate
           (Value_A, State_B, "User", "Password", "Domain", Nonce, 0,
            Request_A, Used_A, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Core_Client.Authentication_Stage_Of (Value_A) =
              SMB.Core_Client.Challenge_Received
            and then not SMB.Engine.Has_Signing_Key (State_B)
            and then SMB.Engine.Has_Validated_Response (State_B),
           "foreign authentication preparation mutated engine");
         SMB.Core_Client.Prepare_Authenticate
           (Value_A, State_A, "User", "Password", "Domain", Nonce, 0,
            Request_A, Used_A, Status);
         Assert (Status = SMB.Ok, "prepare owner A authenticate");
         SMB.Core_Client.Prepare_Authenticate
           (Value_B, State_B, "User", "Password", "Domain", Nonce, 0,
            Request_B, Used_B, Status);
         Assert (Status = SMB.Ok, "prepare owner B authenticate");
         SMB.Core_Client.Authentication_Send_Succeeded
           (Value_A, State_A, Status);
         Assert (Status = SMB.Ok, "acknowledge owner A authenticate");
         SMB.Core_Client.Authentication_Send_Succeeded
           (Value_B, State_B, Status);
         Assert (Status = SMB.Ok, "acknowledge owner B authenticate");
         Message_A := SMB.Wire.U64 (Request_A, 24);
         Message_B := SMB.Wire.U64 (Request_B, 24);
         Assert
           (Message_A = Message_B
            and then SMB.Engine.Current_Session_Id (State_A) =
              SMB.Engine.Current_Session_Id (State_B),
            "owner context authentication collision");
         Final_A := Final_Response (Message_A, SMB.Success, False, False);
         Final_B := Final_Response (Message_B, SMB.Success, False, False);
         SMB.Core_Client.Complete_Authenticate
           (Value_A, State_B, Final_A, Nt_Status, Status);
         Assert
            (Status = SMB.Invalid_State_Status
            and then SMB.Core_Client.Authentication_Stage_Of (Value_A) =
              SMB.Core_Client.Authenticate_Sent
            and then SMB.Engine.Has_Pending_Request (State_B)
            and then SMB.Engine.Has_Signing_Key (State_B),
           "foreign final response consumed another engine");
         SMB.Core_Client.Abort_Authentication (Value_A, State_B, Status);
         Assert
            (Status = SMB.Invalid_State_Status
            and then SMB.Core_Client.Authentication_Stage_Of (Value_A) =
              SMB.Core_Client.Authenticate_Sent
            and then SMB.Engine.Current_Phase (State_B) =
              SMB.Engine.Negotiated
            and then SMB.Engine.Has_Pending_Request (State_B)
            and then SMB.Engine.Has_Signing_Key (State_B)
            and then not SMB.Engine.Has_Validated_Response (State_B)
            and then SMB.Engine.Current_Session_Id (State_B) =
              SMB.Core_Client.Authentication_Session_Id_Of (Value_B),
           "foreign abort invalidated another engine");
         SMB.Core_Client.Complete_Authenticate
           (Value_A, State_A, Final_A, Nt_Status, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Engine.Current_Phase (State_A) =
              SMB.Engine.Authenticated,
           "owner A final response");
         SMB.Core_Client.Complete_Authenticate
           (Value_B, State_B, Final_B, Nt_Status, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Engine.Current_Phase (State_B) =
              SMB.Engine.Authenticated,
           "owner B final response");

         Prepare_Negotiated (Stale_State);
         SMB.Core_Client.Prepare_Negotiate
           (Stale_Value, Stale_State, Stale_Request, Stale_Used, Status);
         Assert (Status = SMB.Ok, "prepare stale-epoch negotiate");
         Stale_Message := SMB.Wire.U64 (Stale_Request, 24);
         SMB.Core_Client.Authentication_Send_Succeeded
           (Stale_Value, Stale_State, Status);
         Assert (Status = SMB.Ok, "acknowledge stale-epoch negotiate");
         SMB.Engine.Invalidate (Stale_State, Status);
         Assert (Status = SMB.Ok, "invalidate stale-epoch owner");
         SMB.Engine.Mark_Connected (Stale_State, Status);
         Assert (Status = SMB.Ok, "reconnect stale-epoch owner");
         Stale_Response := Challenge_Response
           (Stale_Message, SMB.Status_More_Processing_Required, Challenge);
         SMB.Core_Client.Complete_Challenge
           (Stale_Value, Stale_State, Stale_Response, Nt_Status, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Core_Client.Authentication_Stage_Of (Stale_Value) =
              SMB.Core_Client.Negotiate_Sent,
           "stale-epoch challenge was accepted");
         SMB.Core_Client.Abort_Authentication
           (Stale_Value, Stale_State, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine.Current_Phase (Stale_State) =
              SMB.Engine.Transport_Connected,
           "stale-epoch abort mutated state");
      end;

      declare
         Failed_State : SMB.Engine.Engine_State;
         Failed_Value : SMB.Core_Client.Authentication;
         Failed_Request : SMB.Bytes
           (0 .. SMB.Core_Client.Authentication_Request_Size - 1) :=
             (others => 0);
         Failed_Response : SMB.Bytes (0 .. Challenge'Length + 71) :=
           (others => 0);
         Failed_Used : Natural;
      begin
         Prepare_Negotiated (Failed_State);
         SMB.Core_Client.Prepare_Negotiate
           (Failed_Value, Failed_State, Failed_Request, Failed_Used, Status);
         Message_Id := SMB.Wire.U64 (Failed_Request, 24);
         SMB.Core_Client.Authentication_Send_Succeeded
           (Failed_Value, Failed_State, Status);
         Failed_Response := Challenge_Response
           (Message_Id, SMB.Success, Challenge);
         SMB.Core_Client.Complete_Challenge
           (Failed_Value, Failed_State, Failed_Response, Nt_Status, Status);
         Assert
           (Status /= SMB.Ok
            and then Nt_Status = SMB.Success
            and then not SMB.Engine.Has_Signing_Key (Failed_State)
            and then not SMB.Engine.Has_Pending_Request (Failed_State)
            and then SMB.Engine.Signing_Key_Is_Zero (Failed_State),
            "successful challenge status installed a key or advanced");
      end;

      declare
         Failed_State : SMB.Engine.Engine_State;
         Failed_Value : SMB.Core_Client.Authentication;
         Failed_Request : SMB.Bytes
           (0 .. SMB.Core_Client.Authentication_Request_Size - 1) :=
             (others => 0);
         Malformed : constant SMB.Bytes := (0 => 0);
         Failed_Used : Natural;
      begin
         Prepare_Negotiated (Failed_State);
         SMB.Core_Client.Prepare_Negotiate
           (Failed_Value, Failed_State, Failed_Request, Failed_Used, Status);
         Message_Id := SMB.Wire.U64 (Failed_Request, 24);
         SMB.Core_Client.Authentication_Send_Succeeded
           (Failed_Value, Failed_State, Status);
         declare
            Failed_Response : constant SMB.Bytes := Challenge_Response
              (Message_Id, SMB.Status_More_Processing_Required, Malformed);
         begin
            SMB.Core_Client.Complete_Challenge
              (Failed_Value, Failed_State, Failed_Response, Nt_Status, Status);
         end;
         SMB.Core_Client.Prepare_Authenticate
           (Failed_Value, Failed_State, "User", "Password", "Domain", Nonce,
            0, Failed_Request, Failed_Used, Status);
         Assert
           (Status in SMB.Invalid_Encoding | SMB.Invalid_Protocol
            and then SMB.Core_Client.Authentication_Stage_Of (Failed_Value) =
              SMB.Core_Client.Authentication_Failed
            and then SMB.Engine.Current_Phase (Failed_State) =
              SMB.Engine.Disconnected
            and then SMB.Engine.Signing_Key_Is_Zero (Failed_State)
            and then not SMB.Engine.Has_Pending_Request (Failed_State),
            "malformed challenge was not distinguished and invalidated");
      end;

      for Fault in 1 .. 3 loop
         declare
            Failed_State : SMB.Engine.Engine_State;
            Failed_Value : SMB.Core_Client.Authentication;
            Failed_Request : SMB.Bytes
              (0 .. SMB.Core_Client.Authentication_Request_Size - 1) :=
                (others => 0);
            Failed_Response : SMB.Bytes (0 .. 100) := (others => 0);
            Failed_Used : Natural;
         begin
            Prepare_Negotiated (Failed_State);
            Prepare_Final_Request
              (Failed_State, Failed_Value, Failed_Request, Failed_Used);
            Message_Id := SMB.Wire.U64 (Failed_Request, 24);
            if Fault = 3 then
               Failed_Response := Final_Response
                 (Message_Id, SMB.Status_Access_Denied, False, False);
            else
               Failed_Response := Final_Response
                 (Message_Id, SMB.Success, Fault = 1, Fault = 2);
            end if;
            SMB.Core_Client.Complete_Authenticate
              (Failed_Value, Failed_State, Failed_Response, Nt_Status, Status);
            Assert
              (SMB.Engine.Current_Phase (Failed_State) =
                 SMB.Engine.Disconnected
               and then SMB.Engine.Signing_Key_Is_Zero (Failed_State)
               and then not SMB.Engine.Has_Pending_Request (Failed_State),
               "rejected final authentication retained session state");
            if Fault = 3 then
               Assert
                 (Status = SMB.Ok
                  and then Nt_Status = SMB.Status_Access_Denied
                 and then SMB.Core_Client.Authentication_Stage_Of
                    (Failed_Value) = SMB.Core_Client.Authentication_Failed,
                 "signed authentication NT status was not preserved");
            elsif Fault = 1 then
               Assert
                 (Status = SMB.Signature_Error
                  and then Nt_Status = 0
                  and then SMB.Core_Client.Authentication_Stage_Of
                    (Failed_Value) = SMB.Core_Client.Authentication_Failed,
                  "bad final signature was accepted");
            else
               Assert
                 (Status = SMB.Invalid_Protocol
                  and then Nt_Status = 0
                  and then SMB.Core_Client.Authentication_Stage_Of
                    (Failed_Value) = SMB.Core_Client.Authentication_Failed,
                  "bad final MIC was accepted");
            end if;
         end;
      end loop;
   end Test_Core_Client_Authentication;

   procedure Test_Final_Spnego is
      Accept_Completed : constant SMB.Bytes :=
        (16#A1#, 16#07#, 16#30#, 16#05#, 16#A0#, 16#03#,
         16#0A#, 16#01#, 16#00#);
      Nonminimal_Length : constant SMB.Bytes :=
        (16#A1#, 16#81#, 16#07#, 16#30#, 16#05#,
         16#A0#, 16#03#, 16#0A#, 16#01#, 16#00#);
      Requested_MIC : constant SMB.Bytes :=
        (16#A1#, 16#07#, 16#30#, 16#05#, 16#A3#, 16#03#,
         16#04#, 16#01#, 16#00#);
      Duplicate_State : constant SMB.Bytes :=
        (16#A1#, 16#0C#, 16#30#, 16#0A#,
         16#A0#, 16#03#, 16#0A#, 16#01#, 16#00#,
         16#A0#, 16#03#, 16#0A#, 16#01#, 16#00#);
      Empty_Token : constant SMB.Bytes := (1 .. 0 => 0);
      Key : SMB.Crypto.Digest_128;
      Server_MIC : constant SMB.Bytes :=
        (1, 0, 0, 0, 16#0A#, 16#FB#, 16#34#, 16#90#,
         16#3A#, 16#3E#, 16#4E#, 16#54#, 0, 0, 0, 0);
      Signed_Final : SMB.Bytes (0 .. 28) :=
        (16#A1#, 16#1B#, 16#30#, 16#19#,
         16#A0#, 16#03#, 16#0A#, 16#01#, 0,
         16#A3#, 16#12#, 16#04#, 16#10#,
         1, 0, 0, 0, 16#0A#, 16#FB#, 16#34#, 16#90#,
         16#3A#, 16#3E#, 16#4E#, 16#54#, 0, 0, 0, 0);
      Status : SMB.Core_Status;
   begin
      for I in Key'Range loop
         Key (I) := SMB.Byte (I);
      end loop;
      Assert_Equal
        (SMB.Core_NTLM.Mechanism_List_MIC (Key, False),
         SMB.Bytes'(1, 0, 0, 0, 16#49#, 16#EA#, 16#44#, 16#2B#,
                    16#EB#, 16#10#, 16#41#, 16#47#, 0, 0, 0, 0),
         "NTLM client mechanism-list MIC vector");
      Assert_Equal
        (SMB.Core_NTLM.Mechanism_List_MIC (Key, True), Server_MIC,
         "NTLM server mechanism-list MIC vector");
      SMB.Core_NTLM.Validate_Final_Token (Signed_Final, Status, Server_MIC);
      Assert (Status = SMB.Ok, "valid SPNEGO mechanism-list MIC");
      Signed_Final (17) := Signed_Final (17) xor 1;
      SMB.Core_NTLM.Validate_Final_Token (Signed_Final, Status, Server_MIC);
      Assert (Status = SMB.Signature_Error, "tampered SPNEGO MIC accepted");
      SMB.Core_NTLM.Validate_Final_Token (Accept_Completed, Status, Server_MIC);
      Assert (Status = SMB.Signature_Error, "missing mandatory SPNEGO MIC accepted");
      SMB.Core_NTLM.Validate_Final_Token (Accept_Completed, Status);
      Assert (Status = SMB.Ok, "valid SPNEGO accept-completed token");
      SMB.Core_NTLM.Validate_Final_Token (Empty_Token, Status);
      Assert (Status = SMB.Ok, "empty successful SPNEGO token");
      SMB.Core_NTLM.Validate_Final_Token (Nonminimal_Length, Status);
      Assert (Status /= SMB.Ok, "nonminimal DER length accepted");
      SMB.Core_NTLM.Validate_Final_Token (Requested_MIC, Status);
      Assert (Status /= SMB.Ok, "SPNEGO mechListMIC accepted");
      SMB.Core_NTLM.Validate_Final_Token (Duplicate_State, Status);
      Assert (Status /= SMB.Ok, "duplicate SPNEGO state accepted");
   end Test_Final_Spnego;

   procedure Test_Core_Protocol is
      File_Id : constant SMB.Bytes (0 .. 15) := (others => 16#11#);
      Read_Body : SMB.Bytes (0 .. 48) := (others => 0);
      Create_Body : SMB.Bytes (0 .. 56) := (others => 0);
      Used : Natural;
      Status : SMB.Core_Status;
      Packet : SMB.Bytes (0 .. 79) := (others => 0);
      Negotiate_Packet : SMB.Bytes (0 .. 127) := (others => 0);
      Close_Packet : SMB.Bytes (0 .. 123) := (others => 0);
      Error_Packet : SMB.Bytes (0 .. 71) := (others => 0);
      Info : SMB.Core_Protocol.Response_Info;
      Directory : SMB.Bytes (0 .. 105) := (others => 0);
      Cursor : Natural := 0;
      Directory_Info : SMB.Core_Protocol.Directory_Info;
      Chunk, Pages, Entries : Natural;
   begin
      SMB.Core_Protocol.Build_Read
        (File_Id, 16#0102_0304_0506_0708#, 16#1234#,
         Read_Body, Used, Status);
      Assert (Status = SMB.Ok and then Used = 49, "bounded READ builder");
      Assert
        (Read_Body (4) = 16#34# and then Read_Body (5) = 16#12#
         and then Read_Body (6) = 0 and then Read_Body (7) = 0,
         "READ length wire offset");
      Assert
        (Read_Body (32) = 0 and then Read_Body (33) = 0
         and then Read_Body (34) = 0 and then Read_Body (35) = 0,
         "READ minimum-count wire offset");
      Assert (Read_Body (48) = 1, "READ dynamic buffer byte");
      SMB.Core_Protocol.Build_Create
        (SMB.Bytes'(1 .. 0 => 0), 0, 1, False,
         Create_Body, Used, Status);
      Assert
        (Status = SMB.Ok and then Used = 57
         and then Create_Body (0) = 57
         and then Create_Body (46) = 0 and then Create_Body (47) = 0
         and then Create_Body (40) = 16#40#
         and then Create_Body (56) = 0,
         "empty CREATE name padding");

      Negotiate_Packet (64) := 65;
      Negotiate_Packet (66) := 1;
      Negotiate_Packet (68) := 16#10#;
      Negotiate_Packet (69) := 2;
      Negotiate_Packet (80) := 16#78#;
      Negotiate_Packet (98) := 1;
      Negotiate_Packet (102) := 1;
      SMB.Core_Protocol.Parse_Response
        (Negotiate_Packet, SMB.Core_Wire.Command_Code (0),
         SMB.Success, Info, Status);
      Assert (Status = SMB.Ok, "negotiate response validation");
      Assert (Info.Max_Read = 65_536, "negotiate read-size clamping");
      Negotiate_Packet (124) := 1;
      SMB.Core_Protocol.Parse_Response
        (Negotiate_Packet, SMB.Core_Wire.Command_Code (0),
         SMB.Success, Info, Status);
      Assert (Status /= SMB.Ok, "nonzero NEGOTIATE reserved DWORD accepted");
      Negotiate_Packet (124) := 0;

      Packet (64) := 17;
      Packet (66) := 80;
      Packet (68) := 0;
      Packet (69) := 0;
      Packet (70) := 0;
      Packet (71) := 0;
      SMB.Core_Protocol.Parse_Response
        (Packet, SMB.Core_Wire.Command_Code (8), SMB.Success, Info, Status);
      Assert (Status = SMB.Ok and then Info.Data_Length = 0,
              "zero-length READ response");
      Packet (76) := 1;
      SMB.Core_Protocol.Parse_Response
        (Packet, SMB.Core_Wire.Command_Code (8), SMB.Success, Info, Status);
      Assert (Status /= SMB.Ok, "nonzero READ reserved DWORD accepted");
      Packet (76 .. 79) := (others => 0);
      Packet (68 .. 71) := (16#FF#, 16#FF#, 16#FF#, 16#FF#);
      SMB.Core_Protocol.Parse_Response
        (Packet, SMB.Core_Wire.Command_Code (8), SMB.Success, Info, Status);
      Assert (Status /= SMB.Ok, "oversized READ response length accepted");
      Packet (66) := 16#FF#;
      Packet (68 .. 71) := (others => 0);
      SMB.Core_Protocol.Parse_Response
        (Packet, SMB.Core_Wire.Command_Code (8), SMB.Success, Info, Status);
      Assert (Status /= SMB.Ok, "out-of-packet READ response offset accepted");

      Close_Packet (64) := 60;
      SMB.Core_Protocol.Parse_Response
        (Close_Packet, SMB.Core_Wire.Command_Code (6),
         SMB.Success, Info, Status);
      Assert (Status = SMB.Ok, "CLOSE response flags zero rejected");
      Close_Packet (66) := 1;
      SMB.Core_Protocol.Parse_Response
        (Close_Packet, SMB.Core_Wire.Command_Code (6),
         SMB.Success, Info, Status);
      Assert (Status = SMB.Ok, "CLOSE POSTQUERY_ATTRIB flag rejected");
      Close_Packet (66) := 2;
      SMB.Core_Protocol.Parse_Response
        (Close_Packet, SMB.Core_Wire.Command_Code (6),
         SMB.Success, Info, Status);
      Assert (Status /= SMB.Ok, "unsupported CLOSE response flag accepted");

      Error_Packet (64) := 9;
      SMB.Core_Protocol.Parse_Response
        (Error_Packet, SMB.Core_Wire.Command_Code (8),
         SMB.Status_End_Of_File, Info, Status);
      Assert (Status = SMB.Ok, "valid SMB2.1 error response rejected");
      Error_Packet (66) := 1;
      SMB.Core_Protocol.Parse_Response
        (Error_Packet, SMB.Core_Wire.Command_Code (8),
         SMB.Status_End_Of_File, Info, Status);
      Assert (Status /= SMB.Ok, "nonzero SMB2.1 error reserved byte accepted");
      Error_Packet (66) := 0;
      Error_Packet (67) := 1;
      SMB.Core_Protocol.Parse_Response
        (Error_Packet, SMB.Core_Wire.Command_Code (8),
         SMB.Status_End_Of_File, Info, Status);
      Assert (Status /= SMB.Ok, "nonzero SMB2.1 error reserved byte accepted");
      SMB.Core_Protocol.Parse_Response
        (Error_Packet, SMB.Core_Wire.Command_Code (99),
         SMB.Status_End_Of_File, Info, Status);
      Assert
        (Status = SMB.Unsupported_Feature,
         "unknown command accepted through error response path");

      Directory (60) := 2;
      Directory (104) := Character'Pos ('x');
      Directory (105) := 0;
      SMB.Core_Protocol.Parse_Directory_Entry
        (Directory, Cursor, Directory_Info, Status);
      Assert
        (Status = SMB.Ok and then Cursor = Directory'Length
         and then Directory_Info.Name_Offset = 104
         and then Directory_Info.Name_Length = 2,
         "bounded directory entry parser");
      Directory (0 .. 3) := (16#FF#, 16#FF#, 16#FF#, 16#FF#);
      Cursor := 0;
      SMB.Core_Protocol.Parse_Directory_Entry
        (Directory, Cursor, Directory_Info, Status);
      Assert (Status /= SMB.Ok, "oversized directory next offset accepted");

      Pages := SMB.Core_Protocol.Maximum_Directory_Pages - 1;
      SMB.Core_Protocol.Count_Directory_Page (Pages, Status);
      Assert
        (Status = SMB.Ok
         and then Pages = SMB.Core_Protocol.Maximum_Directory_Pages,
         "directory page cap accepted final page");
      SMB.Core_Protocol.Count_Directory_Page (Pages, Status);
      Assert
        (Status = SMB.Resource_Limit
         and then Pages = SMB.Core_Protocol.Maximum_Directory_Pages,
         "directory page cap exceeded");
      Entries := SMB.Core_Protocol.Maximum_Directory_Entries - 1;
      SMB.Core_Protocol.Count_Directory_Entry (Entries, Status);
      Assert
        (Status = SMB.Ok
         and then Entries = SMB.Core_Protocol.Maximum_Directory_Entries,
         "directory entry cap accepted final entry");
      SMB.Core_Protocol.Count_Directory_Entry (Entries, Status);
      Assert
        (Status = SMB.Resource_Limit
         and then Entries = SMB.Core_Protocol.Maximum_Directory_Entries,
         "directory entry cap exceeded");

      SMB.Core_Protocol.Select_Transfer_Amount
        (65_536, 4_096, Chunk, Status);
      Assert
        (Status = SMB.Ok and then Chunk = 4_096,
         "bounded transfer chunk selection");
      SMB.Core_Protocol.Select_Transfer_Amount
        (1, 0, Chunk, Status);
      Assert
        (Status /= SMB.Ok and then Chunk = 0,
         "zero transfer limit accepted");
   end Test_Core_Protocol;

   procedure Test_Engine_Receipts is
      use type SMB.Core_Client.Directory_Stage;
      use type SMB.Core_Client.Metadata_Stage;
      use type SMB.Core_Client.Metadata_State_Snapshot;
      State : SMB.Engine.Engine_State;
      Foreign_State : SMB.Engine.Engine_State;
      Status : SMB.Core_Status;
      Nt_Status : SMB.DWord;
      Message_Id : SMB.QWord;
      Expected : SMB.Engine.Request_Expectation;
      Token : SMB.Engine.Handle_Token := (others => 0);
      Directory_Token : SMB.Engine.Handle_Token := (others => 0);
      Foreign_Token : SMB.Engine.Handle_Token := (others => 0);
      File_Id : constant SMB.Bytes (0 .. 15) :=
        (16#10#, 16#21#, 16#32#, 16#43#, 16#54#, 16#65#, 16#76#, 16#87#,
         16#98#, 16#A9#, 16#BA#, 16#CB#, 16#DC#, 16#ED#, 16#FE#, 16#0F#);
      Wrong_File_Id : constant SMB.Bytes (0 .. 15) := (others => 1);
      Coordinator : SMB.Core_Client.Operation;
      Directory_Create : SMB.Core_Client.Operation;
      Foreign_Create : SMB.Core_Client.Operation;
      Close_Coordinator : SMB.Core_Client.Operation;
      Coordinator_Packet : SMB.Bytes (0 .. 121) := (others => 0);
      Close_Packet : SMB.Bytes (0 .. 87) := (others => 0);
      Coordinator_Used : Natural;
      Coordinator_Token : SMB.Engine.Handle_Token := (others => 0);
      Rejected_Token : SMB.Engine.Handle_Token := (others => 0);
      Validated_File_Id : SMB.Bytes (0 .. 15) := (others => 0);
      Validated_Access : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
      Validated_Directory : Boolean := False;
      Session_Id : constant SMB.QWord := 16#1234#;
      Tree_Id : constant SMB.DWord := 16#1020_3040#;
      Key : SMB.Bytes (0 .. 15) := (others => 0);
      Final_Token : constant SMB.Bytes (0 .. 28) :=
        (16#A1#, 16#1B#, 16#30#, 16#19#,
         16#A0#, 16#03#, 16#0A#, 16#01#, 0,
         16#A3#, 16#12#, 16#04#, 16#10#,
         1, 0, 0, 0, 16#0A#, 16#FB#, 16#34#, 16#90#,
         16#3A#, 16#3E#, 16#4E#, 16#54#, 0, 0, 0, 0);

      procedure Prepare_Response
        (Packet : in out SMB.Bytes;
         Command : SMB.Core_Wire.Command_Code;
         Reply_Id : SMB.QWord;
         Reply_Tree_Id : SMB.DWord;
         Reply_Session_Id : SMB.QWord;
         Signed : Boolean) is
      begin
         SMB.Wire.Initialize_Header
           (Packet, SMB.Word (Command), Reply_Id, Reply_Tree_Id,
            Reply_Session_Id);
         SMB.Wire.Put_U32 (Packet, 16, (if Signed then 9 else 1));
      end Prepare_Response;

      procedure Reconnect_Share
        (Target : in out SMB.Engine.Engine_State;
         Initialize_State : Boolean := True) is
      begin
         if Initialize_State then
            SMB.Engine.Initialize (Target, Status);
            Assert (Status = SMB.Ok, "reinitialize after coordinator abort");
         end if;
         SMB.Engine.Mark_Connected (Target, Status);
         Assert (Status = SMB.Ok, "reconnect transport after coordinator abort");
         declare
            Response : SMB.Bytes (0 .. 127) := (others => 0);
         begin
            SMB.Engine.Begin_Request
              (Target, SMB.Core_Wire.Command_Code (0), False, False,
               Message_Id, Expected, Status);
            Assert (Status = SMB.Ok, "reconnect negotiate request");
            Prepare_Response
              (Response, SMB.Core_Wire.Command_Code (0), Message_Id, 0, 0,
               False);
            Response (64) := 65;
            Response (66) := 1;
            Response (68) := 16#10#;
            Response (69) := 2;
            Response (98) := 1;
            Response (102) := 1;
            SMB.Engine.Accept_Response (Target, Response, Nt_Status, Status);
            Assert (Status = SMB.Ok, "reconnect negotiate response");
            SMB.Engine.Mark_Negotiated (Target, 65_536, 65_536, Status);
            Assert (Status = SMB.Ok, "reconnect negotiated phase");
         end;
         declare
            Response : SMB.Bytes (0 .. 71) := (others => 0);
         begin
            SMB.Engine.Begin_Request
              (Target, SMB.Core_Wire.Command_Code (1), False, False,
               Message_Id, Expected, Status);
            Assert (Status = SMB.Ok, "reconnect challenge request");
            Prepare_Response
              (Response, SMB.Core_Wire.Command_Code (1), Message_Id,
               0, Session_Id, False);
            SMB.Wire.Put_U32
              (Response, 8, SMB.Status_More_Processing_Required);
            Response (64) := 9;
            SMB.Engine.Accept_Response (Target, Response, Nt_Status, Status);
            Assert (Status = SMB.Ok, "reconnect challenge response");
            SMB.Engine.Install_Session_Key (Target, Session_Id, Key, Status);
            Assert (Status = SMB.Ok, "reconnect session key");
         end;
         declare
            Response : SMB.Bytes (0 .. 100) := (others => 0);
         begin
            SMB.Engine.Begin_Request
              (Target, SMB.Core_Wire.Command_Code (1), False, True,
               Message_Id, Expected, Status);
            Assert (Status = SMB.Ok, "reconnect final session request");
            Prepare_Response
              (Response, SMB.Core_Wire.Command_Code (1), Message_Id,
               0, Session_Id, True);
            Response (64) := 9;
            SMB.Wire.Put_U16 (Response, 68, 72);
            SMB.Wire.Put_U16 (Response, 70, Final_Token'Length);
            for Index in Final_Token'Range loop
               Response (72 + Index) := Final_Token (Index);
            end loop;
            SMB.Wire.Sign (Response, Key);
            SMB.Engine.Accept_Response (Target, Response, Nt_Status, Status);
            Assert (Status = SMB.Ok, "reconnect signed session response");
            SMB.Engine.Mark_Authenticated (Target, Status);
            Assert (Status = SMB.Ok, "reconnect authenticated phase");
         end;
         declare
            Response : SMB.Bytes (0 .. 79) := (others => 0);
         begin
            SMB.Engine.Begin_Request
              (Target, SMB.Core_Wire.Command_Code (3), True, True,
               Message_Id, Expected, Status);
            Assert (Status = SMB.Ok, "reconnect tree connect request");
            Prepare_Response
              (Response, SMB.Core_Wire.Command_Code (3), Message_Id,
               Tree_Id, Session_Id, True);
            Response (64) := 16;
            Response (66) := 1;
            SMB.Wire.Sign (Response, Key);
            SMB.Engine.Accept_Response (Target, Response, Nt_Status, Status);
            Assert (Status = SMB.Ok, "reconnect tree connect response");
            SMB.Engine.Mark_Share_Connected (Target, Tree_Id, Status);
            Assert (Status = SMB.Ok, "reconnect share-connected phase");
         end;
      end Reconnect_Share;

      procedure Reconnect_Share is
      begin
         Reconnect_Share (State);
      end Reconnect_Share;

      procedure Create_Directory_Handle
        (Target : in out SMB.Engine.Engine_State;
         Create_Operation : in out SMB.Core_Client.Operation;
         Result_Token : out SMB.Engine.Handle_Token;
         Is_Directory : Boolean := True)
      is
         Request : SMB.Bytes (0 .. 121) := (others => 0);
         Response : SMB.Bytes (0 .. 151) := (others => 0);
         Used : Natural;
      begin
         SMB.Core_Client.Prepare_Create
           (Create_Operation, Target, SMB.Bytes'(0, 0),
            SMB.Engine.Read_Only, False, 1, Is_Directory,
            Request, Used, Status);
         Assert (Status = SMB.Ok and then Used = Request'Length,
                 "prepare directory test handle");
         SMB.Core_Client.Send_Succeeded (Create_Operation, Target, Status);
         Assert (Status = SMB.Ok, "acknowledge directory test CREATE");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (5),
            SMB.Wire.U64 (Request, 24), Tree_Id, Session_Id, True);
         Response (64) := 89;
         Response (128 .. 143) := File_Id;
         SMB.Wire.Sign (Response, Key);
         SMB.Core_Client.Complete
           (Create_Operation, Target, Response, Nt_Status,
            Result_Token, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status = SMB.Success,
            "complete directory test CREATE");
      end Create_Directory_Handle;

      procedure Test_Directory_Coordinator is
         Directory_A, Directory_B :
           SMB.Core_Client.Directory_Enumeration;
         Zero_Directory, Error_Directory, Malformed_Directory,
           Bad_Signature_Directory :
           SMB.Core_Client.Directory_Enumeration;
         Query_A, Query_B : SMB.Bytes (0 .. 97) := (others => 0);
         Response : SMB.Bytes (0 .. 291) := (others => 0);
         Second_Response : SMB.Bytes (0 .. 177) := (others => 0);
         Terminal_Response : SMB.Bytes (0 .. 71) := (others => 0);
         Page_One : SMB.Bytes (0 .. 219) := (others => 0);
         Page_Two : SMB.Bytes (0 .. 105) := (others => 0);
         Bad_Page : SMB.Bytes (0 .. 105) := (others => 0);
         Short_Name : SMB.Bytes (0 .. 0) := (others => 0);
         Name : SMB.Bytes (0 .. 3) := (others => 0);
         Entry_Info : SMB.Core_Protocol.Directory_Info;
         Used, Name_Used : Natural;
         Owner : SMB.QWord;
         Epoch : SMB.QWord;

         procedure Make_Response
           (Target : SMB.Engine.Engine_State;
            Packet : in out SMB.Bytes;
            Request : SMB.Bytes;
            Page : SMB.Bytes;
            Response_Status : SMB.DWord := SMB.Success)
         is
            Key_Value : constant SMB.Bytes :=
              SMB.Engine.Current_Signing_Key (Target);
         begin
            Prepare_Response
              (Packet, SMB.Core_Wire.Command_Code (14),
               SMB.Wire.U64 (Request, 24), Tree_Id, Session_Id, True);
            SMB.Wire.Put_U32 (Packet, 8, Response_Status);
            SMB.Wire.Put_U16 (Packet, 64, 9);
            SMB.Wire.Put_U16
              (Packet, 66, (if Page'Length = 0 then 0 else 72));
            SMB.Wire.Put_U32 (Packet, 68, SMB.DWord (Page'Length));
            if Page'Length > 0 then
               Packet (72 .. 72 + Page'Length - 1) := Page;
            end if;
            SMB.Wire.Sign (Packet, Key_Value);
         end Make_Response;

         procedure Prepare_Directory_Request
           (Value : in out SMB.Core_Client.Directory_Enumeration;
            Target : in out SMB.Engine.Engine_State;
            Packet : in out SMB.Bytes)
         is
         begin
            SMB.Core_Client.Prepare_Directory_Query
              (Value, Target, Packet, Used, Status);
            Assert
              (Status = SMB.Ok and then Used = 98
               and then SMB.Wire.U16 (Packet, 12) = 14
               and then SMB.Wire.U64 (Packet, 24) > 0
               and then Packet (67) = 1
               and then Packet (72 .. 87) = File_Id
               and then SMB.Wire.U32 (Packet, 92) = 65_536
               and then SMB.Wire.Verify_Signature
                 (Packet, SMB.Engine.Current_Signing_Key (Target)),
               "signed first QUERY_DIRECTORY request fields");
         end Prepare_Directory_Request;
      begin
         Page_One (0 .. 3) := (112, 0, 0, 0);
         Page_One (60 .. 63) := (2, 0, 0, 0);
         Page_One (104 .. 105) := (97, 0);
         Page_One (112 + 60 .. 112 + 63) := (4, 0, 0, 0);
         Page_One (112 + 104 .. 112 + 107) := (98, 0, 99, 0);
         SMB.Wire.Put_U64 (Page_One, 40, 123);
         SMB.Wire.Put_U32 (Page_One, 56, 16#20#);
         SMB.Wire.Put_U64 (Page_One, 112 + 40, 456);
         SMB.Wire.Put_U32 (Page_One, 112 + 56, 16#10#);
         Page_Two (60 .. 63) := (2, 0, 0, 0);
         Page_Two (104 .. 105) := (100, 0);
         SMB.Wire.Put_U64 (Page_Two, 40, 789);
         SMB.Wire.Put_U32 (Page_Two, 56, 16#20#);
         Reconnect_Share (State);
         Reconnect_Share (Foreign_State);
         Create_Directory_Handle (State, Directory_Create, Directory_Token);
         Create_Directory_Handle
           (Foreign_State, Foreign_Create, Foreign_Token);
         SMB.Core_Client.Start_Directory
           (Directory_A, State, Directory_Token, Status);
         Assert (Status = SMB.Ok, "start first directory coordinator");
         SMB.Core_Client.Start_Directory
           (Directory_B, Foreign_State, Foreign_Token, Status);
         Assert (Status = SMB.Ok, "start colliding directory coordinator");

         Prepare_Directory_Request (Directory_A, State, Query_A);
         Prepare_Directory_Request (Directory_B, Foreign_State, Query_B);
         Assert (Query_A = Query_B, "directory expectations did not collide");
         Make_Response (Foreign_State, Response, Query_B, Page_One);
         SMB.Core_Client.Complete_Directory_Page
           (Directory_A, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine.Has_Pending_Request (State)
            and then SMB.Core_Client.Directory_Stage_Of (Directory_A) =
              SMB.Core_Client.Query_Prepared,
           "directory completion before send acknowledgement advanced");
         SMB.Core_Client.Directory_Send_Succeeded
           (Directory_A, State, Status);
         Assert (Status = SMB.Ok, "acknowledge first directory query");
         SMB.Core_Client.Directory_Send_Succeeded
           (Directory_B, Foreign_State, Status);
         Assert (Status = SMB.Ok, "acknowledge colliding directory query");
         SMB.Core_Client.Complete_Directory_Page
           (Directory_A, Foreign_State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine.Has_Pending_Request (Foreign_State)
            and then SMB.Engine.Has_Signing_Key (Foreign_State)
            and then SMB.Core_Client.Directory_Stage_Of (Directory_A) =
              SMB.Core_Client.Query_Sent,
           "foreign directory completion consumed colliding response");
         SMB.Core_Client.Abort_Directory
           (Directory_A, Foreign_State, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine.Has_Pending_Request (Foreign_State)
            and then SMB.Engine.Has_Signing_Key (Foreign_State),
           "foreign directory abort invalidated matching Engine");

         SMB.Core_Client.Complete_Directory_Page
           (Directory_A, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Core_Client.Directory_Stage_Of (Directory_A) =
              SMB.Core_Client.Page_Ready,
           "complete first directory page");
         SMB.Core_Client.Complete_Directory_Page
           (Directory_A, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Core_Client.Directory_Stage_Of (Directory_A) =
              SMB.Core_Client.Page_Ready,
           "duplicate directory page completion advanced");
         SMB.Core_Client.Complete_Directory_Page
           (Directory_B, Foreign_State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Core_Client.Directory_Stage_Of (Directory_B) =
              SMB.Core_Client.Page_Ready,
           "complete colliding directory page");
         SMB.Core_Client.Prepare_Directory_Query
           (Directory_A, State, Query_A, Used, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then not SMB.Engine.Has_Pending_Request (State),
           "query prepared before page drain");
         Response := (others => 0);

         SMB.Core_Client.Next_Directory_Entry
           (Directory_A, State, Name, Name_Used, Entry_Info, Status);
         Assert
           (Status = SMB.Ok and then Name (0 .. 1) = SMB.Bytes'(97, 0)
            and then Entry_Info.Size = 123,
           "owned page snapshot changed with caller packet");
         SMB.Core_Client.Next_Directory_Entry
           (Directory_B, State, Name, Name_Used, Entry_Info, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Core_Client.Directory_Cursor_Of (Directory_B) = 0
            and then SMB.Engine.Has_Signing_Key (State),
           "foreign directory entry extraction advanced");

         SMB.Core_Client.Next_Directory_Entry
           (Directory_B, Foreign_State, Short_Name, Name_Used,
            Entry_Info, Status);
         Assert
           (Status = SMB.Resource_Limit
            and then Name_Used = 0
            and then SMB.Core_Client.Directory_Cursor_Of (Directory_B) = 0
            and then SMB.Core_Client.Directory_Entry_Count_Of (Directory_B) = 0,
           "short directory name buffer advanced page");
         SMB.Core_Client.Next_Directory_Entry
           (Directory_B, Foreign_State, Name, Name_Used, Entry_Info, Status);
         Assert
           (Status = SMB.Ok and then Name_Used = 2
            and then Name (0 .. 1) = SMB.Bytes'(97, 0)
            and then Entry_Info.Size = 123
            and then Entry_Info.Attributes = 16#20#,
           "directory snapshot first entry");
         SMB.Core_Client.Next_Directory_Entry
           (Directory_B, Foreign_State, Name, Name_Used, Entry_Info, Status);
         Assert
           (Status = SMB.Ok and then Name_Used = 4
            and then Name = SMB.Bytes'(98, 0, 99, 0)
            and then Entry_Info.Size = 456
            and then Entry_Info.Attributes = 16#10#,
           "directory snapshot second entry");
         Assert
           (SMB.Core_Client.Directory_Stage_Of (Directory_B) =
              SMB.Core_Client.Query_Ready,
           "directory page did not drain");
         SMB.Core_Client.Prepare_Directory_Query
           (Directory_B, Foreign_State, Query_B, Used, Status);
         Assert
           (Status = SMB.Ok and then Used = 98 and then Query_B (67) = 0
            and then SMB.Wire.Verify_Signature
              (Query_B, SMB.Engine.Current_Signing_Key (Foreign_State)),
           "second QUERY_DIRECTORY restart or signature");
         SMB.Core_Client.Directory_Send_Succeeded
           (Directory_B, Foreign_State, Status);
         Assert (Status = SMB.Ok, "acknowledge second directory query");
         Make_Response (Foreign_State, Second_Response, Query_B, Page_Two);
         SMB.Core_Client.Complete_Directory_Page
           (Directory_B, Foreign_State, Second_Response, Nt_Status, Status);
         Assert (Status = SMB.Ok, "complete second directory page");
         SMB.Core_Client.Next_Directory_Entry
           (Directory_B, Foreign_State, Name, Name_Used, Entry_Info, Status);
         Assert
           (Status = SMB.Ok and then Name (0 .. 1) = SMB.Bytes'(100, 0)
            and then Entry_Info.Size = 789,
           "second-page directory entry");
         SMB.Core_Client.Prepare_Directory_Query
           (Directory_B, Foreign_State, Query_B, Used, Status);
         Assert (Status = SMB.Ok and then Query_B (67) = 0,
                 "terminal QUERY_DIRECTORY restart flag");
         SMB.Core_Client.Directory_Send_Succeeded
           (Directory_B, Foreign_State, Status);
         Assert (Status = SMB.Ok, "acknowledge terminal directory query");
         Make_Response
           (Foreign_State, Terminal_Response, Query_B, Page_Two (1 .. 0),
            SMB.Status_No_More_Files);
         SMB.Core_Client.Complete_Directory_Page
           (Directory_B, Foreign_State, Terminal_Response, Nt_Status, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status = SMB.Status_No_More_Files
            and then SMB.Core_Client.Directory_Stage_Of (Directory_B) =
              SMB.Core_Client.Directory_Finished
            and then not SMB.Engine.Has_Pending_Request (Foreign_State)
            and then not SMB.Engine.Has_Validated_Response (Foreign_State),
           "No_More_Files directory terminal");

         SMB.Core_Client.Start_Directory
           (Zero_Directory, Foreign_State, Foreign_Token, Status);
         Assert (Status = SMB.Ok, "start zero-data directory enumeration");
         SMB.Core_Client.Prepare_Directory_Query
           (Zero_Directory, Foreign_State, Query_B, Used, Status);
         SMB.Core_Client.Directory_Send_Succeeded
           (Zero_Directory, Foreign_State, Status);
         Make_Response
           (Foreign_State, Terminal_Response, Query_B, Page_Two (1 .. 0));
         SMB.Core_Client.Complete_Directory_Page
           (Zero_Directory, Foreign_State, Terminal_Response,
            Nt_Status, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status = SMB.Success
            and then SMB.Core_Client.Directory_Stage_Of (Zero_Directory) =
              SMB.Core_Client.Directory_Finished,
           "zero-data directory terminal");

         SMB.Core_Client.Start_Directory
           (Error_Directory, Foreign_State, Foreign_Token, Status);
         SMB.Core_Client.Prepare_Directory_Query
           (Error_Directory, Foreign_State, Query_B, Used, Status);
         SMB.Core_Client.Directory_Send_Succeeded
           (Error_Directory, Foreign_State, Status);
         Make_Response
           (Foreign_State, Terminal_Response, Query_B, Page_Two (1 .. 0),
            16#C000_0022#);
         SMB.Core_Client.Complete_Directory_Page
           (Error_Directory, Foreign_State, Terminal_Response,
            Nt_Status, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status = 16#C000_0022#
            and then SMB.Core_Client.Directory_Stage_Of (Error_Directory) =
              SMB.Core_Client.Directory_Finished
            and then SMB.Engine.Has_Signing_Key (Foreign_State)
            and then not SMB.Engine.Has_Pending_Request (Foreign_State),
           "valid directory NT error did not preserve healthy Engine");

         SMB.Core_Client.Start_Directory
           (Malformed_Directory, Foreign_State, Foreign_Token, Status);
         SMB.Core_Client.Prepare_Directory_Query
           (Malformed_Directory, Foreign_State, Query_B, Used, Status);
         SMB.Core_Client.Directory_Send_Succeeded
           (Malformed_Directory, Foreign_State, Status);
         Bad_Page (0 .. 3) := (1, 0, 0, 0);
         Bad_Page (60 .. 63) := (2, 0, 0, 0);
         Bad_Page (104 .. 105) := (120, 0);
         Make_Response (Foreign_State, Second_Response, Query_B, Bad_Page);
         SMB.Core_Client.Complete_Directory_Page
           (Malformed_Directory, Foreign_State, Second_Response,
            Nt_Status, Status);
         SMB.Core_Client.Next_Directory_Entry
           (Malformed_Directory, Foreign_State, Name, Name_Used,
            Entry_Info, Status);
         Assert
           (Status /= SMB.Ok
            and then SMB.Engine.Current_Phase (Foreign_State) =
              SMB.Engine.Disconnected
            and then SMB.Engine.Signing_Key_Is_Zero (Foreign_State)
            and then not SMB.Engine.Has_Pending_Request (Foreign_State)
            and then not SMB.Engine.Has_Validated_Response (Foreign_State),
           "malformed directory record did not invalidate Engine");

         Owner := SMB.Engine.Current_Owner_Id (State);
         Epoch := SMB.Engine.Current_Epoch (State);
         SMB.Engine.Invalidate (State, Status);
         Assert (Status = SMB.Ok, "invalidate stale directory context");
         Reconnect_Share (State, Initialize_State => False);
         Create_Directory_Handle (State, Directory_Create, Directory_Token);
         SMB.Core_Client.Abort_Directory (Directory_A, State, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine.Current_Owner_Id (State) = Owner
            and then SMB.Engine.Current_Epoch (State) /= Epoch
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Share_Connected
            and then SMB.Engine.Has_Signing_Key (State),
           "stale directory abort affected same-owner reconnected Engine");

         SMB.Core_Client.Start_Directory
           (Bad_Signature_Directory, State, Directory_Token, Status);
         SMB.Core_Client.Prepare_Directory_Query
           (Bad_Signature_Directory, State, Query_A, Used, Status);
         SMB.Core_Client.Directory_Send_Succeeded
           (Bad_Signature_Directory, State, Status);
         Make_Response (State, Second_Response, Query_A, Page_Two);
         Second_Response (48) := Second_Response (48) xor 1;
         SMB.Core_Client.Complete_Directory_Page
           (Bad_Signature_Directory, State, Second_Response,
            Nt_Status, Status);
         Assert
           (Status = SMB.Signature_Error
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected
            and then SMB.Engine.Signing_Key_Is_Zero (State)
            and then not SMB.Engine.Has_Pending_Request (State),
           "tampered directory response did not invalidate Engine");
      end Test_Directory_Coordinator;

      procedure Create_Transfer_Handle is
         Response : SMB.Bytes (0 .. 151) := (others => 0);
      begin
         SMB.Core_Client.Prepare_Create
           (Coordinator, State, SMB.Bytes'(0, 0), SMB.Engine.Read_Write,
            False, 1, False, Coordinator_Packet, Coordinator_Used, Status);
         Assert (Status = SMB.Ok, "prepare transfer test handle");
         SMB.Core_Client.Send_Succeeded (Coordinator, State, Status);
         Assert (Status = SMB.Ok, "acknowledge transfer test CREATE");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (5),
            SMB.Wire.U64 (Coordinator_Packet, 24),
            Tree_Id, Session_Id, True);
         Response (64) := 89;
         Response (128 .. 143) := File_Id;
         SMB.Wire.Sign (Response, Key);
         SMB.Core_Client.Complete
           (Coordinator, State, Response, Nt_Status,
            Coordinator_Token, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status = SMB.Success,
            "complete transfer test CREATE");
      end Create_Transfer_Handle;

      function Rejects_Negotiation return Boolean is
      begin
         SMB.Engine.Mark_Negotiated (State, 65_536, 65_536, Status);
         return Status /= SMB.Ok;
      end Rejects_Negotiation;

      function Rejects_Authentication return Boolean is
      begin
         SMB.Engine.Mark_Authenticated (State, Status);
         return Status /= SMB.Ok;
      end Rejects_Authentication;

      function Rejects_Tree_Connection return Boolean is
      begin
         SMB.Engine.Mark_Share_Connected (State, 1, Status);
         return Status /= SMB.Ok;
      end Rejects_Tree_Connection;

      function Rejects_Handle_Registration return Boolean is
      begin
         SMB.Engine.Register_Handle
           (State, File_Id, SMB.Engine.Read_Only, False, Token, Status);
         return Status /= SMB.Ok;
      end Rejects_Handle_Registration;
   begin
      SMB.Engine.Initialize (State, Status);
      Assert (Status = SMB.Ok, "engine initialization");
      SMB.Engine.Mark_Connected (State, Status);
      Assert (Status = SMB.Ok, "engine transport transition");
      SMB.Core_Client.Prepare_Close
        (Coordinator, State, (Owner => 0, Epoch => 0, Ticket => 1),
         Coordinator_Packet, Coordinator_Used, Status);
      Assert
        (Status /= SMB.Ok and then not SMB.Engine.Has_Pending_Request (State),
         "stale coordinator CLOSE token accepted");
      SMB.Core_Client.Prepare_Close
        (Coordinator, State,
         (Owner => SMB.Engine.Current_Owner_Id (State) + 1,
          Epoch => SMB.Engine.Current_Epoch (State), Ticket => 1),
         Coordinator_Packet, Coordinator_Used, Status);
      Assert
        (Status /= SMB.Ok and then not SMB.Engine.Has_Pending_Request (State),
         "foreign coordinator CLOSE token accepted");
      SMB.Engine.Install_Session_Key (State, Session_Id, Key, Status);
      Assert (Status /= SMB.Ok, "session key installed without a receipt");
      SMB.Engine.Close_Handle (State, Token, Status);
      Assert (Status /= SMB.Ok, "handle closed without a matching receipt");

      SMB.Engine.Initialize (State, Status);
      Assert
        (Status /= SMB.Ok
         and then SMB.Engine.Current_Phase (State) =
           SMB.Engine.Transport_Connected,
         "engine reinitialized an active connection");

      Assert (Rejects_Negotiation, "negotiation without receipt accepted");
      Assert (Rejects_Authentication, "authentication without receipt accepted");
      Assert (Rejects_Tree_Connection, "tree connection without receipt accepted");
      Assert (Rejects_Handle_Registration, "handle registration without receipt accepted");

      for Index in Key'Range loop
         Key (Index) := SMB.Byte (Index);
      end loop;
      declare
         Response : SMB.Bytes (0 .. 127) := (others => 0);
      begin
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (0), False, False,
            Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "begin negotiate request");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (0), Message_Id, 0, 0, False);
         Response (64) := 65;
         Response (66) := 1;
         Response (68) := 16#10#;
         Response (69) := 2;
         Response (98) := 1;
         Response (102) := 1;
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status = SMB.Success,
            "accept negotiate receipt");
         SMB.Engine.Mark_Negotiated (State, 65_536, 65_536, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Engine.Current_Phase (State) = SMB.Engine.Negotiated,
            "consume negotiate receipt");
      end;

      declare
         Response : SMB.Bytes (0 .. 71) := (others => 0);
      begin
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (1), False, False,
            Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "begin challenge request");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (1), Message_Id,
            0, Session_Id, False);
         SMB.Wire.Put_U32
           (Response, 8, SMB.Status_More_Processing_Required);
         Response (64) := 9;
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Ok
            and then Nt_Status = SMB.Status_More_Processing_Required,
            "accept session challenge receipt");
         SMB.Engine.Install_Session_Key
           (State, Session_Id + 1, Key, Status);
         Assert
           (Status /= SMB.Ok
            and then SMB.Engine.Has_Validated_Response (State),
            "challenge receipt accepted with a different session id");
         SMB.Engine.Install_Session_Key (State, Session_Id, Key, Status);
         Assert (Status = SMB.Ok, "consume challenge receipt");
      end;

      declare
         Response : SMB.Bytes (0 .. 100) := (others => 0);
      begin
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (1), False, True,
            Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "begin final session setup request");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (1), Message_Id,
            0, Session_Id, True);
         Response (64) := 9;
         SMB.Wire.Put_U16 (Response, 68, 72);
         SMB.Wire.Put_U16 (Response, 70, Final_Token'Length);
         for Index in Final_Token'Range loop
            Response (72 + Index) := Final_Token (Index);
         end loop;
         SMB.Wire.Sign (Response, Key);
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status = SMB.Success,
            "accept signed final session setup");
         SMB.Engine.Mark_Authenticated (State, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Engine.Current_Phase (State) = SMB.Engine.Authenticated,
            "consume authenticated session receipt once");
      end;

      declare
         Response : SMB.Bytes (0 .. 79) := (others => 0);
      begin
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (3), True, True,
            Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "begin tree connect request");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (3), Message_Id,
            Tree_Id, Session_Id, True);
         Response (64) := 16;
         Response (66) := 1;
         SMB.Wire.Sign (Response, Key);
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert (Status = SMB.Ok, "accept tree connect receipt");
         SMB.Engine.Mark_Share_Connected (State, Tree_Id, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Engine.Current_Phase (State) = SMB.Engine.Share_Connected,
            "consume tree connect receipt");
      end;

      declare
         Response : SMB.Bytes (0 .. 151) := (others => 0);
      begin
         SMB.Core_Client.Prepare_Create
           (Coordinator, State, SMB.Bytes'(0, 0), SMB.Engine.Read_Write,
            True, 3, False, Coordinator_Packet, Coordinator_Used, Status);
         Assert (Status = SMB.Ok, "coordinator CREATE preparation");
         Assert
           (Coordinator_Packet (88 .. 91) =
              SMB.Bytes'
                (SMB.Core_Wire.U32_Byte
                   (SMB.Core_Client.Access_Mask
                      (SMB.Engine.Read_Write, True), 0),
                 SMB.Core_Wire.U32_Byte
                   (SMB.Core_Client.Access_Mask
                      (SMB.Engine.Read_Write, True), 1),
                 SMB.Core_Wire.U32_Byte
                   (SMB.Core_Client.Access_Mask
                      (SMB.Engine.Read_Write, True), 2),
                 SMB.Core_Wire.U32_Byte
                   (SMB.Core_Client.Access_Mask
                      (SMB.Engine.Read_Write, True), 3))
            and then Coordinator_Packet (104) = 16#40#
            and then Coordinator_Packet (100) = 3
            and then SMB.Core_Client.Create_Delete_Access_Of
              (Coordinator)
            and then SMB.Core_Client.Create_Disposition_Of
              (Coordinator) = 3,
            "CREATE wire mask, options, and input metadata");
         SMB.Core_Client.Send_Succeeded (Coordinator, State, Status);
         Assert (Status = SMB.Ok, "coordinator CREATE send acknowledgement");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (5),
            SMB.Wire.U64 (Coordinator_Packet, 24),
            Tree_Id, Session_Id, True);
         Response (64) := 89;
         Response (128 .. 143) := File_Id;
         SMB.Wire.Sign (Response, Key);
         SMB.Core_Client.Complete
           (Coordinator, State, Response, Nt_Status,
            Coordinator_Token, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status = SMB.Success
            and then SMB.Engine.Has_Open_Handles (State),
            "coordinator CREATE completion and handle registration");
         SMB.Engine.Validate_Handle
           (State, Coordinator_Token, False, False, Validated_File_Id,
            Validated_Access, Validated_Directory, Status);
         Assert
           (Status = SMB.Ok
            and then Validated_File_Id = File_Id
            and then Validated_Access = SMB.Engine.Read_Write
            and then not Validated_Directory,
            "CREATE input metadata registered on returned handle");
         declare
            Original : constant SMB.Bytes (1 .. 5) :=
              (16#11#, 16#22#, 16#33#, 16#44#, 16#55#);
            Mutable_Data : SMB.Bytes (1 .. 5) := Original;
            Write_Transfer : SMB.Core_Client.Transfer (5);
            Read_Transfer : SMB.Core_Client.Transfer (5);
            Boundary_Transfer : SMB.Core_Client.Transfer (1);
            Empty_Transfer : SMB.Core_Client.Transfer (0);
            Write_Packet : SMB.Bytes (0 .. 116) := (others => 0);
            Read_Packet : SMB.Bytes (0 .. 112) := (others => 0);
            Write_Response : SMB.Bytes (0 .. 79) := (others => 0);
            Read_Response : SMB.Bytes (0 .. 84) := (others => 0);
            Result : SMB.Bytes (0 .. 4) := (others => 0);
            Invalid_Token : constant SMB.Engine.Handle_Token :=
              (Owner => 0, Epoch => 0, Ticket => 0);
            Used : Natural;
         begin
            SMB.Core_Client.Start_Read
              (Boundary_Transfer, State, Invalid_Token, 0, 1, Status);
            Assert
              (Status = SMB.Invalid_Handle_Status
               and then not SMB.Engine.Has_Pending_Request (State),
               "invalid transfer token reserved a request");
            SMB.Core_Client.Start_Write
              (Boundary_Transfer, State, Coordinator_Token,
               SMB.QWord'Last, SMB.Bytes'(1 => 16#AA#), Status);
            Assert
              (Status = SMB.Invalid_Offset
               and then not SMB.Engine.Has_Pending_Request (State),
               "overflowing transfer range reserved a request");

            SMB.Core_Client.Start_Write
              (Empty_Transfer, State, Coordinator_Token, 0,
               SMB.Bytes'(1 .. 0 => 0), Status);
            Assert
              (Status = SMB.Ok
               and then SMB.Core_Client.Transfer_Stage_Of (Empty_Transfer) =
                 SMB.Core_Client.Transfer_Finished
               and then SMB.Core_Client.Transfer_Completed_Of (Empty_Transfer) = 0
               and then not SMB.Engine.Has_Pending_Request (State),
               "empty WRITE must finish without reserving a request");

            SMB.Core_Client.Start_Write
              (Write_Transfer, State, Coordinator_Token, 100,
               Mutable_Data, Status);
            Assert (Status = SMB.Ok, "transfer WRITE start");
            Mutable_Data := (others => 0);
            SMB.Core_Client.Prepare_Next
              (Write_Transfer, State, Write_Packet, Used, Status);
            Assert
              (Status = SMB.Ok and then Used = 117
               and then Write_Packet (72 .. 79) =
                 SMB.Bytes'(100, 0, 0, 0, 0, 0, 0, 0)
               and then Write_Packet (112 .. 116) = Original,
               "WRITE snapshot and encoded initial offset");
            SMB.Core_Client.Transfer_Send_Succeeded
              (Write_Transfer, State, Status);
            Assert (Status = SMB.Ok, "transfer WRITE send acknowledgement");
            Prepare_Response
              (Write_Response, SMB.Core_Wire.Command_Code (9),
               SMB.Wire.U64 (Write_Packet, 24), Tree_Id, Session_Id, True);
            Write_Response (64) := 17;
            SMB.Wire.Put_U16 (Write_Response, 66, 1);
            SMB.Wire.Put_U32 (Write_Response, 68, 3);
            SMB.Wire.Put_U32 (Write_Response, 72, 1);
            SMB.Wire.Put_U16 (Write_Response, 76, 1);
            SMB.Wire.Put_U16 (Write_Response, 78, 1);
            SMB.Wire.Sign (Write_Response, Key);
            SMB.Core_Client.Complete_Write
              (Write_Transfer, State, Write_Response, Nt_Status, Status);
            Assert
              (Status = SMB.Ok and then Nt_Status = SMB.Success
               and then SMB.Core_Client.Transfer_Completed_Of
                 (Write_Transfer) = 3,
               "reserved WRITE response fields were not ignored");
            SMB.Core_Client.Complete_Write
              (Write_Transfer, State, Write_Response, Nt_Status, Status);
            Assert
              (Status = SMB.Invalid_State_Status
               and then SMB.Core_Client.Transfer_Completed_Of
                 (Write_Transfer) = 3,
               "duplicate WRITE completion advanced progress");
            SMB.Core_Client.Prepare_Next
              (Write_Transfer, State, Write_Packet, Used, Status);
            Assert
              (Status = SMB.Ok
               and then SMB.Core_Wire.Encoded_U64 (Write_Packet, 72) = 103
               and then Write_Packet (112 .. 113) =
                 SMB.Bytes'(16#44#, 16#55#),
               "partial WRITE continuation offset and original payload");
            SMB.Core_Client.Transfer_Send_Succeeded
              (Write_Transfer, State, Status);
            Prepare_Response
              (Write_Response, SMB.Core_Wire.Command_Code (9),
               SMB.Wire.U64 (Write_Packet, 24), Tree_Id, Session_Id, True);
            Write_Response (64) := 17;
            SMB.Wire.Put_U32 (Write_Response, 68, 2);
            SMB.Wire.Sign (Write_Response, Key);
            SMB.Core_Client.Complete_Write
              (Write_Transfer, State, Write_Response, Nt_Status, Status);
            Assert
              (Status = SMB.Ok
               and then SMB.Core_Client.Transfer_Stage_Of (Write_Transfer) =
                 SMB.Core_Client.Transfer_Finished,
               "WRITE transfer completion");

            SMB.Core_Client.Start_Write
              (Write_Transfer, State, Coordinator_Token, 100, Original, Status);
            SMB.Core_Client.Prepare_Next
              (Write_Transfer, State, Write_Packet, Used, Status);
            SMB.Core_Client.Transfer_Send_Succeeded
              (Write_Transfer, State, Status);
            Prepare_Response
              (Write_Response, SMB.Core_Wire.Command_Code (9),
               SMB.Wire.U64 (Write_Packet, 24), Tree_Id, Session_Id, True);
            Write_Response (64) := 17;
            SMB.Wire.Put_U32 (Write_Response, 68, 3);
            SMB.Wire.Sign (Write_Response, Key);
            SMB.Core_Client.Complete_Write
              (Write_Transfer, State, Write_Response, Nt_Status, Status);
            Assert (Status = SMB.Ok, "WRITE progress before NTSTATUS error");
            SMB.Core_Client.Prepare_Next
              (Write_Transfer, State, Write_Packet, Used, Status);
            SMB.Core_Client.Transfer_Send_Succeeded
              (Write_Transfer, State, Status);
            Prepare_Response
              (Write_Response, SMB.Core_Wire.Command_Code (9),
               SMB.Wire.U64 (Write_Packet, 24), Tree_Id, Session_Id, True);
            Write_Response (64) := 9;
            SMB.Wire.Put_U32 (Write_Response, 8, SMB.Status_Access_Denied);
            SMB.Wire.Sign (Write_Response, Key);
            SMB.Core_Client.Complete_Write
              (Write_Transfer, State, Write_Response, Nt_Status, Status);
            Assert
              (Status = SMB.Ok and then Nt_Status = SMB.Status_Access_Denied
               and then SMB.Core_Client.Transfer_Completed_Of (Write_Transfer) = 3
               and then SMB.Core_Client.Transfer_Remaining_Of (Write_Transfer) = 2
               and then SMB.Core_Client.Transfer_Stage_Of (Write_Transfer) =
                 SMB.Core_Client.Transfer_Finished
               and then SMB.Engine.Current_Phase (State) =
                 SMB.Engine.Share_Connected
               and then not SMB.Engine.Has_Validated_Response (State)
               and then not SMB.Engine.Has_Pending_Request (State),
               "NTSTATUS after partial WRITE advanced progress or kept receipt");

            SMB.Core_Client.Start_Read
              (Read_Transfer, State, Coordinator_Token, 200, 5, Status);
            Assert (Status = SMB.Ok, "transfer READ start");
            SMB.Core_Client.Prepare_Next
              (Read_Transfer, State, Read_Packet, Used, Status);
            SMB.Core_Client.Transfer_Send_Succeeded
              (Read_Transfer, State, Status);
            Prepare_Response
              (Read_Response, SMB.Core_Wire.Command_Code (8),
               SMB.Wire.U64 (Read_Packet, 24), Tree_Id, Session_Id, True);
            Read_Response (64) := 17;
            Read_Response (66) := 80;
            SMB.Wire.Put_U32 (Read_Response, 68, 5);
            Read_Response (80 .. 84) := Original;
            SMB.Wire.Sign (Read_Response, Key);
            SMB.Core_Client.Complete_Read
              (Read_Transfer, State, Read_Response, Nt_Status, Status);
            SMB.Core_Client.Copy_Read_Result
              (Read_Transfer, Result, Used, Status);
            Assert
              (Status = SMB.Ok and then Used = 5
               and then Result = Original,
               "validated READ bytes copied from transfer buffer");

            SMB.Core_Client.Start_Read
              (Read_Transfer, State, Coordinator_Token, 300, 5, Status);
            SMB.Core_Client.Prepare_Next
              (Read_Transfer, State, Read_Packet, Used, Status);
            SMB.Core_Client.Transfer_Send_Succeeded
              (Read_Transfer, State, Status);
            Read_Response := (others => 0);
            Prepare_Response
              (Read_Response, SMB.Core_Wire.Command_Code (8),
               SMB.Wire.U64 (Read_Packet, 24), Tree_Id, Session_Id, True);
            Read_Response (64) := 17;
            SMB.Wire.Put_U16 (Read_Response, 66, 80);
            SMB.Wire.Put_U32 (Read_Response, 68, 2);
            Read_Response (80 .. 81) := Original (1 .. 2);
            SMB.Wire.Sign (Read_Response, Key);
            SMB.Core_Client.Complete_Read
              (Read_Transfer, State, Read_Response, Nt_Status, Status);
            SMB.Core_Client.Copy_Read_Result
              (Read_Transfer, Result, Used, Status);
            Assert
              (Status = SMB.Ok and then Used = 2
               and then Result (0 .. 1) = Original (1 .. 2)
               and then SMB.Core_Client.Transfer_Stage_Of (Read_Transfer) =
                 SMB.Core_Client.Transfer_Finished,
               "short READ terminates with validated prefix");

            SMB.Core_Client.Start_Read
              (Read_Transfer, State, Coordinator_Token, 400, 5, Status);
            SMB.Core_Client.Prepare_Next
              (Read_Transfer, State, Read_Packet, Used, Status);
            SMB.Core_Client.Transfer_Send_Succeeded
              (Read_Transfer, State, Status);
            Read_Response := (others => 0);
            Prepare_Response
              (Read_Response, SMB.Core_Wire.Command_Code (8),
               SMB.Wire.U64 (Read_Packet, 24), Tree_Id, Session_Id, True);
            Read_Response (64) := 17;
            SMB.Wire.Put_U16 (Read_Response, 66, 80);
            SMB.Wire.Sign (Read_Response, Key);
            SMB.Core_Client.Complete_Read
              (Read_Transfer, State, Read_Response, Nt_Status, Status);
            SMB.Core_Client.Copy_Read_Result
              (Read_Transfer, Result, Used, Status);
            Assert
              (Status = SMB.Ok and then Used = 0
               and then SMB.Core_Client.Transfer_Stage_Of (Read_Transfer) =
                 SMB.Core_Client.Transfer_Finished,
               "zero-length READ terminates without retry");

            SMB.Core_Client.Start_Read
              (Read_Transfer, State, Coordinator_Token, 500, 5, Status);
            SMB.Core_Client.Prepare_Next
              (Read_Transfer, State, Read_Packet, Used, Status);
            SMB.Core_Client.Transfer_Send_Succeeded
              (Read_Transfer, State, Status);
            Read_Response := (others => 0);
            Prepare_Response
              (Read_Response, SMB.Core_Wire.Command_Code (8),
               SMB.Wire.U64 (Read_Packet, 24), Tree_Id, Session_Id, True);
            SMB.Wire.Put_U32 (Read_Response, 8, SMB.Status_End_Of_File);
            Read_Response (64) := 9;
            SMB.Wire.Sign (Read_Response, Key);
            SMB.Core_Client.Complete_Read
              (Read_Transfer, State, Read_Response, Nt_Status, Status);
            Assert
              (Status = SMB.Ok and then Nt_Status = SMB.Status_End_Of_File
               and then SMB.Core_Client.Transfer_Completed_Of (Read_Transfer)
                 = 0
               and then SMB.Core_Client.Transfer_Stage_Of (Read_Transfer) =
                 SMB.Core_Client.Transfer_Finished
               and then SMB.Engine.Current_Phase (State) =
                 SMB.Engine.Share_Connected
               and then not SMB.Engine.Has_Pending_Request (State),
               "EOF READ finishes without progress or invalidation");

            SMB.Core_Client.Start_Read
              (Read_Transfer, State, Coordinator_Token, 550, 5, Status);
            SMB.Core_Client.Prepare_Next
              (Read_Transfer, State, Read_Packet, Used, Status);
            SMB.Core_Client.Transfer_Send_Succeeded
              (Read_Transfer, State, Status);
            Read_Response := (others => 0);
            Prepare_Response
              (Read_Response, SMB.Core_Wire.Command_Code (8),
               SMB.Wire.U64 (Read_Packet, 24), Tree_Id, Session_Id, True);
            SMB.Wire.Put_U32 (Read_Response, 8, SMB.Status_Access_Denied);
            Read_Response (64) := 9;
            SMB.Wire.Sign (Read_Response, Key);
            SMB.Core_Client.Complete_Read
              (Read_Transfer, State, Read_Response, Nt_Status, Status);
            Assert
              (Status = SMB.Ok and then Nt_Status = SMB.Status_Access_Denied
               and then SMB.Core_Client.Transfer_Completed_Of (Read_Transfer)
                 = 0
               and then SMB.Core_Client.Transfer_Stage_Of (Read_Transfer) =
                 SMB.Core_Client.Transfer_Finished
               and then SMB.Engine.Current_Phase (State) =
                 SMB.Engine.Share_Connected
               and then not SMB.Engine.Has_Pending_Request (State),
               "signed NTSTATUS READ error advanced or invalidated state");

            declare
               Large_Transfer : SMB.Core_Client.Transfer
                 (SMB.Core_Protocol.Maximum_IO_Chunk + 1);
               Large_Response : SMB.Bytes
                 (0 .. 79 + SMB.Core_Protocol.Maximum_IO_Chunk);
               Final_Response : SMB.Bytes (0 .. 80) := (others => 0);
               Large_Result : SMB.Bytes
                 (0 .. SMB.Core_Protocol.Maximum_IO_Chunk);
            begin
               SMB.Core_Client.Start_Read
                 (Large_Transfer, State, Coordinator_Token, 600,
                  SMB.Core_Protocol.Maximum_IO_Chunk + 1, Status);
               SMB.Core_Client.Prepare_Next
                 (Large_Transfer, State, Read_Packet, Used, Status);
               SMB.Core_Client.Transfer_Send_Succeeded
                 (Large_Transfer, State, Status);
               Large_Response := (others => 0);
               Prepare_Response
                 (Large_Response, SMB.Core_Wire.Command_Code (8),
                  SMB.Wire.U64 (Read_Packet, 24), Tree_Id, Session_Id, True);
               Large_Response (64) := 17;
               SMB.Wire.Put_U16 (Large_Response, 66, 80);
               SMB.Wire.Put_U32
                 (Large_Response, 68,
                  SMB.Core_Protocol.Maximum_IO_Chunk);
               for Index in 0 .. SMB.Core_Protocol.Maximum_IO_Chunk - 1 loop
                  Large_Response (80 + Index) := SMB.Byte (Index mod 256);
               end loop;
               SMB.Wire.Sign (Large_Response, Key);
               SMB.Core_Client.Complete_Read
                 (Large_Transfer, State, Large_Response, Nt_Status, Status);
               Assert
                 (Status = SMB.Ok
                  and then SMB.Core_Client.Transfer_Completed_Of
                    (Large_Transfer) =
                      SMB.Core_Protocol.Maximum_IO_Chunk
                  and then SMB.Core_Client.Transfer_Stage_Of
                    (Large_Transfer) = SMB.Core_Client.Ready,
                  "full READ chunk preserves remaining transfer");
               SMB.Core_Client.Prepare_Next
                 (Large_Transfer, State, Read_Packet, Used, Status);
               Assert
                 (Status = SMB.Ok
                  and then SMB.Core_Wire.Encoded_U64 (Read_Packet, 72) =
                    600 + SMB.Core_Protocol.Maximum_IO_Chunk,
                  "READ chunk continuation advances validated offset");
               SMB.Core_Client.Transfer_Send_Succeeded
                 (Large_Transfer, State, Status);
               Prepare_Response
                 (Final_Response, SMB.Core_Wire.Command_Code (8),
                  SMB.Wire.U64 (Read_Packet, 24), Tree_Id, Session_Id, True);
               Final_Response (64) := 17;
               SMB.Wire.Put_U16 (Final_Response, 66, 80);
               SMB.Wire.Put_U32 (Final_Response, 68, 1);
               Final_Response (80) := 16#AA#;
               SMB.Wire.Sign (Final_Response, Key);
               SMB.Core_Client.Complete_Read
                 (Large_Transfer, State, Final_Response, Nt_Status, Status);
               SMB.Core_Client.Copy_Read_Result
                 (Large_Transfer, Large_Result, Used, Status);
               Assert
                 (Status = SMB.Ok
                  and then Used =
                    SMB.Core_Protocol.Maximum_IO_Chunk + 1
                  and then Large_Result (0) = 0
                  and then Large_Result (255) = 255
                  and then Large_Result (SMB.Core_Protocol.Maximum_IO_Chunk)
                    = 16#AA#,
                  "multi-chunk READ result preserves accumulated prefix");

               SMB.Core_Client.Start_Read
                 (Large_Transfer, State, Coordinator_Token, 600,
                  SMB.Core_Protocol.Maximum_IO_Chunk + 1, Status);
               SMB.Core_Client.Prepare_Next
                 (Large_Transfer, State, Read_Packet, Used, Status);
               SMB.Core_Client.Transfer_Send_Succeeded
                 (Large_Transfer, State, Status);
               SMB.Wire.Put_U64
                 (Large_Response, 24, SMB.Wire.U64 (Read_Packet, 24));
               SMB.Wire.Sign (Large_Response, Key);
               SMB.Core_Client.Complete_Read
                 (Large_Transfer, State, Large_Response, Nt_Status, Status);
               Assert (Status = SMB.Ok, "READ progress before EOF");
               SMB.Core_Client.Prepare_Next
                 (Large_Transfer, State, Read_Packet, Used, Status);
               SMB.Core_Client.Transfer_Send_Succeeded
                 (Large_Transfer, State, Status);
               Prepare_Response
                 (Final_Response, SMB.Core_Wire.Command_Code (8),
                  SMB.Wire.U64 (Read_Packet, 24), Tree_Id, Session_Id, True);
               Final_Response (64) := 9;
               SMB.Wire.Put_U32 (Final_Response, 8, SMB.Status_End_Of_File);
               SMB.Wire.Sign (Final_Response, Key);
               SMB.Core_Client.Complete_Read
                 (Large_Transfer, State, Final_Response, Nt_Status, Status);
               Assert
                 (Status = SMB.Ok and then Nt_Status = SMB.Status_End_Of_File,
                  "EOF after a full READ chunk");
               SMB.Core_Client.Copy_Read_Result
                 (Large_Transfer, Large_Result, Used, Status);
               Assert
                 (Status = SMB.Ok
                  and then Used = SMB.Core_Protocol.Maximum_IO_Chunk
                  and then (for all Index in 0 .. Used - 1 =>
                    Large_Result (Index) = SMB.Byte (Index mod 256))
                  and then not SMB.Engine.Has_Pending_Request (State)
                  and then not SMB.Engine.Has_Validated_Response (State),
                  "EOF after progress lost the validated READ prefix");
            end;
         end;
         SMB.Core_Client.Complete
           (Coordinator, State, Response, Nt_Status,
            Rejected_Token, Status);
         Assert (Status /= SMB.Ok, "duplicate coordinator completion accepted");
         SMB.Core_Client.Prepare_Close
           (Close_Coordinator, State, Coordinator_Token,
            Close_Packet, Coordinator_Used, Status);
         Assert
           (Status = SMB.Ok,
            "coordinator CLOSE preparation " & SMB.Core_Status'Image (Status));
         Assert
           (Close_Packet (72 .. 87) = Validated_File_Id,
            "coordinator CLOSE encoded validated FileId");
         SMB.Core_Client.Complete
           (Close_Coordinator, State, Response, Nt_Status,
            Rejected_Token, Status);
         Assert (Status /= SMB.Ok, "coordinator response-before-send accepted");
         SMB.Core_Client.Send_Succeeded (Close_Coordinator, State, Status);
         Assert (Status = SMB.Ok, "coordinator CLOSE send acknowledgement");
         declare
            Close_Response : SMB.Bytes (0 .. 123) := (others => 0);
         begin
            Prepare_Response
              (Close_Response, SMB.Core_Wire.Command_Code (6),
               SMB.Wire.U64 (Close_Packet, 24),
               Tree_Id, Session_Id, True);
            Close_Response (64) := 60;
            SMB.Wire.Sign (Close_Response, Key);
            SMB.Core_Client.Complete
              (Close_Coordinator, State, Close_Response, Nt_Status,
               Coordinator_Token, Status);
            Assert
              (Status = SMB.Ok and then Nt_Status = SMB.Success
               and then not SMB.Engine.Has_Open_Handles (State),
               "coordinator CLOSE completion");
            SMB.Core_Client.Complete
              (Close_Coordinator, State, Close_Response, Nt_Status,
               Coordinator_Token, Status);
            Assert (Status /= SMB.Ok, "duplicate CLOSE completion accepted");
         end;
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (5), True, True,
            Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "begin create request");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (5), Message_Id,
            Tree_Id, Session_Id, True);
         Response (64) := 89;
         Response (128 .. 143) := File_Id;
         SMB.Wire.Sign (Response, Key);
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert (Status = SMB.Ok, "accept create receipt");
         SMB.Engine.Register_Handle
           (State, Wrong_File_Id, SMB.Engine.Read_Only, False, Token, Status);
         Assert
           (Status /= SMB.Ok,
            "wrong CREATE file id accepted");
         SMB.Engine.Register_Handle
           (State, File_Id, SMB.Engine.Read_Only, False, Token, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Engine.Has_Open_Handles (State),
            "register handle from matching create receipt");
         Assert (Rejects_Handle_Registration,
                 "create receipt was reusable for handle registration");
      end;

      declare
         Response : SMB.Bytes (0 .. 79) := (others => 0);
      begin
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (8), True, True,
            Message_Id, Expected, Status, Request_Amount => 1);
         Assert (Status = SMB.Ok, "begin signed read request");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (8), Message_Id,
            Tree_Id, Session_Id, True);
         Response (64) := 17;
         Response (66) := 80;
         SMB.Wire.Sign (Response, Key);
         Response (48) := Response (48) xor 1;
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Signature_Error
            and then Nt_Status = 0
            and then SMB.Engine.Current_Phase (State) = SMB.Engine.Disconnected
            and then not SMB.Engine.Has_Signing_Key (State)
            and then not SMB.Engine.Has_Pending_Request (State)
            and then not SMB.Engine.Has_Open_Handles (State),
            "tampered response did not invalidate session and handles");
      end;

      Reconnect_Share;
      SMB.Core_Client.Prepare_Create
        (Coordinator, State, SMB.Bytes'(0, 0), SMB.Engine.Read_Only,
         False, 1, False, Coordinator_Packet, Coordinator_Used, Status);
      Assert (Status = SMB.Ok, "coordinator prepare before abort");
      SMB.Core_Client.Abort_Operation (Coordinator, State, Status);
      Assert
        (Status = SMB.Ok
         and then not SMB.Engine.Has_Pending_Request (State)
         and then not SMB.Engine.Has_Signing_Key (State)
         and then SMB.Engine.Current_Phase (State) = SMB.Engine.Disconnected,
         "coordinator abort left request or session state");
      Reconnect_Share;
      SMB.Core_Client.Prepare_Create
        (Coordinator, State, SMB.Bytes'(0, 0), SMB.Engine.Read_Only,
         False, 1, False, Coordinator_Packet, Coordinator_Used, Status);
      Assert
        (Status = SMB.Ok and then SMB.Engine.Has_Pending_Request (State),
         "coordinator was not reusable after abort and reconnect");
      SMB.Core_Client.Abort_Operation (Coordinator, State, Status);
      Assert (Status = SMB.Ok, "abort reused coordinator request");

      Reconnect_Share;
      Create_Transfer_Handle;
      declare
         Transfer : SMB.Core_Client.Transfer (1);
         Packet : SMB.Bytes (0 .. 112) := (others => 0);
         Used : Natural;
      begin
         SMB.Core_Client.Start_Write
           (Transfer, State, Coordinator_Token, 0,
            SMB.Bytes'(0 => 16#AA#), Status);
         SMB.Core_Client.Prepare_Next
           (Transfer, State, Packet, Used, Status);
         Assert (Status = SMB.Ok, "prepare transfer for abort");
         SMB.Core_Client.Abort_Transfer (Transfer, State, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Core_Client.Transfer_Stage_Of (Transfer) =
              SMB.Core_Client.Transfer_Failed
            and then not SMB.Engine.Has_Pending_Request (State)
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected,
            "transfer abort retained request or session");
      end;

      Reconnect_Share;
      Create_Transfer_Handle;
      declare
         Transfer : SMB.Core_Client.Transfer (1);
         Packet : SMB.Bytes (0 .. 112) := (others => 0);
         Response : SMB.Bytes (0 .. 79) := (others => 0);
         Used : Natural;
      begin
         SMB.Core_Client.Start_Write
           (Transfer, State, Coordinator_Token, 0,
            SMB.Bytes'(0 => 16#AA#), Status);
         SMB.Core_Client.Prepare_Next
           (Transfer, State, Packet, Used, Status);
         SMB.Core_Client.Transfer_Send_Succeeded
           (Transfer, State, Status);
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (9),
            SMB.Wire.U64 (Packet, 24), Tree_Id, Session_Id, True);
         Response (64) := 17;
         SMB.Wire.Put_U32 (Response, 68, 0);
         SMB.Wire.Sign (Response, Key);
         SMB.Core_Client.Complete_Write
           (Transfer, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Invalid_Protocol
            and then Nt_Status = SMB.Success
            and then SMB.Core_Client.Transfer_Completed_Of (Transfer) = 0
            and then SMB.Core_Client.Transfer_Stage_Of (Transfer) =
              SMB.Core_Client.Transfer_Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected
            and then not SMB.Engine.Has_Open_Handles (State),
            "zero-count WRITE did not invalidate transfer state");
      end;

      Reconnect_Share;
      Create_Transfer_Handle;
      declare
         Transfer : SMB.Core_Client.Transfer (1);
         Packet : SMB.Bytes (0 .. 112) := (others => 0);
         Response : SMB.Bytes (0 .. 79) := (others => 0);
         Used : Natural;
      begin
         SMB.Core_Client.Start_Write
           (Transfer, State, Coordinator_Token, 0,
            SMB.Bytes'(0 => 16#AA#), Status);
         SMB.Core_Client.Prepare_Next
           (Transfer, State, Packet, Used, Status);
         SMB.Core_Client.Transfer_Send_Succeeded
           (Transfer, State, Status);
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (9),
            SMB.Wire.U64 (Packet, 24), Tree_Id, Session_Id, True);
         Response (64) := 17;
         SMB.Wire.Put_U32 (Response, 68, 2);
         SMB.Wire.Sign (Response, Key);
         SMB.Core_Client.Complete_Write
           (Transfer, State, Response, Nt_Status, Status);
         Assert
           (Status /= SMB.Ok
            and then SMB.Core_Client.Transfer_Completed_Of (Transfer) = 0
            and then SMB.Core_Client.Transfer_Stage_Of (Transfer) =
              SMB.Core_Client.Transfer_Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected
            and then not SMB.Engine.Has_Pending_Request (State),
            "over-count WRITE response advanced or kept the session");
      end;

      Reconnect_Share;
      Create_Transfer_Handle;
      declare
         Transfer : SMB.Core_Client.Transfer (1);
         Packet : SMB.Bytes (0 .. 112) := (others => 0);
         Response : SMB.Bytes (0 .. 80) := (others => 0);
         Used : Natural;
      begin
         SMB.Core_Client.Start_Read
           (Transfer, State, Coordinator_Token, 0, 1, Status);
         SMB.Core_Client.Prepare_Next
           (Transfer, State, Packet, Used, Status);
         SMB.Core_Client.Transfer_Send_Succeeded
           (Transfer, State, Status);
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (8),
            SMB.Wire.U64 (Packet, 24), Tree_Id, Session_Id, True);
         Response (64) := 17;
         SMB.Wire.Put_U16 (Response, 66, 80);
         SMB.Wire.Put_U32 (Response, 68, 1);
         Response (80) := 16#AA#;
         SMB.Wire.Sign (Response, Key);
         Response (48) := Response (48) xor 1;
         SMB.Core_Client.Complete_Read
           (Transfer, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Signature_Error
            and then SMB.Core_Client.Transfer_Completed_Of (Transfer) = 0
            and then SMB.Core_Client.Transfer_Stage_Of (Transfer) =
              SMB.Core_Client.Transfer_Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected
            and then not SMB.Engine.Has_Pending_Request (State),
            "tampered transfer response advanced progress or kept the session");
      end;
      Test_Directory_Coordinator;
      Reconnect_Share;
      declare
         Metadata : SMB.Core_Client.Metadata_Operation;
         False_Metadata : SMB.Core_Client.Metadata_Operation;
         Rename_Metadata : SMB.Core_Client.Metadata_Operation;
         Error_Metadata : SMB.Core_Client.Metadata_Operation;
         Malformed_Metadata : SMB.Core_Client.Metadata_Operation;
         Bad_Signature_Metadata : SMB.Core_Client.Metadata_Operation;
         Create_Op : SMB.Core_Client.Operation;
         File_Create_Op : SMB.Core_Client.Operation;
         Signature_Create_Op : SMB.Core_Client.Operation;
         Metadata_Token : SMB.Engine.Handle_Token;
         File_Token : SMB.Engine.Handle_Token;
         Signature_Token : SMB.Engine.Handle_Token;
         Request : SMB.Bytes (0 .. 96) := (others => 0);
         Rename_Request : SMB.Bytes (3 .. 122) := (others => 0);
         Short_Request : SMB.Bytes (0 .. 95) := (others => 0);
         Response : SMB.Bytes (0 .. 71) := (others => 0);
         Metadata_Used : Natural;
         Checked_Id : SMB.Bytes (0 .. 15);
         Checked_Access : SMB.Engine.Access_Kind;
         Checked_Directory : Boolean;
         Expected_Metadata : SMB.Engine.Request_Expectation;
         Before_Metadata_State : SMB.Engine.Engine_State;
         Before_Metadata_Context : SMB.Core_Client.Metadata_State_Snapshot;
         Before_Invalid_State : SMB.Engine.Engine_State;
         Before_Invalid_Context : SMB.Core_Client.Metadata_State_Snapshot;
         Name : constant SMB.Bytes (7 .. 10) := (16#41#, 0, 16#42#, 0);
         Odd_Name : constant SMB.Bytes (4 .. 6) := (16#41#, 0, 16#42#);
      begin
         Create_Directory_Handle (State, Create_Op, Metadata_Token);
         SMB.Core_Client.Prepare_Disposition
           (Metadata, State, Metadata_Token, True, Request,
            Metadata_Used, Status);
         Expected_Metadata :=
           (Command => SMB.Core_Wire.Command_Code (17),
            Message_Id => SMB.Wire.U64 (Request, 24),
            Tree_Id => Tree_Id,
            Session_Id => Session_Id,
            Match_Tree => True,
            Match_Session => True,
            Request_Signed => True,
            Signed => True,
            Request_Amount => 0,
            Close_Token => (others => 0));
         Assert
           (Status = SMB.Ok and then Metadata_Used = 97
            and then SMB.Core_Wire.Encoded_U16 (Request, 4) = 64
            and then SMB.Core_Wire.Encoded_U16 (Request, 6) = 1
            and then SMB.Core_Wire.Encoded_U16 (Request, 12) = 17
            and then SMB.Core_Wire.Encoded_U32 (Request, 16) = 8
            and then SMB.Core_Wire.Encoded_U32 (Request, 36) = Tree_Id
            and then SMB.Core_Wire.Encoded_U64 (Request, 40) = Session_Id
            and then SMB.Core_Wire.Encoded_U16 (Request, 64) = 33
            and then Request (66) = 1 and then Request (67) = 13
            and then SMB.Core_Wire.Encoded_U32 (Request, 68) = 1
            and then SMB.Core_Wire.Encoded_U16 (Request, 72) = 96
            and then SMB.Core_Wire.Encoded_U16 (Request, 74) = 0
            and then SMB.Core_Wire.Encoded_U32 (Request, 76) = 0
            and then Request (80 .. 95) = File_Id
            and then Request (96) = 1
            and then SMB.Engine.Pending_Request_Matches
              (State, Expected_Metadata),
            "SET_INFO disposition packet");
         Assert
           (SMB.Wire.Verify_Signature
              (Request, SMB.Engine.Current_Signing_Key (State)),
            "signed SET_INFO disposition request");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (17),
            SMB.Wire.U64 (Request, 24), Tree_Id, Session_Id, True);
         Before_Metadata_State := State;
         Before_Metadata_Context :=
           SMB.Core_Client.Metadata_Snapshot_Of (Metadata);
         SMB.Core_Client.Complete_Metadata
           (Metadata, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Core_Client.Metadata_Stage_Of (Metadata) =
              SMB.Core_Client.Metadata_Prepared
            and then SMB.Engine.Has_Pending_Request (State)
            and then SMB.Engine."=" (State, Before_Metadata_State)
            and then SMB.Core_Client.Metadata_Snapshot_Of (Metadata) =
              Before_Metadata_Context,
            "SET_INFO completion before acknowledgement made progress");
         SMB.Core_Client.Metadata_Send_Succeeded
           (Metadata, State, Status);
         Assert (Status = SMB.Ok, "SET_INFO send acknowledgement");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (17),
            SMB.Wire.U64 (Request, 24), Tree_Id, Session_Id, True);
         Response (64) := 2;
         SMB.Wire.Sign (Response, Key);
         SMB.Core_Client.Complete_Metadata
           (Metadata, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status = SMB.Success
            and then SMB.Core_Client.Metadata_Stage_Of (Metadata) =
              SMB.Core_Client.Metadata_Finished
            and then not SMB.Engine.Has_Pending_Request (State)
            and then not SMB.Engine.Has_Validated_Response (State),
            "SET_INFO completion status and receipt");
         SMB.Engine.Validate_Handle
           (State, Metadata_Token, False, False, Checked_Id,
            Checked_Access, Checked_Directory, Status);
         Assert
           (Status = SMB.Ok and then Checked_Id = File_Id
            and then Checked_Directory,
            "SET_INFO completion preserves handle");
         Before_Metadata_State := State;
         Before_Metadata_Context :=
           SMB.Core_Client.Metadata_Snapshot_Of (Metadata);
         SMB.Core_Client.Complete_Metadata
           (Metadata, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Core_Client.Metadata_Stage_Of (Metadata) =
              SMB.Core_Client.Metadata_Finished
            and then SMB.Engine."=" (State, Before_Metadata_State)
            and then SMB.Core_Client.Metadata_Snapshot_Of (Metadata) =
              Before_Metadata_Context,
            "SET_INFO duplicate completion made progress");
         SMB.Core_Client.Prepare_Disposition
           (False_Metadata, State, Metadata_Token, False, Request,
            Metadata_Used, Status);
         Assert (Status = SMB.Ok and then Request (96) = 0,
                 "SET_INFO disposition false");
         SMB.Core_Client.Metadata_Send_Succeeded
           (False_Metadata, State, Status);
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (17),
            SMB.Wire.U64 (Request, 24), Tree_Id, Session_Id, True);
         Response (64) := 2;
         SMB.Wire.Sign (Response, Key);
         SMB.Core_Client.Complete_Metadata
           (False_Metadata, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status = SMB.Success
            and then not SMB.Engine.Has_Pending_Request (State)
            and then not SMB.Engine.Has_Validated_Response (State),
            "SET_INFO false disposition completion");
         SMB.Core_Client.Prepare_Rename
           (Rename_Metadata, State, Metadata_Token, Name, Rename_Request,
            Metadata_Used, Status);
         Expected_Metadata :=
           (Command => SMB.Core_Wire.Command_Code (17),
            Message_Id => SMB.Wire.U64 (Rename_Request, 24),
            Tree_Id => Tree_Id,
            Session_Id => Session_Id,
            Match_Tree => True,
            Match_Session => True,
            Request_Signed => True,
            Signed => True,
            Request_Amount => 0,
            Close_Token => (others => 0));
         Assert
            (Status = SMB.Ok and then Metadata_Used = 120
            and then SMB.Core_Wire.Encoded_U16 (Rename_Request, 4) = 64
            and then SMB.Core_Wire.Encoded_U16 (Rename_Request, 6) = 1
            and then SMB.Core_Wire.Encoded_U16 (Rename_Request, 12) = 17
            and then SMB.Core_Wire.Encoded_U32 (Rename_Request, 16) = 8
            and then SMB.Core_Wire.Encoded_U32 (Rename_Request, 36) = Tree_Id
            and then SMB.Core_Wire.Encoded_U64 (Rename_Request, 40) =
              Session_Id
            and then SMB.Core_Wire.Encoded_U16 (Rename_Request, 64) = 33
            and then Rename_Request (Rename_Request'First + 66) = 1
            and then Rename_Request (Rename_Request'First + 67) = 10
            and then SMB.Core_Wire.Encoded_U32 (Rename_Request, 68) = 24
            and then SMB.Core_Wire.Encoded_U16 (Rename_Request, 72) = 96
            and then SMB.Core_Wire.Encoded_U16 (Rename_Request, 74) = 0
            and then SMB.Core_Wire.Encoded_U32 (Rename_Request, 76) = 0
            and then Rename_Request (Rename_Request'First + 80 ..
                                     Rename_Request'First + 95) = File_Id
            and then Rename_Request (Rename_Request'First + 96) = 0
            and then Rename_Request (Rename_Request'First + 97) = 0
            and then SMB.Core_Wire.Encoded_U16 (Rename_Request, 98) = 0
            and then SMB.Core_Wire.Encoded_U64 (Rename_Request, 104) = 0
            and then Rename_Request (Rename_Request'First + 66) = 1
            and then SMB.Wire.U32 (Rename_Request, 112) = 4
            and then Rename_Request (Rename_Request'First + 116 ..
                                     Rename_Request'First + 119) = Name
            and then SMB.Engine.Pending_Request_Matches
              (State, Expected_Metadata),
            "SET_INFO rename body and nonzero bounds");
         Assert
           (SMB.Wire.Verify_Signature
              (Rename_Request, SMB.Engine.Current_Signing_Key (State)),
            "signed SET_INFO rename request");
         SMB.Core_Client.Metadata_Send_Succeeded
           (Rename_Metadata, State, Status);
         Assert (Status = SMB.Ok, "SET_INFO rename acknowledgement");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (17),
            SMB.Wire.U64 (Rename_Request, 24), Tree_Id, Session_Id, True);
         Response (64) := 2;
         SMB.Wire.Sign (Response, Key);
         SMB.Core_Client.Complete_Metadata
           (Rename_Metadata, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status = SMB.Success
            and then SMB.Core_Client.Metadata_Stage_Of (Rename_Metadata) =
              SMB.Core_Client.Metadata_Finished,
            "SET_INFO rename completion");

         Create_Directory_Handle
           (State, File_Create_Op, File_Token, Is_Directory => False);
         SMB.Core_Client.Prepare_Disposition
           (Error_Metadata, State, File_Token, True, Request,
            Metadata_Used, Status);
         Assert (Status = SMB.Ok, "SET_INFO file disposition preparation");
         SMB.Core_Client.Metadata_Send_Succeeded
           (Error_Metadata, State, Status);
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (17),
            SMB.Wire.U64 (Request, 24), Tree_Id, Session_Id, True);
         SMB.Wire.Put_U32 (Response, 8, SMB.Status_Access_Denied);
         Response (64) := 9;
         SMB.Wire.Sign (Response, Key);
         SMB.Core_Client.Complete_Metadata
           (Error_Metadata, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status = SMB.Status_Access_Denied
            and then SMB.Core_Client.Metadata_Stage_Of (Error_Metadata) =
              SMB.Core_Client.Metadata_Finished
            and then not SMB.Engine.Has_Pending_Request (State)
            and then not SMB.Engine.Has_Validated_Response (State),
            "SET_INFO signed NTSTATUS preserves usable state");
         SMB.Engine.Validate_Handle
           (State, File_Token, False, False, Checked_Id,
            Checked_Access, Checked_Directory, Status);
         Assert
           (Status = SMB.Ok and then Checked_Id = File_Id
            and then Checked_Access = SMB.Engine.Read_Only
            and then not Checked_Directory,
            "SET_INFO file handle remains usable after NTSTATUS");

         Before_Invalid_State := State;
         Before_Invalid_Context :=
           SMB.Core_Client.Metadata_Snapshot_Of (Malformed_Metadata);
         SMB.Core_Client.Prepare_Rename
           (Malformed_Metadata, State, File_Token, Odd_Name, Rename_Request,
            Metadata_Used, Status);
         Assert
           (Status = SMB.Invalid_Length and then Metadata_Used = 0
            and then SMB.Core_Client.Metadata_Stage_Of (Malformed_Metadata) =
              SMB.Core_Client.Metadata_Idle
            and then SMB.Engine."=" (State, Before_Invalid_State)
            and then SMB.Core_Client.Metadata_Snapshot_Of
              (Malformed_Metadata) = Before_Invalid_Context,
            "SET_INFO odd rename rejected without progress");
         SMB.Core_Client.Prepare_Rename
           (Malformed_Metadata, State, File_Token, SMB.Bytes'(1 .. 0 => 0),
            Rename_Request, Metadata_Used, Status);
         Assert
           (Status = SMB.Invalid_Length and then Metadata_Used = 0
            and then SMB.Engine."=" (State, Before_Invalid_State)
            and then SMB.Core_Client.Metadata_Snapshot_Of
              (Malformed_Metadata) = Before_Invalid_Context,
                 "SET_INFO empty rename rejected");
         SMB.Core_Client.Prepare_Rename
           (Malformed_Metadata, State, File_Token, Name, Short_Request,
            Metadata_Used, Status);
         Assert
           (Status = SMB.Resource_Limit and then Metadata_Used = 0
            and then SMB.Engine."=" (State, Before_Invalid_State)
            and then SMB.Core_Client.Metadata_Snapshot_Of
              (Malformed_Metadata) = Before_Invalid_Context,
            "SET_INFO short output rejected");
         SMB.Core_Client.Prepare_Rename
           (Malformed_Metadata, State, File_Token, Name, Rename_Request,
            Metadata_Used, Status);
         SMB.Core_Client.Metadata_Send_Succeeded
           (Malformed_Metadata, State, Status);
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (17),
            SMB.Wire.U64 (Rename_Request, 24), Tree_Id, Session_Id, True);
         Response (64) := 3;
         SMB.Wire.Sign (Response, Key);
         SMB.Core_Client.Complete_Metadata
           (Malformed_Metadata, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Invalid_Protocol
            and then SMB.Core_Client.Metadata_Stage_Of (Malformed_Metadata) =
              SMB.Core_Client.Metadata_Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected,
            "SET_INFO malformed signed success invalidated state");
         SMB.Core_Client.Prepare_Disposition
           (Malformed_Metadata, State, File_Token, False, Request,
            Metadata_Used, Status);
         Assert (Status = SMB.Invalid_State_Status and then Metadata_Used = 0,
                 "SET_INFO failed operation cannot be retried");

         Reconnect_Share;
         Create_Directory_Handle
           (State, Signature_Create_Op, Signature_Token,
            Is_Directory => False);
         SMB.Core_Client.Prepare_Disposition
           (Bad_Signature_Metadata, State, Signature_Token, False, Request,
            Metadata_Used, Status);
         SMB.Core_Client.Metadata_Send_Succeeded
           (Bad_Signature_Metadata, State, Status);
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (17),
            SMB.Wire.U64 (Request, 24), Tree_Id, Session_Id, True);
         Response (64) := 2;
         SMB.Wire.Sign (Response, Key);
         Response (48) := Response (48) xor 1;
         SMB.Core_Client.Complete_Metadata
           (Bad_Signature_Metadata, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Signature_Error
            and then SMB.Core_Client.Metadata_Stage_Of
              (Bad_Signature_Metadata) = SMB.Core_Client.Metadata_Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected,
            "SET_INFO tampered signature did not invalidate state");
         SMB.Core_Client.Prepare_Disposition
           (Bad_Signature_Metadata, State, Signature_Token, False, Request,
            Metadata_Used, Status);
         Assert
           (Status = SMB.Invalid_State_Status and then Metadata_Used = 0,
            "SET_INFO signature failure cannot be retried");
      end;
      declare
         Owner_Create : SMB.Core_Client.Operation;
         Foreign_Create : SMB.Core_Client.Operation;
         Owner_Metadata : SMB.Core_Client.Metadata_Operation;
         Foreign_Metadata : SMB.Core_Client.Metadata_Operation;
         Owner_Token : SMB.Engine.Handle_Token;
         Foreign_Metadata_Token : SMB.Engine.Handle_Token;
         Owner_Packet : SMB.Bytes (0 .. 96) := (others => 0);
         Foreign_Packet : SMB.Bytes (0 .. 96) := (others => 0);
         Metadata_Response : SMB.Bytes (0 .. 71) := (others => 0);
         Owner_Used : Natural;
         Foreign_Used : Natural;
         Owner_State_Before : SMB.Engine.Engine_State;
         Foreign_State_Before : SMB.Engine.Engine_State;
         Owner_Metadata_Before : SMB.Core_Client.Metadata_State_Snapshot;
         Foreign_Metadata_Before : SMB.Core_Client.Metadata_State_Snapshot;
         Owner_Id_Before : SMB.QWord;
         Owner_Epoch_Before : SMB.QWord;
      begin
         Reconnect_Share (State);
         Reconnect_Share (Foreign_State);
         Create_Directory_Handle
           (State, Owner_Create, Owner_Token, Is_Directory => False);
         Create_Directory_Handle
           (Foreign_State, Foreign_Create, Foreign_Metadata_Token,
            Is_Directory => False);
         SMB.Core_Client.Prepare_Disposition
           (Owner_Metadata, State, Owner_Token, False, Owner_Packet,
            Owner_Used, Status);
         Assert (Status = SMB.Ok, "SET_INFO owner context prepared");
         SMB.Core_Client.Prepare_Disposition
           (Foreign_Metadata, Foreign_State, Foreign_Metadata_Token, False,
            Foreign_Packet, Foreign_Used, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Wire.U64 (Owner_Packet, 24) =
              SMB.Wire.U64 (Foreign_Packet, 24),
            "SET_INFO foreign contexts have colliding request ids");
         Owner_State_Before := State;
         Foreign_State_Before := Foreign_State;
         Owner_Metadata_Before :=
           SMB.Core_Client.Metadata_Snapshot_Of (Owner_Metadata);
         Foreign_Metadata_Before :=
           SMB.Core_Client.Metadata_Snapshot_Of (Foreign_Metadata);
         SMB.Core_Client.Metadata_Send_Succeeded
           (Owner_Metadata, Foreign_State, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine."=" (State, Owner_State_Before)
            and then SMB.Engine."=" (Foreign_State, Foreign_State_Before)
            and then SMB.Core_Client.Metadata_Snapshot_Of (Owner_Metadata) =
              Owner_Metadata_Before
            and then SMB.Core_Client.Metadata_Snapshot_Of
              (Foreign_Metadata) = Foreign_Metadata_Before,
            "SET_INFO foreign send context caused no damage");

         SMB.Core_Client.Metadata_Send_Succeeded
           (Owner_Metadata, State, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Core_Client.Metadata_Stage_Of (Owner_Metadata) =
              SMB.Core_Client.Metadata_Sent,
            "SET_INFO owner context acknowledged");
         Prepare_Response
           (Metadata_Response, SMB.Core_Wire.Command_Code (17),
            SMB.Wire.U64 (Owner_Packet, 24), Tree_Id, Session_Id, True);
         Metadata_Response (64) := 2;
         SMB.Wire.Sign (Metadata_Response, Key);
         Owner_State_Before := State;
         Foreign_State_Before := Foreign_State;
         Owner_Metadata_Before :=
           SMB.Core_Client.Metadata_Snapshot_Of (Owner_Metadata);
         Foreign_Metadata_Before :=
           SMB.Core_Client.Metadata_Snapshot_Of (Foreign_Metadata);
         SMB.Core_Client.Complete_Metadata
           (Owner_Metadata, Foreign_State, Metadata_Response, Nt_Status,
            Status);
         Assert
           (Status = SMB.Invalid_State_Status and then Nt_Status = 0
            and then SMB.Engine."=" (State, Owner_State_Before)
            and then SMB.Engine."=" (Foreign_State, Foreign_State_Before)
            and then SMB.Core_Client.Metadata_Snapshot_Of (Owner_Metadata) =
              Owner_Metadata_Before
            and then SMB.Core_Client.Metadata_Snapshot_Of
              (Foreign_Metadata) = Foreign_Metadata_Before,
            "SET_INFO foreign completion context caused no damage");
         SMB.Core_Client.Abort_Metadata
           (Owner_Metadata, Foreign_State, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine."=" (State, Owner_State_Before)
            and then SMB.Engine."=" (Foreign_State, Foreign_State_Before)
            and then SMB.Core_Client.Metadata_Snapshot_Of (Owner_Metadata) =
              Owner_Metadata_Before
            and then SMB.Core_Client.Metadata_Snapshot_Of
              (Foreign_Metadata) = Foreign_Metadata_Before,
            "SET_INFO foreign abort context caused no damage");

         SMB.Engine.Accept_Response
           (State, Metadata_Response, Nt_Status, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Engine.Has_Validated_Response (State)
            and then not SMB.Engine.Has_Pending_Request (State),
            "SET_INFO receipt-preservation fixture response accepted");
         Owner_State_Before := State;
         Owner_Metadata_Before :=
           SMB.Core_Client.Metadata_Snapshot_Of (Owner_Metadata);
         SMB.Core_Client.Abort_Metadata
           (Owner_Metadata, State, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine."=" (State, Owner_State_Before)
            and then SMB.Core_Client.Metadata_Snapshot_Of (Owner_Metadata) =
              Owner_Metadata_Before,
            "SET_INFO abort preserves unrelated validated receipt");
         SMB.Engine.Discard_Response_Receipt (State, Status);
         Assert
           (Status = SMB.Ok
            and then not SMB.Engine.Has_Validated_Response (State),
            "SET_INFO receipt-preservation fixture receipt discarded");

         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (17), True, True,
            Message_Id, Expected, Status);
         Assert
           (Status = SMB.Ok
            and then Message_Id /= SMB.Wire.U64 (Owner_Packet, 24),
            "SET_INFO unrelated request has a different message id");
         Metadata_Response := (others => 0);
         Prepare_Response
           (Metadata_Response, SMB.Core_Wire.Command_Code (17),
            SMB.Wire.U64 (Owner_Packet, 24), Tree_Id, Session_Id, True);
         Metadata_Response (64) := 2;
         SMB.Wire.Sign (Metadata_Response, Key);
         Owner_State_Before := State;
         Owner_Metadata_Before :=
           SMB.Core_Client.Metadata_Snapshot_Of (Owner_Metadata);
         SMB.Core_Client.Complete_Metadata
           (Owner_Metadata, State, Metadata_Response, Nt_Status, Status);
         Assert
           (Status = SMB.Invalid_State_Status and then Nt_Status = 0
            and then SMB.Engine."=" (State, Owner_State_Before)
            and then SMB.Core_Client.Metadata_Snapshot_Of (Owner_Metadata) =
              Owner_Metadata_Before,
            "SET_INFO completion preserves unrelated pending request");
         SMB.Core_Client.Abort_Metadata
           (Owner_Metadata, State, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine."=" (State, Owner_State_Before)
            and then SMB.Core_Client.Metadata_Snapshot_Of (Owner_Metadata) =
              Owner_Metadata_Before,
            "SET_INFO abort preserves unrelated pending request");

         Owner_Id_Before := SMB.Engine.Current_Owner_Id (State);
         Owner_Epoch_Before := SMB.Engine.Current_Epoch (State);
         SMB.Engine.Invalidate (State, Status);
         Assert (Status = SMB.Ok, "SET_INFO epoch fixture invalidated");
         Reconnect_Share (State, Initialize_State => False);
         Assert
           (SMB.Engine.Current_Owner_Id (State) = Owner_Id_Before
            and then SMB.Engine.Current_Epoch (State) /= Owner_Epoch_Before,
            "SET_INFO same owner reconnected in a new epoch");
         declare
            Fresh_Create : SMB.Core_Client.Operation;
            Fresh_Metadata : SMB.Core_Client.Metadata_Operation;
            Fresh_Token : SMB.Engine.Handle_Token;
            Fresh_Packet : SMB.Bytes (0 .. 96) := (others => 0);
            Fresh_Used : Natural;
            Fresh_State_Before : SMB.Engine.Engine_State;
            Fresh_Metadata_Before :
              SMB.Core_Client.Metadata_State_Snapshot;
            Old_Metadata_Context : constant
              SMB.Core_Client.Metadata_State_Snapshot :=
                SMB.Core_Client.Metadata_Snapshot_Of (Owner_Metadata);
         begin
            Create_Directory_Handle
              (State, Fresh_Create, Fresh_Token, Is_Directory => False);
            SMB.Core_Client.Prepare_Disposition
              (Fresh_Metadata, State, Fresh_Token, False, Fresh_Packet,
               Fresh_Used, Status);
            Assert
              (Status = SMB.Ok and then Fresh_Used = 97
               and then SMB.Wire.U64 (Fresh_Packet, 24) =
                 SMB.Wire.U64 (Owner_Packet, 24)
               and then SMB.Engine.Current_Owner_Id (State) = Owner_Id_Before
               and then SMB.Engine.Current_Epoch (State) /= Owner_Epoch_Before
               and then Old_Metadata_Context.Stage =
                 SMB.Core_Client.Metadata_Sent
               and then Old_Metadata_Context.Owner = Owner_Id_Before
               and then Old_Metadata_Context.Epoch = Owner_Epoch_Before
               and then SMB.Engine.Pending_Request_Matches
                 (State, Old_Metadata_Context.Expected),
              "SET_INFO stale metadata collides with live wire context");
            Metadata_Response := (others => 0);
            Prepare_Response
              (Metadata_Response, SMB.Core_Wire.Command_Code (17),
               SMB.Wire.U64 (Owner_Packet, 24), Tree_Id, Session_Id, True);
            Metadata_Response (64) := 2;
            SMB.Wire.Sign (Metadata_Response, Key);
            Fresh_State_Before := State;
            Fresh_Metadata_Before :=
              SMB.Core_Client.Metadata_Snapshot_Of (Fresh_Metadata);
            SMB.Core_Client.Complete_Metadata
              (Owner_Metadata, State, Metadata_Response, Nt_Status, Status);
            Assert
              (Status = SMB.Invalid_State_Status and then Nt_Status = 0
               and then SMB.Engine."=" (State, Fresh_State_Before)
               and then SMB.Core_Client.Metadata_Snapshot_Of
                 (Fresh_Metadata) = Fresh_Metadata_Before
               and then SMB.Core_Client.Metadata_Snapshot_Of
                 (Owner_Metadata) = Old_Metadata_Context,
              "SET_INFO stale completion preserves live new-epoch operation");
            SMB.Core_Client.Abort_Metadata
              (Owner_Metadata, State, Status);
            Assert
              (Status = SMB.Invalid_State_Status
               and then SMB.Engine."=" (State, Fresh_State_Before)
               and then SMB.Core_Client.Metadata_Snapshot_Of
                 (Fresh_Metadata) = Fresh_Metadata_Before
               and then SMB.Core_Client.Metadata_Snapshot_Of
                 (Owner_Metadata) = Old_Metadata_Context,
              "SET_INFO stale abort preserves live new-epoch operation");
         end;
         SMB.Engine.Invalidate (State, Status);
         Assert (Status = SMB.Ok, "SET_INFO state cleanup");
         SMB.Engine.Invalidate (Foreign_State, Status);
         Assert (Status = SMB.Ok, "SET_INFO foreign state cleanup");
      end;
   end Test_Engine_Receipts;

   procedure Test_Engine_Malformed_Close is
      State : SMB.Engine.Engine_State;
      Status : SMB.Core_Status;
      Nt_Status : SMB.DWord;
      Message_Id : SMB.QWord;
      Expected : SMB.Engine.Request_Expectation;
      Token : SMB.Engine.Handle_Token;
      Session_Id : constant SMB.QWord := 16#1234#;
      Tree_Id : constant SMB.DWord := 16#1020_3040#;
      Key : constant SMB.Bytes (0 .. 15) :=
        (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
      File_Id : constant SMB.Bytes (0 .. 15) := (others => 16#22#);
      Final_Token : constant SMB.Bytes (0 .. 28) :=
        (16#A1#, 16#1B#, 16#30#, 16#19#,
         16#A0#, 16#03#, 16#0A#, 16#01#, 0,
         16#A3#, 16#12#, 16#04#, 16#10#,
         1, 0, 0, 0, 16#0A#, 16#FB#, 16#34#, 16#90#,
         16#3A#, 16#3E#, 16#4E#, 16#54#, 0, 0, 0, 0);

      procedure Prepare_Response
        (Packet : in out SMB.Bytes;
         Command : SMB.Core_Wire.Command_Code;
         Reply_Id : SMB.QWord;
         Reply_Tree_Id : SMB.DWord;
         Reply_Session_Id : SMB.QWord;
         Signed : Boolean) is
      begin
         SMB.Wire.Initialize_Header
           (Packet, SMB.Word (Command), Reply_Id, Reply_Tree_Id,
            Reply_Session_Id);
         SMB.Wire.Put_U32 (Packet, 16, (if Signed then 9 else 1));
      end Prepare_Response;
   begin
      SMB.Engine.Initialize (State, Status);
      Assert (Status = SMB.Ok, "malformed CLOSE engine initialization");
      SMB.Engine.Mark_Connected (State, Status);
      Assert (Status = SMB.Ok, "malformed CLOSE transport transition");

      declare
         Response : SMB.Bytes (0 .. 127) := (others => 0);
      begin
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (0), False, False,
            Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE begin negotiate");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (0), Message_Id, 0, 0, False);
         Response (64) := 65;
         Response (66) := 1;
         Response (68) := 16#10#;
         Response (69) := 2;
         Response (96) := 1;
         Response (100) := 1;
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE accept negotiate");
         SMB.Engine.Mark_Negotiated (State, 1, 1, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE negotiate transition");
      end;

      declare
         Response : SMB.Bytes (0 .. 71) := (others => 0);
      begin
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (1), False, False,
            Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE begin challenge");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (1), Message_Id,
            0, Session_Id, False);
         SMB.Wire.Put_U32
           (Response, 8, SMB.Status_More_Processing_Required);
         Response (64) := 9;
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE accept challenge");
         SMB.Engine.Install_Session_Key (State, Session_Id, Key, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE install session key");
      end;

      declare
         Response : SMB.Bytes (0 .. 100) := (others => 0);
      begin
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (1), False, True,
            Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE begin final setup");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (1), Message_Id,
            0, Session_Id, True);
         Response (64) := 9;
         SMB.Wire.Put_U16 (Response, 68, 72);
         SMB.Wire.Put_U16 (Response, 70, Final_Token'Length);
         for Index in Final_Token'Range loop
            Response (72 + Index) := Final_Token (Index);
         end loop;
         SMB.Wire.Sign (Response, Key);
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE accept final setup");
         SMB.Engine.Mark_Authenticated (State, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE authenticate");
      end;

      declare
         Response : SMB.Bytes (0 .. 79) := (others => 0);
      begin
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (3), True, True,
            Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE begin tree connect");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (3), Message_Id,
            Tree_Id, Session_Id, True);
         Response (64) := 16;
         Response (66) := 1;
         SMB.Wire.Sign (Response, Key);
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE accept tree connect");
         SMB.Engine.Mark_Share_Connected (State, Tree_Id, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE share transition");
      end;

      declare
         Response : SMB.Bytes (0 .. 151) := (others => 0);
      begin
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (5), True, True,
            Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE begin CREATE");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (5), Message_Id,
            Tree_Id, Session_Id, True);
         Response (64) := 89;
         Response (128 .. 143) := File_Id;
         SMB.Wire.Sign (Response, Key);
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE accept CREATE");
         SMB.Engine.Register_Handle
           (State, File_Id, SMB.Engine.Read_Write, False, Token, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE register handle");
      end;

      declare
         Response : SMB.Bytes (0 .. 123) := (others => 0);
      begin
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (6), True, True,
            Message_Id, Expected, Status, Close_Token => Token);
         Assert (Status = SMB.Ok, "malformed CLOSE begin close");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (6), Message_Id,
            Tree_Id, Session_Id, True);
         Response (64) := 60;
         Response (68) := 1;
         SMB.Wire.Sign (Response, Key);
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert
           (Status /= SMB.Ok
            and then Nt_Status = 0
            and then SMB.Engine.Current_Phase (State) = SMB.Engine.Disconnected
            and then not SMB.Engine.Has_Pending_Request (State)
            and then not SMB.Engine.Has_Validated_Response (State)
            and then not SMB.Engine.Has_Open_Handles (State)
            and then not SMB.Engine.Has_Signing_Key (State)
            and then SMB.Engine.Signing_Key_Is_Zero (State),
            "signed malformed CLOSE did not fully invalidate Engine");
      end;
   end Test_Engine_Malformed_Close;

   procedure Test_Text_And_Wire is
      UTF8 : constant String :=
        Character'Val (16#E6#) & Character'Val (16#97#)
        & Character'Val (16#A5#) & Character'Val (16#F0#)
        & Character'Val (16#9F#) & Character'Val (16#98#)
        & Character'Val (16#80#);
      UTF16 : constant SMB.Bytes := SMB.Text.To_UTF16LE (UTF8);
      Packet : SMB.Bytes (0 .. 63) := (others => 0);
      Tree_Packet : SMB.Bytes (0 .. 63) := (others => 0);
      Key : constant SMB.Bytes (0 .. 15) := (others => 16#11#);
   begin
      Assert (UTF16'Length = 6, "UTF-16 surrogate conversion");
      Assert (SMB.Text.From_UTF16LE (UTF16) = UTF8, "UTF-16 round trip");
      SMB.Wire.Initialize_Header (Packet, SMB.Wire.Read_Command, 7);
      SMB.Wire.Put_U16 (Packet, 6, 1);
      SMB.Wire.Put_U32 (Packet, 16, 1);
      Assert (SMB.Wire.U64 (Packet, 24) = 7, "SMB message id");
      SMB.Wire.Initialize_Header
        (Tree_Packet, SMB.Wire.Read_Command, 11, 16#1122_3344#);
      Assert (SMB.Wire.U32 (Tree_Packet, 36) = 16#1122_3344#,
              "SMB tree id wire offset");
      Assert (SMB.Wire.U32 (Tree_Packet, 32) = 0,
              "SMB process id must not contain tree id");
      Assert (SMB.Wire.Validate_Header
        (Packet,
         (Command => SMB.Wire.Read_Command, Message_Id => 7,
          Tree_Id => 0, Session_Id => 0, Signed => False)) = 0,
        "SMB response header");
      SMB.Wire.Sign (Packet, Key);
      Assert (SMB.Wire.Verify_Signature (Packet, Key), "SMB signature");
      Packet (10) := Packet (10) xor 1;
      Assert (not SMB.Wire.Verify_Signature (Packet, Key),
              "tampered SMB signature");
      begin
         declare
            Ignored : constant SMB.Word := SMB.Wire.U16 (Packet, 63);
         begin
            Assert (Ignored = 0, "unreachable malformed wire value");
         end;
         raise Program_Error with "wire bounds check did not fire";
      exception
         when SMB.Protocol_Error => null;
      end;
      begin
         declare
            Ignored_Status : constant SMB.DWord := SMB.Wire.Validate_Header
              (Packet,
               (Command => SMB.Wire.Read_Command, Message_Id => 7,
                Tree_Id => 0, Session_Id => 0, Signed => True));
         begin
            Assert (Ignored_Status = 0, "unreachable unsigned SMB response");
         end;
         raise Program_Error with "unsigned SMB response was accepted";
      exception
         when SMB.Protocol_Error => null;
      end;
      begin
         declare
            Invalid_UTF8 : constant SMB.Bytes := SMB.Text.To_UTF16LE
              (Character'Val (16#C0#) & Character'Val (16#AF#));
         begin
            Assert (Invalid_UTF8'Length = 0, "unreachable invalid UTF-8");
         end;
         raise Program_Error with "overlong UTF-8 was accepted";
      exception
         when SMB.Protocol_Error => null;
      end;
      begin
         declare
            Invalid_UTF16 : constant String :=
              SMB.Text.From_UTF16LE (Hex ("00d8"));
         begin
            Assert (Invalid_UTF16'Length = 0, "unreachable UTF-16 surrogate");
         end;
         raise Program_Error with "unpaired UTF-16 surrogate was accepted";
      exception
         when SMB.Protocol_Error => null;
      end;
      begin
         declare
            Non_Ascii_User : constant String :=
              SMB.Text.NTLM_Username
                (Character'Val (16#E3#) & Character'Val (16#81#)
                 & Character'Val (16#82#));
         begin
            Assert (Non_Ascii_User'Length = 0, "unreachable NTLM username");
         end;
         raise Program_Error with "non-ASCII NTLM username was accepted";
      exception
         when SMB.Authentication_Error => null;
      end;
      declare
         Token : constant SMB.Bytes := SMB.NTLM.Negotiate_Token;
      begin
         Assert (Token'Length > 0, "SPNEGO token");
      end;
      declare
         Nonce : constant SMB.Bytes (0 .. 7) := (others => 0);
         Empty_Token : constant SMB.Bytes := SMB.Bytes'(1 .. 0 => 0);
      begin
         begin
            declare
               Invalid_Challenge : constant SMB.NTLM.Authentication_Result :=
                 SMB.NTLM.Authenticate
                   ("User", "Password", "Domain", Nonce, Empty_Token);
            begin
               Assert
                 (Invalid_Challenge.Security_Token'Length = 0,
                  "unreachable malformed SPNEGO token");
            end;
            raise Program_Error with "malformed SPNEGO token was accepted";
         exception
            when SMB.Protocol_Error => null;
         end;
      end;
   end Test_Text_And_Wire;
begin
   Test_Crypto;
   Test_Framing;
   Test_Core_Wire;
   Test_NTLM_Authenticate;
   Test_Core_Client_Authentication;
   Test_Final_Spnego;
   Test_Core_Protocol;
   Test_Engine_Malformed_Close;
   Test_Engine_Receipts;
   Test_Text_And_Wire;
   Ada.Text_IO.Put_Line ("AdaSMB unit tests passed");
end Test_Suite;
