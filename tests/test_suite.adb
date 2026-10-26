with Ada.Text_IO;
with SMB;
with SMB.Core_Auth;
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
   use type SMB.Engine.Phase;
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
      Chunk : Natural;
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
      State : SMB.Engine.Engine_State;
      Status : SMB.Core_Status;
      Nt_Status : SMB.DWord;
      Message_Id : SMB.QWord;
      Expected : SMB.Engine.Request_Expectation;
      Token : SMB.Engine.Handle_Token := (others => 0);
      File_Id : constant SMB.Bytes (0 .. 15) := (others => 0);
      Wrong_File_Id : constant SMB.Bytes (0 .. 15) := (others => 1);
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
   Test_NTLM_Authenticate;
   Test_Final_Spnego;
   Test_Core_Protocol;
   Test_Engine_Malformed_Close;
   Test_Engine_Receipts;
   Test_Text_And_Wire;
   Ada.Text_IO.Put_Line ("AdaSMB unit tests passed");
end Test_Suite;
