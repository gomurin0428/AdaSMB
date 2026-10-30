with SMB.Crypto;

package SMB.Core_NTLM is
   pragma SPARK_Mode (On);
   use type SMB.Byte;

   function Challenge_Slice_Valid
     (Token : SMB.Bytes; Offset, Length : Natural) return Boolean is
     (Offset <= Token'Length
      and then Length <= Token'Length - Offset
      and then Length >= 48
      and then Token (Token'First + Offset .. Token'First + Offset + 11) =
        SMB.Bytes'(16#4E#, 16#54#, 16#4C#, 16#4D#, 16#53#, 16#53#,
                   16#50#, 0, 2, 0, 0, 0))
   with Ghost, Pre => Token'Length <= 65_535;

   function Signing_Magic (From_Server : Boolean) return String is
     ((if From_Server then
         "session key to server-to-client signing key magic constant"
       else "session key to client-to-server signing key magic constant")
      & Character'Val (0));

   function Signing_Key_Material
     (Session_Key : SMB.Crypto.Digest_128;
      From_Server : Boolean) return SMB.Bytes
   with Post =>
     Signing_Key_Material'Result'First = 0
     and then Signing_Key_Material'Result'Length =
       16 + Signing_Magic (From_Server)'Length
     and then Signing_Key_Material'Result (0 .. 15) = Session_Key
     and then
       (for all I in Signing_Magic (From_Server)'Range =>
          Signing_Key_Material'Result
            (16 + I - Signing_Magic (From_Server)'First) =
              SMB.Byte (Character'Pos (Signing_Magic (From_Server) (I))));

   --  Sequence number zero followed by the DER NTLM mechanism list.
   Mechanism_List_Signature_Input : constant SMB.Bytes (0 .. 17) :=
     (0, 0, 0, 0, 16#30#, 16#0C#, 16#06#, 16#0A#,
      16#2B#, 16#06#, 16#01#, 16#04#, 16#01#,
      16#82#, 16#37#, 16#02#, 16#02#, 16#0A#);

   function Mechanism_List_MIC
     (Session_Key : SMB.Crypto.Digest_128;
      From_Server : Boolean) return SMB.Crypto.Digest_128
   with Post =>
     Mechanism_List_MIC'Result (0 .. 3) = SMB.Bytes'(1, 0, 0, 0)
     and then Mechanism_List_MIC'Result (4 .. 11) =
       SMB.Crypto.HMAC_MD5
         (SMB.Crypto.MD5 (Signing_Key_Material (Session_Key, From_Server)),
          Mechanism_List_Signature_Input) (0 .. 7)
     and then Mechanism_List_MIC'Result (12 .. 15) = SMB.Bytes'(0, 0, 0, 0);

   procedure Extract_Challenge
     (Token : SMB.Bytes;
      Type2_Offset : out Natural;
      Type2_Length : out Natural;
      Status : out SMB.Core_Status)
   with Pre => Token'Length <= 65_535,
     Post =>
       Type2_Offset <= Token'Length
       and then Type2_Length <= Token'Length - Type2_Offset
       and then (if Status = SMB.Ok then
         Challenge_Slice_Valid (Token, Type2_Offset, Type2_Length)
         else Type2_Offset = 0 and then Type2_Length = 0);

   -- Keep the potentially short-circuiting equality oracle proof-only.
   pragma Assertion_Policy (Post => Ignore);
   procedure Validate_Final_Token
     (Token : SMB.Bytes;
      Status : out SMB.Core_Status;
      Expected_MIC : SMB.Bytes := (1 .. 0 => 0))
   with Pre => Token'Length <= SMB.Maximum_Frame_Size
     and Expected_MIC'Length <= 16,
     Post =>
       (if Token'Length = 0 then
          Status = (if Expected_MIC'Length = 0 then SMB.Ok
                    else SMB.Signature_Error))
       and then
         (if Status = SMB.Ok and then Expected_MIC'Length /= 0 then
            Expected_MIC'Length = 16
            and then Token'Length >= 16
            and then Token (Token'Last - 15 .. Token'Last) = Expected_MIC);
end SMB.Core_NTLM;
