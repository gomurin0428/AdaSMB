with SMB.Crypto;

package SMB.Core_NTLM is
   pragma SPARK_Mode (On);

   function Challenge_Slice_Valid
     (Token : SMB.Bytes; Offset, Length : Natural) return Boolean is
     (Offset <= Token'Length
      and then Length <= Token'Length - Offset
      and then Length >= 48
      and then Token (Token'First + Offset .. Token'First + Offset + 11) =
        SMB.Bytes'(16#4E#, 16#54#, 16#4C#, 16#4D#, 16#53#, 16#53#,
                   16#50#, 0, 2, 0, 0, 0))
   with Ghost, Pre => Token'Length <= 65_535;

   function Mechanism_List_MIC
     (Session_Key : SMB.Crypto.Digest_128;
      From_Server : Boolean) return SMB.Crypto.Digest_128;

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
