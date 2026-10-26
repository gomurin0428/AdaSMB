with SMB.Crypto;

package SMB.Core_NTLM is
   pragma SPARK_Mode (On);

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
       and then (if Status = SMB.Ok then Type2_Length >= 48);

   procedure Validate_Final_Token
     (Token : SMB.Bytes;
      Status : out SMB.Core_Status;
      Expected_MIC : SMB.Bytes := (1 .. 0 => 0))
   with Pre => Token'Length <= SMB.Maximum_Frame_Size
     and Expected_MIC'Length <= 16;
end SMB.Core_NTLM;
