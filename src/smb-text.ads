package SMB.Text is
   pragma SPARK_Mode (Off);
   function To_UTF16LE (Value : String) return SMB.Bytes;
   function From_UTF16LE (Value : SMB.Bytes) return String;
   function NTLM_Username (Value : String) return String;
end SMB.Text;
