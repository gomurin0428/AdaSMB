package SMB.Crypto is
   pragma SPARK_Mode (On);

   Maximum_Hash_Input : constant :=
     SMB.Maximum_Frame_Size + 64;

   subtype Digest_128 is SMB.Bytes (0 .. 15);
   subtype Digest_256 is SMB.Bytes (0 .. 31);

   function MD4 (Message : SMB.Bytes) return Digest_128
   with Pre => Message'Length <= Maximum_Hash_Input;

   function MD5 (Message : SMB.Bytes) return Digest_128
   with Pre => Message'Length <= Maximum_Hash_Input;

   function SHA256 (Message : SMB.Bytes) return Digest_256
   with Pre => Message'Length <= Maximum_Hash_Input;

   function HMAC_MD5 (Key, Message : SMB.Bytes) return Digest_128
   with Pre =>
     Key'Length <= SMB.Maximum_Frame_Size
     and Message'Length <= SMB.Maximum_Frame_Size;

   function HMAC_SHA256 (Key, Message : SMB.Bytes) return Digest_256
   with Pre =>
     Key'Length <= SMB.Maximum_Frame_Size
     and Message'Length <= SMB.Maximum_Frame_Size;

   -- Keep the potentially short-circuiting equality oracle proof-only.
   pragma Assertion_Policy (Post => Ignore);
   function Constant_Time_Equal (Left, Right : SMB.Bytes) return Boolean
   with Pre =>
     Left'Length <= Maximum_Hash_Input
     and Right'Length <= Maximum_Hash_Input,
     Post => Constant_Time_Equal'Result = (Left = Right);
end SMB.Crypto;
