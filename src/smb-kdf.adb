package body SMB.KDF is
   pragma SPARK_Mode (On);

   --  The counter i = 1 and the output length L = 128 bits, each 32 bits
   --  big-endian, and the zero byte between the label and the context.
   Counter : constant SMB.Bytes (0 .. 3) := (0, 0, 0, 1);
   Separator : constant SMB.Bytes (0 .. 0) := (others => 0);
   Output_Bits : constant SMB.Bytes (0 .. 3) := (0, 0, 0, 16#80#);

   --  "SMBSigningKey\0"
   Signing_Label : constant SMB.Bytes (0 .. 13) :=
     (16#53#, 16#4D#, 16#42#, 16#53#, 16#69#, 16#67#, 16#6E#, 16#69#,
      16#6E#, 16#67#, 16#4B#, 16#65#, 16#79#, 16#00#);

   --  "SMBC2SCipherKey\0"
   Encryption_Label : constant SMB.Bytes (0 .. 15) :=
     (16#53#, 16#4D#, 16#42#, 16#43#, 16#32#, 16#53#, 16#43#, 16#69#,
      16#70#, 16#68#, 16#65#, 16#72#, 16#4B#, 16#65#, 16#79#, 16#00#);

   --  "SMBS2CCipherKey\0"
   Decryption_Label : constant SMB.Bytes (0 .. 15) :=
     (16#53#, 16#4D#, 16#42#, 16#53#, 16#32#, 16#43#, 16#43#, 16#69#,
      16#70#, 16#68#, 16#65#, 16#72#, 16#4B#, 16#65#, 16#79#, 16#00#);

   --  The PRF input is fed in its parts, so no copy of it is assembled.
   function Derive
     (Session_Key : SMB.Crypto.Digest_128;
      Purpose : Key_Purpose;
      Preauth_Hash : SMB.Crypto.Digest_512) return SMB.Crypto.Digest_128
   is
      State : SMB.Crypto.HMAC_SHA256_Context;
      Block : SMB.Crypto.Digest_256;
   begin
      SMB.Crypto.HMAC_SHA256_Start (State, Session_Key);
      SMB.Crypto.HMAC_SHA256_Update (State, Counter);
      case Purpose is
         when Signing =>
            SMB.Crypto.HMAC_SHA256_Update (State, Signing_Label);
         when Encryption =>
            SMB.Crypto.HMAC_SHA256_Update (State, Encryption_Label);
         when Decryption =>
            SMB.Crypto.HMAC_SHA256_Update (State, Decryption_Label);
      end case;
      SMB.Crypto.HMAC_SHA256_Update (State, Separator);
      SMB.Crypto.HMAC_SHA256_Update (State, Preauth_Hash);
      SMB.Crypto.HMAC_SHA256_Update (State, Output_Bits);
      SMB.Crypto.HMAC_SHA256_Finish (State, Block);
      return Block (SMB.Crypto.Digest_128'Range);
   end Derive;

end SMB.KDF;
