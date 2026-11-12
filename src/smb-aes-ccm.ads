with Interfaces;

--  AES-CCM (NIST SP 800-38C, RFC 3610) as SMB 3.x encrypts messages
--  (MS-SMB2 3.1.4.3): a 16-byte key for AES-128-CCM or a 32-byte key for
--  AES-256-CCM, an 11-byte nonce, which leaves a 4-byte length field
--  (L = 4), and a 16-byte tag. SMB passes the 32 bytes of the transform
--  header from its Nonce field on as associated data, and the tag is the
--  header's Signature field.
--
--  Data is encrypted and decrypted in place. Open releases nothing it has
--  not authenticated: when the tag does not match, Data is all zeros.
--
--  The tag comparison is SMB.Crypto.Constant_Time_Equal, and the counter
--  and length encodings depend only on lengths, so no branch or table index
--  depends on the key, the data or the tag. That is a coding rule, not a
--  proved property: the proof covers run-time safety and the contract of
--  Open, and the known-answer and differential tests cover the results.
--  Nothing is wiped except Data after a rejected tag. Seal and Open leave
--  the key schedule, the CBC-MAC chain and the key stream on the stack,
--  and a rejected Open also leaves there the last block of the plaintext
--  it decrypted and the tag that the forged message would have needed.
package SMB.AES.CCM is
   pragma SPARK_Mode (On);

   use type Interfaces.Unsigned_8;

   subtype Nonce_88 is SMB.Bytes (0 .. 10);
   subtype Tag_128 is SMB.Bytes (0 .. 15);

   --  The longest associated data with the two-byte length encoding
   --  (2**16 - 2**8 - 1 bytes). SMB's is always 32 bytes.
   Maximum_AAD_Length : constant := 65_279;

   procedure Seal
     (Key : SMB.Bytes;
      Nonce : Nonce_88;
      AAD : SMB.Bytes;
      Data : in out SMB.Bytes;
      Tag : out Tag_128)
   with Pre => (Key'Length = 16 or else Key'Length = 32)
       and then AAD'Length <= Maximum_AAD_Length
       and then Data'Length <= SMB.Maximum_Frame_Size;

   --  Authentic is True when Tag matches. When it does not, Data is all
   --  zeros.
   procedure Open
     (Key : SMB.Bytes;
      Nonce : Nonce_88;
      AAD : SMB.Bytes;
      Data : in out SMB.Bytes;
      Tag : Tag_128;
      Authentic : out Boolean)
   with Pre => (Key'Length = 16 or else Key'Length = 32)
       and then AAD'Length <= Maximum_AAD_Length
       and then Data'Length <= SMB.Maximum_Frame_Size,
     Post => (if not Authentic then (for all I in Data'Range => Data (I) = 0));

end SMB.AES.CCM;
