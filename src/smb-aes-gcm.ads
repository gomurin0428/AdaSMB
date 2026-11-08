with Interfaces;

--  AES-128-GCM (NIST SP 800-38D) as SMB 3.1.1 encrypts messages (MS-SMB2
--  3.1.4.3): a 12-byte nonce and a 16-byte tag. SMB passes the 32 bytes of
--  the transform header from its Nonce field on as associated data, and the
--  tag is the header's Signature field.
--
--  Data is encrypted and decrypted in place. Open releases nothing it has
--  not authenticated: when the tag does not match, Data is all zeros.
--
--  GHASH multiplies in GF(2^128) one bit at a time and takes or drops each
--  term with a mask made from the bit, not with a branch or a table. The tag
--  comparison is SMB.Crypto.Constant_Time_Equal, and the counter and length
--  blocks depend only on lengths, so no branch or table index depends on
--  the key, the data or the tag. That is a coding rule, not a proved
--  property: the proof covers run-time safety and the contract of Open, and
--  the known-answer and differential tests cover the results. Nothing is
--  wiped except Data after a rejected tag. Seal and Open leave the key
--  schedule, the hash subkey, the GHASH state and the last key stream block
--  on the stack. Open decrypts as it hashes, so a rejected Open also leaves
--  there the last byte of the forged message's plaintext and the tag that
--  message would have needed, and the key stream block with the ciphertext
--  gives its last plaintext block.
package SMB.AES.GCM is
   pragma SPARK_Mode (On);

   use type Interfaces.Unsigned_8;

   subtype Nonce_96 is SMB.Bytes (0 .. 11);
   subtype Tag_128 is SMB.Bytes (0 .. 15);

   procedure Seal
     (Key : Key_128;
      Nonce : Nonce_96;
      AAD : SMB.Bytes;
      Data : in out SMB.Bytes;
      Tag : out Tag_128)
   with Pre => AAD'Length <= SMB.Maximum_Frame_Size
       and then Data'Length <= SMB.Maximum_Frame_Size;

   --  Authentic is True when Tag matches. When it does not, Data is all
   --  zeros.
   procedure Open
     (Key : Key_128;
      Nonce : Nonce_96;
      AAD : SMB.Bytes;
      Data : in out SMB.Bytes;
      Tag : Tag_128;
      Authentic : out Boolean)
   with Pre => AAD'Length <= SMB.Maximum_Frame_Size
       and then Data'Length <= SMB.Maximum_Frame_Size,
     Post => (if not Authentic then (for all I in Data'Range => Data (I) = 0));

end SMB.AES.GCM;
