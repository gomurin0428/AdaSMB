with Interfaces;

--  AES-GCM (NIST SP 800-38D) as SMB 3.1.1 encrypts messages (MS-SMB2
--  3.1.4.3): a 16-byte key for AES-128-GCM or a 32-byte key for
--  AES-256-GCM, a 12-byte nonce and a 16-byte tag. SMB passes the 32 bytes
--  of the transform header from its Nonce field on as associated data, and
--  the tag is the header's Signature field.
--
--  With nothing to encrypt, GCM is GMAC, which SMB 3.1.1 signs with when
--  the server chooses AES-GMAC (MS-SMB2 3.1.4.1): the tag of the whole
--  message, with its Signature field zeroed, as associated data, under the
--  16-byte signing key. MAC computes it in one call, and the incremental
--  form takes the message in pieces (see MAC_Context).
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
   pragma Unevaluated_Use_Of_Old (Allow);

   use type Interfaces.Unsigned_8;

   subtype Nonce_96 is SMB.Bytes (0 .. 11);
   subtype Tag_128 is SMB.Bytes (0 .. 15);

   procedure Seal
     (Key : SMB.Bytes;
      Nonce : Nonce_96;
      AAD : SMB.Bytes;
      Data : in out SMB.Bytes;
      Tag : out Tag_128)
   with Pre => (Key'Length = 16 or else Key'Length = 32)
       and then AAD'Length <= SMB.Maximum_Frame_Size
       and then Data'Length <= SMB.Maximum_Frame_Size;

   --  Authentic is True when Tag matches. When it does not, Data is all
   --  zeros.
   procedure Open
     (Key : SMB.Bytes;
      Nonce : Nonce_96;
      AAD : SMB.Bytes;
      Data : in out SMB.Bytes;
      Tag : Tag_128;
      Authentic : out Boolean)
   with Pre => (Key'Length = 16 or else Key'Length = 32)
       and then AAD'Length <= SMB.Maximum_Frame_Size
       and then Data'Length <= SMB.Maximum_Frame_Size,
     Post => (if not Authentic then (for all I in Data'Range => Data (I) = 0));

   --  GMAC: the tag of Message as associated data, with no data. A 16-byte
   --  key gives AES-128-GMAC, SMB's signing MAC, and a 32-byte key
   --  AES-256-GMAC.
   function MAC
     (Key : SMB.Bytes;
      Nonce : Nonce_96;
      Message : SMB.Bytes) return Tag_128
   with Pre => (Key'Length = 16 or else Key'Length = 32)
       and then Message'Length <= SMB.Maximum_Frame_Size;

   --  The incremental form of MAC, so that a caller can feed a frame as its
   --  header, a zero signature and the rest without copying them together.
   --  GHASH pads only the last block of the message with zeros, so every
   --  piece but the last must be whole blocks: Update needs the length so
   --  far to be a multiple of 16. A default context is empty, wiped and not
   --  Ready. Start keeps the hash subkey and the encrypted first counter
   --  block, not the key schedule; Finish wipes the context, and nothing
   --  else is wiped: not MAC's local context, and not the copies that
   --  Expand_Key and the compiler leave on the stack.
   type MAC_Context is private;

   function Ready (Context : MAC_Context) return Boolean;
   function Length (Context : MAC_Context) return Natural;
   --  True when the context holds no key material and no message state.
   function Wiped (Context : MAC_Context) return Boolean;

   --  Starts a message, discarding any unfinished one.
   procedure Start
     (Context : out MAC_Context;
      Key : SMB.Bytes;
      Nonce : Nonce_96)
   with Pre => Key'Length = 16 or else Key'Length = 32,
     Post => Ready (Context) and then Length (Context) = 0;

   procedure Update (Context : in out MAC_Context; Message : SMB.Bytes)
   with Pre => Ready (Context)
       and then Length (Context) mod 16 = 0
       and then Message'Length <= SMB.Maximum_Frame_Size
       and then Length (Context) <= SMB.Maximum_Frame_Size - Message'Length,
     Post => Ready (Context)
       and then Length (Context) = Length (Context)'Old + Message'Length;

   procedure Finish (Context : in out MAC_Context; Tag : out Tag_128)
   with Pre => Ready (Context),
     Post => not Ready (Context) and then Wiped (Context);

private
   --  The hash subkey H, the GHASH state so far and the encrypted counter
   --  block 1 (J0), which masks the tag, all as blocks.
   type MAC_Context is record
      Subkey : Block := (others => 0);
      Hash : Block := (others => 0);
      Mask : Block := (others => 0);
      Total : Natural := 0;
      Started : Boolean := False;
   end record;

   --  Every component at its default.
   Cleared : constant MAC_Context := (others => <>);

   function Ready (Context : MAC_Context) return Boolean is
     (Context.Started and then Context.Total <= SMB.Maximum_Frame_Size);

   function Length (Context : MAC_Context) return Natural is
     (Context.Total);

   function Wiped (Context : MAC_Context) return Boolean is
     (Context = Cleared);
end SMB.AES.GCM;
