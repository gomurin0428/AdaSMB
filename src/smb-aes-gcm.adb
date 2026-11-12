with SMB.Crypto;

package body SMB.AES.GCM is
   pragma SPARK_Mode (On);

   use type Interfaces.Unsigned_64;

   --  Every helper has a contract, if only Post => True, so that GNATprove
   --  proves it once and its callers see only the contract (see SMB.AES).

   subtype Word is Interfaces.Unsigned_64;

   --  An element of GF(2^128): a block read as two big-endian 64-bit words.
   --  In GCM's bit order the first bit of the block, the top bit of High,
   --  is the coefficient of x**0, and the last, the low bit of Low, that of
   --  x**127.
   type Element is record
      High : Word;
      Low : Word;
   end record;

   function "xor" (Left, Right : Element) return Element is
     ((Left.High xor Right.High, Left.Low xor Right.Low))
     with Post => True;

   --  The eight bytes of Value from First on, read big-endian.
   function Word_At (Value : Block; First : Natural) return Word is
     (Interfaces.Shift_Left (Word (Value (First)), 56)
      or Interfaces.Shift_Left (Word (Value (First + 1)), 48)
      or Interfaces.Shift_Left (Word (Value (First + 2)), 40)
      or Interfaces.Shift_Left (Word (Value (First + 3)), 32)
      or Interfaces.Shift_Left (Word (Value (First + 4)), 24)
      or Interfaces.Shift_Left (Word (Value (First + 5)), 16)
      or Interfaces.Shift_Left (Word (Value (First + 6)), 8)
      or Word (Value (First + 7)))
     with Pre => First in 0 | 8,
       Post => True;

   function To_Element (Value : Block) return Element is
     ((Word_At (Value, 0), Word_At (Value, 8)))
     with Post => True;

   --  Byte Index of Value, counting from the top byte as 0.
   function Byte_Of (Value : Word; Index : Natural) return SMB.Byte is
     (SMB.Byte (Interfaces.Shift_Right (Value, 56 - 8 * Index) mod 2**8))
     with Pre => Index <= 7,
       Post => True;

   function To_Block (Value : Element) return Block is
     (Byte_Of (Value.High, 0), Byte_Of (Value.High, 1),
      Byte_Of (Value.High, 2), Byte_Of (Value.High, 3),
      Byte_Of (Value.High, 4), Byte_Of (Value.High, 5),
      Byte_Of (Value.High, 6), Byte_Of (Value.High, 7),
      Byte_Of (Value.Low, 0), Byte_Of (Value.Low, 1),
      Byte_Of (Value.Low, 2), Byte_Of (Value.Low, 3),
      Byte_Of (Value.Low, 4), Byte_Of (Value.Low, 5),
      Byte_Of (Value.Low, 6), Byte_Of (Value.Low, 7))
     with Post => True;

   --  The reduction constant R = 11100001 || 0**120, as the top word.
   R_High : constant Word := 16#E100_0000_0000_0000#;

   --  X times Y, SP 800-38D algorithm 1. For each bit of X from the first,
   --  the product takes V when the bit is set, and V is then multiplied by
   --  x, reduced by R when its last bit falls out. Both choices are a mask,
   --  zero or all ones, made from the bit.
   function Multiply (X, Y : Element) return Element
     with Post => True
   is
      Product : Element := (0, 0);
      V : Element := Y;
      Source : Word;
      Take : Word;
      Reduce : Word;
   begin
      for I in 0 .. 127 loop
         Source := (if I < 64 then X.High else X.Low);
         Take := 0 - (Interfaces.Shift_Right (Source, 63 - I mod 64) and 1);
         Product.High := Product.High xor (V.High and Take);
         Product.Low := Product.Low xor (V.Low and Take);
         Reduce := 0 - (V.Low and 1);
         V.Low :=
           Interfaces.Shift_Right (V.Low, 1)
           or Interfaces.Shift_Left (V.High, 63);
         V.High := Interfaces.Shift_Right (V.High, 1) xor (R_High and Reduce);
      end loop;
      return Product;
   end Multiply;

   --  One GHASH step: State := (State xor Chunk) * H.
   procedure Absorb (State : in out Element; H : Element; Chunk : Block)
     with Post => True
   is
   begin
      State := Multiply (State xor To_Element (Chunk), H);
   end Absorb;

   --  GHASH over Data, the last block padded with zeros.
   procedure Absorb_Bytes
     (State : in out Element; H : Element; Data : SMB.Bytes)
     with Pre => Data'Length <= SMB.Maximum_Frame_Size,
       Post => True
   is
      Chunk : Block;
      Offset : Natural := 0;
      Count : Natural;
   begin
      while Offset < Data'Length loop
         Count := Natural'Min (Block'Length, Data'Length - Offset);
         Chunk := (others => 0);
         for J in 0 .. Count - 1 loop
            Chunk (J) := Data (Data'First + Offset + J);
         end loop;
         Absorb (State, H, Chunk);
         Offset := Offset + Count;
         pragma Loop_Invariant (Offset <= Data'Length);
         pragma Loop_Variant (Increases => Offset);
      end loop;
   end Absorb_Bytes;

   --  A counter block: the nonce, then Value as a four-byte big-endian
   --  number. Value is below 2**24, so its top byte is zero.
   function Counter_Block (Nonce : Nonce_96; Value : Natural) return Block is
     (Nonce (0), Nonce (1), Nonce (2), Nonce (3), Nonce (4), Nonce (5),
      Nonce (6), Nonce (7), Nonce (8), Nonce (9), Nonce (10), Nonce (11),
      0, SMB.Byte (Value / 2**16), SMB.Byte (Value / 2**8 mod 2**8),
      SMB.Byte (Value mod 2**8))
     with Pre => Value < 2**24,
       Post => True;

   --  Encrypts or decrypts Data in place with the counter blocks from 2 on,
   --  and returns the tag: GHASH of the associated data, the ciphertext
   --  (Data after encryption, or before decryption) and their lengths in
   --  bits, masked with the encrypted counter block 1 (J0).
   procedure Transform
     (Schedule : Key_Schedule;
      Nonce : Nonce_96;
      AAD : SMB.Bytes;
      Data : in out SMB.Bytes;
      Decrypt : Boolean;
      Tag : out Tag_128)
     with Pre => Ready (Schedule)
       and then AAD'Length <= SMB.Maximum_Frame_Size
       and then Data'Length <= SMB.Maximum_Frame_Size,
       Post => True
   is
      H : constant Element := To_Element (Encrypt (Schedule, (others => 0)));
      State : Element := (0, 0);
      Stream : Block;
      Cipher : Block;
      Offset : Natural := 0;
      Counter : Natural := 2;
      Count : Natural;
      Input : SMB.Byte;
      Output : SMB.Byte;
   begin
      Absorb_Bytes (State, H, AAD);
      while Offset < Data'Length loop
         Count := Natural'Min (Block'Length, Data'Length - Offset);
         Stream := Encrypt (Schedule, Counter_Block (Nonce, Counter));
         --  GHASH pads the last block of ciphertext with zeros.
         Cipher := (others => 0);
         for J in 0 .. Count - 1 loop
            Input := Data (Data'First + Offset + J);
            Output := Input xor Stream (J);
            Data (Data'First + Offset + J) := Output;
            Cipher (J) := (if Decrypt then Input else Output);
         end loop;
         Absorb (State, H, Cipher);
         Offset := Offset + Count;
         Counter := Counter + 1;
         pragma Loop_Invariant (Offset <= Data'Length);
         pragma Loop_Invariant (Counter <= Offset + 2);
         pragma Loop_Variant (Increases => Offset);
      end loop;
      Absorb
        (State, H,
         To_Block ((8 * Word (AAD'Length), 8 * Word (Data'Length))));
      Tag := To_Block
        (State xor To_Element (Encrypt (Schedule, Counter_Block (Nonce, 1))));
   end Transform;

   procedure Seal
     (Key : SMB.Bytes;
      Nonce : Nonce_96;
      AAD : SMB.Bytes;
      Data : in out SMB.Bytes;
      Tag : out Tag_128)
   is
      Schedule : Key_Schedule;
   begin
      Expand_Key (Key, Schedule);
      Transform (Schedule, Nonce, AAD, Data, False, Tag);
   end Seal;

   procedure Open
     (Key : SMB.Bytes;
      Nonce : Nonce_96;
      AAD : SMB.Bytes;
      Data : in out SMB.Bytes;
      Tag : Tag_128;
      Authentic : out Boolean)
   is
      Schedule : Key_Schedule;
      Expected : Tag_128;
   begin
      Expand_Key (Key, Schedule);
      Transform (Schedule, Nonce, AAD, Data, True, Expected);
      Authentic := SMB.Crypto.Constant_Time_Equal (Expected, Tag);
      if not Authentic then
         Data := (others => 0);
      end if;
   end Open;

end SMB.AES.GCM;
