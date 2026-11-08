with SMB.Crypto;

package body SMB.AES.CCM is
   pragma SPARK_Mode (On);

   --  Every helper has a contract, if only Post => True, so that GNATprove
   --  proves it once and its callers see only the contract (see SMB.AES).

   --  The flags byte of B0: Adata (16#40#) when there is associated data,
   --  (M - 2) / 2 = 7 for the 16-byte tag in bits 3 to 5 (16#38#), and
   --  L - 1 = 3 in bits 0 to 2. A counter block's flags byte is L - 1 alone.
   B0_Flags_With_AAD : constant SMB.Byte := 16#7B#;
   B0_Flags_Without_AAD : constant SMB.Byte := 16#3B#;
   Counter_Flags : constant SMB.Byte := 16#03#;

   function Xor_Block (Left, Right : Block) return Block
     with Post => True
   is
      Result : Block;
   begin
      for I in Block'Range loop
         Result (I) := Left (I) xor Right (I);
      end loop;
      return Result;
   end Xor_Block;

   --  B0 or a counter block: Flags, the nonce, then Value as a four-byte
   --  big-endian number (the message length in B0, the counter otherwise).
   --  Value is at most 2**20, so its top byte is zero.
   function Nonce_Block
     (Flags : SMB.Byte; Nonce : Nonce_88; Value : Natural) return Block
   is
     (Flags, Nonce (0), Nonce (1), Nonce (2), Nonce (3), Nonce (4), Nonce (5),
      Nonce (6), Nonce (7), Nonce (8), Nonce (9), Nonce (10),
      0, SMB.Byte (Value / 2**16), SMB.Byte (Value / 2**8 mod 2**8),
      SMB.Byte (Value mod 2**8))
     with Pre => Value <= SMB.Maximum_Frame_Size,
       Post => True;

   --  Runs the CBC-MAC over the encoded associated data: its two-byte
   --  length, the data, and zeros up to a whole block.
   procedure Absorb_AAD
     (Schedule : Key_Schedule; Chain : in out Block; AAD : SMB.Bytes)
     with Pre => Ready (Schedule)
       and then AAD'Length in 1 .. Maximum_AAD_Length,
       Post => True
   is
      Current : Block := (others => 0);
      Used : Natural range 0 .. Block'Length := 2;
   begin
      Current (0) := SMB.Byte (AAD'Length / 2**8);
      Current (1) := SMB.Byte (AAD'Length mod 2**8);
      for I in AAD'Range loop
         if Used = Block'Length then
            Chain := Encrypt (Schedule, Xor_Block (Chain, Current));
            Current := (others => 0);
            Used := 0;
         end if;
         Current (Used) := AAD (I);
         Used := Used + 1;
      end loop;
      Chain := Encrypt (Schedule, Xor_Block (Chain, Current));
   end Absorb_AAD;

   --  Encrypts or decrypts Data in place with the counter blocks from 1 on,
   --  and returns the tag: the CBC-MAC of B0, the associated data and the
   --  plaintext (Data before encryption, or after decryption), masked with
   --  the encrypted counter block 0.
   procedure Transform
     (Schedule : Key_Schedule;
      Nonce : Nonce_88;
      AAD : SMB.Bytes;
      Data : in out SMB.Bytes;
      Decrypt : Boolean;
      Tag : out Tag_128)
     with Pre => Ready (Schedule)
       and then AAD'Length <= Maximum_AAD_Length
       and then Data'Length <= SMB.Maximum_Frame_Size,
       Post => True
   is
      Chain : Block;
      Stream : Block;
      Plain : Block;
      Offset : Natural := 0;
      Counter : Natural := 1;
      Count : Natural;
      Input : SMB.Byte;
      Output : SMB.Byte;
   begin
      Chain := Encrypt
        (Schedule,
         Nonce_Block
           ((if AAD'Length > 0 then B0_Flags_With_AAD
             else B0_Flags_Without_AAD),
            Nonce, Data'Length));
      if AAD'Length > 0 then
         Absorb_AAD (Schedule, Chain, AAD);
      end if;
      while Offset < Data'Length loop
         Count := Natural'Min (Block'Length, Data'Length - Offset);
         Stream := Encrypt
           (Schedule, Nonce_Block (Counter_Flags, Nonce, Counter));
         --  The CBC-MAC pads the last block with zeros.
         Plain := (others => 0);
         for J in 0 .. Count - 1 loop
            Input := Data (Data'First + Offset + J);
            Output := Input xor Stream (J);
            Data (Data'First + Offset + J) := Output;
            Plain (J) := (if Decrypt then Output else Input);
         end loop;
         Chain := Encrypt (Schedule, Xor_Block (Chain, Plain));
         Offset := Offset + Count;
         Counter := Counter + 1;
         pragma Loop_Invariant (Offset <= Data'Length);
         pragma Loop_Invariant (Counter <= Offset + 1);
         pragma Loop_Variant (Increases => Offset);
      end loop;
      Tag := Xor_Block
        (Chain, Encrypt (Schedule, Nonce_Block (Counter_Flags, Nonce, 0)));
   end Transform;

   procedure Seal
     (Key : Key_128;
      Nonce : Nonce_88;
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
     (Key : Key_128;
      Nonce : Nonce_88;
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

end SMB.AES.CCM;
