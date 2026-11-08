--  AES-128 in the encryption direction only (FIPS 197), the block cipher
--  under SMB 3.1.1's AES-CMAC signing and AES-CCM/AES-GCM encryption. Those
--  modes never run the cipher backwards.
--
--  The S-box is computed with GF(2^8) arithmetic on bit planes, and
--  MixColumns multiplies by x with a mask, so no table index or branch
--  depends on the key or the data. That is a coding rule, not a proved
--  property: the proof covers run-time safety, and the known-answer and
--  differential tests cover the results.
package SMB.AES is
   pragma SPARK_Mode (On);

   subtype Block is SMB.Bytes (0 .. 15);
   subtype Key_128 is SMB.Bytes (0 .. 15);

   --  The eleven round keys of one key.
   type Key_Schedule is private;

   procedure Expand_Key (Key : Key_128; Schedule : out Key_Schedule);

   function Encrypt (Schedule : Key_Schedule; Plain : Block) return Block;

private
   type Key_Schedule is record
      Round_Keys : SMB.Bytes (0 .. 175) := (others => 0);
   end record;
end SMB.AES;
