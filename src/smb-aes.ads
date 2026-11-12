--  AES-128 and AES-256 in the encryption direction only (FIPS 197), the
--  block cipher under SMB 3.1.1's AES-CMAC signing and AES-CCM/AES-GCM
--  encryption. Those modes never run the cipher backwards.
--
--  The S-box is computed with GF(2^8) arithmetic on bit planes, and
--  MixColumns doubles a byte by multiplying the reduction constant by the
--  byte's top bit, so no table index or branch depends on the key or the
--  data. That is a coding rule, not a proved
--  property: the proof covers run-time safety, and the known-answer and
--  differential tests cover the results.
package SMB.AES is
   pragma SPARK_Mode (On);

   subtype Block is SMB.Bytes (0 .. 15);
   subtype Key_128 is SMB.Bytes (0 .. 15);
   subtype Key_256 is SMB.Bytes (0 .. 31);

   --  The round keys of one key: eleven for AES-128, fifteen for AES-256.
   --  A schedule is Ready only once Expand_Key has filled it, so Encrypt
   --  never runs on the zero default.
   type Key_Schedule is private;

   function Ready (Schedule : Key_Schedule) return Boolean;

   --  A 16-byte key selects AES-128 and a 32-byte key AES-256.
   procedure Expand_Key (Key : SMB.Bytes; Schedule : out Key_Schedule)
   with Pre => Key'Length = 16 or else Key'Length = 32,
     Post => Ready (Schedule);

   function Encrypt (Schedule : Key_Schedule; Plain : Block) return Block
   with Pre => Ready (Schedule);

private
   --  0 until Expand_Key runs, then 10 or 14.
   subtype Round_Count is Natural range 0 .. 14;

   type Key_Schedule is record
      Round_Keys : SMB.Bytes (0 .. 239) := (others => 0);
      Rounds : Round_Count := 0;
   end record;

   function Ready (Schedule : Key_Schedule) return Boolean is
     (Schedule.Rounds = 10 or else Schedule.Rounds = 14);
end SMB.AES;
