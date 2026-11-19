--  Unsigned integers as SMB2 puts them on the wire: little-endian, the byte
--  at the lowest offset the least significant (MS-SMB2 section 1.3 and 2.2;
--  MS-DTYP section 2.2 for the 16-, 32- and 64-bit types). Defined as sums of
--  each byte times a power of 256, not by shifting, so that a proof that the
--  code's shifts agree with them means something.
package SMB.Spec.Encoding
  with Ghost, SPARK_Mode
is
   use type SMB.Word;
   use type SMB.DWord;
   use type SMB.QWord;

   --  The 2, 4 or 8 bytes of Data from Offset on (counted from Data'First).
   --  The bound on Data'Length is the core's: every frame fits it.
   function LE16 (Data : SMB.Bytes; Offset : Natural) return SMB.Word is
     (SMB.Word (Data (Data'First + Offset))
      + SMB.Word (Data (Data'First + Offset + 1)) * 256)
   with Pre =>
     Data'Length <= SMB.Maximum_Frame_Size
     and then Data'Length >= 2 and then Offset <= Data'Length - 2;

   function LE32 (Data : SMB.Bytes; Offset : Natural) return SMB.DWord is
     (SMB.DWord (Data (Data'First + Offset))
      + SMB.DWord (Data (Data'First + Offset + 1)) * 2 ** 8
      + SMB.DWord (Data (Data'First + Offset + 2)) * 2 ** 16
      + SMB.DWord (Data (Data'First + Offset + 3)) * 2 ** 24)
   with Pre =>
     Data'Length <= SMB.Maximum_Frame_Size
     and then Data'Length >= 4 and then Offset <= Data'Length - 4;

   function LE64 (Data : SMB.Bytes; Offset : Natural) return SMB.QWord is
     (SMB.QWord (LE32 (Data, Offset))
      + SMB.QWord (LE32 (Data, Offset + 4)) * 2 ** 32)
   with Pre =>
     Data'Length <= SMB.Maximum_Frame_Size
     and then Data'Length >= 8 and then Offset <= Data'Length - 8;

   --  Byte Index (0 for the least significant) of Value's encoding.
   function LE_Byte (Value : SMB.QWord; Index : Natural) return SMB.Byte is
     (SMB.Byte ((Value / 2 ** (8 * Index)) mod 256))
   with Pre => Index < 8;
end SMB.Spec.Encoding;
