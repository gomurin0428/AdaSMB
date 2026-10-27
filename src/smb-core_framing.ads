package SMB.Core_Framing is
   pragma SPARK_Mode (On);
   use type SMB.Byte;

   subtype Frame_Header is SMB.Bytes (0 .. 3);

   procedure Encode
     (Length : Natural;
      Header : out Frame_Header;
      Status : out SMB.Core_Status)
   with Post =>
     (if Length in 64 .. SMB.Maximum_Frame_Size then
        Status = SMB.Ok
        and then Header (0) = 0
        and then Header (1) = SMB.Byte (Length / 65_536)
        and then Header (2) = SMB.Byte ((Length / 256) mod 256)
        and then Header (3) = SMB.Byte (Length mod 256)
      else Status = SMB.Invalid_Length);

   procedure Decode
     (Header : Frame_Header;
      Length : out Natural;
      Status : out SMB.Core_Status)
   with Post =>
     (if Status = SMB.Ok then Length in 64 .. SMB.Maximum_Frame_Size
      else Length = 0);
end SMB.Core_Framing;
