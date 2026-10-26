package SMB.Core_Framing is
   pragma SPARK_Mode (On);

   subtype Frame_Header is SMB.Bytes (0 .. 3);

   procedure Encode
     (Length : Natural;
      Header : out Frame_Header;
      Status : out SMB.Core_Status)
   with Post =>
     (if Status = SMB.Ok then Length in 64 .. SMB.Maximum_Frame_Size);

   procedure Decode
     (Header : Frame_Header;
      Length : out Natural;
      Status : out SMB.Core_Status)
   with Post =>
     (if Status = SMB.Ok then Length in 64 .. SMB.Maximum_Frame_Size
      else Length = 0);
end SMB.Core_Framing;
