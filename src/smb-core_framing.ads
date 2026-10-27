package SMB.Core_Framing is
   pragma SPARK_Mode (On);
   use type SMB.Byte;

   subtype Frame_Header is SMB.Bytes (0 .. 3);

   function Payload_Length (Header : Frame_Header) return Natural is
     (Natural (Header (1)) * 65_536
      + Natural (Header (2)) * 256 + Natural (Header (3)));

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
      else Status = SMB.Invalid_Length
        and then (for all I in Header'Range => Header (I) = 0));

   procedure Decode
     (Header : Frame_Header;
      Length : out Natural;
      Status : out SMB.Core_Status)
   with Post =>
     Status =
       (if Header (0) /= 0 then SMB.Unsupported_Feature
        elsif Payload_Length (Header) not in 64 .. SMB.Maximum_Frame_Size
          then SMB.Invalid_Length
        else SMB.Ok)
     and then Length = (if Status = SMB.Ok then Payload_Length (Header) else 0);
end SMB.Core_Framing;
