package body SMB.Core_Framing is
   pragma SPARK_Mode (On);

   procedure Encode
     (Length : Natural;
      Header : out Frame_Header;
      Status : out SMB.Core_Status) is
   begin
      Header := (others => 0);
      if Length not in 64 .. SMB.Maximum_Frame_Size then
         Status := SMB.Invalid_Length;
         return;
      end if;
      Header (1) := SMB.Byte (Length / 65_536);
      Header (2) := SMB.Byte ((Length / 256) mod 256);
      Header (3) := SMB.Byte (Length mod 256);
      Status := SMB.Ok;
   end Encode;

   procedure Decode
     (Header : Frame_Header;
      Length : out Natural;
      Status : out SMB.Core_Status)
   is
      Parsed : Natural;
   begin
      Length := 0;
      if Header (0) /= 0 then
         Status := SMB.Unsupported_Feature;
         return;
      end if;
      Parsed := Payload_Length (Header);
      if Parsed not in 64 .. SMB.Maximum_Frame_Size then
         Status := SMB.Invalid_Length;
         return;
      end if;
      Length := Parsed;
      Status := SMB.Ok;
   end Decode;
end SMB.Core_Framing;
