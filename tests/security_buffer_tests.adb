with Ada.Text_IO;
with SMB.Core_Protocol;
with SMB.Core_Wire;

procedure Security_Buffer_Tests is
   use type SMB.Core_Status;
   use type SMB.QWord;

   Lengths : constant array (Positive range <>) of Natural :=
     (0, 1, 7, 8, 16, 24, 32, 127, 128, 129, 255, 256, 65_535);
   Cases : Natural := 0;

   procedure Put
     (Packet : in out SMB.Bytes; Offset, Width : Natural; Value : Natural)
   is
      Rest : Natural := Value;
   begin
      for I in 0 .. Width - 1 loop
         Packet (Packet'First + Offset + I) := SMB.Byte (Rest mod 256);
         Rest := Rest / 256;
      end loop;
   end Put;
begin
   for Rebased in 0 .. 1 loop
      for Phase in 0 .. 2 loop
         declare
            First : constant Natural := 7 * Rebased;
            Packet : SMB.Bytes (First .. First + 255) := (others => 0);
            Negotiate : constant Boolean := Phase = 0;
            Command : constant SMB.Core_Wire.Command_Code :=
              (if Negotiate then 0 else 1);
            Nt_Status : constant SMB.DWord :=
              (if Phase = 1 then SMB.Status_More_Processing_Required else SMB.Success);
            Fixed_Size : constant Natural := (if Negotiate then 128 else 72);
            Offset_Field : constant Natural := (if Negotiate then 120 else 68);

            procedure Check (Offset, Length : Natural) is
               Info : SMB.Core_Protocol.Response_Info;
               Status : SMB.Core_Status;
               Fits : constant Boolean :=
                 Offset + Length <= 256 and then
                   (Length = 0 or else Offset >= Fixed_Size);
               Expected_Offset : constant Natural :=
                 (if Negotiate and Length = 0 then 0 else Offset);
            begin
               Put (Packet, Offset_Field, 2, Offset);
               Put (Packet, Offset_Field + 2, 2, Length);
               SMB.Core_Protocol.Parse_Response
                 (Packet, Command, Nt_Status, Info, Status);
               Cases := Cases + 1;
               if Status /= (if Fits then SMB.Ok else SMB.Invalid_Offset)
                 or else (Fits and then
                   (Info.Data_Offset /= Expected_Offset
                    or else Info.Data_Length /= Length
                    or else Info.Session_Id /= (if Negotiate then 0 else 1)))
               then
                  raise Program_Error with "security buffer phase" & Phase'Image
                    & " offset" & Offset'Image & " length" & Length'Image
                    & " status " & Status'Image;
               end if;
            end Check;
         begin
            Put (Packet, 64, 2, (if Negotiate then 65 else 9));
            if Negotiate then
               Put (Packet, 66, 2, 1);
               Put (Packet, 68, 2, 16#0210#);
               Put (Packet, 96, 4, 65_536);
               Put (Packet, 100, 4, 65_536);
            else
               Put (Packet, 40, 8, 1);
            end if;
            for Offset in 0 .. 256 loop
               for Length of Lengths loop
                  Check (Offset, Length);
               end loop;
            end loop;
            for Length of Lengths loop
               Check (65_535, Length);
            end loop;
         end;
      end loop;
   end loop;
   Ada.Text_IO.Put_Line ("security buffer mutation cases:" & Cases'Image);
end Security_Buffer_Tests;
