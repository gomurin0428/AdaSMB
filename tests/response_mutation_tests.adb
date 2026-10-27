with Ada.Text_IO;
with SMB.Core_Protocol;
with SMB.Core_Wire;

procedure Response_Mutation_Tests is
   use type SMB.Core_Status;
   use type SMB.DWord;
   use type SMB.QWord;

   type Layout is record
      Command : SMB.Core_Wire.Command_Code;
      Size, Structure : Natural;
   end record;
   Layouts : constant array (Positive range <>) of Layout :=
     ((0, 128, 65), (1, 72, 9), (2, 68, 4), (3, 80, 16),
      (4, 68, 4), (5, 152, 89), (6, 124, 60), (8, 80, 17),
      (9, 80, 17), (14, 72, 9), (17, 66, 2));
   Lengths : constant array (Positive range <>) of SMB.DWord :=
     (0, 1, 8, 16, 17, 24, 25, 255, 256, 65_535, 65_536, 65_537,
      SMB.DWord'Last);
   Cases : Natural := 0;
   Info : SMB.Core_Protocol.Response_Info;

   procedure Put
     (Packet : in out SMB.Bytes; Offset, Width : Natural; Value : SMB.DWord)
   is
      Rest : SMB.DWord := Value;
   begin
      for I in 0 .. Width - 1 loop
         Packet (Packet'First + Offset + I) := SMB.Byte (Rest mod 256);
         Rest := Rest / 256;
      end loop;
   end Put;

   procedure Seed (Packet : out SMB.Bytes; Item : Layout) is
   begin
      Packet := (others => 0);
      Put (Packet, 64, 2, SMB.DWord (Item.Structure));
      case Item.Command is
         when 0 =>
            Put (Packet, 66, 2, 1);
            Put (Packet, 68, 2, 16#0210#);
            Put (Packet, 96, 4, 65_536);
            Put (Packet, 100, 4, 65_536);
         when 1 =>
            Put (Packet, 40, 8, 1);
         when 3 =>
            Put (Packet, 36, 4, 1);
            Put (Packet, 66, 1, 1);
         when 8 =>
            Put (Packet, 66, 1, 80);
         when 9 =>
            Put (Packet, 68, 4, 1);
         when others => null;
      end case;
   end Seed;

   procedure Check
     (Packet : SMB.Bytes; Command : SMB.Core_Wire.Command_Code;
      Expected : Boolean; Label : String; Nt_Status : SMB.DWord := SMB.Success)
   is
      Status : SMB.Core_Status;
   begin
      SMB.Core_Protocol.Parse_Response (Packet, Command, Nt_Status, Info, Status);
      Cases := Cases + 1;
      if (Status = SMB.Ok) /= Expected then
         raise Program_Error with
           Label & " command" & Command'Image & " case" & Cases'Image
           & " length" & Packet'Length'Image & " status " & Status'Image;
      end if;
      if Status = SMB.Ok
        and then (Info.Data_Offset > Packet'Length
                  or else Info.Data_Length > Packet'Length - Info.Data_Offset)
      then
         raise Program_Error with "accepted range outside packet: " & Label;
      end if;
   end Check;
begin
   for Rebased in 0 .. 1 loop
      declare
         First : constant Natural := Rebased * 7;
         Packet : SMB.Bytes (First .. First + 255);
      begin
         for Item of Layouts loop
            Seed (Packet, Item);
            Check (Packet (First .. First + Item.Size - 1),
                   Item.Command, True, "baseline");
            for Cut in 0 .. Item.Size - 1 loop
               --  Keep a nonzero lower bound for the empty slice as well.
               declare
                  Short : SMB.Bytes (7 .. 6 + Cut);
               begin
                  if Cut > 0 then
                     Short := Packet (First .. First + Cut - 1);
                  end if;
                  Check (Short, Item.Command, False, "fixed-body truncation");
               end;
            end loop;
            for Byte_Index in 0 .. 1 loop
               for Value in 0 .. 255 loop
                  Seed (Packet, Item);
                  Packet (First + 64 + Byte_Index) := SMB.Byte (Value);
                  Check
                    (Packet (First .. First + Item.Size - 1), Item.Command,
                     Value = (if Byte_Index = 0 then Item.Structure else 0),
                     "StructureSize byte mutation");
               end loop;
            end loop;
            for Count of Lengths loop
               Packet := (others => 0);
               Put (Packet, 64, 2, 9);
               Put (Packet, 68, 4, Count);
               Check (Packet (First .. First + 87), Item.Command,
                      Count <= 16, "ERROR ByteCount", 16#C000_0034#);
            end loop;
         end loop;

         for Directory in Boolean loop
            declare
               Command : constant SMB.Core_Wire.Command_Code :=
                 (if Directory then 14 else 8);
               Fixed_Size : constant Natural := (if Directory then 72 else 80);
               Offset_Width : constant Natural := (if Directory then 2 else 1);
               Item : constant Layout :=
                 (Command, Fixed_Size, (if Directory then 9 else 17));
            begin
               for Offset in 0 .. 255 loop
                  for Count of Lengths loop
                     Seed (Packet, Item);
                     Put (Packet, 66, Offset_Width, SMB.DWord (Offset));
                     Put (Packet, 68, 4, Count);
                     Check
                       (Packet (First .. First + 95), Command,
                        SMB.QWord (Offset) + SMB.QWord (Count) <= 96
                        and then (Count = 0 or else Offset >= Fixed_Size),
                        "buffer offset/length cross-product");
                     if SMB.QWord (Offset) + SMB.QWord (Count) <= 96
                       and then (Count = 0 or else Offset >= Fixed_Size)
                       and then (Info.Data_Offset /= Offset
                                 or else Info.Data_Length /= Natural (Count))
                     then
                        raise Program_Error with "accepted buffer range changed";
                     end if;
                  end loop;
               end loop;
               if Directory then
                  Put (Packet, 66, 2, 65_535);
                  Put (Packet, 68, 4, 0);
                  Check (Packet, Command, False, "high WORD offset");
               end if;
               declare
                  Large : SMB.Bytes (First .. First + Fixed_Size + 65_536);
               begin
                  for Count in 65_535 .. 65_537 loop
                     Seed (Large, Item);
                     Put (Large, 66, Offset_Width, SMB.DWord (Fixed_Size));
                     Put (Large, 68, 4, SMB.DWord (Count));
                     Check (Large, Command, Count <= 65_536,
                            "library IO cap with sufficient packet capacity");
                  end loop;
               end;
            end;
         end loop;

         for Byte_Index in 0 .. 3 loop
            for Value in 0 .. 255 loop
               declare
                  Count : constant SMB.DWord := SMB.DWord (Value) * 256 ** Byte_Index;
               begin
                  Seed (Packet, (9, 80, 17));
                  Put (Packet, 68, 4, Count);
                  Check (Packet (First .. First + 79), 9,
                         Count in 1 .. 65_536, "WRITE Count byte mutation");
                  if Count in 1 .. 65_536 and then Info.Count /= Natural (Count) then
                     raise Program_Error with "WRITE Count changed";
                  end if;
               end;
            end loop;
         end loop;
         for Offset in 66 .. 79 loop
            if Offset not in 68 .. 71 then
               for Value in 0 .. 255 loop
                  Seed (Packet, (9, 80, 17));
                  Packet (First + Offset) := SMB.Byte (Value);
                  Check (Packet (First .. First + 79), 9, True,
                         "WRITE reserved byte must be ignored");
                  if Info.Count /= 1 then
                     raise Program_Error with "reserved byte changed WRITE Count";
                  end if;
               end loop;
            end if;
         end loop;
         for Byte_Index in 0 .. 1 loop
            for Value in 0 .. 255 loop
               Seed (Packet, (6, 124, 60));
               Packet (First + 66 + Byte_Index) := SMB.Byte (Value);
               Check (Packet (First .. First + 123), 6,
                      (if Byte_Index = 0 then Value <= 1 else Value = 0),
                      "CLOSE supported flag mask");
            end loop;
         end loop;
      end;
   end loop;
   Ada.Text_IO.Put_Line ("response mutation cases:" & Cases'Image);
end Response_Mutation_Tests;
