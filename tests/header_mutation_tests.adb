with Ada.Text_IO;
with SMB.Core_Wire;

procedure Header_Mutation_Tests is
   use type SMB.Core_Status;
   use type SMB.Byte;
   use type SMB.DWord;

   Expected : SMB.Core_Wire.Expected_Header :=
     (Command => 8, Message_Id => 16#0102_0304_0506_0708#,
      Tree_Id => 16#1234_5678#, Session_Id => 16#1122_3344_5566_7788#,
      Match_Tree => True, Match_Session => True, Signed => True);
   Peer_Status : constant SMB.DWord := 16#C000_0034#;
   Cases : Natural := 0;

   procedure Seed (Packet : out SMB.Bytes) is
      Status : SMB.Core_Status;
   begin
      Packet := (others => 0);
      SMB.Core_Wire.Initialize_Header
        (Packet, Expected.Command, Expected.Message_Id, Expected.Tree_Id,
         Expected.Session_Id, 1, Status);
      if Status /= SMB.Ok then
         raise Program_Error with "header fixture initialization";
      end if;
      Packet (Packet'First + 16) := (if Expected.Signed then 9 else 1);
      SMB.Core_Wire.Write_U32 (Packet, 8, Peer_Status, Status);
      if Status /= SMB.Ok then
         raise Program_Error with "header fixture NTSTATUS";
      end if;
   end Seed;

   procedure Check
     (Packet : SMB.Bytes; Want : SMB.Core_Status; Label : String;
      Interim : Boolean := False) is
      Status : SMB.Core_Status;
      Nt_Status : SMB.DWord;
   begin
      SMB.Core_Wire.Validate_Header
        (Packet, Expected, Nt_Status, Status, Interim => Interim);
      Cases := Cases + 1;
      if Status /= Want
        or else Nt_Status /=
          (if Want /= SMB.Ok then 0
           elsif Interim then SMB.Status_Pending else Peer_Status)
      then
         raise Program_Error with Label & " case" & Cases'Image
           & " got " & Status'Image & " expected " & Want'Image;
      end if;
   end Check;
begin
   for Rebased in 0 .. 2 loop
      declare
         First : constant Natural :=
           (if Rebased = 2 then Natural'Last - 95 else 7 * Rebased);
         Packet : SMB.Bytes (First .. First + 95);
      begin
         Seed (Packet);
         Check (Packet, SMB.Ok, "baseline");
         for Cut in 0 .. 63 loop
            declare
               Short : SMB.Bytes (7 .. 6 + Cut);
            begin
               if Cut > 0 then
                  Short := Packet (First .. First + Cut - 1);
               end if;
               Check (Short, SMB.Invalid_Length, "header truncation");
            end;
         end loop;
         for Offset in 0 .. 47 loop
            if Offset in 0 .. 5 | 12 .. 13 | 20 .. 31 | 36 .. 47 then
               Seed (Packet);
               declare
                  Original : constant SMB.Byte := Packet (First + Offset);
               begin
                  for Value in SMB.Byte loop
                     Packet (First + Offset) := Value;
                     Check
                       (Packet,
                        (if Value = Original then SMB.Ok
                         elsif Offset in 12 .. 13 | 24 .. 31 | 36 .. 47
                         then SMB.Correlation_Error else SMB.Invalid_Protocol),
                        "header field byte" & Offset'Image & " value" & Value'Image);
                  end loop;
               end;
            end if;
         end loop;
         for Offset in 16 .. 19 loop
            for Value in SMB.Byte loop
               Seed (Packet);
               Packet (First + Offset) := Value;
               Check
                 (Packet,
                  (if Offset > 16 then SMB.Ok
                   elsif (Value and 1) = 0 or else (Value and 2) /= 0
                   then SMB.Unsupported_Feature
                   elsif (Value and 8) = 0 then SMB.Signature_Error else SMB.Ok),
                  "header flag byte");
            end loop;
         end loop;
         for Match_Tree in Boolean loop
            for Match_Session in Boolean loop
               Expected.Match_Tree := Match_Tree;
               Expected.Match_Session := Match_Session;
               for Change_Tree in Boolean loop
                  Seed (Packet);
                  if Change_Tree then
                     Packet (First + 36) := Packet (First + 36) xor 1;
                  else
                     Packet (First + 40) := Packet (First + 40) xor 1;
                  end if;
                  Check
                    (Packet,
                     (if (if Change_Tree then Match_Tree else Match_Session)
                      then SMB.Correlation_Error else SMB.Ok),
                     "optional ID correlation");
               end loop;
            end loop;
         end loop;
         Expected.Match_Tree := True;
         Expected.Match_Session := True;
         Expected.Signed := False;
         Seed (Packet);
         Check (Packet, SMB.Ok, "unsigned preauthentication header");
         Packet (First + 16) := 9;
         Check (Packet, SMB.Signature_Error, "unexpected SIGNED flag");
         for Signed in Boolean loop
            Expected.Signed := Signed;
            for Interim in Boolean loop
               for Offset in 48 .. 63 loop
                  for Value in SMB.Byte loop
                     Seed (Packet);
                     if Interim then
                        declare
                           Status : SMB.Core_Status;
                        begin
                           Packet (First + 16) := (if Signed then 11 else 3);
                           SMB.Core_Wire.Write_U64 (Packet, 32, 17, Status);
                           if Status /= SMB.Ok then
                              raise Program_Error with "pending fixture AsyncId";
                           end if;
                           SMB.Core_Wire.Write_U32
                             (Packet, 8, SMB.Status_Pending, Status);
                           if Status /= SMB.Ok then
                              raise Program_Error with "pending fixture NTSTATUS";
                           end if;
                        end;
                     end if;
                     Packet (First + Offset) := Value;
                     Check
                       (Packet,
                        (if Signed or Interim or Value = 0 then SMB.Ok
                         else SMB.Signature_Error),
                        "header signature field policy", Interim);
                  end loop;
               end loop;
            end loop;
         end loop;
         Expected.Signed := True;
      end;
   end loop;
   Ada.Text_IO.Put_Line ("header mutation cases:" & Cases'Image);
end Header_Mutation_Tests;
