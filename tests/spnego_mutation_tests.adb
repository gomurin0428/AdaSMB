with Ada.Text_IO;
with SMB.Core_NTLM;

procedure Spnego_Mutation_Tests is
   use type SMB.Byte;
   use type SMB.Bytes;
   use type SMB.Core_Status;

   MIC : constant SMB.Bytes :=
     (1, 0, 0, 0, 16#0A#, 16#FB#, 16#34#, 16#90#,
      16#3A#, 16#3E#, 16#4E#, 16#54#, 0, 0, 0, 0);
   State_Field : constant SMB.Bytes := (16#A0#, 3, 16#0A#, 1, 0);
   MIC_Field : constant SMB.Bytes := SMB.Bytes'(16#A3#, 18, 4, 16) & MIC;
   Mechanism : constant SMB.Bytes :=
     (16#A1#, 12, 6, 10, 16#2B#, 6, 1, 4, 1, 16#82#, 16#37#, 2, 2, 10);
   Empty_Response : constant SMB.Bytes := (16#A2#, 2, 4, 0);
   Empty : constant SMB.Bytes := (1 .. 0 => 0);
   Cases : Natural := 0;

   function Wrap (Fields : SMB.Bytes) return SMB.Bytes is
     (SMB.Bytes'(16#A1#, SMB.Byte (Fields'Length + 2), 16#30#,
                 SMB.Byte (Fields'Length)) & Fields);

   Seed : constant SMB.Bytes := Wrap (State_Field & MIC_Field);

   procedure Check
     (Token : SMB.Bytes; Should_Accept : Boolean; Label : String;
      Signature_Error : Boolean := False; Expected_MIC : SMB.Bytes := MIC)
   is
      Status : SMB.Core_Status;
   begin
      SMB.Core_NTLM.Validate_Final_Token (Token, Status, Expected_MIC);
      Cases := Cases + 1;
      if (Status = SMB.Ok) /= Should_Accept
        or else (Signature_Error and then Status /= SMB.Signature_Error)
      then
         raise Program_Error with Label & " case" & Cases'Image
           & " status " & Status'Image;
      end if;
   end Check;
begin
   for Rebased in 0 .. 2 loop
      declare
         First : constant Natural :=
           (if Rebased = 2 then Natural'Last - (Seed'Length - 1)
            else 7 * Rebased);
         MIC_First : constant Natural :=
           (if Rebased = 2 then Natural'Last - 15 else 11 * Rebased);
         Token : SMB.Bytes (First .. First + (Seed'Length - 1));
         Expected : SMB.Bytes (MIC_First .. MIC_First + 15);
      begin
         for Offset in 0 .. Seed'Length - 1 loop
            for Value in SMB.Byte loop
               Token := Seed;
               Token (First + Offset) := Value;
               Check
                 (Token, Value = Seed (Seed'First + Offset),
                  "final SPNEGO byte mutation",
                  Signature_Error => Offset >= 13 and then
                    Value /= Seed (Seed'First + Offset));
            end loop;
         end loop;
         Token := Seed;
         for Cut in 0 .. Seed'Length - 1 loop
            declare
               Short : SMB.Bytes (First + 1 .. First + Cut);
            begin
               if Cut > 0 then
                  Short := Token (First .. First + Cut - 1);
               end if;
               Check (Short, False, "final SPNEGO truncation");
            end;
         end loop;
         Token := Seed;
         for Offset in 0 .. 15 loop
            for Value in SMB.Byte loop
               Expected := MIC;
               Expected (MIC_First + Offset) := Value;
               Check
                 (Token, Value = MIC (MIC'First + Offset),
                  "final SPNEGO expected MIC mutation",
                  Signature_Error => Value /= MIC (MIC'First + Offset),
                  Expected_MIC => Expected);
            end loop;
         end loop;
      end;
   end loop;
   for With_Mechanism in Boolean loop
      for With_Response in Boolean loop
         Check
           (Wrap (State_Field & (if With_Mechanism then Mechanism else Empty)
             & (if With_Response then Empty_Response else Empty) & MIC_Field),
            True, "supported optional final fields");
      end loop;
   end loop;
   Check (Wrap (State_Field), False, "missing MIC", Signature_Error => True);
   Check (Empty, False, "empty token with mandatory MIC", Signature_Error => True);
   Check (Wrap (State_Field & State_Field & MIC_Field), False, "duplicate state");
   Check (Wrap (State_Field & MIC_Field & MIC_Field), False, "duplicate MIC");
   Check (Wrap (MIC_Field & State_Field), False, "reordered final fields");
   Check (Wrap (MIC_Field), False, "missing complete state");
   Check (Seed & SMB.Bytes'(0 => 0), False, "trailing data");
   Check
     (SMB.Bytes'(16#A1#, 16#81#, 27) & Seed (Seed'First + 2 .. Seed'Last),
      False, "nonminimal long-form length");
   Check
     (SMB.Bytes'(16#A1#, 16#82#, 0, 27) & Seed (Seed'First + 2 .. Seed'Last),
      False, "leading zero DER length");
   Check
     (SMB.Bytes'(16#A1#, 16#80#) & Seed (Seed'First + 2 .. Seed'Last)
        & SMB.Bytes'(0, 0), False, "indefinite DER length");
   for Length in 0 .. 15 loop
      Check
        (Seed, False, "short expected MIC", Expected_MIC => MIC (MIC'First .. MIC'First + Length - 1));
   end loop;
   for Length in 0 .. 16 loop
      Check
        (Empty, Length = 0, "empty final token MIC policy",
         Signature_Error => Length /= 0,
         Expected_MIC => MIC (MIC'First .. MIC'First + Length - 1));
   end loop;
   Check (Wrap (State_Field), True, "MIC not required", Expected_MIC => Empty);
   Ada.Text_IO.Put_Line ("final SPNEGO mutation cases:" & Cases'Image);
end Spnego_Mutation_Tests;
