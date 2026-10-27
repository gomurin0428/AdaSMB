with Ada.Text_IO;
with SMB.Core_NTLM;

procedure Challenge_Mutation_Tests is
   use type SMB.Byte;
   use type SMB.Bytes;
   use type SMB.Core_Status;

   Header : constant SMB.Bytes :=
     (16#4E#, 16#54#, 16#4C#, 16#4D#, 16#53#, 16#53#, 16#50#, 0, 2, 0, 0, 0);
   State_Field : constant SMB.Bytes := (16#A0#, 3, 16#0A#, 1, 1);
   Mechanism : constant SMB.Bytes :=
     (16#A1#, 12, 6, 10, 16#2B#, 6, 1, 4, 1, 16#82#, 16#37#, 2, 2, 10);
   SPNEGO_OID : constant SMB.Bytes := (6, 6, 16#2B#, 6, 1, 5, 5, 2);
   Cases : Natural := 0;

   function TLV (Tag : SMB.Byte; Content : SMB.Bytes) return SMB.Bytes is
   begin
      if Content'Length < 128 then
         return SMB.Bytes'(Tag, SMB.Byte (Content'Length)) & Content;
      elsif Content'Length < 256 then
         return SMB.Bytes'(Tag, 16#81#, SMB.Byte (Content'Length)) & Content;
      else
         return SMB.Bytes'(Tag, 16#82#, SMB.Byte (Content'Length / 256),
                           SMB.Byte (Content'Length mod 256)) & Content;
      end if;
   end TLV;

   function Type2 (Length : Natural) return SMB.Bytes is
      Result : SMB.Bytes (0 .. Length - 1) := (others => 0);
   begin
      Result (0 .. 11) := Header;
      return Result;
   end Type2;

   function Wrap (Fields : SMB.Bytes; GSS : Boolean) return SMB.Bytes is
      Response : constant SMB.Bytes := TLV (16#A1#, TLV (16#30#, Fields));
   begin
      return (if GSS then TLV (16#60#, SPNEGO_OID & Response) else Response);
   end Wrap;

   function Response_Field (Length : Natural) return SMB.Bytes is
     (TLV (16#A2#, TLV (4, Type2 (Length))));

   procedure Check
     (Token : SMB.Bytes; Should_Accept : Boolean; Label : String;
      Expected_Length : Natural := 48)
   is
      Offset, Length : Natural := Natural'Last;
      Status : SMB.Core_Status;
   begin
      SMB.Core_NTLM.Extract_Challenge (Token, Offset, Length, Status);
      Cases := Cases + 1;
      if (Status = SMB.Ok) /= Should_Accept then
         raise Program_Error with Label & " case" & Cases'Image
           & " status " & Status'Image;
      end if;
      if Should_Accept then
         if Length /= Expected_Length
           or else Offset /= Token'Length - Expected_Length
           or else Token (Token'First + Offset .. Token'Last) /= Type2 (Expected_Length)
         then
            raise Program_Error with "incorrect extracted challenge slice";
         end if;
      elsif Offset /= 0 or else Length /= 0 then
         raise Program_Error with "failed challenge extraction published a partial slice";
      end if;
   end Check;

   Lengths : constant array (Positive range <>) of Natural :=
     (48, 127, 128, 255, 256, 4096, 65_500);
begin
   for GSS in Boolean loop
      declare
         Seed : constant SMB.Bytes :=
           Wrap (State_Field & Mechanism & Response_Field (48), GSS);
         Offset : constant Natural := Seed'Length - 48;
         State_Position : constant Natural := (if GSS then 18 else 8);
      begin
         for Rebased in 0 .. 1 loop
            declare
               First : constant Natural := 7 * Rebased;
               Token : SMB.Bytes (First .. First + Seed'Length - 1);
            begin
               for Position in 0 .. Offset + 11 loop
                  for Value in SMB.Byte loop
                     Token := Seed;
                     Token (First + Position) := Value;
                     Check
                       (Token, Value = Seed (Seed'First + Position)
                        or else (Position = State_Position and then Value = 3),
                        "challenge prefix mutation");
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
                     Check (Short, False, "challenge truncation");
                  end;
               end loop;
            end;
         end loop;
         Check
           (Wrap (State_Field & Mechanism & Response_Field (48)
             & Response_Field (48), GSS), False, "duplicate response after extraction");
         Check
           (Wrap (State_Field & Mechanism & Response_Field (48)
             & SMB.Bytes'(16#A3#, 2, 4, 0), GSS), False,
            "unsupported field after extraction");
         Check
           (Wrap (State_Field & Mechanism & Response_Field (48)
             & State_Field, GSS), False, "reordered state after extraction");
         for Size of Lengths loop
            declare
               Length : constant Natural :=
                 (if GSS and Size = 65_500 then 65_488 else Size);
            begin
               Check
                 (Wrap (State_Field & Mechanism & Response_Field (Length), GSS),
                  True, "DER length boundary", Length);
            end;
         end loop;
      end;
   end loop;
   Ada.Text_IO.Put_Line ("challenge extraction cases:" & Cases'Image);
end Challenge_Mutation_Tests;
