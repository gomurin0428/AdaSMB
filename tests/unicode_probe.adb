with Ada.Text_IO;
with SMB;
with SMB.Core_Text;
with SMB.Text;

procedure Unicode_Probe is
   use type SMB.Bytes;
   use type SMB.Core_Status;

   function Hex (Value : String) return SMB.Bytes is
      function Digit (C : Character) return Natural is
      begin
         case C is
            when '0' .. '9' => return Character'Pos (C) - Character'Pos ('0');
            when 'a' .. 'f' => return Character'Pos (C) - Character'Pos ('a') + 10;
            when others => raise Program_Error with "invalid fixture hex";
         end case;
      end Digit;
   begin
      if Value = "-" then
         return SMB.Bytes'(1 .. 0 => 0);
      end if;
      if Value'Length = 0 or else Value'Length mod 2 /= 0 then
         raise Program_Error with "invalid fixture hex length";
      end if;
      declare
         Result : SMB.Bytes (1 .. Value'Length / 2);
      begin
         for I in Result'Range loop
            Result (I) := SMB.Byte
              (16 * Digit (Value (Value'First + 2 * (I - 1)))
               + Digit (Value (Value'First + 2 * (I - 1) + 1)));
         end loop;
         return Result;
      end;
   end Hex;

   function As_String (Value : SMB.Bytes) return String is
      Result : String (11 .. 10 + Value'Length);
   begin
      for I in Result'Range loop
         Result (I) := Character'Val (Value (Value'First + I - Result'First));
      end loop;
      return Result;
   end As_String;

   procedure Check_8
     (Input, Expected : SMB.Bytes; Expected_Status : SMB.Core_Status) is
      Capacity : constant Natural :=
        (if Expected_Status = SMB.Ok then Expected'Length else 2 * Input'Length);
      Output : SMB.Bytes (7 .. 6 + Capacity);
      Used : Natural;
      Status : SMB.Core_Status;
      Text : constant String := As_String (Input);
   begin
      SMB.Core_Text.UTF8_To_UTF16 (Text, Output, Used, Status);
      if Status /= Expected_Status or else Used > Capacity
        or else Used mod 2 /= 0
      then
         raise Program_Error with "UTF-8 status/bounds mismatch: "
           & SMB.Core_Status'Image (Status);
      end if;
      if Status = SMB.Ok then
         if Used /= Expected'Length
           or else Output (Output'First .. Output'First + Used - 1) /= Expected
           or else SMB.Text.To_UTF16LE (Text) /= Expected
         then
            raise Program_Error with "UTF-8 result mismatch";
         end if;
         declare
            Ample_Output : SMB.Bytes (31 .. 30 + 2 * Input'Length);
            Ample_Used : Natural;
            Ample_Status : SMB.Core_Status;
         begin
            SMB.Core_Text.UTF8_To_UTF16
              (Text, Ample_Output, Ample_Used, Ample_Status);
            if Ample_Status /= SMB.Ok or else Ample_Used /= Expected'Length
              or else Ample_Output
                (Ample_Output'First .. Ample_Output'First + Ample_Used - 1)
                  /= Expected
            then
               raise Program_Error with "UTF-8 ample-buffer result mismatch";
            end if;
         end;
      else
         begin
            declare
               Unexpected : constant SMB.Bytes := SMB.Text.To_UTF16LE (Text);
               pragma Unreferenced (Unexpected);
            begin
               raise Program_Error with "public UTF-8 accepted invalid input";
            end;
         exception
            when SMB.Protocol_Error => null;
         end;
      end if;
   end Check_8;

   procedure Check_16
     (Input, Expected : SMB.Bytes; Expected_Status : SMB.Core_Status) is
      Capacity : constant Natural :=
        (if Expected_Status = SMB.Ok then Expected'Length else 2 * Input'Length);
      Output : String (13 .. 12 + Capacity);
      Used : Natural;
      Status : SMB.Core_Status;
      Validation_Status : SMB.Core_Status;
      Validation_Input : constant SMB.Bytes (29 .. 28 + Input'Length) := Input;
   begin
      SMB.Core_Text.Validate_UTF16 (Validation_Input, Validation_Status);
      if Validation_Status /= Expected_Status then
         raise Program_Error with "UTF-16 validator status mismatch: "
           & SMB.Core_Status'Image (Validation_Status);
      end if;
      SMB.Core_Text.UTF16_To_UTF8 (Input, Output, Used, Status);
      if Status /= Expected_Status or else Used > Capacity then
         raise Program_Error with "UTF-16 status/bounds mismatch: "
           & SMB.Core_Status'Image (Status);
      end if;
      if Status = SMB.Ok then
         if Used /= Expected'Length
           or else Output (Output'First .. Output'First + Used - 1) /=
             As_String (Expected)
           or else SMB.Text.From_UTF16LE (Input) /= As_String (Expected)
         then
            raise Program_Error with "UTF-16 result mismatch";
         end if;
         declare
            Ample_Output : String (23 .. 22 + 2 * Input'Length);
            Ample_Used : Natural;
            Ample_Status : SMB.Core_Status;
         begin
            SMB.Core_Text.UTF16_To_UTF8
              (Input, Ample_Output, Ample_Used, Ample_Status);
            if Ample_Status /= SMB.Ok or else Ample_Used /= Expected'Length
              or else Ample_Output
                (Ample_Output'First .. Ample_Output'First + Ample_Used - 1)
                  /= As_String (Expected)
            then
               raise Program_Error with "UTF-16 ample-buffer result mismatch";
            end if;
         end;
      else
         begin
            declare
               Unexpected : constant String := SMB.Text.From_UTF16LE (Input);
               pragma Unreferenced (Unexpected);
            begin
               raise Program_Error with "public UTF-16 accepted invalid input";
            end;
         exception
            when SMB.Protocol_Error => null;
         end;
      end if;
   end Check_16;

   Line : String (1 .. 4_096);
   Last : Natural := 0;
   Count : Natural := 0;
begin
   while not Ada.Text_IO.End_Of_File loop
      Ada.Text_IO.Get_Line (Line, Last);
      if Last < 5 or else Last = Line'Length or else Line (2) /= ' ' then
         raise Program_Error with "invalid fixture line";
      end if;
      declare
         Separator : Natural := 0;
      begin
         for I in 3 .. Last loop
            if Line (I) = ' ' then
               Separator := I;
               exit;
            end if;
         end loop;
         if Separator = 0 or else Separator = Last then
            raise Program_Error with "invalid fixture separator";
         end if;
         declare
            Input : constant SMB.Bytes := Hex (Line (3 .. Separator - 1));
            Expected_Text : constant String := Line (Separator + 1 .. Last);
            Status : constant SMB.Core_Status :=
              (if Expected_Text = "E" then SMB.Invalid_Encoding
               elsif Expected_Text = "L" then SMB.Invalid_Length else SMB.Ok);
            Expected : constant SMB.Bytes :=
              (if Status = SMB.Ok then Hex (Expected_Text)
               else SMB.Bytes'(1 .. 0 => 0));
         begin
            case Line (1) is
               when 'P' =>
                  if Status /= SMB.Ok then
                     raise Program_Error with "pair fixture must be valid";
                  end if;
                  Check_8 (Input, Expected, SMB.Ok);
                  Check_16 (Expected, Input, SMB.Ok);
               when '8' => Check_8 (Input, Expected, Status);
               when '6' => Check_16 (Input, Expected, Status);
               when others => raise Program_Error with "invalid fixture mode";
            end case;
         end;
      end;
      Count := Count + 1;
   end loop;
   Ada.Text_IO.Put_Line ("PASS" & Natural'Image (Count));
exception
   when others =>
      Ada.Text_IO.Put_Line
        (Ada.Text_IO.Standard_Error,
         "Fixture" & Natural'Image (Count + 1) & ": " & Line (1 .. Last));
      raise;
end Unicode_Probe;
