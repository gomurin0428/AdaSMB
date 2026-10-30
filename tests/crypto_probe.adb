with Ada.Unchecked_Deallocation;
with Ada.Text_IO;
with SMB.Crypto;
with SMB.Core_NTLM;
with SMB.Core_Wire;
with SMB.Wire;

procedure Crypto_Probe is
   use type SMB.Bytes;
   use type SMB.Core_Status;

   type Bytes_Access is access SMB.Bytes;
   type String_Access is access String;
   procedure Free_Bytes is new Ada.Unchecked_Deallocation
     (SMB.Bytes, Bytes_Access);

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
         raise Program_Error with "invalid fixture length";
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

   procedure Check_Hashes (Data, MD4, MD5, SHA256 : SMB.Bytes) is
   begin
      for Rebased in 0 .. 1 loop
         declare
            First : constant Natural := 7 * Rebased;
            Input : Bytes_Access := null;
         begin
            Input := new SMB.Bytes (First .. First + Data'Length - 1);
            Input.all := Data;
            if SMB.Crypto.MD4 (Input.all) /= MD4 then
               raise Program_Error with "MD4 mismatch";
            end if;
            if SMB.Crypto.MD5 (Input.all) /= MD5 then
               raise Program_Error with "MD5 mismatch";
            end if;
            if SMB.Crypto.SHA256 (Input.all) /= SHA256 then
               raise Program_Error with "SHA256 mismatch";
            end if;
            Free_Bytes (Input);
         exception
            when others =>
               Free_Bytes (Input);
               raise;
         end;
      end loop;
   end Check_Hashes;

   procedure Check_HMAC (Key, Data, MD5, SHA256 : SMB.Bytes) is
   begin
      for Key_Rebased in 0 .. 1 loop
         for Data_Rebased in 0 .. 1 loop
            declare
               Key_First : constant Natural := 7 * Key_Rebased;
               Data_First : constant Natural := 7 * Data_Rebased;
               Input_Key : Bytes_Access := null;
               Input_Data : Bytes_Access := null;
            begin
               Input_Key := new SMB.Bytes
                 (Key_First .. Key_First + Key'Length - 1);
               Input_Data := new SMB.Bytes
                 (Data_First .. Data_First + Data'Length - 1);
               Input_Key.all := Key;
               Input_Data.all := Data;
               if SMB.Crypto.HMAC_MD5 (Input_Key.all, Input_Data.all) /= MD5 then
                  raise Program_Error with "HMAC-MD5 mismatch";
               end if;
               if SMB.Crypto.HMAC_SHA256 (Input_Key.all, Input_Data.all) /= SHA256 then
                  raise Program_Error with "HMAC-SHA256 mismatch";
               end if;
               Free_Bytes (Input_Data);
               Free_Bytes (Input_Key);
            exception
               when others =>
                  Free_Bytes (Input_Data);
                  Free_Bytes (Input_Key);
                  raise;
            end;
         end loop;
      end loop;
   end Check_HMAC;

   procedure Check_MIC (Key : SMB.Bytes; From_Server : Boolean;
                        Expected : SMB.Bytes) is
   begin
      if Key'Length /= 16 or else Expected'Length /= 16 then
         raise Program_Error with "invalid MIC fixture";
      end if;
      if SMB.Core_NTLM.Mechanism_List_MIC
        (SMB.Crypto.Digest_128 (Key), From_Server) /= Expected
      then
         raise Program_Error with "mechanism-list MIC mismatch";
      end if;
   end Check_MIC;

   procedure Check_Wire
     (Key, Data, Expected : SMB.Bytes;
      Expected_Status : SMB.Core_Status;
      Signing : Boolean;
      Expected_Valid : Boolean := False)
   is
   begin
      for Key_Rebased in 0 .. 1 loop
         for Data_Rebased in 0 .. 1 loop
            declare
               Key_First : constant Natural := 7 * Key_Rebased;
               Data_First : constant Natural := 7 * Data_Rebased;
               Input_Key : Bytes_Access := null;
               Input_Data : Bytes_Access := null;
               Status : SMB.Core_Status;
               Valid : Boolean := True;
            begin
               Input_Key := new SMB.Bytes
                 (Key_First .. Key_First + Key'Length - 1);
               Input_Data := new SMB.Bytes
                 (Data_First .. Data_First + Data'Length - 1);
               Input_Key.all := Key;
               Input_Data.all := Data;
               if Signing then
                  SMB.Core_Wire.Sign (Input_Data.all, Input_Key.all, Status);
                  if Status /= Expected_Status or else Input_Data.all /= Expected then
                     raise Program_Error with "core signing mismatch";
                  end if;
                  Input_Data.all := Data;
                  begin
                     SMB.Wire.Sign (Input_Data.all, Input_Key.all);
                     if Expected_Status /= SMB.Ok then
                        raise Program_Error with "public signing accepted invalid input";
                     end if;
                  exception
                     when SMB.Protocol_Error =>
                        if Expected_Status = SMB.Ok then
                           raise Program_Error with "public signing rejected valid input";
                        end if;
                  end;
                  if Input_Data.all /= Expected then
                     raise Program_Error with "public signing output mismatch";
                  end if;
               else
                  SMB.Core_Wire.Verify_Signature
                    (Input_Data.all, Input_Key.all, Valid, Status);
                  if Status /= Expected_Status or else Valid /= Expected_Valid then
                     raise Program_Error with "core verification mismatch";
                  end if;
                  if SMB.Wire.Verify_Signature (Input_Data.all, Input_Key.all)
                    /= Expected_Valid
                  then
                     raise Program_Error with "public verification mismatch";
                  end if;
               end if;
               Free_Bytes (Input_Data);
               Free_Bytes (Input_Key);
            exception
               when others =>
                  Free_Bytes (Input_Data);
                  Free_Bytes (Input_Key);
                  raise;
            end;
         end loop;
      end loop;
   end Check_Wire;

   Count : Natural := 0;
   Line_Buffer : constant String_Access :=
     new String (1 .. 6 * SMB.Maximum_Frame_Size + 128);
begin
   while not Ada.Text_IO.End_Of_File loop
      declare
         Line_Last : Natural;
      begin
         Ada.Text_IO.Get_Line (Line_Buffer.all, Line_Last);
         declare
            Line : String renames Line_Buffer (1 .. Line_Last);
            Boundaries : array (0 .. 5) of Natural :=
              (5 => Line'Last + 1, others => 0);
            Found : Natural := 0;

            function Field (Index : Positive) return String is
              (Line (Boundaries (Index - 1) + 1 ..
                     Boundaries (Index) - 1));
         begin
            for I in Line'Range loop
               if Line (I) = ' ' then
                  Found := Found + 1;
                  if Found > 4 then
                     raise Program_Error with "too many fixture fields";
                  end if;
                  Boundaries (Found) := I;
               end if;
            end loop;
            if Found /= 4 then
               raise Program_Error with "missing fixture fields";
            end if;
            if Field (1) = "D" then
               Check_Hashes
                 (Hex (Field (2)), Hex (Field (3)),
                  Hex (Field (4)), Hex (Field (5)));
            elsif Field (1) = "H" then
              Check_HMAC
                (Hex (Field (2)), Hex (Field (3)),
                 Hex (Field (4)), Hex (Field (5)));
            elsif Field (1) = "M" then
               if Field (5) /= "-" then
                  raise Program_Error with "invalid MIC fixture";
               end if;
               Check_MIC
                 (Hex (Field (2)), Boolean'Value (Field (3)), Hex (Field (4)));
            elsif Field (1) = "S" then
               Check_Wire
                 (Hex (Field (2)), Hex (Field (3)), Hex (Field (4)),
                  SMB.Core_Status'Value (Field (5)), Signing => True);
            elsif Field (1) = "V" then
               Check_Wire
                 (Hex (Field (2)), Hex (Field (3)), SMB.Bytes'(1 .. 0 => 0),
                  SMB.Core_Status'Value (Field (5)), Signing => False,
                  Expected_Valid => Boolean'Value (Field (4)));
            else
               raise Program_Error with "unknown fixture operation";
            end if;
            Count := Count + 1;
         end;
      end;
   end loop;
   Ada.Text_IO.Put_Line ("PASS" & Count'Image);
exception
   when others =>
      Ada.Text_IO.Put_Line (Ada.Text_IO.Standard_Error,
        "crypto fixture" & Natural'Image (Count + 1));
      raise;
end Crypto_Probe;
