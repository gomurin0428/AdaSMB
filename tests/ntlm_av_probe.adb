with Ada.Text_IO;
with SMB.Core_Auth;
with SMB.Crypto;
with SMB.NTLM;

procedure NTLM_AV_Probe is
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

   --  An empty Expected means a rejection, with the status named by
   --  Rejection, or any status when Rejection is "-".
   procedure Check
     (Token, Expected_Key, Expected : SMB.Bytes; Clock : SMB.QWord;
      Rejection : String := "-")
   is
      Nonce : constant SMB.Bytes := Hex ("ffffff0011223344");
   begin
      for Rebased in 0 .. 1 loop
         declare
            First : constant Natural := 7 * Rebased;
            Input : constant SMB.Bytes
              (First .. First + Token'Length - 1) := Token;
            Output : SMB.Bytes (First .. First + 65_534) := (others => 16#EE#);
            Used : Natural := 1;
            Key : SMB.Crypto.Digest_128 := (others => 16#EE#);
            Status : SMB.Core_Status;
         begin
            SMB.Core_Auth.Authenticate
              ("User", "Password", "Domain", Nonce, Input, Clock,
               Output, Used, Key, Status);
            if Expected'Length = 0 then
               if Status = SMB.Ok or else Used /= 0
                 or else Key /= (Key'Range => 0)
               then
                  raise Program_Error with "malformed AV input exposed authentication output";
               end if;
               if Rejection /= "-"
                 and then Status /= SMB.Core_Status'Value (Rejection)
               then
                  raise Program_Error with "AV rejection status " & Status'Image
                    & ", expected " & Rejection;
               end if;
               begin
                  declare
                     Unexpected : constant SMB.NTLM.Authentication_Result :=
                       SMB.NTLM.Authenticate
                         ("User", "Password", "Domain", Nonce, Input, Clock);
                     pragma Unreferenced (Unexpected);
                  begin
                     raise Program_Error with "public API accepted malformed AV input";
                  end;
               exception
                  --  A message too large to build is a resource limit, not
                  --  a protocol violation.
                  when SMB.Protocol_Error =>
                     if Rejection = "Resource_Limit" then
                        raise Program_Error with "public API reported a resource limit as a protocol error";
                     end if;
                  when SMB.Authentication_Error =>
                     if Rejection /= "Resource_Limit" then
                        raise;
                     end if;
               end;
            else
               if Status /= SMB.Ok or else Used /= Expected'Length
                 or else Key /= Expected_Key
                 or else Output (First .. First + Used - 1) /= Expected
               then
                  raise Program_Error with "AV authentication oracle mismatch: "
                    & Status'Image;
               end if;
               declare
                  Result : constant SMB.NTLM.Authentication_Result :=
                    SMB.NTLM.Authenticate
                      ("User", "Password", "Domain", Nonce, Input, Clock);
               begin
                  if Result.Session_Key /= Expected_Key
                    or else Result.Security_Token /= Expected
                  then
                     raise Program_Error with "public AV authentication oracle mismatch";
                  end if;
               end;
            end if;
         end;
      end loop;
   end Check;

   Count : Natural := 0;
begin
   while not Ada.Text_IO.End_Of_File loop
      declare
         Line : constant String := Ada.Text_IO.Get_Line;
         Separators : array (1 .. 3) of Natural := (others => 0);
         Found : Natural := 0;
      begin
         for I in Line'Range loop
            if Line (I) = ' ' then
               Found := Found + 1;
               if Found > 3 then
                  raise Program_Error with "too many fixture fields";
               end if;
               Separators (Found) := I;
            end if;
         end loop;
         if Found /= 3 then
            raise Program_Error with "missing fixture fields";
         end if;
         declare
            Key_Field : constant String :=
              Line (Separators (2) + 1 .. Separators (3) - 1);
            Rejected : constant Boolean :=
              Line (Separators (3) + 1 .. Line'Last) = "-";
         begin
            Check
              (Hex (Line (1 .. Separators (1) - 1)),
               (if Rejected then Hex ("-") else Hex (Key_Field)),
               Hex (Line (Separators (3) + 1 .. Line'Last)),
               SMB.QWord'Value (Line (Separators (1) + 1 .. Separators (2) - 1)),
               (if Rejected then Key_Field else "-"));
         end;
         Count := Count + 1;
      end;
   end loop;
   Ada.Text_IO.Put_Line ("PASS" & Count'Image);
exception
   when others =>
      Ada.Text_IO.Put_Line (Ada.Text_IO.Standard_Error,
        "NTLM AV fixture" & Natural'Image (Count + 1));
      raise;
end NTLM_AV_Probe;
