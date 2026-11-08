with Ada.Unchecked_Deallocation;
with Ada.Text_IO;
with SMB.AES;
with SMB.AES.CMAC;
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

   --  One-shot and in three incremental parts, at two array lower bounds.
   procedure Check_SHA512 (Data, SHA512 : SMB.Bytes) is
   begin
      for Rebased in 0 .. 1 loop
         declare
            First : constant Natural := 7 * Rebased;
            Input : Bytes_Access := null;
            Context : SMB.Crypto.SHA512_Context;
            Digest : SMB.Crypto.Digest_512;
         begin
            Input := new SMB.Bytes (First .. First + Data'Length - 1);
            Input.all := Data;
            if SMB.Crypto.SHA512 (Input.all) /= SHA512 then
               raise Program_Error with "SHA512 mismatch";
            end if;
            declare
               Third : constant Natural := Data'Length / 3;
            begin
               SMB.Crypto.SHA512_Start (Context);
               SMB.Crypto.SHA512_Update
                 (Context, Input (First .. First + Third - 1));
               SMB.Crypto.SHA512_Update
                 (Context, Input (First + Third .. First + 2 * Third - 1));
               SMB.Crypto.SHA512_Update
                 (Context, Input (First + 2 * Third .. Input'Last));
               SMB.Crypto.SHA512_Finish (Context, Digest);
            end;
            if Digest /= SHA512 then
               raise Program_Error with "incremental SHA512 mismatch";
            end if;
            Free_Bytes (Input);
         exception
            when others =>
               Free_Bytes (Input);
               raise;
         end;
      end loop;
   end Check_SHA512;

   --  The schedule is used twice, to check that encrypting leaves it intact.
   procedure Check_AES (Key, Plain, Cipher : SMB.Bytes) is
      Schedule : SMB.AES.Key_Schedule;
      Key_Block : SMB.AES.Key_128;
      Plain_Block, Cipher_Block : SMB.AES.Block;
   begin
      if Key'Length /= 16 or else Plain'Length /= 16
        or else Cipher'Length /= 16
      then
         raise Program_Error with "invalid AES fixture";
      end if;
      Key_Block := Key;
      Plain_Block := Plain;
      Cipher_Block := Cipher;
      SMB.AES.Expand_Key (Key_Block, Schedule);
      for Repeat in 1 .. 2 loop
         if SMB.AES.Encrypt (Schedule, Plain_Block) /= Cipher_Block then
            raise Program_Error with "AES mismatch";
         end if;
      end loop;
   end Check_AES;

   --  One-shot at three lower bounds (the last one ends just below
   --  Natural'Last) and incrementally: in the pieces Core_Wire signs (48
   --  bytes, 16, the rest) and in thirds at each bound; at the first, in two
   --  parts at every point (around each block boundary past 80 bytes), in
   --  three parts at every pair of points up to 40 bytes, and byte by byte
   --  up to 300. Past 4,096 bytes only the one-shot runs and the Core_Wire
   --  pieces at the first bound remain. One context serves every run, so
   --  each Start must reset a finished context, and the first one an
   --  abandoned context under another key.
   type Offsets is array (Positive range <>) of Natural;

   procedure Check_CMAC (Key, Data, Expected : SMB.Bytes) is
      Length : constant Natural := Data'Length;
      Key_Block : SMB.AES.Key_128;
      Context : SMB.AES.CMAC.MAC_Context;
      Result : SMB.AES.CMAC.Tag_128;
      Input : Bytes_Access := null;

      --  Feeds Input in pieces that end at each cut, then the rest.
      procedure Run (Cuts : Offsets) is
         From : Natural := Input'First;
      begin
         SMB.AES.CMAC.Start (Context, Key_Block);
         for Cut of Cuts loop
            SMB.AES.CMAC.Update (Context, Input (From .. Input'First + Cut - 1));
            if SMB.AES.CMAC.Length (Context) /= Cut then
               raise Program_Error with "CMAC length mismatch";
            end if;
            From := Input'First + Cut;
         end loop;
         SMB.AES.CMAC.Update (Context, Input (From .. Input'Last));
         if not SMB.AES.CMAC.Ready (Context)
           or else SMB.AES.CMAC.Length (Context) /= Length
         then
            raise Program_Error with "CMAC length mismatch";
         end if;
         SMB.AES.CMAC.Finish (Context, Result);
         if SMB.AES.CMAC.Ready (Context) then
            raise Program_Error with "finished CMAC context is ready";
         end if;
         if Result /= Expected then
            raise Program_Error with "incremental CMAC mismatch";
         end if;
      end Run;

      procedure Run_Near_Boundaries is
      begin
         for Boundary in 0 .. 4 loop
            for Offset in -1 .. 1 loop
               if 16 * Boundary + Offset in 0 .. Length then
                  Run ((1 => 16 * Boundary + Offset));
               end if;
               if Length - 16 * Boundary + Offset in 0 .. Length then
                  Run ((1 => Length - 16 * Boundary + Offset));
               end if;
            end loop;
         end loop;
      end Run_Near_Boundaries;
   begin
      if Key'Length /= 16 or else Expected'Length /= 16 then
         raise Program_Error with "invalid CMAC fixture";
      end if;
      Key_Block := Key;
      SMB.AES.CMAC.Start (Context, (others => 16#A5#));
      SMB.AES.CMAC.Update (Context, (1 .. 21 => 16#5A#));
      for Base in 0 .. 2 loop
         declare
            First : constant Natural :=
              (case Base is
                  when 0 => 0,
                  when 1 => 7,
                  when others => Natural'Last - Length);
         begin
            Input := new SMB.Bytes (First .. First + (Length - 1));
            Input.all := Data;
            if SMB.AES.CMAC.MAC (Key_Block, Input.all) /= Expected then
               raise Program_Error with "CMAC mismatch";
            end if;
            if Length >= 64 and then (Base = 0 or else Length <= 4096) then
               Run ((48, 64));
            end if;
            if Length <= 4096 then
               Run ((Length / 3, 2 * Length / 3));
            end if;
            if Base = 0 and then Length <= 4096 then
               if Length <= 80 then
                  for Cut in 0 .. Length loop
                     Run ((1 => Cut));
                  end loop;
               else
                  Run_Near_Boundaries;
               end if;
               if Length <= 40 then
                  for Cut_1 in 0 .. Length loop
                     for Cut_2 in Cut_1 .. Length loop
                        Run ((Cut_1, Cut_2));
                     end loop;
                  end loop;
               end if;
               if Length <= 300 then
                  declare
                     Bytes : Offsets (1 .. Length - 1);
                  begin
                     for I in Bytes'Range loop
                        Bytes (I) := I;
                     end loop;
                     Run (Bytes);
                  end;
               end if;
            end if;
            Free_Bytes (Input);
         exception
            when others =>
               Free_Bytes (Input);
               raise;
         end;
      end loop;
   end Check_CMAC;

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
            elsif Field (1) = "X" then
               if Field (4) /= "-" or else Field (5) /= "-" then
                  raise Program_Error with "invalid SHA-512 fixture";
               end if;
               Check_SHA512 (Hex (Field (2)), Hex (Field (3)));
            elsif Field (1) = "A" then
               if Field (5) /= "-" then
                  raise Program_Error with "invalid AES fixture";
               end if;
               Check_AES (Hex (Field (2)), Hex (Field (3)), Hex (Field (4)));
            elsif Field (1) = "C" then
               if Field (5) /= "-" then
                  raise Program_Error with "invalid CMAC fixture";
               end if;
               Check_CMAC (Hex (Field (2)), Hex (Field (3)), Hex (Field (4)));
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
