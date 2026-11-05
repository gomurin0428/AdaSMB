with Ada.Exceptions;
with Ada.Text_IO;
with Ada.Streams;
with Ada.Command_Line;
with Ada.Characters.Handling;
with SMB;
with SMB.Core_Auth;
with SMB.Clock;
with SMB.Core_Clock;
with SMB.Core_Client;
with SMB.Core_Connection;
with SMB.Core_Framing;
with SMB.Core_NTLM;
with SMB.Core_Protocol;
with SMB.Core_Text;
with SMB.Core_Transport;
with SMB.Core_Wire;
with SMB.Crypto;
with SMB.Engine;
with SMB.Entropy;
with SMB.NTLM;
with SMB.Text;
with SMB.Wire;
with Response_Mutation_Tests;
with Header_Mutation_Tests;
with Security_Buffer_Tests;
with Spnego_Mutation_Tests;
with Challenge_Mutation_Tests;
with Async_Engine_Tests;
with SMB.Heap_Owner_Tests;

procedure Test_Suite is
   use type SMB.Core_Status;
   use type SMB.Core_Wire.Command_Code;
   use type SMB.Engine.Access_Kind;
   use type SMB.Engine.Phase;
   use type SMB.Core_Client.Transfer_Stage;
   use type SMB.Core_Client.Authentication_Stage;
   use type SMB.Core_Connection.Connection_State_Snapshot;
   use type SMB.Core_Connection.Connection_Stage;
   use type SMB.Bytes;

   use type SMB.Byte;
   use type SMB.DWord;
   use type SMB.QWord;
   use type SMB.Word;

   procedure Assert (Condition : Boolean; Message : String) is
   begin
      if not Condition then
         raise Program_Error with Message;
      end if;
   end Assert;

   --  Fails unless Action raises the exception Error.
   procedure Expect_Error
     (Action : not null access procedure;
      Error : Ada.Exceptions.Exception_Id;
      Message : String)
   is
      use type Ada.Exceptions.Exception_Id;
   begin
      begin
         Action.all;
      exception
         when Raised : others =>
            if Ada.Exceptions.Exception_Identity (Raised) = Error then
               return;
            end if;
            raise Program_Error with
              Message & ": raised " & Ada.Exceptions.Exception_Name (Raised);
      end;
      raise Program_Error with Message;
   end Expect_Error;

   procedure Test_Authentication_Preflight is
      procedure Check
        (User, Password, Domain : String; Expected : SMB.Core_Status) is
         Status : SMB.Core_Status;
      begin
         SMB.Core_Auth.Validate_Credentials (User, Password, Domain, Status);
         Assert (Status = Expected, "credential preflight status mismatch");
      end Check;
      Euro : constant String :=
        Character'Val (16#E2#) & Character'Val (16#82#)
        & Character'Val (16#AC#);
      Invalid_UTF8 : constant String := (1 => Character'Val (16#FF#));
      Nul : constant String := (1 => Character'Val (0));
      Maximum : constant String
        (31 .. 30 + SMB.Core_Auth.Maximum_Credential_Bytes) := (others => 'a');
      Excess : constant String
        (31 .. 31 + SMB.Core_Auth.Maximum_Credential_Bytes) := (others => 'a');
   begin
      Check ("user", "", "", SMB.Ok);
      Check ("user", Euro, Euro, SMB.Ok);
      Check (Maximum, Maximum, Maximum, SMB.Ok);
      Check (Excess, "", "", SMB.Resource_Limit);
      Check ("user", Excess, "", SMB.Resource_Limit);
      Check ("user", "", Excess, SMB.Resource_Limit);
      Check ("", "", "", SMB.Unsupported_Feature);
      Check (Euro, "", "", SMB.Unsupported_Feature);
      Check (Nul, "", "", SMB.Unsupported_Feature);
      Check ("user", Invalid_UTF8, "", SMB.Unsupported_Feature);
      Check ("user", "", Invalid_UTF8, SMB.Unsupported_Feature);
      Check ("user", Nul, "", SMB.Unsupported_Feature);
      Check ("user", "", Nul, SMB.Unsupported_Feature);
   end Test_Authentication_Preflight;

   procedure Test_NTLM_Uppercase is
      Count : Natural := 0;

      procedure Check
        (Input : String; Capacity : Natural; Output_First : Positive := 29) is
         Output : String (Output_First .. Output_First - 1 + Capacity) :=
           (others => '!');
         Status : SMB.Core_Status;
         Expected_Status : constant SMB.Core_Status :=
           (if Capacity /= Input'Length then SMB.Invalid_Length
            elsif (for all C of Input => Character'Pos (C) < 128) then SMB.Ok
            else SMB.Invalid_Encoding);
      begin
         SMB.Core_Text.Uppercase_NTLM_User (Input, Output, Status);
         Assert (Status = Expected_Status, "NTLM uppercase exact status");
         if Status = SMB.Ok then
            Assert
              (Output = Ada.Characters.Handling.To_Upper (Input),
               "NTLM uppercase character correspondence");
         elsif Status = SMB.Invalid_Length then
            Assert
              ((for all C of Output => C = Character'Val (0)),
               "NTLM uppercase length rejection clears output");
         end if;
         if Capacity = Input'Length then
            if Expected_Status = SMB.Ok then
               Assert
                 (SMB.Text.NTLM_Username (Input) =
                    Ada.Characters.Handling.To_Upper (Input),
                  "public NTLM uppercase correspondence");
            else
               begin
                  declare
                     Unexpected : constant String :=
                       SMB.Text.NTLM_Username (Input);
                     pragma Unreferenced (Unexpected);
                  begin
                     raise Program_Error with "public NTLM accepted non-ASCII";
                  end;
               exception
                  when SMB.Authentication_Error => null;
               end;
            end if;
         end if;
         Count := Count + 1;
      end Check;
   begin
      for Code in 0 .. 255 loop
         Check (String'(17 => Character'Val (Code)), 1);
         for Position in 17 .. 19 loop
            declare
               Input : String (17 .. 19) := "azm";
            begin
               Input (Position) := Character'Val (Code);
               for Capacity in 0 .. 4 loop
                  Check (Input, Capacity);
               end loop;
            end;
         end loop;
      end loop;
      Check ("", 0);
      Check ("", 1);
      Check
        (String'(1 .. SMB.Core_Auth.Maximum_Credential_Bytes => 'a'),
         SMB.Core_Auth.Maximum_Credential_Bytes);
      Check (String'(Positive'Last => 'z'), 1, Positive'Last);
      Assert (Count = 4_100, "NTLM uppercase coverage");
      Ada.Text_IO.Put_Line ("NTLM uppercase: 4100 cases passed");
   end Test_NTLM_Uppercase;

   procedure Test_UTF_Capacity is
      procedure Check_Vector
        (UTF8 : String; UTF16 : SMB.Bytes;
         UTF8_Prefix : Natural := 0; UTF16_Prefix : Natural := 0) is
         Input_8 : constant String (11 .. 10 + UTF8'Length) := UTF8;
         Input_16 : constant SMB.Bytes (17 .. 16 + UTF16'Length) := UTF16;
         Output_8 : String (31 .. 30 + UTF8'Length);
         Output_16 : SMB.Bytes (23 .. 22 + UTF16'Length);
         Used : Natural;
         Status : SMB.Core_Status;
      begin
         SMB.Core_Text.UTF8_To_UTF16 (Input_8, Output_16, Used, Status);
         Assert (Status = SMB.Ok and then Used = UTF16'Length
                 and then Output_16 = UTF16, "UTF-16 exact-fit conversion");
         SMB.Core_Text.UTF16_To_UTF8 (Input_16, Output_8, Used, Status);
         Assert (Status = SMB.Ok and then Used = UTF8'Length
                 and then Output_8 = UTF8, "UTF-8 exact-fit conversion");
         if UTF8'Length > 0 then
            declare
               Short_8 : String (31 .. 29 + UTF8'Length);
               Short_16 : SMB.Bytes (23 .. 21 + UTF16'Length);
            begin
               SMB.Core_Text.UTF8_To_UTF16 (Input_8, Short_16, Used, Status);
               Assert (Status = SMB.Invalid_Length and then Used = UTF16_Prefix
                       and then Used mod 2 = 0,
                       "UTF-16 short buffer stops before a partial scalar");
               for Offset in 0 .. Short_16'Length - 1 loop
                  Assert
                    (Short_16 (Short_16'First + Offset) =
                       (if Offset < Used then UTF16 (UTF16'First + Offset)
                        else 0), "UTF-16 short buffer prefix and untouched tail");
               end loop;
               SMB.Core_Text.UTF16_To_UTF8 (Input_16, Short_8, Used, Status);
               Assert (Status = SMB.Invalid_Length and then Used = UTF8_Prefix,
                       "UTF-8 short buffer stops before a partial scalar");
               if Short_8'Length > 0 then
                  for Offset in 0 .. Short_8'Length - 1 loop
                     Assert
                       (Short_8 (Short_8'First + Offset) =
                          (if Offset < Used then UTF8 (UTF8'First + Offset)
                           else Character'Val (0)),
                        "UTF-8 short buffer prefix and untouched tail");
                  end loop;
               end if;
            end;
         end if;
      end Check_Vector;

      procedure Check_Zero_Tail
        (UTF8 : String; Capacity : Natural;
         Expected_Status : SMB.Core_Status; Expected_Prefix : SMB.Bytes) is
         Input : constant String (11 .. 10 + UTF8'Length) := UTF8;
         Output : SMB.Bytes (23 .. 22 + Capacity) := (others => 16#A5#);
         Used : Natural;
         Status : SMB.Core_Status;
      begin
         SMB.Core_Text.UTF8_To_UTF16 (Input, Output, Used, Status);
         Assert
           (Status = Expected_Status and then Used = Expected_Prefix'Length
            and then Used <= Output'Length,
            "UTF-16 zero-tail status and length");
         for I in Output'Range loop
            Assert
              (Output (I) =
                 (if I - Output'First < Used then
                    Expected_Prefix (Expected_Prefix'First + I - Output'First)
                  else 0),
               "UTF-16 exact prefix and zero tail");
         end loop;
      end Check_Zero_Tail;

      procedure Check_UTF8_Zero_Tail
        (UTF16 : SMB.Bytes; Capacity : Natural;
         Expected_Status : SMB.Core_Status; Expected_Prefix : String) is
         Input : constant SMB.Bytes (17 .. 16 + UTF16'Length) := UTF16;
         Output : String (31 .. 30 + Capacity) :=
           (others => Character'Val (16#A5#));
         Used : Natural;
         Status : SMB.Core_Status;
      begin
         SMB.Core_Text.UTF16_To_UTF8 (Input, Output, Used, Status);
         Assert
           (Status = Expected_Status and then Used = Expected_Prefix'Length
            and then Used <= Output'Length,
            "UTF-8 zero-tail status and length");
         for I in Output'Range loop
            Assert
              (Output (I) =
                 (if I - Output'First < Used then
                    Expected_Prefix (Expected_Prefix'First + I - Output'First)
                  else Character'Val (0)),
               "UTF-8 exact prefix and zero tail");
         end loop;
      end Check_UTF8_Zero_Tail;

      E_Acute : constant String :=
        Character'Val (16#C3#) & Character'Val (16#A9#);
      Euro : constant String := Character'Val (16#E2#)
        & Character'Val (16#82#) & Character'Val (16#AC#);
      Smile : constant String := Character'Val (16#F0#)
        & Character'Val (16#9F#) & Character'Val (16#98#)
        & Character'Val (16#80#);
   begin
      Check_UTF8_Zero_Tail (SMB.Bytes'(1 .. 0 => 0), 5, SMB.Ok, "");
      Check_UTF8_Zero_Tail (SMB.Bytes'(16#41#, 0), 4, SMB.Ok, "A");
      Check_UTF8_Zero_Tail
        (SMB.Bytes'(16#3D#, 16#D8#, 0, 16#DE#), 7, SMB.Ok, Smile);
      Check_UTF8_Zero_Tail
        (SMB.Bytes'(16#41#, 0, 16#AC#, 16#20#), 2, SMB.Invalid_Length, "A");
      Check_UTF8_Zero_Tail
        (SMB.Bytes'(16#3D#, 16#D8#, 0, 16#DE#), 3, SMB.Invalid_Length, "");
      Check_UTF8_Zero_Tail
        (SMB.Bytes'(16#41#, 0, 0, 0), 4, SMB.Invalid_Encoding, "A");
      Check_UTF8_Zero_Tail
        (SMB.Bytes'(16#41#, 0, 16#FF#), 4, SMB.Invalid_Length, "");
      Check_Zero_Tail ("", 5, SMB.Ok, SMB.Bytes'(1 .. 0 => 0));
      Check_Zero_Tail ("A", 5, SMB.Ok, SMB.Bytes'(16#41#, 0));
      Check_Zero_Tail
        (Smile, 7, SMB.Ok, SMB.Bytes'(16#3D#, 16#D8#, 0, 16#DE#));
      Check_Zero_Tail
        ("AB", 3, SMB.Invalid_Length, SMB.Bytes'(16#41#, 0));
      Check_Zero_Tail
        (Smile, 3, SMB.Invalid_Length, SMB.Bytes'(1 .. 0 => 0));
      Check_Zero_Tail
        ("A" & Character'Val (16#FF#), 5, SMB.Invalid_Encoding,
         SMB.Bytes'(16#41#, 0));
      Check_Vector ("", SMB.Bytes'(1 .. 0 => 0));
      Check_Vector ("A", SMB.Bytes'(16#41#, 0));
      Check_Vector (E_Acute, SMB.Bytes'(16#E9#, 0));
      Check_Vector (Euro, SMB.Bytes'(16#AC#, 16#20#));
      Check_Vector (Smile, SMB.Bytes'(16#3D#, 16#D8#, 0, 16#DE#));
      Check_Vector ("A" & Euro, SMB.Bytes'(16#41#, 0, 16#AC#, 16#20#), 1, 2);
      Check_Vector
        ("A" & Smile, SMB.Bytes'(16#41#, 0, 16#3D#, 16#D8#, 0, 16#DE#), 1, 2);
      Check_Vector
        (Smile & "A", SMB.Bytes'(16#3D#, 16#D8#, 0, 16#DE#, 16#41#, 0), 4, 4);
      declare
         Output : SMB.Bytes (11 .. 16) := (others => 16#FF#);
         Used : Natural;
         Status : SMB.Core_Status;
      begin
         SMB.Core_Text.UTF8_To_UTF16 ("", Output, Used, Status);
         Assert
           (Status = SMB.Ok and then Used = 0
            and then (for all B of Output => B = 0),
            "empty UTF-8 succeeds with unused output capacity");
      end;
      declare
         Input : constant String (11 .. 13) := "AB" & Character'Val (16#FF#);
         Output : SMB.Bytes (23 .. 28);
         Used : Natural;
         Status : SMB.Core_Status;
      begin
         SMB.Core_Text.UTF8_To_UTF16
           (Input, Output (23 .. 24), Used, Status);
         Assert
           (Status = SMB.Invalid_Length and then Used = 2
            and then Output (23 .. 24) = SMB.Bytes'(16#41#, 0),
            "UTF-8 capacity failure can precede a later encoding failure");
         SMB.Core_Text.UTF8_To_UTF16 (Input, Output, Used, Status);
         Assert
           (Status = SMB.Invalid_Encoding and then Used = 4
            and then Output = SMB.Bytes'(16#41#, 0, 16#42#, 0, 0, 0),
            "ample UTF-16 capacity exposes the invalid UTF-8 suffix");
      end;
      declare
         Input : constant String (5 .. 4 + SMB.Maximum_Frame_Size) :=
           (others => 'A');
         Output : SMB.Bytes (11 .. 10 + 2 * Input'Length);
         Used : Natural;
         Status : SMB.Core_Status;
      begin
         SMB.Core_Text.UTF8_To_UTF16 (Input, Output, Used, Status);
         Assert
           (Status = SMB.Ok and then Used = Output'Length
            and then (for all I in Output'Range =>
              Output (I) = (if (I - Output'First) mod 2 = 0 then 16#41# else 0)),
            "maximum UTF-8 ASCII input fits the two-times capacity bound");
      end;
      declare
         Input : constant String (Positive'Last - 3 .. Positive'Last) :=
           Character'Val (16#F4#) & Character'Val (16#8F#)
           & Character'Val (16#BF#) & Character'Val (16#BF#);
         Output : SMB.Bytes (Natural'Last - 3 .. Natural'Last);
         Used : Natural;
         Status : SMB.Core_Status;
      begin
         SMB.Core_Text.UTF8_To_UTF16 (Input, Output, Used, Status);
         Assert
           (Status = SMB.Ok and then Used = 4
            and then Output = SMB.Bytes'(16#FF#, 16#DB#, 16#FF#, 16#DF#),
            "UTF-16 output prefix at highest array bounds");
      end;
      declare
         Input : constant String := "A" & Smile & Character'Val (16#80#);
         Output : SMB.Bytes (19 .. 26);
         Used : Natural;
         Status : SMB.Core_Status;
      begin
         SMB.Core_Text.UTF8_To_UTF16 (Input, Output, Used, Status);
         Assert
           (Status = SMB.Invalid_Encoding and then Used = 6
            and then Output =
              SMB.Bytes'(16#41#, 0, 16#3D#, 16#D8#, 0, 16#DE#, 0, 0),
            "invalid UTF-8 suffix preserves a complete surrogate pair");
      end;
      declare
         Input : constant SMB.Bytes (Natural'Last - 3 .. Natural'Last) :=
           (16#FF#, 16#DB#, 16#FF#, 16#DF#);
         Output : String (Positive'Last - 3 .. Positive'Last);
         Used : Natural;
         Status : SMB.Core_Status;
      begin
         SMB.Core_Text.UTF16_To_UTF8 (Input, Output, Used, Status);
         Assert
           (Status = SMB.Ok and then Used = 4
            and then Output = Character'Val (16#F4#) & Character'Val (16#8F#)
              & Character'Val (16#BF#) & Character'Val (16#BF#),
            "maximum Unicode scalar at highest array bounds");
      end;
      declare
         Input : SMB.Bytes (17 .. 17 + 65_536 - 1);
         Output : String (31 .. 31 + 32_768 - 1);
         Used : Natural;
         Status : SMB.Core_Status;
      begin
         for I in 0 .. 32_767 loop
            Input (Input'First + 2 * I) := 16#41#;
            Input (Input'First + 2 * I + 1) := 0;
         end loop;
         SMB.Core_Text.UTF16_To_UTF8 (Input, Output, Used, Status);
         Assert
           (Status = SMB.Ok and then Used = Output'Length
            and then (for all C of Output => C = 'A'),
            "UTF-16 conversion above standalone validator length limit");
         Input (Input'Last - 1) := 0;
         Input (Input'Last) := 16#D8#;
         SMB.Core_Text.UTF16_To_UTF8 (Input, Output, Used, Status);
         Assert
           (Status = SMB.Invalid_Encoding and then Used = 32_767
            and then (for all I in Output'First .. Output'Last - 1 =>
                        Output (I) = 'A')
            and then Output (Output'Last) = Character'Val (0),
            "long UTF-16 orphan surrogate preserves only converted prefix");
         SMB.Core_Text.UTF16_To_UTF8
           (Input, Output (Output'First .. Output'Last - 2), Used, Status);
         Assert
           (Status = SMB.Invalid_Length and then Used = 32_766,
            "UTF-16 capacity failure can precede a later encoding failure");
      end;
      declare
         Input : String (1 .. 49_152);
         Output : SMB.Bytes (0 .. SMB.Core_Protocol.Maximum_Name_Bytes - 1);
         Used : Natural;
         Status : SMB.Core_Status;
      begin
         for I in 0 .. 16_383 loop
            Input (3 * I + 1 .. 3 * I + 3) :=
              Character'Val (16#E3#) & Character'Val (16#81#)
              & Character'Val (16#82#);
         end loop;
         SMB.Core_Text.UTF8_To_UTF16 (Input, Output, Used, Status);
         Assert (Status = SMB.Ok and then Used = 32_768,
                 "multibyte name fits the actual UTF-16 protocol capacity");
         for I in 0 .. 16_383 loop
            Assert (Output (2 * I) = 16#42# and then Output (2 * I + 1) = 16#30#,
                    "long multibyte name byte correspondence");
         end loop;
      end;
      declare
         Oversized : constant String (1 .. SMB.Maximum_Frame_Size + 1) :=
           (others => 'a');
      begin
         begin
            declare
               Unexpected : constant SMB.Bytes := SMB.Text.To_UTF16LE (Oversized);
               pragma Unreferenced (Unexpected);
            begin
               raise Program_Error with "oversized public UTF-8 input accepted";
            end;
         exception
            when SMB.Protocol_Error => null;
         end;
         begin
            declare
               Unexpected : constant String := SMB.Text.NTLM_Username (Oversized);
               pragma Unreferenced (Unexpected);
            begin
               raise Program_Error with "oversized public username accepted";
            end;
         exception
            when SMB.Authentication_Error => null;
         end;
      end;
      declare
         Oversized : constant SMB.Bytes (1 .. SMB.Maximum_Frame_Size + 1) :=
           (others => 0);
      begin
         begin
            declare
               Unexpected : constant String := SMB.Text.From_UTF16LE (Oversized);
               pragma Unreferenced (Unexpected);
            begin
               raise Program_Error with "oversized public UTF-16 input accepted";
            end;
         exception
            when SMB.Protocol_Error => null;
         end;
      end;
      declare
         Limit : constant String (1 .. SMB.Maximum_Frame_Size) :=
           (others => 'a');
         UTF16 : constant SMB.Bytes := SMB.Text.To_UTF16LE (Limit);
         User : constant String := SMB.Text.NTLM_Username (Limit);
         Back : constant String := SMB.Text.From_UTF16LE
           (UTF16 (UTF16'First .. UTF16'First + SMB.Maximum_Frame_Size - 1));
      begin
         Assert
           (UTF16'Length = 2 * Limit'Length, "public UTF-8 input at the limit");
         Assert
           (User'Length = Limit'Length
            and then (for all C of User => C = 'A'),
            "public username at the limit");
         Assert
           (Back = Limit (1 .. SMB.Maximum_Frame_Size / 2),
            "public UTF-16 input at the limit");
      end;
      --  Continuation bytes just above 16#BF# in each position of a
      --  four-byte sequence; a low surrogate first; a high surrogate
      --  followed by U+E000.
      declare
         C0 : constant Character := Character'Val (16#C0#);
         F1 : constant Character := Character'Val (16#F1#);
         X : constant Character := Character'Val (16#80#);
         Output_16 : SMB.Bytes (1 .. 8);
         Output_8 : String (1 .. 8);
         Used : Natural;
         Status : SMB.Core_Status;

         procedure Reject_UTF8 (Input : String; Message : String) is
         begin
            SMB.Core_Text.UTF8_To_UTF16 (Input, Output_16, Used, Status);
            Assert (Status = SMB.Invalid_Encoding, Message);
         end Reject_UTF8;

         procedure Reject_UTF16 (Input : SMB.Bytes; Message : String) is
         begin
            SMB.Core_Text.UTF16_To_UTF8 (Input, Output_8, Used, Status);
            Assert (Status = SMB.Invalid_Encoding, Message);
            SMB.Core_Text.Validate_UTF16 (Input, Status);
            Assert (Status = SMB.Invalid_Encoding, Message & " (validation)");
         end Reject_UTF16;
      begin
         SMB.Core_Text.UTF8_To_UTF16 (F1 & X & X & X, Output_16, Used, Status);
         Assert (Status = SMB.Ok and then Used = 4, "U+40000 in UTF-8");
         Reject_UTF8 (F1 & C0 & X & X, "second byte C0 of four");
         Reject_UTF8 (F1 & X & C0 & X, "third byte C0 of four");
         Reject_UTF8 (F1 & X & X & C0, "fourth byte C0 of four");
         Reject_UTF16 ((16#00#, 16#DC#, 16#00#, 16#DC#), "leading low surrogate");
         Reject_UTF16
           ((16#00#, 16#D8#, 16#00#, 16#E0#), "high surrogate before U+E000");
      end;
   end Test_UTF_Capacity;

   procedure Test_Path_Contracts is
      procedure Check_Path
        (Value : String; Valid : Boolean; Allow_Empty : Boolean := False) is
         Input : constant String (11 .. 10 + Value'Length) := Value;
         Output : String (29 .. 28 + Value'Length) := (others => '!');
         Expected : String := Value;
         Status : SMB.Core_Status;
      begin
         for C of Expected loop
            if C = '/' then
               C := '\';
            end if;
         end loop;
         SMB.Core_Text.Validate_Path (Input, Output, Allow_Empty, Status);
         Assert
           (Status = (if Valid then SMB.Ok else SMB.Invalid_Value),
            "path lexical acceptance");
         if Valid then
            Assert (Output = Expected, "path exact normalization");
         else
            Assert ((for all C of Output => C = Character'Val (0)),
                    "rejected path exposes no partial normalized name");
         end if;
      end Check_Path;

      function Reference_Valid (Value : String; Allow_Empty : Boolean)
                                return Boolean is
         Start : Natural := 0;
      begin
         if Value'Length = 0 then
            return Allow_Empty;
         end if;
         for Offset in 0 .. Value'Length - 1 loop
            declare
               C : constant Character := Value (Value'First + Offset);
            begin
               if C = Character'Val (0) or else C = ':' then
                  return False;
               elsif C = '/' or else C = '\' then
                  if Offset = Start or else Offset = Value'Length - 1
                    or else Value (Value'First + Start
                                   .. Value'First + Offset - 1) = ".."
                  then
                     return False;
                  end if;
                  Start := Offset + 1;
               end if;
            end;
         end loop;
         return Value (Value'First + Start .. Value'Last) /= "..";
      end Reference_Valid;

      Alphabet : constant String := "a./\:" & Character'Val (0);
      Status : SMB.Core_Status;
   begin
      Check_Path ("", False);
      Check_Path ("", True, True);
      Check_Path ("a/b\c", True);
      Check_Path ("./.hidden/..x/.../x..", True);
      Check_Path ("../file", False);
      Check_Path ("a/../file", False);
      Check_Path ("a\..", False);
      Check_Path ("/a", False);
      Check_Path ("\a", False);
      Check_Path ("a/", False);
      Check_Path ("a\\b", False);
      Check_Path ("C:file", False);
      Check_Path ("a" & Character'Val (0) & "b", False);
      Check_Path (Character'Val (16#C3#) & Character'Val (16#A9#) & "/x", True);
      for Length in 0 .. 4 loop
         for Code in 0 .. Alphabet'Length ** Length - 1 loop
            declare
               Value : String (1 .. Length);
               Rest : Natural := Code;
            begin
               for I in Value'Range loop
                  Value (I) := Alphabet (Rest mod Alphabet'Length + 1);
                  Rest := Rest / Alphabet'Length;
               end loop;
               Check_Path (Value, Reference_Valid (Value, False));
               Check_Path (Value, Reference_Valid (Value, True), True);
            end;
         end loop;
      end loop;
      declare
         Large : String (1 .. 65_534) := (others => 'a');
      begin
         Check_Path (Large, True);
         Large (Large'Last - 2 .. Large'Last) := "/..";
         Check_Path (Large, False);
      end;
      declare
         Input : constant String (Integer'Last - 2 .. Integer'Last) := "a/b";
         Output : String (Integer'Last - 2 .. Integer'Last);
      begin
         SMB.Core_Text.Validate_Path (Input, Output, False, Status);
         Assert (Status = SMB.Ok and then Output = "a\b",
                 "path indices near Integer'Last");
      end;
      SMB.Core_Text.Validate_Share ("share name", Status);
      Assert (Status = SMB.Ok, "valid share");
      SMB.Core_Text.Validate_Share ("", Status);
      Assert (Status = SMB.Invalid_Value, "empty share");
      declare
         Forbidden : constant String := "/\:" & Character'Val (0);
      begin
         for C of Forbidden loop
            SMB.Core_Text.Validate_Share ("a" & C & "b", Status);
            Assert (Status = SMB.Invalid_Value, "share rejects forbidden bytes");
         end loop;
      end;
   end Test_Path_Contracts;

   procedure Test_Core_Clock is
      Value : SMB.QWord;
      Status : SMB.Core_Status;
      Now : SMB.QWord;
   begin
      SMB.Core_Clock.To_Filetime (1601, 1, 1, 0, 0, Value, Status);
      Assert (Status = SMB.Ok and then Value = 0, "FILETIME epoch");
      SMB.Core_Clock.To_Filetime (1970, 1, 1, 0, 0, Value, Status);
      Assert (Status = SMB.Ok and then Value = 116_444_736_000_000_000,
              "FILETIME Unix epoch");
      SMB.Core_Clock.To_Filetime (2000, 3, 1, 1, 9_999_999, Value, Status);
      Assert (Status = SMB.Ok
              and then Value = 125_963_424_019_999_999,
              "FILETIME leap century and ticks");
      SMB.Core_Clock.To_Filetime (2016, 12, 31, 86_400, 0, Value, Status);
      Assert (Status = SMB.Ok
              and then Value = 131_277_024_000_000_000,
              "FILETIME leap second maps to next day");
      SMB.Core_Clock.To_Filetime
        (9999, 12, 31, 86_400, 9_999_999, Value, Status);
      Assert (Status = SMB.Ok
              and then Value = 2_650_467_744_009_999_999,
              "FILETIME maximum accepted time");
      SMB.Core_Clock.To_Filetime (1900, 2, 29, 0, 0, Value, Status);
      Assert (Status = SMB.Invalid_Value and then Value = 0,
              "FILETIME rejects non-leap century day");
      SMB.Core_Clock.To_Filetime (1600, 12, 31, 0, 0, Value, Status);
      Assert (Status = SMB.Invalid_Value and then Value = 0,
              "FILETIME rejects years before 1601");
      SMB.Core_Clock.To_Filetime (2024, 4, 31, 0, 0, Value, Status);
      Assert (Status = SMB.Invalid_Value, "FILETIME rejects invalid day");
      SMB.Core_Clock.To_Filetime (2024, 13, 1, 0, 0, Value, Status);
      Assert (Status = SMB.Invalid_Value, "FILETIME rejects invalid month");
      SMB.Core_Clock.To_Filetime (2024, 1, 1, 86_401, 0, Value, Status);
      Assert (Status = SMB.Invalid_Value, "FILETIME rejects invalid seconds");
      SMB.Core_Clock.To_Filetime (2024, 1, 1, 0, 10_000_000, Value, Status);
      Assert (Status = SMB.Invalid_Value, "FILETIME rejects invalid ticks");
      SMB.Core_Clock.To_Filetime (2024, 1, 1, 0, -1, Value, Status);
      Assert (Status = SMB.Invalid_Value, "FILETIME rejects negative ticks");
      SMB.Core_Clock.To_Filetime
        (Integer'First, Integer'Last, Integer'First,
         Integer'Last, Integer'First, Value, Status);
      Assert (Status = SMB.Invalid_Value and then Value = 0,
              "FILETIME rejects extreme input before arithmetic");
      Assert (SMB.Core_Clock.Seconds_Of_Day (23, 59, 59, False) = 86_399
              and then SMB.Core_Clock.Seconds_Of_Day
                (23, 59, 59, True) = 86_400,
              "FILETIME seconds and leap-second normalization");
      Assert (SMB.Core_Clock.Fraction_Ticks (0.0) = 0
              and then SMB.Core_Clock.Fraction_Ticks (0.000_000_049) = 0
              and then SMB.Core_Clock.Fraction_Ticks (0.000_000_050) = 0
              and then SMB.Core_Clock.Fraction_Ticks (0.000_000_099) = 0
              and then SMB.Core_Clock.Fraction_Ticks (0.000_000_100) = 1
              and then SMB.Core_Clock.Fraction_Ticks (0.999_999_950) = 9_999_999
              and then SMB.Core_Clock.Fraction_Ticks (0.999_999_999) = 9_999_999,
              "FILETIME subsecond truncation never rounds up to next second");
      Now := SMB.Clock.Current_Filetime;
      Assert (Now > 116_444_736_000_000_000,
              "public clock returns a FILETIME after the Unix epoch");
   end Test_Core_Clock;

   procedure Test_Core_Transport is
      use type Ada.Streams.Stream_Element;
      use type Ada.Streams.Stream_Element_Offset;
      use type Ada.Streams.Stream_Element_Array;
      Packet : SMB.Bytes (5 .. 68);
      Frame : Ada.Streams.Stream_Element_Array (7 .. 74);
      Short : Ada.Streams.Stream_Element_Array (1 .. 67);
      Chunk : constant Ada.Streams.Stream_Element_Array (7 .. 11) :=
        (1, 2, 3, 4, 5);
      Buffer : SMB.Bytes (5 .. 10) := (others => 16#EE#);
      Position : Natural := 0;
      First : Ada.Streams.Stream_Element_Offset;
      Status : SMB.Core_Status;
   begin
      for I in Packet'Range loop
         Packet (I) := SMB.Byte (I);
      end loop;
      SMB.Core_Transport.Build_Frame (Packet, Frame, Status);
      Assert
        (Status = SMB.Ok and then Frame (7 .. 10) =
           Ada.Streams.Stream_Element_Array'(0, 0, 0, 64),
         "nonzero-bound native frame header");
      for I in Packet'Range loop
         Assert
           (Frame (11 + Ada.Streams.Stream_Element_Offset (I - Packet'First)) =
              Ada.Streams.Stream_Element (Packet (I)), "native frame payload");
      end loop;
      SMB.Core_Transport.Build_Frame (Packet, Short, Status);
      Assert (Status = SMB.Invalid_Length and then
                (for all I in Short'Range => Short (I) = 0),
              "short native frame buffer");
      SMB.Core_Transport.Build_Frame (Packet (5 .. 67), Short, Status);
      Assert (Status = SMB.Invalid_Length, "undersized packet rejected");
      declare
         Large : constant SMB.Bytes (0 .. SMB.Maximum_Frame_Size - 1) :=
           (others => 16#A5#);
         Wire : Ada.Streams.Stream_Element_Array
           (1 .. SMB.Core_Transport.Maximum_Wire_Size);
      begin
         SMB.Core_Transport.Build_Frame (Large, Wire, Status);
         Assert
           (Status = SMB.Ok and then Wire (1 .. 4) =
              Ada.Streams.Stream_Element_Array'(0, 16, 0, 0)
            and then Wire (5) = 16#A5# and then Wire (Wire'Last) = 16#A5#,
            "maximum frame includes its four-byte prefix");
      end;

      SMB.Core_Transport.Receive_Chunk (Chunk, 8, Buffer, Position, Status);
      Assert
        (Status = SMB.Ok and then Position = 2
         and then Buffer = SMB.Bytes'(1, 2, 16#EE#, 16#EE#, 16#EE#, 16#EE#),
         "partial receive preserves unused tail");
      SMB.Core_Transport.Receive_Chunk
        (Ada.Streams.Stream_Element_Array'(10 => 3, 11 => 4, 12 => 5),
         12, Buffer, Position, Status);
      Assert
        (Status = SMB.Ok and then Position = 5
         and then Buffer = SMB.Bytes'(1, 2, 3, 4, 5, 16#EE#),
         "receive continuation preserves prefix");
      declare
         Before : constant SMB.Bytes := Buffer;
      begin
         SMB.Core_Transport.Receive_Chunk (Chunk, 8, Buffer, Position, Status);
         Assert (Status = SMB.Invalid_Length and then Position = 5
                 and then Buffer = Before, "receive overcount has no effect");
         SMB.Core_Transport.Receive_Chunk (Chunk, 6, Buffer, Position, Status);
         Assert (Status = SMB.Invalid_Length and then Position = 5
                 and then Buffer = Before, "receive EOF has no effect");
         SMB.Core_Transport.Receive_Chunk (Chunk, 12, Buffer, Position, Status);
         Assert (Status = SMB.Invalid_Length and then Position = 5
                 and then Buffer = Before, "invalid receive end has no effect");
      end;
      SMB.Core_Transport.Receive_Chunk
        (Ada.Streams.Stream_Element_Array'(1 => 6), 1, Buffer, Position, Status);
      Assert (Status = SMB.Ok and then Position = 6
              and then Buffer = SMB.Bytes'(1, 2, 3, 4, 5, 6),
              "complete byte-exact receive");
      SMB.Core_Transport.Receive_Chunk (Chunk, 7, Buffer, Position, Status);
      Assert (Status = SMB.Invalid_Offset and then Position = 6,
              "receive cannot progress beyond completion");
      Position := Natural'Last;
      SMB.Core_Transport.Receive_Chunk (Chunk, 7, Buffer, Position, Status);
      Assert (Status = SMB.Invalid_Offset and then Position = Natural'Last,
              "invalid large receive position is not narrowed");

      Position := 0;
      SMB.Core_Transport.Prepare_Write (Chunk, Position, First, Status);
      Assert (Status = SMB.Ok and then First = 7, "initial send slice");
      SMB.Core_Transport.Advance_Write (Chunk, 8, Position, Status);
      Assert (Status = SMB.Ok and then Position = 2, "partial send progress");
      SMB.Core_Transport.Prepare_Write (Chunk, Position, First, Status);
      Assert (Status = SMB.Ok and then First = 9, "send resumes without replay");
      SMB.Core_Transport.Advance_Write (Chunk, 8, Position, Status);
      Assert (Status = SMB.Invalid_Length and then Position = 2,
              "zero send does not advance");
      SMB.Core_Transport.Advance_Write (Chunk, 9, Position, Status);
      Assert (Status = SMB.Ok and then Position = 3, "one-element send");
      SMB.Core_Transport.Advance_Write (Chunk, 12, Position, Status);
      Assert (Status = SMB.Invalid_Length and then Position = 3,
              "send overcount does not advance");
      SMB.Core_Transport.Advance_Write (Chunk, 11, Position, Status);
      Assert (Status = SMB.Ok and then Position = 5, "complete partial send");
      SMB.Core_Transport.Prepare_Write (Chunk, Position, First, Status);
      Assert (Status = SMB.Invalid_Offset and then First = Chunk'First,
              "completed send has a canonical failed slice");
      SMB.Core_Transport.Advance_Write (Chunk, 11, Position, Status);
      Assert (Status = SMB.Invalid_Offset and then Position = 5,
              "duplicate completion does not advance");
      declare
         Ends : constant array (Positive range 1 .. 4) of
           Ada.Streams.Stream_Element_Offset :=
             (Ada.Streams.Stream_Element_Offset'First, 6, 12,
              Ada.Streams.Stream_Element_Offset'Last);
         Positions : constant array (Positive range 1 .. 4) of Natural :=
           (0, 4, 6, Natural'Last);
         Before : constant SMB.Bytes := Buffer;
      begin
         for Initial of Positions loop
            SMB.Core_Transport.Prepare_Write (Chunk, Initial, First, Status);
            Assert
              ((if Initial < Chunk'Length then
                 Status = SMB.Ok and then First = Chunk'First +
                   Ada.Streams.Stream_Element_Offset (Initial)
               else Status = SMB.Invalid_Offset and then First = Chunk'First),
               "send slice result at boundary position");
            for Last of Ends loop
               Position := Initial;
               SMB.Core_Transport.Receive_Chunk
                 (Chunk, Last, Buffer, Position, Status);
               Assert
                 (Status = (if Initial >= Buffer'Length then SMB.Invalid_Offset
                            else SMB.Invalid_Length)
                  and then Position = Initial and then Buffer = Before,
                  "receive failure status precedence and preservation");
               Position := Initial;
               SMB.Core_Transport.Advance_Write (Chunk, Last, Position, Status);
               Assert
                 (Status = (if Initial >= Chunk'Length then SMB.Invalid_Offset
                            else SMB.Invalid_Length)
                  and then Position = Initial,
                  "send failure status precedence and preservation");
            end loop;
         end loop;
      end;
      declare
         Empty : constant Ada.Streams.Stream_Element_Array
           (SMB.Core_Transport.Maximum_Wire_Size + 1 ..
            SMB.Core_Transport.Maximum_Wire_Size) := (others => 0);
         Empty_Buffer : SMB.Bytes (Natural'Last .. Natural'Last - 1) :=
           (others => 0);
         Before : constant SMB.Bytes := Buffer;
      begin
         Position := 0;
         SMB.Core_Transport.Receive_Chunk
           (Empty, Empty'Last, Buffer, Position, Status);
         Assert (Status = SMB.Invalid_Length and then Position = 0
                 and then Buffer = Before, "empty chunk preserves receive state");
         SMB.Core_Transport.Receive_Chunk
           (Empty, Empty'Last, Empty_Buffer, Position, Status);
         Assert (Status = SMB.Invalid_Offset and then Position = 0,
                 "empty destination precedes invalid chunk length");
         SMB.Core_Transport.Prepare_Write (Empty, Position, First, Status);
         Assert (Status = SMB.Invalid_Offset and then First = Empty'First,
                 "empty send canonical slice at maximum bound");
         SMB.Core_Transport.Advance_Write (Empty, Empty'Last, Position, Status);
         Assert (Status = SMB.Invalid_Offset and then Position = 0,
                 "empty send keeps position");
      end;
   end Test_Core_Transport;

   procedure Test_Framing is
      Sizes : constant array (Positive range 1 .. 15) of Natural :=
        (0, 1, 63, 64, 65, 255, 256, 257, 65_535, 65_536, 65_537,
         SMB.Maximum_Frame_Size - 1, SMB.Maximum_Frame_Size,
         SMB.Maximum_Frame_Size + 1, 16#FF_FFFF#);
      Header : SMB.Core_Framing.Frame_Header;
      Length : Natural;
      Status : SMB.Core_Status;
   begin
      for Size of Sizes loop
         declare
            Expected : constant SMB.Core_Framing.Frame_Header :=
              (0, SMB.Byte (Size / 65_536),
               SMB.Byte ((Size / 256) mod 256), SMB.Byte (Size mod 256));
         begin
            Header := (others => 16#A5#);
            SMB.Core_Framing.Encode (Size, Header, Status);
            if Size in 64 .. SMB.Maximum_Frame_Size then
               Assert (Status = SMB.Ok and then Header = Expected,
                       "exact big-endian frame encoding");
            else
               Assert (Status = SMB.Invalid_Length
                       and then Header = SMB.Core_Framing.Frame_Header'(others => 0),
                       "invalid frame encoding clears header");
            end if;
            for Kind in SMB.Byte loop
               Header := Expected;
               Header (0) := Kind;
               Length := Natural'Last;
               Status := SMB.Ok;
               SMB.Core_Framing.Decode (Header, Length, Status);
               if Kind /= 0 then
                  Assert (Status = SMB.Unsupported_Feature and then Length = 0,
                          "unsupported frame kind takes priority and clears length");
               elsif Size in 64 .. SMB.Maximum_Frame_Size then
                  Assert (Status = SMB.Ok and then Length = Size,
                          "exact big-endian frame decoding");
               else
                  Assert (Status = SMB.Invalid_Length and then Length = 0,
                          "invalid frame length is rejected and cleared");
               end if;
            end loop;
         end;
      end loop;
      SMB.Core_Framing.Encode (Natural'Last, Header, Status);
      Assert (Status = SMB.Invalid_Length
              and then Header = SMB.Core_Framing.Frame_Header'(others => 0),
              "extreme frame encoding clears header");
      Ada.Text_IO.Put_Line ("framing status/length matrix: 3840 cases passed");
   end Test_Framing;

   procedure Test_Wire_Primitive_Boundaries is
      type Example is record
         Value : SMB.QWord;
         Wire : SMB.Bytes (0 .. 7);
      end record;
      Examples : constant array (Positive range 1 .. 4) of Example :=
        ((0, (others => 0)),
         (1, (1, 0, 0, 0, 0, 0, 0, 0)),
         (16#0123_4567_89AB_CDEF#,
          (16#EF#, 16#CD#, 16#AB#, 16#89#, 16#67#, 16#45#, 16#23#, 16#01#)),
         (SMB.QWord'Last, (others => 16#FF#)));
      Widths : constant array (Positive range 1 .. 3) of Positive := (2, 4, 8);
      Header_Sizes : constant array (Positive range 1 .. 6) of Natural :=
        (0, 1, 63, 64, 65, 80);
      Header_Bytes : constant SMB.Bytes (0 .. 63) :=
        (0 => 16#FE#, 1 => 16#53#, 2 => 16#4D#, 3 => 16#42#,
         4 => 64, 6 => 1, 12 => 8, 14 => 16#34#, 15 => 16#12#,
         24 => 16#EF#, 25 => 16#CD#, 26 => 16#AB#, 27 => 16#89#,
         28 => 16#67#, 29 => 16#45#, 30 => 16#23#, 31 => 16#01#,
         36 => 16#40#, 37 => 16#30#, 38 => 16#20#, 39 => 16#10#,
         40 => 16#10#, 41 => 16#32#, 42 => 16#54#, 43 => 16#76#,
         44 => 16#98#, 45 => 16#BA#, 46 => 16#DC#, 47 => 16#FE#,
         others => 0);
      Integer_Count : Natural := 0;
      Header_Count : Natural := 0;

      function Lower_Bound (Size, Rebase : Natural) return Natural is
        (if Rebase = 0 then (if Size = 0 then 1 else 0)
         elsif Rebase = 1 then 17
         elsif Size = 0 then Natural'Last
         else Natural'Last - (Size - 1));

      procedure Check_Integer
        (First, Last, Offset : Natural; Width : Positive; Item : Example)
      is
         Data : SMB.Bytes (First .. Last) := (others => 16#A5#);
         Expected : SMB.Bytes (Data'Range) := Data;
         Fits : constant Boolean :=
           Offset <= Data'Length and then Data'Length - Offset >= Width;
         Expected_Status : constant SMB.Core_Status :=
           (if Fits then SMB.Ok else SMB.Invalid_Offset);
         Expected_Value : constant SMB.QWord :=
           (if Width = 2 then Item.Value and 16#FFFF#
            elsif Width = 4 then Item.Value and 16#FFFF_FFFF#
            else Item.Value);
         Value_16 : SMB.Word := SMB.Word'Last;
         Value_32 : SMB.DWord := SMB.DWord'Last;
         Value_64 : SMB.QWord := SMB.QWord'Last;
         Actual : SMB.QWord;
         Status : SMB.Core_Status;
      begin
         if Fits then
            for I in 0 .. Width - 1 loop
               Expected (Data'First + Offset + I) := Item.Wire (I);
            end loop;
         end if;
         case Width is
            when 2 =>
               SMB.Core_Wire.Write_U16
                 (Data, Offset, SMB.Word (Expected_Value), Status);
            when 4 =>
               SMB.Core_Wire.Write_U32
                 (Data, Offset, SMB.DWord (Expected_Value), Status);
            when others =>
               SMB.Core_Wire.Write_U64 (Data, Offset, Expected_Value, Status);
         end case;
         Assert (Status = Expected_Status and then Data = Expected,
                 "wire write exact status, bytes and untouched remainder");
         case Width is
            when 2 =>
               SMB.Core_Wire.Read_U16 (Data, Offset, Value_16, Status);
               Actual := SMB.QWord (Value_16);
            when 4 =>
               SMB.Core_Wire.Read_U32 (Data, Offset, Value_32, Status);
               Actual := SMB.QWord (Value_32);
            when others =>
               SMB.Core_Wire.Read_U64 (Data, Offset, Value_64, Status);
               Actual := Value_64;
         end case;
         Assert (Status = Expected_Status
                 and then Actual = (if Fits then Expected_Value else 0),
                 "wire read exact status, value and cleared rejection");
         Integer_Count := Integer_Count + 1;
      end Check_Integer;

      procedure Check_Header (First, Last : Natural) is
         Data : SMB.Bytes (First .. Last) := (others => 16#A5#);
         Expected : SMB.Bytes (Data'Range) := Data;
         Fits : constant Boolean := Data'Length >= Header_Bytes'Length;
         Status : SMB.Core_Status;
      begin
         if Fits then
            for I in Header_Bytes'Range loop
               Expected (Data'First + I) := Header_Bytes (I);
            end loop;
         end if;
         SMB.Core_Wire.Initialize_Header
           (Data, 8, 16#0123_4567_89AB_CDEF#, 16#1020_3040#,
            16#FEDC_BA98_7654_3210#, 16#1234#, Status);
         Assert
           (Status = (if Fits then SMB.Ok else SMB.Invalid_Length)
            and then Data = Expected,
            "header initialization exact status, bytes and failure preservation");
         Header_Count := Header_Count + 1;
      end Check_Header;
   begin
      for Rebase in 0 .. 2 loop
         for Size in 0 .. 12 loop
            declare
               First : constant Natural := Lower_Bound (Size, Rebase);
               Last : constant Natural :=
                 (if Size = 0 then First - 1 else First + (Size - 1));
            begin
               for Step in 0 .. 14 loop
                  for Width of Widths loop
                     for Item of Examples loop
                        Check_Integer
                          (First, Last,
                           (if Step = 14 then Natural'Last else Step),
                           Width, Item);
                     end loop;
                  end loop;
               end loop;
            end;
         end loop;
         for Size of Header_Sizes loop
            declare
               First : constant Natural := Lower_Bound (Size, Rebase);
               Last : constant Natural :=
                 (if Size = 0 then First - 1 else First + (Size - 1));
            begin
               Check_Header (First, Last);
            end;
         end loop;
      end loop;
      Ada.Text_IO.Put_Line
        ("wire primitive boundaries:" & Natural'Image (Integer_Count)
         & " integer cases," & Natural'Image (Header_Count) & " header cases");
   end Test_Wire_Primitive_Boundaries;

   procedure Test_Core_Wire is
      Data : SMB.Bytes (10 .. 25) := (others => 16#A5#);
      Empty : SMB.Bytes (1 .. 0) := (others => 0);
      Signed : SMB.Bytes (100 .. 179) := (others => 16#A5#);
      Key : constant SMB.Bytes (0 .. 15) := (others => 0);
      Value_16 : SMB.Word;
      Value_32 : SMB.DWord;
      Status : SMB.Core_Status;
   begin
      SMB.Core_Wire.Write_U32
        (Data, 4, 16#7856_3412#, Status);
      Assert (Status = SMB.Ok, "nonzero-bound U32 write");
      Assert
        (Data (10) = 16#A5# and then Data (25) = 16#A5#
         and then Data (14) = 16#12# and then Data (17) = 16#78#,
         "U32 write preserved outside range");
      SMB.Core_Wire.Read_U32 (Data, 4, Value_32, Status);
      Assert (Status = SMB.Ok and then Value_32 = 16#7856_3412#,
              "nonzero-bound U32 round trip");
      SMB.Core_Wire.Write_U16 (Data, 9, 16#BEEF#, Status);
      Assert (Status = SMB.Ok, "nonzero-bound U16 write");
      SMB.Core_Wire.Read_U16 (Data, 9, Value_16, Status);
      Assert (Status = SMB.Ok and then Value_16 = 16#BEEF#,
              "nonzero-bound U16 round trip");
      SMB.Core_Wire.Write_U32 (Empty, 0, 0, Status);
      Assert (Status /= SMB.Ok, "empty U32 write accepted");
      SMB.Core_Wire.Sign (Signed, Key, Status);
      Assert
        (Status = SMB.Ok and then Signed (100) = 16#A5#
         and then Signed (164) = 16#A5#,
         "signature preserved bytes outside signature field");
      Signed := (others => 16#A5#);
      SMB.Core_Wire.Initialize_Header
        (Signed, 8, 123, 0, 0, 1, Status);
      Assert
        (Status = SMB.Ok
         and then (for all Index in 164 .. 179 => Signed (Index) = 16#A5#),
         "core header initialization must preserve an assembled body");
      SMB.Wire.Initialize_Header (Signed, SMB.Wire.Read_Command, 124);
      Assert
        (SMB.Wire.U64 (Signed, 24) = 124
         and then (for all Index in 164 .. 179 => Signed (Index) = 0),
         "public header initialization must clear a reused packet body");
      --  STATUS_PENDING belongs to interim responses only, and an interim
      --  response must carry it.
      declare
         Header : SMB.Bytes (0 .. 63) := (others => 0);
         Expected : constant SMB.Core_Wire.Expected_Header :=
           (Command => 8, Message_Id => 7, Tree_Id => 0, Session_Id => 0,
            Match_Tree => False, Match_Session => False, Signed => False);
         Nt_Status : SMB.DWord;
      begin
         SMB.Core_Wire.Initialize_Header (Header, 8, 7, 0, 0, 1, Status);
         SMB.Core_Wire.Write_U32 (Header, 16, 1, Status);
         SMB.Core_Wire.Write_U32 (Header, 8, SMB.Status_Pending, Status);
         SMB.Core_Wire.Validate_Header (Header, Expected, Nt_Status, Status);
         Assert (Status = SMB.Invalid_Protocol,
                 "STATUS_PENDING in a final response");
         SMB.Core_Wire.Write_U32 (Header, 8, 0, Status);
         SMB.Core_Wire.Write_U32 (Header, 16, 3, Status);
         SMB.Core_Wire.Validate_Header
           (Header, Expected, Nt_Status, Status, Interim => True);
         Assert (Status = SMB.Invalid_Protocol,
                 "interim response without STATUS_PENDING");
         SMB.Core_Wire.Write_U32 (Header, 16, 1, Status);
         SMB.Core_Wire.Write_U16 (Header, 14, 0, Status);
         SMB.Core_Wire.Validate_Header (Header, Expected, Nt_Status, Status);
         Assert (Status = SMB.Invalid_Protocol,
                 "final response that grants no credits");
      end;
   end Test_Core_Wire;

   function ASCII (Value : String) return SMB.Bytes is
   begin
      if Value'Length = 0 then
         return SMB.Bytes'(1 .. 0 => 0);
      end if;
      declare
         Result : SMB.Bytes (0 .. Value'Length - 1);
      begin
      for I in Value'Range loop
         Result (I - Value'First) := SMB.Byte (Character'Pos (Value (I)));
      end loop;
      return Result;
      end;
   end ASCII;

   function Hex (Value : String) return SMB.Bytes is
      Result : SMB.Bytes (0 .. Value'Length / 2 - 1);
      function Nibble (C : Character) return SMB.Byte is
      begin
         if C in '0' .. '9' then
            return SMB.Byte (Character'Pos (C) - Character'Pos ('0'));
         elsif C in 'a' .. 'f' then
            return SMB.Byte (10 + Character'Pos (C) - Character'Pos ('a'));
         elsif C in 'A' .. 'F' then
            return SMB.Byte (10 + Character'Pos (C) - Character'Pos ('A'));
         end if;
         raise Program_Error with "invalid hexadecimal test vector";
      end Nibble;
   begin
      Assert (Value'Length mod 2 = 0, "odd hexadecimal vector");
      for I in Result'Range loop
         Result (I) := Nibble (Value (Value'First + I * 2)) * 16
           + Nibble (Value (Value'First + I * 2 + 1));
      end loop;
      return Result;
   end Hex;

   procedure Assert_Equal (Actual, Expected : SMB.Bytes; Message : String) is
   begin
      Assert (SMB.Crypto.Constant_Time_Equal (Actual, Expected), Message);
   end Assert_Equal;

   procedure Test_Crypto_Equality is
      Count : Natural := 0;
      procedure Check (Left, Right : SMB.Bytes) is
      begin
         Assert
           (SMB.Crypto.Constant_Time_Equal (Left, Right) = (Left = Right),
            "byte equality disagrees with Ada array equality");
         Count := Count + 1;
      end Check;
      Digest_Lengths : constant array (Positive range 1 .. 2) of Positive :=
        (16, 32);
   begin
      for L in SMB.Byte loop
         for R in SMB.Byte loop
            Check (SMB.Bytes'(11 => L), SMB.Bytes'(37 => R));
         end loop;
      end loop;
      for L in 0 .. 3 loop
         for R in 0 .. 3 loop
            Check (SMB.Bytes'(11 .. 10 + L => 0),
                   SMB.Bytes'(37 .. 36 + R => 0));
         end loop;
      end loop;
      for Length of Digest_Lengths loop
         declare
            Left : SMB.Bytes (11 .. 10 + Length);
            Right : SMB.Bytes (37 .. 36 + Length);
         begin
            for I in 0 .. Length - 1 loop
               Left (Left'First + I) := SMB.Byte ((17 * I + 19) mod 256);
            end loop;
            Right := Left;
            Check (Left, Right);
            for I in Right'Range loop
               for Bit in 0 .. 7 loop
                  Right (I) := Right (I) xor SMB.Byte (2 ** Bit);
                  Check (Left, Right);
                  Right (I) := Right (I) xor SMB.Byte (2 ** Bit);
               end loop;
            end loop;
            Right (Right'First) := Right (Right'First) xor 1;
            Right (Right'First + 1) := Right (Right'First + 1) xor 1;
            Check (Left, Right);
         end;
      end loop;
      declare
         Left : constant SMB.Bytes (0 .. 3) := (0, 16#7F#, 16#80#, 16#FF#);
         Right : SMB.Bytes (Natural'Last - 3 .. Natural'Last) := Left;
      begin
         Check (Left, Right);
         Right (Right'Last) := Right (Right'Last) xor 1;
         Check (Left, Right);
         Check (SMB.Bytes'(1 .. 0 => 0),
                SMB.Bytes'(Natural'Last .. Natural'Last - 1 => 0));
      end;
      declare
         Left : constant SMB.Bytes (0 .. SMB.Crypto.Maximum_Hash_Input - 1) :=
           (others => 16#55#);
         Right : SMB.Bytes (17 .. 16 + SMB.Crypto.Maximum_Hash_Input) := Left;
      begin
         Check (Left, Right);
         Right (Right'Last) := Right (Right'Last) xor 1;
         Check (Left, Right);
         Check (Left, Right (Right'First .. Right'Last - 1));
      end;
      Ada.Text_IO.Put_Line
        ("AdaSMB byte equality tests passed:" & Natural'Image (Count) & " cases");
   end Test_Crypto_Equality;

   procedure Test_Crypto is
      Empty : constant SMB.Bytes := ASCII ("");
      ABC : constant SMB.Bytes := ASCII ("abc");
      HMAC_Message : constant SMB.Bytes :=
        ASCII ("what do ya want for nothing?");
      Long_HMAC_Message : constant SMB.Bytes :=
        ASCII ("Test Using Larger Than Block-Size Key - Hash Key First");
      Long_HMAC_Key : constant SMB.Bytes (0 .. 130) := (others => 16#AA#);
      Boundary_Lengths : constant array (Positive range 1 .. 4) of Natural :=
        (55, 56, 63, 64);
      NT_Hash : constant SMB.Bytes :=
        SMB.Crypto.MD4 (SMB.Text.To_UTF16LE ("Password"));
      NTLMv2_Key : constant SMB.Bytes := SMB.Crypto.HMAC_MD5
        (NT_Hash,
         SMB.Text.To_UTF16LE (SMB.Text.NTLM_Username ("User") & "Domain"));
   begin
      Assert_Equal
        (SMB.Crypto.MD4 (Empty),
         Hex ("31d6cfe0d16ae931b73c59d7e0c089c0"), "MD4 empty");
      Assert_Equal
        (SMB.Crypto.MD4 (ABC),
         Hex ("a448017aaf21d8525fc10ae87aa6729d"), "MD4 abc");
      Assert_Equal
        (SMB.Crypto.MD5 (Empty),
         Hex ("d41d8cd98f00b204e9800998ecf8427e"), "MD5 empty");
      Assert_Equal
        (SMB.Crypto.MD5 (ABC),
         Hex ("900150983cd24fb0d6963f7d28e17f72"), "MD5 abc");
      Assert_Equal
        (SMB.Crypto.SHA256 (Empty),
         Hex
           ("e3b0c44298fc1c149afbf4c8996fb924"
            & "27ae41e4649b934ca495991b7852b855"),
         "SHA-256 empty");
      Assert_Equal
        (SMB.Crypto.SHA256 (ABC),
         Hex
           ("ba7816bf8f01cfea414140de5dae2223"
            & "b00361a396177a9cb410ff61f20015ad"),
         "SHA-256 abc");
      Assert_Equal
        (SMB.Crypto.HMAC_MD5 (ASCII ("Jefe"), HMAC_Message),
         Hex ("750c783e6ab0b503eaa86e310a5db738"), "HMAC-MD5 RFC 2202");
      Assert_Equal
        (NTLMv2_Key, Hex ("0c868a403bfd7a93a3001ef22ef02e3f"),
         "NTLMv2 response-key known answer");
      Assert_Equal
        (SMB.Crypto.HMAC_SHA256 (ASCII ("Jefe"), HMAC_Message),
         Hex
           ("5bdcc146bf60754e6a042426089575c7"
            & "5a003f089d2739839dec58b964ec3843"),
         "HMAC-SHA256 RFC 4231");
      Assert_Equal
        (SMB.Crypto.HMAC_SHA256 (Long_HMAC_Key, Long_HMAC_Message),
         Hex ("60e431591ee0b67f0d8a26aacbf5b77f"
              & "8e0bc6213728c5140546040f0ee37f54"),
         "HMAC-SHA256 RFC 4231 long-key vector");
      for Vector_Index in Boundary_Lengths'Range loop
         declare
            Length : constant Natural := Boundary_Lengths (Vector_Index);
            Input : constant SMB.Bytes (0 .. Length - 1) :=
              (others => SMB.Byte (Character'Pos ('a')));
         begin
            case Length is
               when 55 =>
                  Assert_Equal
                    (SMB.Crypto.MD5 (Input),
                     Hex ("ef1772b6dff9a122358552954ad0df65"),
                     "MD5 padding vector, 55 bytes");
                  Assert_Equal
                    (SMB.Crypto.SHA256 (Input),
                     Hex ("9f4390f8d30c2dd92ec9f095b65e2b9a"
                          & "e9b0a925a5258e241c9f1e910f734318"),
                     "SHA-256 padding vector, 55 bytes");
               when 56 =>
                  Assert_Equal
                    (SMB.Crypto.MD5 (Input),
                     Hex ("3b0c8ac703f828b04c6c197006d17218"),
                     "MD5 padding vector, 56 bytes");
                  Assert_Equal
                    (SMB.Crypto.SHA256 (Input),
                     Hex ("b35439a4ac6f0948b6d6f9e3c6af0f5f"
                          & "590ce20f1bde7090ef7970686ec6738a"),
                     "SHA-256 padding vector, 56 bytes");
               when 63 =>
                  Assert_Equal
                    (SMB.Crypto.MD5 (Input),
                     Hex ("b06521f39153d618550606be297466d5"),
                     "MD5 padding vector, 63 bytes");
                  Assert_Equal
                    (SMB.Crypto.SHA256 (Input),
                     Hex ("7d3e74a05d7db15bce4ad9ec0658ea98"
                          & "e3f06eeecf16b4c6fff2da457ddc2f34"),
                     "SHA-256 padding vector, 63 bytes");
               when 64 =>
                  Assert_Equal
                    (SMB.Crypto.MD5 (Input),
                     Hex ("014842d480b571495a4a0363793f7367"),
                     "MD5 padding vector, 64 bytes");
                  Assert_Equal
                    (SMB.Crypto.SHA256 (Input),
                     Hex ("ffe054fe7ae0cb6dc65c3af9b61d5209"
                          & "f439851db43d0ba5997337df154668eb"),
                     "SHA-256 padding vector, 64 bytes");
               when others =>
                  raise Program_Error with "unexpected hash vector length";
            end case;
         end;
      end loop;
      declare
         Message : SMB.Bytes (0 .. 199);
         Expected : SMB.Crypto.Digest_256;
         Digest : SMB.Crypto.Digest_256;
         Context : SMB.Crypto.HMAC_SHA256_Context;
      begin
         for I in Message'Range loop
            Message (I) := SMB.Byte (I mod 251);
         end loop;
         Expected := SMB.Crypto.HMAC_SHA256 (Long_HMAC_Key, Message);
         for Split in 0 .. Message'Length loop
            SMB.Crypto.HMAC_SHA256_Start (Context, Long_HMAC_Key);
            SMB.Crypto.HMAC_SHA256_Update (Context, Message (0 .. Split - 1));
            SMB.Crypto.HMAC_SHA256_Update
              (Context, Message (Split .. Message'Last));
            SMB.Crypto.HMAC_SHA256_Finish (Context, Digest);
            Assert_Equal
              (Digest, Expected,
               "incremental HMAC-SHA256 split" & Integer'Image (Split));
            Assert
              (not SMB.Crypto.HMAC_SHA256_Ready (Context),
               "finished HMAC-SHA256 context is still ready");
         end loop;
      end;
      Ada.Text_IO.Put_Line
        ("incremental HMAC-SHA256: 201 two-part splits passed");
      --  Starting again discards what an unfinished context has taken in.
      declare
         Key : constant SMB.Bytes := (16#0B#, 16#0B#, 16#0B#, 16#0B#);
         Message : constant SMB.Bytes := (16#61#, 16#62#, 16#63#);
         SHA_Context : SMB.Crypto.HMAC_SHA256_Context;
         SHA_Digest : SMB.Crypto.Digest_256;
         MD5_Context : SMB.Crypto.HMAC_MD5_Context;
         MD5_Digest : SMB.Crypto.Digest_128;
      begin
         SMB.Crypto.HMAC_SHA256_Start (SHA_Context, Key);
         SMB.Crypto.HMAC_SHA256_Update (SHA_Context, Message);
         SMB.Crypto.HMAC_SHA256_Start (SHA_Context, Key);
         SMB.Crypto.HMAC_SHA256_Update (SHA_Context, Message);
         SMB.Crypto.HMAC_SHA256_Finish (SHA_Context, SHA_Digest);
         Assert_Equal
           (SHA_Digest, SMB.Crypto.HMAC_SHA256 (Key, Message),
            "restarted HMAC-SHA256 context");
         SMB.Crypto.HMAC_MD5_Start (MD5_Context, Key);
         SMB.Crypto.HMAC_MD5_Update (MD5_Context, Message);
         SMB.Crypto.HMAC_MD5_Start (MD5_Context, Key);
         SMB.Crypto.HMAC_MD5_Update (MD5_Context, Message);
         SMB.Crypto.HMAC_MD5_Finish (MD5_Context, MD5_Digest);
         Assert_Equal
           (MD5_Digest, SMB.Crypto.HMAC_MD5 (Key, Message),
            "restarted HMAC-MD5 context");
      end;
   end Test_Crypto;

   procedure Test_NTLM_Authenticate is
      Challenge : constant SMB.Bytes := Hex
        ("a1818e30818ba0030a0101a10c060a2b06010401823702020aa27604744e544c"
         & "4d53535000020000000c000c0030000000158288200123456789abcdef000000"
         & "0000000000380038003c00000044006f006d00610069006e0001000c00530065"
         & "00720076006500720002000c0044006f006d00610069006e0007000800080706"
         & "0504030201060004000200000000000000");
      Expected : constant SMB.Bytes := Hex
        ("a182010a30820106a281ef0481ec4e544c4d5353500003000000180018005800"
         & "000068006800700000000c000c00d800000008000800e400000000000000ec00"
         & "000000000000ec0000001582882000000000000000003909823c8592086081bb"
         & "35de5f578366000000000000000000000000000000000000000000000000a3e8"
         & "7cafaf3a8c12a0bec29d2d579a5101010000000000000807060504030201ffff"
         & "ff00112233440000000001000c0053006500720076006500720002000c004400"
         & "6f006d00610069006e0007000800080706050403020106000400020000000000"
         & "00000000000044006f006d00610069006e005500530045005200a31204100100"
         & "0000dc73cbb3b8b19e6200000000");
      Auth : constant SMB.NTLM.Authentication_Result :=
        SMB.NTLM.Authenticate
          ("User", "Password", "Domain", Hex ("ffffff0011223344"), Challenge);

      procedure Check_Output_Buffers is
         Negotiate : constant SMB.Bytes := Hex
           ("604006062b0601050502a0363034a00e300c060a2b06010401823702020a"
            & "a22204204e544c4d5353500001000000158288200000000000000000"
            & "0000000000000000");
         Nonce : constant SMB.Bytes := Hex ("ffffff0011223344");
         Key : constant SMB.Bytes := Hex ("e711de05352dfa50de477e818cffec55");
         Invalid_UTF8 : constant String := (1 => Character'Val (16#FF#));
         Cases : Natural := 0;

         procedure Check
           (Capacity, Rebased : Natural; Is_Auth : Boolean;
            User : String := "User"; Password : String := "Password";
            Domain : String := "Domain"; Token : SMB.Bytes := Challenge;
            Want : SMB.Core_Status := SMB.Ok)
         is
            First : constant Natural :=
              (if Rebased = 2 then
                 (if Capacity = 0 then Natural'Last
                  else Natural'Last - (Capacity - 1))
               else 1 + 17 * Rebased);
            Output : SMB.Bytes (First .. First + (Capacity - 1)) :=
              (others => 16#A5#);
            Session_Key : SMB.Crypto.Digest_128 := (others => 16#A5#);
            Used : Natural := Natural'Last;
            Status : SMB.Core_Status;

            procedure Check_Cleared is
            begin
               Assert (Used = 0, "rejected authentication retained length");
               Assert
                 (Session_Key = (Session_Key'Range => 0),
                  "rejected authentication retained key");
               Assert
                 (Output = (Output'Range => 0),
                  "rejected token retained output bytes");
            end Check_Cleared;
         begin
            if Is_Auth then
               SMB.Core_Auth.Authenticate
                 (User, Password, Domain, Nonce, Token, 0,
                  Output, Used, Session_Key, Status);
            else
               SMB.Core_Auth.Build_Negotiate_Token (Output, Used, Status);
            end if;
            Assert (Status = Want, "token output status mismatch");
            Cases := Cases + 1;
            if Status = SMB.Ok then
               Assert
                 (Used = (if Is_Auth then Expected'Length else Negotiate'Length),
                  "token output length mismatch");
               Assert_Equal
                 (Output (First .. First + (Used - 1)),
                  (if Is_Auth then Expected else Negotiate),
                  "token output changed with buffer bounds");
               if Is_Auth then
                  Assert_Equal (Session_Key, Key, "token output key mismatch");
               end if;
            else
               Assert (Used = 0, "rejected token retained length");
               if Is_Auth then
                  Check_Cleared;
               end if;
            end if;
            Assert
              ((for all Index in Output'Range =>
                 (if Index - First >= Used then Output (Index) = 0)),
               "token output retained unused bytes");
            if Is_Auth and then Status = SMB.Ok then
               SMB.Core_Auth.Authenticate
                 (User, Password, Domain, Nonce, SMB.Bytes'(1 .. 0 => 0), 0,
                  Output, Used, Session_Key, Status);
               Assert (Status = SMB.Invalid_Encoding, "reused token rejection");
               Check_Cleared;
               Cases := Cases + 1;
            end if;
         end Check;
      begin
         for Rebased in 0 .. 2 loop
            for Is_Auth in Boolean loop
               declare
                  Length : constant Natural :=
                    (if Is_Auth then Expected'Length else Negotiate'Length);
                  Capacities : constant array (Positive range <>) of Natural :=
                    (0, 1, Length - 1, Length, Length + 1,
                     SMB.Core_Auth.Maximum_Security_Token);
               begin
                  for Capacity of Capacities loop
                     Check
                       (Capacity, Rebased, Is_Auth,
                        Want => (if Capacity < Length then SMB.Resource_Limit
                                 else SMB.Ok));
                  end loop;
               end;
            end loop;
            Check (Expected'Length + 1, Rebased, True, User => "",
                   Want => SMB.Unsupported_Feature);
            Check (Expected'Length + 1, Rebased, True,
                   Password => Invalid_UTF8, Want => SMB.Unsupported_Feature);
            Check (Expected'Length + 1, Rebased, True,
                   Domain => Invalid_UTF8, Want => SMB.Unsupported_Feature);
            Check (Expected'Length + 1, Rebased, True,
                   Token => SMB.Bytes'(0 .. 15 => 0),
                   Want => SMB.Invalid_Encoding);
         end loop;
         Ada.Text_IO.Put_Line ("authentication output buffer cases:" & Cases'Image);
      end Check_Output_Buffers;
   begin
      Check_Output_Buffers;
      Assert_Equal
        (Auth.Security_Token, Expected, "NTLM Type3 and SPNEGO MIC vector");
      Assert_Equal
        (Auth.Session_Key, Hex ("e711de05352dfa50de477e818cffec55"),
         "NTLM session base key vector");
      declare
         Type1 : constant SMB.Bytes := Hex
           ("4e544c4d53535000010000001582882000000000000000000000000000000000");
         Type3_First : constant := 14;
         Type3_Last : constant := 249;
         MIC_First : constant := Type3_First + 72;
         MIC_Last : constant := MIC_First + 15;
         Fields : constant array (Positive range <>) of Natural := (14, 15, 42, 43);
         Type2_Offset, Type2_Length : Natural;
         Extract_Status : SMB.Core_Status;
         Cases : Natural := 0;

         procedure Check_MaxLen (Token : SMB.Bytes) is
            Result : constant SMB.NTLM.Authentication_Result :=
              SMB.NTLM.Authenticate
                ("User", "Password", "Domain", Hex ("ffffff0011223344"), Token);
            Type3 : SMB.Bytes := Expected (Type3_First .. Type3_Last);
            Expected_Token : SMB.Bytes := Expected;
         begin
            Type3 (MIC_First .. MIC_Last) := (others => 0);
            Expected_Token (MIC_First .. MIC_Last) := SMB.Crypto.HMAC_MD5
              (Hex ("e711de05352dfa50de477e818cffec55"),
               Type1 & Token
                 (Token'First + Type2_Offset
                  .. Token'First + Type2_Offset + Type2_Length - 1) & Type3);
            Assert_Equal
              (Result.Session_Key, Hex ("e711de05352dfa50de477e818cffec55"),
               "ignored challenge MaxLen changed session key");
            Assert_Equal
              (Result.Security_Token, Expected_Token,
               "challenge MaxLen must remain in authenticated transcript");
            Cases := Cases + 1;
         end Check_MaxLen;
      begin
         SMB.Core_NTLM.Extract_Challenge
           (Challenge, Type2_Offset, Type2_Length, Extract_Status);
         Assert (Extract_Status = SMB.Ok, "MaxLen fixture extraction");
         for Rebased in 0 .. 1 loop
            declare
               First : constant Natural := Rebased * 7;
               Token : SMB.Bytes (First .. First + Challenge'Length - 1);
            begin
               for Field of Fields loop
                  for Value in SMB.Byte loop
                     Token := Challenge;
                     Token (First + Type2_Offset + Field) := Value;
                     Check_MaxLen (Token);
                  end loop;
               end loop;
               Token := Challenge;
               Token (First + Type2_Offset + 12 .. First + Type2_Offset + 13) :=
                 (others => 0);
               Token (First + Type2_Offset + 14 .. First + Type2_Offset + 15) :=
                 (others => 16#FF#);
               Token (First + Type2_Offset + 16 .. First + Type2_Offset + 19) :=
                 (others => 0);
               Check_MaxLen (Token);
            end;
         end loop;
         Ada.Text_IO.Put_Line ("NTLM ignored MaxLen cases:" & Cases'Image);
      end;
      declare
         Nonce : constant SMB.Bytes (0 .. 7) :=
           (16#FF#, 16#FF#, 16#FF#, 0, 16#11#, 16#22#, 16#33#, 16#44#);
         Type2_Offset, Type2_Length : Natural := 0;
         Extract_Status : SMB.Core_Status;
         Wire_Status : SMB.Core_Status;
         Info_Offset : SMB.DWord := 0;
         Bad_Offset : SMB.Bytes := Challenge;
         Length_Fields : constant array (Positive range <>) of Natural := (12, 40);
         Duplicate_AV : SMB.Bytes := Challenge;
         Nonminimal : SMB.Bytes (0 .. Challenge'Length) := (others => 0);
         Small_Output : SMB.Bytes (0 .. 0) := (others => 0);
         Small_Used : Natural := 1;
         Small_Status : SMB.Core_Status;
         Small_Auth_Output : SMB.Bytes (0 .. 0) := (others => 0);
         Small_Auth_Used : Natural := 1;
         Small_Auth_Key : SMB.Crypto.Digest_128 := (others => 0);
         Small_Auth_Status : SMB.Core_Status;
         procedure Assert_Protocol_Rejected (Token : SMB.Bytes) is
         begin
            declare
               Rejected : constant SMB.NTLM.Authentication_Result :=
                 SMB.NTLM.Authenticate
                   ("User", "Password", "Domain", Nonce, Token);
            begin
               Assert
                 (Rejected.Security_Token'Length = 0,
                  "malformed NTLM challenge unexpectedly returned a token");
            end;
            raise Program_Error with "malformed NTLM challenge was accepted";
         exception
            when SMB.Protocol_Error => null;
         end Assert_Protocol_Rejected;
      begin
         SMB.Core_NTLM.Extract_Challenge
           (Challenge, Type2_Offset, Type2_Length, Extract_Status);
         Assert
           (Extract_Status = SMB.Ok and then Type2_Length >= 48,
            "SPNEGO challenge extraction");
         Bad_Offset
           (Type2_Offset + 16 .. Type2_Offset + 19) :=
             (16#FF#, 16#FF#, 16#FF#, 16#FF#);
         Assert_Protocol_Rejected (Bad_Offset);

         Bad_Offset := Challenge;
         Bad_Offset (Type2_Offset + 44 .. Type2_Offset + 47) := (others => 16#FF#);
         Assert_Protocol_Rejected (Bad_Offset);
         for Field of Length_Fields loop
            Bad_Offset := Challenge;
            Bad_Offset (Type2_Offset + Field .. Type2_Offset + Field + 1) :=
              (others => 16#FF#);
            Assert_Protocol_Rejected (Bad_Offset);
         end loop;

         declare
            Type2_Data : SMB.Bytes (0 .. Type2_Length - 1) :=
              Challenge
                (Type2_Offset .. Type2_Offset + Type2_Length - 1);
         begin
            SMB.Core_Wire.Read_U32
              (Type2_Data, 44, Info_Offset, Wire_Status);
            Assert (Wire_Status = SMB.Ok, "fixture TargetInfo offset");
            Assert
              (Info_Offset <= SMB.DWord (Type2_Length)
               and then Natural (Info_Offset) + 20 <= Type2_Length,
               "fixture TargetInfo bounds");
            Type2_Data (Natural (Info_Offset) + 16) := 1;
            Duplicate_AV
              (Type2_Offset .. Type2_Offset + Type2_Length - 1) := Type2_Data;
            Assert_Protocol_Rejected (Duplicate_AV);
         end;

         Nonminimal (0) := Challenge (0);
         Nonminimal (1) := 16#82#;
         Nonminimal (2) := 0;
         Nonminimal (3) := Challenge (2);
         Nonminimal (4 .. Nonminimal'Last) :=
           Challenge (3 .. Challenge'Last);
         SMB.Core_NTLM.Extract_Challenge
           (Nonminimal, Type2_Offset, Type2_Length, Extract_Status);
         Assert (Extract_Status /= SMB.Ok, "nonminimal challenge DER accepted");

         SMB.Core_Auth.Build_Negotiate_Token
           (Small_Output, Small_Used, Small_Status);
         Assert
           (Small_Status = SMB.Resource_Limit and then Small_Used = 0,
            "short negotiate output buffer was accepted");
         SMB.Core_Auth.Authenticate
           ("User", "Password", "Domain", Nonce, Challenge, 0,
            Small_Auth_Output, Small_Auth_Used, Small_Auth_Key,
            Small_Auth_Status);
         Assert
           (Small_Auth_Status = SMB.Resource_Limit
            and then Small_Auth_Used = 0
            and then Small_Auth_Key = (Small_Auth_Key'Range => 0),
            "short authentication output buffer was accepted");
      end;
      --  The public wrapper: its own bounds, and the exception it maps each
      --  core status to.
      declare
         Nonce : constant SMB.Bytes := Hex ("ffffff0011223344");
         Limit : constant String
           (1 .. SMB.Core_Auth.Maximum_Credential_Bytes) := (others => 'u');
         Excess : constant String
           (1 .. SMB.Core_Auth.Maximum_Credential_Bytes + 1) :=
           (others => 'u');
         Limit_Token : constant SMB.Bytes
           (1 .. SMB.Core_Auth.Maximum_Security_Token) := (others => 0);
         Excess_Token : constant SMB.Bytes
           (1 .. SMB.Core_Auth.Maximum_Security_Token + 1) := (others => 0);
         Core_Negotiate : SMB.Bytes (0 .. 255);
         Core_Used : Natural;
         Core_Status : SMB.Core_Status;

         procedure Expect
           (User, Password, Domain : String; Nonce_Value, Token : SMB.Bytes;
            Error : Ada.Exceptions.Exception_Id; Message : String)
         is
            procedure Run is
               Ignored : constant SMB.NTLM.Authentication_Result :=
                 SMB.NTLM.Authenticate
                   (User, Password, Domain, Nonce_Value, Token);
            begin
               null;
            end Run;
         begin
            Expect_Error (Run'Access, Error, Message);
         end Expect;

         procedure Accept_Limit (User, Password, Domain : String) is
            Result : constant SMB.NTLM.Authentication_Result :=
              SMB.NTLM.Authenticate (User, Password, Domain, Nonce, Challenge);
         begin
            Assert
              (Result.Security_Token'Length > 0,
               "credentials at the length limit");
         end Accept_Limit;
      begin
         SMB.Core_Auth.Build_Negotiate_Token
           (Core_Negotiate, Core_Used, Core_Status);
         Assert
           (Core_Status = SMB.Ok
            and then SMB.NTLM.Negotiate_Token =
              Core_Negotiate (0 .. Core_Used - 1),
            "public negotiate token");
         Accept_Limit (Limit, "Password", "Domain");
         Accept_Limit ("User", Limit, "Domain");
         Accept_Limit ("User", "Password", Limit);
         Expect
           (Excess, "Password", "Domain", Nonce, Challenge,
            SMB.Authentication_Error'Identity, "user over the length limit");
         Expect
           ("User", Excess, "Domain", Nonce, Challenge,
            SMB.Authentication_Error'Identity,
            "password over the length limit");
         Expect
           ("User", "Password", Excess, Nonce, Challenge,
            SMB.Authentication_Error'Identity, "domain over the length limit");
         Expect
           ("User", "Password", "Domain", Nonce (0 .. 6), Challenge,
            SMB.Authentication_Error'Identity, "seven-byte nonce");
         Expect
           ("User", "Password", "Domain", Nonce, Excess_Token,
            SMB.Authentication_Error'Identity,
            "server token over the length limit");
         Expect
           ("User", "Password", "Domain", Nonce, Limit_Token,
            SMB.Protocol_Error'Identity,
            "malformed server token at the length limit");
         Expect
           ("", "Password", "Domain", Nonce, Challenge,
            SMB.Authentication_Error'Identity,
            "unsupported credentials must not read as a malformed challenge");
      end;
   end Test_NTLM_Authenticate;

   procedure Test_Core_Client_Authentication is
      Challenge : constant SMB.Bytes := Hex
        ("a1818e30818ba0030a0101a10c060a2b06010401823702020aa27604744e544c"
         & "4d53535000020000000c000c0030000000158288200123456789abcdef000000"
         & "0000000000380038003c00000044006f006d00610069006e0001000c00530065"
         & "00720076006500720002000c0044006f006d00610069006e0007000800080706"
         & "0504030201060004000200000000000000");
      Expected_Token : constant SMB.Bytes := Hex
        ("a182010a30820106a281ef0481ec4e544c4d5353500003000000180018005800"
         & "000068006800700000000c000c00d800000008000800e400000000000000ec00"
         & "000000000000ec0000001582882000000000000000003909823c8592086081bb"
         & "35de5f578366000000000000000000000000000000000000000000000000a3e8"
         & "7cafaf3a8c12a0bec29d2d579a5101010000000000000807060504030201ffff"
         & "ff00112233440000000001000c0053006500720076006500720002000c004400"
         & "6f006d00610069006e0007000800080706050403020106000400020000000000"
         & "00000000000044006f006d00610069006e005500530045005200a31204100100"
         & "0000dc73cbb3b8b19e6200000000");
      Session_Key : constant SMB.Bytes :=
        Hex ("e711de05352dfa50de477e818cffec55");
      Nonce : constant SMB.Bytes (0 .. 7) :=
        (16#FF#, 16#FF#, 16#FF#, 0, 16#11#, 16#22#, 16#33#, 16#44#);
      Session_Id : constant SMB.QWord := 16#1234#;

      procedure Prepare_Negotiated (State : in out SMB.Engine.Engine_State) is
         Status : SMB.Core_Status;
         Nt_Status : SMB.DWord;
         Message_Id : SMB.QWord;
         Expected : SMB.Engine.Request_Expectation;
         Response : SMB.Bytes (0 .. 127) := (others => 0);
      begin
         SMB.Engine.Initialize (State, Status);
         Assert (Status = SMB.Ok, "authentication engine initialize");
         SMB.Engine.Mark_Connected (State, Status);
         Assert (Status = SMB.Ok, "authentication transport connect");
         SMB.Engine.Begin_Request
           (State, 0, False, False, Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "authentication negotiate reservation");
         SMB.Wire.Initialize_Header (Response, 0, Message_Id, 0, 0);
         SMB.Wire.Put_U32 (Response, 16, 1);
         Response (64) := 65;
         Response (66) := 1;
         Response (68) := 16#10#;
         Response (69) := 2;
         Response (98) := 1;
         Response (102) := 1;
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert (Status = SMB.Ok, "authentication negotiate response");
         SMB.Engine.Mark_Negotiated (State, 65_536, 65_536, Status);
         Assert (Status = SMB.Ok, "authentication negotiated state");
      end Prepare_Negotiated;

      function Challenge_Response
        (Message_Id : SMB.QWord;
         Reply_Status : SMB.DWord;
         Token : SMB.Bytes) return SMB.Bytes
      is
         Packet : SMB.Bytes (0 .. 71 + Token'Length) := (others => 0);
      begin
         SMB.Wire.Initialize_Header
           (Packet, 1, Message_Id, 0, Session_Id);
         SMB.Wire.Put_U32 (Packet, 8, Reply_Status);
         SMB.Wire.Put_U32 (Packet, 16, 1);
         SMB.Wire.Put_U16 (Packet, 64, 9);
         SMB.Wire.Put_U16 (Packet, 68, 72);
         SMB.Wire.Put_U16 (Packet, 70, SMB.Word (Token'Length));
         if Token'Length > 0 then
            Packet (72 .. 71 + Token'Length) := Token;
         end if;
         return Packet;
      end Challenge_Response;

      function Final_Response
        (Message_Id : SMB.QWord;
         Reply_Status : SMB.DWord;
         Tamper_Signature, Tamper_MIC : Boolean;
         MIC_Index : Natural := 4) return SMB.Bytes
      is
         Packet : SMB.Bytes (0 .. 100) := (others => 0);
         Final_Token : SMB.Bytes (0 .. 28) :=
           (16#A1#, 16#1B#, 16#30#, 16#19#,
            16#A0#, 16#03#, 16#0A#, 16#01#, 0,
            16#A3#, 16#12#, 16#04#, 16#10#,
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
         Server_MIC : constant SMB.Bytes :=
           SMB.Core_NTLM.Mechanism_List_MIC (Session_Key, True);
      begin
         for Index in 0 .. 15 loop
            Final_Token (13 + Index) := Server_MIC (Index);
         end loop;
         if Tamper_MIC then
            Final_Token (13 + MIC_Index) :=
              Final_Token (13 + MIC_Index) xor 1;
         end if;
         SMB.Wire.Initialize_Header
           (Packet, 1, Message_Id, 0, Session_Id);
         SMB.Wire.Put_U32 (Packet, 8, Reply_Status);
         SMB.Wire.Put_U32 (Packet, 16, 9);
         SMB.Wire.Put_U16 (Packet, 64, 9);
         if Reply_Status = SMB.Success then
            SMB.Wire.Put_U16 (Packet, 68, 72);
            SMB.Wire.Put_U16 (Packet, 70, SMB.Word (Final_Token'Length));
            Packet (72 .. 100) := Final_Token;
         else
            SMB.Wire.Put_U32 (Packet, 68, 0);
         end if;
         SMB.Wire.Sign (Packet, Session_Key);
         if Tamper_Signature then
            Packet (48) := Packet (48) xor 1;
         end if;
         return Packet;
      end Final_Response;

      procedure Prepare_Final_Request
        (State : in out SMB.Engine.Engine_State;
         Value : in out SMB.Core_Client.Authentication;
         Output : in out SMB.Bytes;
         Used : out Natural) is
         Status : SMB.Core_Status;
         Nt_Status : SMB.DWord;
         Message_Id : SMB.QWord;
      begin
         SMB.Core_Client.Prepare_Negotiate
           (Value, State, Output, Used, Status);
         Assert (Status = SMB.Ok, "prepare coordinator negotiate");
         Message_Id := SMB.Wire.U64 (Output, 24);
         SMB.Core_Client.Authentication_Send_Succeeded (Value, State, Status);
         Assert (Status = SMB.Ok, "acknowledge coordinator negotiate");
         declare
            Response : constant SMB.Bytes := Challenge_Response
              (Message_Id, SMB.Status_More_Processing_Required, Challenge);
         begin
            SMB.Core_Client.Complete_Challenge
              (Value, State, Response, Nt_Status, Status);
            Assert
              (Status = SMB.Ok and then Nt_Status =
                 SMB.Status_More_Processing_Required,
               "complete coordinator challenge");
         end;
         SMB.Core_Client.Prepare_Authenticate
           (Value, State, "User", "Password", "Domain", Nonce, 0,
            Output, Used, Status);
         Assert (Status = SMB.Ok, "prepare coordinator authenticate");
         SMB.Core_Client.Authentication_Send_Succeeded (Value, State, Status);
         Assert (Status = SMB.Ok, "acknowledge coordinator authenticate");
      end Prepare_Final_Request;

      State : SMB.Engine.Engine_State;
      Value : SMB.Core_Client.Authentication;
      Request : SMB.Bytes
        (0 .. SMB.Core_Client.Authentication_Request_Size - 1) :=
          (others => 0);
      Response : SMB.Bytes (0 .. 100) := (others => 0);
      Status : SMB.Core_Status;
      Nt_Status : SMB.DWord;
      Used : Natural;
      Message_Id : SMB.QWord;
   begin
      for Failure_Case in 1 .. 5 loop
         declare
            Fail_State : SMB.Engine.Engine_State;
            Fail_Value : SMB.Core_Client.Authentication;
            Fail_Request : SMB.Bytes
              (0 .. SMB.Core_Client.Authentication_Request_Size - 1) :=
                (others => 0);
            Fail_Used : Natural;
            Fail_Message : SMB.QWord;
            Fail_Nt : SMB.DWord;
            Expected : SMB.Core_Status;
         begin
            Prepare_Negotiated (Fail_State);
            SMB.Core_Client.Prepare_Negotiate
              (Fail_Value, Fail_State, Fail_Request, Fail_Used, Status);
            Assert (Status = SMB.Ok, "prepare failing challenge negotiate");
            Fail_Message := SMB.Wire.U64 (Fail_Request, 24);
            SMB.Core_Client.Authentication_Send_Succeeded
              (Fail_Value, Fail_State, Status);
            Assert (Status = SMB.Ok, "acknowledge failing challenge negotiate");
            declare
               Fail_Response : SMB.Bytes := Challenge_Response
                 (Fail_Message,
                  (case Failure_Case is
                     when 1 => 16#C000006D#,
                     when 2 => SMB.Success,
                     when others => SMB.Status_More_Processing_Required),
                  Challenge);
            begin
               case Failure_Case is
                  when 1 =>
                     SMB.Wire.Put_U32 (Fail_Response, 68, 0);
                     Expected := SMB.Ok;
                  when 2 => Expected := SMB.Invalid_Protocol;
                  when 3 =>
                     SMB.Wire.Put_U64 (Fail_Response, 40, 0);
                     Expected := SMB.Invalid_Protocol;
                  when 4 =>
                     SMB.Wire.Put_U16
                       (Fail_Response, 70,
                        SMB.Word (Challenge'Length + 1));
                     Expected := SMB.Invalid_Offset;
                  when others =>
                     SMB.Wire.Put_U64 (Fail_Response, 24, Fail_Message + 1);
                     Expected := SMB.Correlation_Error;
               end case;
               SMB.Core_Client.Complete_Challenge
                 (Fail_Value, Fail_State, Fail_Response, Fail_Nt, Status);
            end;
            Assert
              (Status = Expected
               and then not
                 (Status = SMB.Ok
                  and then Fail_Nt = SMB.Status_More_Processing_Required)
               and then SMB.Core_Client.Authentication_Stage_Of (Fail_Value) =
                 SMB.Core_Client.Authentication_Failed
               and then
                 SMB.Core_Client.Authentication_Challenge_Length_Of
                   (Fail_Value) = 0
               and then SMB.Engine.Current_Phase (Fail_State) =
                 SMB.Engine.Disconnected
               and then not SMB.Engine.Has_Pending_Request (Fail_State)
               and then not SMB.Engine.Has_Validated_Response (Fail_State)
               and then SMB.Engine.Signing_Key_Is_Zero (Fail_State)
               and then SMB.Engine.Current_Session_Id (Fail_State) = 0,
               "failed challenge completion left state, case"
               & Integer'Image (Failure_Case) & " status "
               & SMB.Core_Status'Image (Status));
         end;
      end loop;
      Ada.Text_IO.Put_Line ("challenge failure cleanup: 5 rejected responses passed");
      for Failure_Case in 1 .. 3 loop
         declare
            Fail_State : SMB.Engine.Engine_State;
            Fail_Value : SMB.Core_Client.Authentication;
            Fail_Request : SMB.Bytes
              (0 .. SMB.Core_Client.Authentication_Request_Size - 1) :=
                (others => 0);
            Fail_Output : SMB.Bytes
              (0 .. (if Failure_Case = 1 then 99
                     else SMB.Core_Client.Authentication_Request_Size - 1)) :=
                (others => 16#AA#);
            Fail_Used : Natural;
            Fail_Message : SMB.QWord;
            Fail_Nt : SMB.DWord;
            Bad_Text : constant String := "Pa" & Character'Val (16#FF#);
         begin
            Prepare_Negotiated (Fail_State);
            SMB.Core_Client.Prepare_Negotiate
              (Fail_Value, Fail_State, Fail_Request, Fail_Used, Status);
            Assert (Status = SMB.Ok, "prepare failing authenticate negotiate");
            Fail_Message := SMB.Wire.U64 (Fail_Request, 24);
            SMB.Core_Client.Authentication_Send_Succeeded
              (Fail_Value, Fail_State, Status);
            Assert (Status = SMB.Ok, "acknowledge failing authenticate negotiate");
            SMB.Core_Client.Complete_Challenge
              (Fail_Value, Fail_State,
               Challenge_Response
                 (Fail_Message, SMB.Status_More_Processing_Required, Challenge),
               Fail_Nt, Status);
            Assert (Status = SMB.Ok, "challenge before failing authenticate");
            case Failure_Case is
               when 1 =>
                  SMB.Core_Client.Prepare_Authenticate
                    (Fail_Value, Fail_State, "User", "Password", "Domain",
                     Nonce, 0, Fail_Output, Fail_Used, Status);
               when 2 =>
                  SMB.Core_Client.Prepare_Authenticate
                    (Fail_Value, Fail_State, "User", Bad_Text, "Domain",
                     Nonce, 0, Fail_Output, Fail_Used, Status);
               when others =>
                  SMB.Core_Client.Prepare_Authenticate
                    (Fail_Value, Fail_State, Bad_Text, "Password", "Domain",
                     Nonce, 0, Fail_Output, Fail_Used, Status);
            end case;
            Assert
              (Status /= SMB.Ok
               and then Status /= SMB.Invalid_State_Status
               and then Fail_Used = 0
               and then (for all B of Fail_Output => B = 0)
               and then SMB.Core_Client.Authentication_Stage_Of (Fail_Value) =
                 SMB.Core_Client.Authentication_Failed
               and then
                 SMB.Core_Client.Authentication_Challenge_Length_Of
                   (Fail_Value) = 0
               and then SMB.Engine.Current_Phase (Fail_State) =
                 SMB.Engine.Disconnected
               and then not SMB.Engine.Has_Pending_Request (Fail_State)
               and then not SMB.Engine.Has_Validated_Response (Fail_State)
               and then SMB.Engine.Signing_Key_Is_Zero (Fail_State)
               and then SMB.Engine.Current_Session_Id (Fail_State) = 0,
               "failed authenticate preparation left state, case"
               & Integer'Image (Failure_Case) & " status "
               & SMB.Core_Status'Image (Status));
         end;
      end loop;
      Ada.Text_IO.Put_Line
        ("authenticate preparation failure cleanup: 3 rejected inputs passed");
      for Reject_Case in 1 .. 3 loop
         declare
            Reject_State : SMB.Engine.Engine_State;
            Reject_Value : SMB.Core_Client.Authentication;
            First_Request : SMB.Bytes
              (0 .. SMB.Core_Client.Authentication_Request_Size - 1) :=
                (others => 0);
            Reject_Output : SMB.Bytes
              (0 .. (if Reject_Case = 1 then 62
                     else SMB.Core_Client.Authentication_Request_Size - 1)) :=
                (others => 16#AA#);
            Reject_Used : Natural;
            Expected_Stage : SMB.Core_Client.Authentication_Stage :=
              SMB.Core_Client.Authentication_Ready;
            Expected_Phase : SMB.Engine.Phase := SMB.Engine.Negotiated;
            Owner, Epoch : SMB.QWord;
            Pending : Boolean;
         begin
            if Reject_Case = 2 then
               SMB.Engine.Initialize (Reject_State, Status);
               Assert (Status = SMB.Ok, "negotiate rejection initialize");
               SMB.Engine.Mark_Connected (Reject_State, Status);
               Assert (Status = SMB.Ok, "negotiate rejection connect");
               Expected_Phase := SMB.Engine.Transport_Connected;
            else
               Prepare_Negotiated (Reject_State);
            end if;
            if Reject_Case = 3 then
               SMB.Core_Client.Prepare_Negotiate
                 (Reject_Value, Reject_State, First_Request, Reject_Used,
                  Status);
               Assert (Status = SMB.Ok, "negotiate before repeated preparation");
               Expected_Stage := SMB.Core_Client.Negotiate_Prepared;
            end if;
            Owner := SMB.Engine.Current_Owner_Id (Reject_State);
            Epoch := SMB.Engine.Current_Epoch (Reject_State);
            Pending := SMB.Engine.Has_Pending_Request (Reject_State);
            SMB.Core_Client.Prepare_Negotiate
              (Reject_Value, Reject_State, Reject_Output, Reject_Used, Status);
            Assert
              (Status = SMB.Invalid_State_Status
               and then Reject_Used = 0
               and then (for all B of Reject_Output => B = 0)
               and then SMB.Core_Client.Authentication_Stage_Of (Reject_Value) =
                 Expected_Stage
               and then SMB.Engine.Current_Phase (Reject_State) =
                 Expected_Phase
               and then SMB.Engine.Has_Pending_Request (Reject_State) = Pending
               and then SMB.Engine.Current_Owner_Id (Reject_State) = Owner
               and then SMB.Engine.Current_Epoch (Reject_State) = Epoch,
               "rejected negotiate preparation changed state, case"
               & Integer'Image (Reject_Case));
            if Reject_Case = 3 then
               SMB.Core_Client.Authentication_Send_Succeeded
                 (Reject_Value, Reject_State, Status);
               Assert
                 (Status = SMB.Ok,
                  "repeated preparation disturbed the pending negotiate");
            end if;
         end;
      end loop;
      declare
         Short_State : SMB.Engine.Engine_State;
         Short_Value : SMB.Core_Client.Authentication;
         Retry_Value : SMB.Core_Client.Authentication;
         Short_Output : SMB.Bytes (0 .. 99) := (others => 16#AA#);
         Retry_Request : SMB.Bytes
           (0 .. SMB.Core_Client.Authentication_Request_Size - 1) :=
             (others => 0);
         Short_Used, Retry_Used : Natural;
         Owner, Epoch : SMB.QWord;
      begin
         Prepare_Negotiated (Short_State);
         Owner := SMB.Engine.Current_Owner_Id (Short_State);
         Epoch := SMB.Engine.Current_Epoch (Short_State);
         SMB.Core_Client.Prepare_Negotiate
           (Short_Value, Short_State, Short_Output, Short_Used, Status);
         Assert
           (Status = SMB.Resource_Limit
            and then Short_Used = 0
            and then (for all B of Short_Output => B = 0)
            and then SMB.Core_Client.Authentication_Stage_Of (Short_Value) =
              SMB.Core_Client.Authentication_Failed
            and then SMB.Core_Client.Authentication_Challenge_Length_Of
              (Short_Value) = 0
            and then SMB.Core_Client.Authentication_Session_Id_Of
              (Short_Value) = 0
            and then SMB.Engine.Current_Phase (Short_State) =
              SMB.Engine.Negotiated
            and then not SMB.Engine.Has_Pending_Request (Short_State)
            and then not SMB.Engine.Has_Validated_Response (Short_State)
            and then not SMB.Engine.Has_Signing_Key (Short_State)
            and then SMB.Engine.Current_Session_Id (Short_State) = 0
            and then SMB.Engine.Current_Owner_Id (Short_State) = Owner
            and then SMB.Engine.Current_Epoch (Short_State) = Epoch,
            "short negotiate output left state");
         SMB.Core_Client.Prepare_Negotiate
           (Short_Value, Short_State, Retry_Request, Retry_Used, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then Retry_Used = 0
            and then SMB.Core_Client.Authentication_Stage_Of (Short_Value) =
              SMB.Core_Client.Authentication_Failed
            and then not SMB.Engine.Has_Pending_Request (Short_State),
            "failed negotiate coordinator was reused");
         SMB.Core_Client.Prepare_Negotiate
           (Retry_Value, Short_State, Retry_Request, Retry_Used, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Core_Client.Authentication_Stage_Of (Retry_Value) =
              SMB.Core_Client.Negotiate_Prepared
            and then SMB.Engine.Has_Pending_Request (Short_State),
            "engine unusable after failed negotiate preparation");
      end;
      Ada.Text_IO.Put_Line
        ("negotiate preparation outcomes: 3 rejected calls, 1 short output"
         & " and 1 retry passed");
      for Reject_Case in 1 .. 4 loop
         declare
            Ack_State, Other_State : SMB.Engine.Engine_State;
            Ack_Value : SMB.Core_Client.Authentication;
            Ack_Request : SMB.Bytes
              (0 .. SMB.Core_Client.Authentication_Request_Size - 1) :=
                (others => 0);
            Ack_Used : Natural;
            Expected_Stage : SMB.Core_Client.Authentication_Stage :=
              SMB.Core_Client.Negotiate_Prepared;
         begin
            Prepare_Negotiated (Ack_State);
            if Reject_Case = 1 then
               Expected_Stage := SMB.Core_Client.Authentication_Ready;
            else
               SMB.Core_Client.Prepare_Negotiate
                 (Ack_Value, Ack_State, Ack_Request, Ack_Used, Status);
               Assert
                 (Status = SMB.Ok,
                  "prepare negotiate before rejected acknowledgement");
            end if;
            case Reject_Case is
               when 1 =>
                  null;
               when 2 =>
                  SMB.Core_Client.Authentication_Send_Succeeded
                    (Ack_Value, Ack_State, Status);
                  Assert (Status = SMB.Ok, "first negotiate acknowledgement");
                  Expected_Stage := SMB.Core_Client.Negotiate_Sent;
               when 3 =>
                  Prepare_Negotiated (Other_State);
               when others =>
                  SMB.Engine.Invalidate (Ack_State, Status);
                  Assert
                    (Status = SMB.Ok,
                     "invalidate before stale acknowledgement");
                  SMB.Engine.Mark_Connected (Ack_State, Status);
                  Assert
                    (Status = SMB.Ok,
                     "reconnect before stale acknowledgement");
            end case;
            if Reject_Case = 3 then
               SMB.Core_Client.Authentication_Send_Succeeded
                 (Ack_Value, Other_State, Status);
            else
               SMB.Core_Client.Authentication_Send_Succeeded
                 (Ack_Value, Ack_State, Status);
            end if;
            Assert
              (Status = SMB.Invalid_State_Status
               and then SMB.Core_Client.Authentication_Stage_Of (Ack_Value) =
                 Expected_Stage
               and then SMB.Core_Client.Authentication_Session_Id_Of
                 (Ack_Value) = 0
               and then SMB.Core_Client.Authentication_Challenge_Length_Of
                 (Ack_Value) = 0,
               "rejected send acknowledgement changed authentication, case"
               & Integer'Image (Reject_Case));
         end;
      end loop;
      Ada.Text_IO.Put_Line
        ("send acknowledgement rejections: 4 rejected calls passed");
      Prepare_Negotiated (State);
      SMB.Core_Client.Prepare_Negotiate
        (Value, State, Request, Used, Status);
      Assert (Status = SMB.Ok, "prepare authentication negotiate");
      Message_Id := SMB.Wire.U64 (Request, 24);
      declare
         Response : constant SMB.Bytes := Challenge_Response
           (Message_Id, SMB.Status_More_Processing_Required, Challenge);
      begin
         SMB.Core_Client.Complete_Challenge
           (Value, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Core_Client.Authentication_Stage_Of (Value) =
              SMB.Core_Client.Negotiate_Prepared,
            "challenge completed before send acknowledgement");
      end;
      SMB.Core_Client.Authentication_Send_Succeeded (Value, State, Status);
      Assert (Status = SMB.Ok, "authentication negotiate acknowledgement");
      declare
         Response : constant SMB.Bytes := Challenge_Response
           (Message_Id, SMB.Status_More_Processing_Required, Challenge);
      begin
         SMB.Core_Client.Complete_Challenge
           (Value, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status =
              SMB.Status_More_Processing_Required
            and then SMB.Core_Client.Authentication_Challenge_Length_Of (Value) =
              Challenge'Length,
            "coordinator challenge accepted");
         SMB.Core_Client.Complete_Challenge
           (Value, State, Response, Nt_Status, Status);
      end;
      Assert
        (Status = SMB.Invalid_State_Status
         and then SMB.Core_Client.Authentication_Stage_Of (Value) =
           SMB.Core_Client.Challenge_Received,
         "duplicate challenge completion advanced authentication");
      SMB.Core_Client.Prepare_Authenticate
        (Value, State, "User", "Password", "Domain", Nonce, 0,
         Request, Used, Status);
      Assert (Status = SMB.Ok, "prepare authentication token");
      Assert
        (Used = 64 + 24 + Expected_Token'Length
         and then Request (88 .. Used - 1) = Expected_Token,
         "coordinator produced the expected NTLM Type 3 token");
      Message_Id := SMB.Wire.U64 (Request, 24);
      Response := Final_Response (Message_Id, SMB.Success, False, False);
      SMB.Core_Client.Complete_Authenticate
        (Value, State, Response, Nt_Status, Status);
      Assert
        (Status = SMB.Invalid_State_Status
         and then Nt_Status = 0
         and then SMB.Core_Client.Authentication_Stage_Of (Value) =
           SMB.Core_Client.Authenticate_Prepared
         and then SMB.Engine.Has_Pending_Request (State)
         and then SMB.Engine.Has_Signing_Key (State),
         "final authentication completed before send acknowledgement");
      SMB.Core_Client.Authentication_Send_Succeeded (Value, State, Status);
      Assert (Status = SMB.Ok, "authentication token acknowledgement");
      SMB.Core_Client.Complete_Authenticate
        (Value, State, Response, Nt_Status, Status);
      Assert
        (Status = SMB.Ok and then Nt_Status = SMB.Success
         and then SMB.Engine.Current_Phase (State) = SMB.Engine.Authenticated
         and then SMB.Core_Client.Authentication_Stage_Of (Value) =
           SMB.Core_Client.Authentication_Finished
         and then not SMB.Engine.Has_Pending_Request (State)
         and then not SMB.Engine.Has_Validated_Response (State)
         and then SMB.Engine.Current_Session_Id (State) /= 0
         and then SMB.Engine.Current_Response_Info (State).Session_Id =
           SMB.Engine.Current_Session_Id (State)
         and then SMB.Engine.Current_Session_Id (State) =
           SMB.Core_Client.Authentication_Session_Id_Of (Value),
         "coordinator completed signed authentication");
      declare
         Info : constant SMB.Core_Protocol.Response_Info :=
           SMB.Engine.Current_Response_Info (State);
         Expected_MIC : constant SMB.Crypto.Digest_128 :=
           SMB.Core_NTLM.Mechanism_List_MIC
             (SMB.Crypto.Digest_128
                (SMB.Engine.Current_Signing_Key (State)), True);
      begin
         Assert
           (Info.Data_Length >= 16
            and then Info.Data_Offset + Info.Data_Length <= Response'Length
            and then Response
              (Response'First + Info.Data_Offset + Info.Data_Length - 16
               .. Response'First + Info.Data_Offset + Info.Data_Length - 1) =
              Expected_MIC,
            "authenticated state retains the accepted final MIC evidence");
      end;

      declare
         State_A, State_B : SMB.Engine.Engine_State;
         Value_A, Value_B : SMB.Core_Client.Authentication;
         Request_A, Request_B : SMB.Bytes
           (0 .. SMB.Core_Client.Authentication_Request_Size - 1) :=
             (others => 0);
         Response_A, Response_B : SMB.Bytes
           (0 .. 71 + Challenge'Length) := (others => 0);
         Final_A, Final_B : SMB.Bytes (0 .. 100) := (others => 0);
         Used_A, Used_B : Natural;
         Message_A, Message_B : SMB.QWord;
         Fresh_Value : SMB.Core_Client.Authentication;
         Fresh_Request : SMB.Bytes
           (0 .. SMB.Core_Client.Authentication_Request_Size - 1) :=
             (others => 0);
         Fresh_Used : Natural;
         Stale_State : SMB.Engine.Engine_State;
         Stale_Value : SMB.Core_Client.Authentication;
         Stale_Request : SMB.Bytes
           (0 .. SMB.Core_Client.Authentication_Request_Size - 1) :=
             (others => 0);
         Stale_Used : Natural;
         Stale_Response : SMB.Bytes
           (0 .. 71 + Challenge'Length) := (others => 0);
         Stale_Message : SMB.QWord;
      begin
         Prepare_Negotiated (State_A);
         Prepare_Negotiated (State_B);
         SMB.Core_Client.Prepare_Negotiate
           (Value_A, State_A, Request_A, Used_A, Status);
         Assert (Status = SMB.Ok, "prepare owner A negotiate");
         SMB.Core_Client.Prepare_Negotiate
           (Value_B, State_B, Request_B, Used_B, Status);
         Assert (Status = SMB.Ok, "prepare owner B negotiate");
         Message_A := SMB.Wire.U64 (Request_A, 24);
         Message_B := SMB.Wire.U64 (Request_B, 24);
         Assert (Message_A = Message_B, "owner context message collision");
         SMB.Core_Client.Authentication_Send_Succeeded
           (Value_A, State_A, Status);
         Assert (Status = SMB.Ok, "acknowledge owner A negotiate");
         SMB.Core_Client.Authentication_Send_Succeeded
           (Value_B, State_B, Status);
         Assert (Status = SMB.Ok, "acknowledge owner B negotiate");
         Response_A := Challenge_Response
           (Message_A, SMB.Status_More_Processing_Required, Challenge);
         Response_B := Challenge_Response
           (Message_B, SMB.Status_More_Processing_Required, Challenge);
         SMB.Core_Client.Complete_Challenge
           (Value_A, State_B, Response_A, Nt_Status, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Core_Client.Authentication_Stage_Of (Value_A) =
              SMB.Core_Client.Negotiate_Sent
            and then SMB.Engine.Has_Pending_Request (State_B),
           "foreign challenge consumed another engine");
         SMB.Core_Client.Complete_Challenge
           (Value_A, State_A, Response_A, Nt_Status, Status);
         Assert (Status = SMB.Ok, "complete owner A challenge");
         SMB.Core_Client.Complete_Challenge
           (Value_B, State_B, Response_B, Nt_Status, Status);
         Assert (Status = SMB.Ok, "complete owner B challenge");
         SMB.Core_Client.Prepare_Negotiate
           (Fresh_Value, State_A, Fresh_Request, Fresh_Used, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Core_Client.Authentication_Stage_Of (Fresh_Value) =
              SMB.Core_Client.Authentication_Ready
            and then SMB.Engine.Has_Validated_Response (State_A),
           "second authentication consumed challenge receipt");
         SMB.Core_Client.Prepare_Authenticate
           (Value_A, State_B, "User", "Password", "Domain", Nonce, 0,
            Request_A, Used_A, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Core_Client.Authentication_Stage_Of (Value_A) =
              SMB.Core_Client.Challenge_Received
            and then not SMB.Engine.Has_Signing_Key (State_B)
            and then SMB.Engine.Has_Validated_Response (State_B),
           "foreign authentication preparation mutated engine");
         SMB.Core_Client.Prepare_Authenticate
           (Value_A, State_A, "User", "Password", "Domain", Nonce, 0,
            Request_A, Used_A, Status);
         Assert (Status = SMB.Ok, "prepare owner A authenticate");
         SMB.Core_Client.Prepare_Authenticate
           (Value_B, State_B, "User", "Password", "Domain", Nonce, 0,
            Request_B, Used_B, Status);
         Assert (Status = SMB.Ok, "prepare owner B authenticate");
         SMB.Core_Client.Authentication_Send_Succeeded
           (Value_A, State_A, Status);
         Assert (Status = SMB.Ok, "acknowledge owner A authenticate");
         SMB.Core_Client.Authentication_Send_Succeeded
           (Value_B, State_B, Status);
         Assert (Status = SMB.Ok, "acknowledge owner B authenticate");
         Message_A := SMB.Wire.U64 (Request_A, 24);
         Message_B := SMB.Wire.U64 (Request_B, 24);
         Assert
           (Message_A = Message_B
            and then SMB.Engine.Current_Session_Id (State_A) =
              SMB.Engine.Current_Session_Id (State_B),
            "owner context authentication collision");
         Final_A := Final_Response (Message_A, SMB.Success, False, False);
         Final_B := Final_Response (Message_B, SMB.Success, False, False);
         SMB.Core_Client.Complete_Authenticate
           (Value_A, State_B, Final_A, Nt_Status, Status);
         Assert
            (Status = SMB.Invalid_State_Status
            and then SMB.Core_Client.Authentication_Stage_Of (Value_A) =
              SMB.Core_Client.Authenticate_Sent
            and then SMB.Engine.Has_Pending_Request (State_B)
            and then SMB.Engine.Has_Signing_Key (State_B),
           "foreign final response consumed another engine");
         SMB.Core_Client.Abort_Authentication (Value_A, State_B, Status);
         Assert
            (Status = SMB.Invalid_State_Status
            and then SMB.Core_Client.Authentication_Stage_Of (Value_A) =
              SMB.Core_Client.Authenticate_Sent
            and then SMB.Engine.Current_Phase (State_B) =
              SMB.Engine.Negotiated
            and then SMB.Engine.Has_Pending_Request (State_B)
            and then SMB.Engine.Has_Signing_Key (State_B)
            and then not SMB.Engine.Has_Validated_Response (State_B)
            and then SMB.Engine.Current_Session_Id (State_B) =
              SMB.Core_Client.Authentication_Session_Id_Of (Value_B),
           "foreign abort invalidated another engine");
         SMB.Core_Client.Complete_Authenticate
           (Value_A, State_A, Final_A, Nt_Status, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Engine.Current_Phase (State_A) =
              SMB.Engine.Authenticated,
           "owner A final response");
         SMB.Core_Client.Complete_Authenticate
           (Value_B, State_B, Final_B, Nt_Status, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Engine.Current_Phase (State_B) =
              SMB.Engine.Authenticated,
           "owner B final response");

         Prepare_Negotiated (Stale_State);
         SMB.Core_Client.Prepare_Negotiate
           (Stale_Value, Stale_State, Stale_Request, Stale_Used, Status);
         Assert (Status = SMB.Ok, "prepare stale-epoch negotiate");
         Stale_Message := SMB.Wire.U64 (Stale_Request, 24);
         SMB.Core_Client.Authentication_Send_Succeeded
           (Stale_Value, Stale_State, Status);
         Assert (Status = SMB.Ok, "acknowledge stale-epoch negotiate");
         SMB.Engine.Invalidate (Stale_State, Status);
         Assert (Status = SMB.Ok, "invalidate stale-epoch owner");
         SMB.Engine.Mark_Connected (Stale_State, Status);
         Assert (Status = SMB.Ok, "reconnect stale-epoch owner");
         Stale_Response := Challenge_Response
           (Stale_Message, SMB.Status_More_Processing_Required, Challenge);
         SMB.Core_Client.Complete_Challenge
           (Stale_Value, Stale_State, Stale_Response, Nt_Status, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Core_Client.Authentication_Stage_Of (Stale_Value) =
              SMB.Core_Client.Negotiate_Sent,
           "stale-epoch challenge was accepted");
         SMB.Core_Client.Abort_Authentication
           (Stale_Value, Stale_State, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine.Current_Phase (Stale_State) =
              SMB.Engine.Transport_Connected,
           "stale-epoch abort mutated state");
      end;

      declare
         Abort_State : SMB.Engine.Engine_State;
         Abort_Value : SMB.Core_Client.Authentication;
         Abort_Request : SMB.Bytes
           (0 .. SMB.Core_Client.Authentication_Request_Size - 1) :=
             (others => 0);
         Abort_Used : Natural;
         Abort_Message : SMB.QWord;
         Abort_Owner : SMB.QWord;
         Abort_Epoch : SMB.QWord;
      begin
         Prepare_Negotiated (Abort_State);
         SMB.Core_Client.Prepare_Negotiate
           (Abort_Value, Abort_State, Abort_Request, Abort_Used, Status);
         Assert (Status = SMB.Ok, "prepare negotiate before abort");
         Abort_Message := SMB.Wire.U64 (Abort_Request, 24);
         SMB.Core_Client.Authentication_Send_Succeeded
           (Abort_Value, Abort_State, Status);
         Assert (Status = SMB.Ok, "acknowledge negotiate before abort");
         SMB.Core_Client.Complete_Challenge
           (Abort_Value, Abort_State,
            Challenge_Response
              (Abort_Message, SMB.Status_More_Processing_Required, Challenge),
            Nt_Status, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Core_Client.Authentication_Challenge_Length_Of
              (Abort_Value) = Challenge'Length
            and then SMB.Core_Client.Authentication_Session_Id_Of
              (Abort_Value) = Session_Id,
            "challenge retained before abort");
         Abort_Owner := SMB.Engine.Current_Owner_Id (Abort_State);
         Abort_Epoch := SMB.Engine.Current_Epoch (Abort_State);
         SMB.Core_Client.Abort_Authentication
           (Abort_Value, Abort_State, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Core_Client.Authentication_Stage_Of (Abort_Value) =
              SMB.Core_Client.Authentication_Failed
            and then SMB.Engine.Current_Phase (Abort_State) =
              SMB.Engine.Disconnected
            and then not SMB.Engine.Has_Pending_Request (Abort_State)
            and then not SMB.Engine.Has_Validated_Response (Abort_State)
            and then SMB.Engine.Signing_Key_Is_Zero (Abort_State)
            and then SMB.Engine.Current_Owner_Id (Abort_State) = Abort_Owner
            and then SMB.Engine.Current_Epoch (Abort_State) = Abort_Epoch + 1
            and then SMB.Engine.Current_Session_Id (Abort_State) = 0
            and then SMB.Core_Client.Authentication_Challenge_Length_Of
              (Abort_Value) = 0,
            "successful abort left authentication state");
      end;

      declare
         Failed_State : SMB.Engine.Engine_State;
         Failed_Value : SMB.Core_Client.Authentication;
         Failed_Request : SMB.Bytes
           (0 .. SMB.Core_Client.Authentication_Request_Size - 1) :=
             (others => 0);
         Failed_Response : SMB.Bytes (0 .. Challenge'Length + 71) :=
           (others => 0);
         Failed_Used : Natural;
      begin
         Prepare_Negotiated (Failed_State);
         SMB.Core_Client.Prepare_Negotiate
           (Failed_Value, Failed_State, Failed_Request, Failed_Used, Status);
         Message_Id := SMB.Wire.U64 (Failed_Request, 24);
         SMB.Core_Client.Authentication_Send_Succeeded
           (Failed_Value, Failed_State, Status);
         Failed_Response := Challenge_Response
           (Message_Id, SMB.Success, Challenge);
         SMB.Core_Client.Complete_Challenge
           (Failed_Value, Failed_State, Failed_Response, Nt_Status, Status);
         Assert
           (Status /= SMB.Ok
            and then Nt_Status = SMB.Success
            and then not SMB.Engine.Has_Signing_Key (Failed_State)
            and then not SMB.Engine.Has_Pending_Request (Failed_State)
            and then SMB.Engine.Signing_Key_Is_Zero (Failed_State),
            "successful challenge status installed a key or advanced");
      end;

      declare
         Failed_State : SMB.Engine.Engine_State;
         Failed_Value : SMB.Core_Client.Authentication;
         Failed_Request : SMB.Bytes
           (0 .. SMB.Core_Client.Authentication_Request_Size - 1) :=
             (others => 0);
         Malformed : constant SMB.Bytes := (0 => 0);
         Failed_Used : Natural;
      begin
         Prepare_Negotiated (Failed_State);
         SMB.Core_Client.Prepare_Negotiate
           (Failed_Value, Failed_State, Failed_Request, Failed_Used, Status);
         Message_Id := SMB.Wire.U64 (Failed_Request, 24);
         SMB.Core_Client.Authentication_Send_Succeeded
           (Failed_Value, Failed_State, Status);
         declare
            Failed_Response : constant SMB.Bytes := Challenge_Response
              (Message_Id, SMB.Status_More_Processing_Required, Malformed);
         begin
            SMB.Core_Client.Complete_Challenge
              (Failed_Value, Failed_State, Failed_Response, Nt_Status, Status);
         end;
         SMB.Core_Client.Prepare_Authenticate
           (Failed_Value, Failed_State, "User", "Password", "Domain", Nonce,
            0, Failed_Request, Failed_Used, Status);
         Assert
           (Status in SMB.Invalid_Encoding | SMB.Invalid_Protocol
            and then SMB.Core_Client.Authentication_Stage_Of (Failed_Value) =
              SMB.Core_Client.Authentication_Failed
            and then SMB.Engine.Current_Phase (Failed_State) =
              SMB.Engine.Disconnected
            and then SMB.Engine.Signing_Key_Is_Zero (Failed_State)
            and then not SMB.Engine.Has_Pending_Request (Failed_State),
            "malformed challenge was not distinguished and invalidated");
      end;

      for Fault in 0 .. 8 loop
         declare
            Failed_State : SMB.Engine.Engine_State;
            Failed_Value : SMB.Core_Client.Authentication;
            Failed_Request : SMB.Bytes
              (0 .. SMB.Core_Client.Authentication_Request_Size - 1) :=
                (others => 0);
            Failed_Response : SMB.Bytes (11 .. 111) := (others => 0);
            Failed_Used : Natural;
            Last : Natural := Failed_Response'Last;
            Hint : SMB.DWord;
         begin
            Prepare_Negotiated (Failed_State);
            Prepare_Final_Request
              (Failed_State, Failed_Value, Failed_Request, Failed_Used);
            Message_Id := SMB.Wire.U64 (Failed_Request, 24);
            Failed_Response := Final_Response
              (Message_Id, 16#C000_006D#, False, False);
            SMB.Wire.Put_U32 (Failed_Response, 16, 1);
            Failed_Response (59 .. 74) := (others => 0);
            case Fault is
               when 1 => SMB.Wire.Put_U64 (Failed_Response, 24, Message_Id + 1);
               when 2 => SMB.Wire.Put_U64 (Failed_Response, 40, Session_Id + 1);
               when 3 => SMB.Wire.Put_U16 (Failed_Response, 12, 3);
               when 4 => Last := Failed_Response'First + 70;
               when 5 => SMB.Wire.Put_U16 (Failed_Response, 64, 8);
               when 6 => SMB.Wire.Put_U32 (Failed_Response, 8, SMB.Success);
               when 7 => SMB.Wire.Put_U32
                 (Failed_Response, 8, SMB.Status_More_Processing_Required);
               when 8 => SMB.Wire.Put_U32 (Failed_Response, 16, 9);
               when others => null;
            end case;
            Hint := SMB.Core_Client.Unverified_Authentication_Status
              (Failed_Value, Failed_State,
               Failed_Response (Failed_Response'First .. Last));
            Assert
              (Hint = (if Fault = 0 then 16#C000_006D# else 0),
               "unsigned authentication hint bounds/correlation/trust fault"
                 & Natural'Image (Fault) & " hint" & SMB.DWord'Image (Hint));
            Assert
              (SMB.Engine.Has_Pending_Request (Failed_State)
               and then SMB.Engine.Has_Signing_Key (Failed_State)
               and then not SMB.Engine.Has_Validated_Response (Failed_State),
               "diagnostic extraction altered authentication state");
            SMB.Core_Client.Complete_Authenticate
              (Failed_Value, Failed_State,
               Failed_Response (Failed_Response'First .. Last),
               Nt_Status, Status);
            Assert
              (Status /= SMB.Ok and then Nt_Status = 0
               and then SMB.Engine.Current_Phase (Failed_State) =
                 SMB.Engine.Disconnected
               and then SMB.Engine.Signing_Key_Is_Zero (Failed_State)
               and then not SMB.Engine.Has_Pending_Request (Failed_State)
               and then not SMB.Engine.Has_Validated_Response (Failed_State)
               and then SMB.Core_Client.Authentication_Challenge_Length_Of
                 (Failed_Value) = 0,
               "unverified response advanced authentication");
            Assert
              (SMB.Core_Client.Unverified_Authentication_Status
                 (Failed_Value, Failed_State, Failed_Response) = 0,
               "stale authentication produced a diagnostic hint");
         end;
      end loop;

      for Fault in 1 .. 3 loop
         declare
            Failed_State : SMB.Engine.Engine_State;
            Failed_Value : SMB.Core_Client.Authentication;
            Failed_Request : SMB.Bytes
              (0 .. SMB.Core_Client.Authentication_Request_Size - 1) :=
                (others => 0);
            Failed_Response : SMB.Bytes (0 .. 100) := (others => 0);
            Failed_Used : Natural;
         begin
            Prepare_Negotiated (Failed_State);
            Prepare_Final_Request
              (Failed_State, Failed_Value, Failed_Request, Failed_Used);
            Message_Id := SMB.Wire.U64 (Failed_Request, 24);
            if Fault = 3 then
               Failed_Response := Final_Response
                 (Message_Id, SMB.Status_Access_Denied, False, False);
            else
               Failed_Response := Final_Response
                 (Message_Id, SMB.Success, Fault = 1, Fault = 2);
            end if;
            SMB.Core_Client.Complete_Authenticate
              (Failed_Value, Failed_State, Failed_Response, Nt_Status, Status);
            Assert
              (SMB.Engine.Current_Phase (Failed_State) =
                 SMB.Engine.Disconnected
               and then SMB.Engine.Signing_Key_Is_Zero (Failed_State)
               and then not SMB.Engine.Has_Pending_Request (Failed_State)
               and then not SMB.Engine.Has_Validated_Response (Failed_State)
               and then SMB.Core_Client.Authentication_Challenge_Length_Of
                 (Failed_Value) = 0,
               "rejected final authentication retained session state");
            if Fault = 3 then
               Assert
                 (Status = SMB.Ok
                  and then Nt_Status = SMB.Status_Access_Denied
                 and then SMB.Core_Client.Authentication_Stage_Of
                    (Failed_Value) = SMB.Core_Client.Authentication_Failed,
                 "signed authentication NT status was not preserved");
            elsif Fault = 1 then
               Assert
                 (Status = SMB.Signature_Error
                  and then Nt_Status = 0
                  and then SMB.Core_Client.Authentication_Stage_Of
                    (Failed_Value) = SMB.Core_Client.Authentication_Failed,
                  "bad final signature was accepted");
            else
               Assert
                 (Status = SMB.Invalid_Protocol
                  and then Nt_Status = 0
                  and then SMB.Core_Client.Authentication_Stage_Of
                    (Failed_Value) = SMB.Core_Client.Authentication_Failed,
                  "bad final MIC was accepted");
            end if;
         end;
      end loop;

      for MIC_Index in 0 .. 15 loop
         declare
            Failed_State : SMB.Engine.Engine_State;
            Failed_Value : SMB.Core_Client.Authentication;
            Failed_Request : SMB.Bytes
              (0 .. SMB.Core_Client.Authentication_Request_Size - 1) :=
                (others => 0);
            Failed_Response : SMB.Bytes (0 .. 100) := (others => 0);
            Failed_Used : Natural;
         begin
            Prepare_Negotiated (Failed_State);
            Prepare_Final_Request
              (Failed_State, Failed_Value, Failed_Request, Failed_Used);
            Message_Id := SMB.Wire.U64 (Failed_Request, 24);
            Failed_Response := Final_Response
              (Message_Id, SMB.Success, False, True, MIC_Index);
            SMB.Core_Client.Complete_Authenticate
              (Failed_Value, Failed_State, Failed_Response, Nt_Status, Status);
            Assert
              (Status = SMB.Invalid_Protocol
               and then Nt_Status = 0
               and then SMB.Engine.Current_Phase (Failed_State) =
                 SMB.Engine.Disconnected
               and then SMB.Engine.Signing_Key_Is_Zero (Failed_State)
               and then not SMB.Engine.Has_Pending_Request (Failed_State)
               and then not SMB.Engine.Has_Validated_Response (Failed_State)
               and then SMB.Core_Client.Authentication_Challenge_Length_Of
                 (Failed_Value) = 0
               and then SMB.Core_Client.Authentication_Stage_Of
                 (Failed_Value) = SMB.Core_Client.Authentication_Failed,
               "final MIC byte mutation was accepted");
         end;
      end loop;
   end Test_Core_Client_Authentication;

   procedure Test_Final_Spnego is
      Accept_Completed : constant SMB.Bytes :=
        (16#A1#, 16#07#, 16#30#, 16#05#, 16#A0#, 16#03#,
         16#0A#, 16#01#, 16#00#);
      Nonminimal_Length : constant SMB.Bytes :=
        (16#A1#, 16#81#, 16#07#, 16#30#, 16#05#,
         16#A0#, 16#03#, 16#0A#, 16#01#, 16#00#);
      Requested_MIC : constant SMB.Bytes :=
        (16#A1#, 16#07#, 16#30#, 16#05#, 16#A3#, 16#03#,
         16#04#, 16#01#, 16#00#);
      Duplicate_State : constant SMB.Bytes :=
        (16#A1#, 16#0C#, 16#30#, 16#0A#,
         16#A0#, 16#03#, 16#0A#, 16#01#, 16#00#,
         16#A0#, 16#03#, 16#0A#, 16#01#, 16#00#);
      Empty_Token : constant SMB.Bytes := (1 .. 0 => 0);
      Key : SMB.Crypto.Digest_128;
      Server_MIC : constant SMB.Bytes :=
        (1, 0, 0, 0, 16#0A#, 16#FB#, 16#34#, 16#90#,
         16#3A#, 16#3E#, 16#4E#, 16#54#, 0, 0, 0, 0);
      Signed_Final : SMB.Bytes (0 .. 28) :=
        (16#A1#, 16#1B#, 16#30#, 16#19#,
         16#A0#, 16#03#, 16#0A#, 16#01#, 0,
         16#A3#, 16#12#, 16#04#, 16#10#,
         1, 0, 0, 0, 16#0A#, 16#FB#, 16#34#, 16#90#,
         16#3A#, 16#3E#, 16#4E#, 16#54#, 0, 0, 0, 0);
      Status : SMB.Core_Status;
   begin
      for I in Key'Range loop
         Key (I) := SMB.Byte (I);
      end loop;
      Assert_Equal
        (SMB.Core_NTLM.Mechanism_List_MIC (Key, False),
         SMB.Bytes'(1, 0, 0, 0, 16#49#, 16#EA#, 16#44#, 16#2B#,
                    16#EB#, 16#10#, 16#41#, 16#47#, 0, 0, 0, 0),
         "NTLM client mechanism-list MIC vector");
      Assert_Equal
        (SMB.Core_NTLM.Mechanism_List_MIC (Key, True), Server_MIC,
         "NTLM server mechanism-list MIC vector");
      SMB.Core_NTLM.Validate_Final_Token (Signed_Final, Status, Server_MIC);
      Assert (Status = SMB.Ok, "valid SPNEGO mechanism-list MIC");
      Signed_Final (17) := Signed_Final (17) xor 1;
      SMB.Core_NTLM.Validate_Final_Token (Signed_Final, Status, Server_MIC);
      Assert (Status = SMB.Signature_Error, "tampered SPNEGO MIC accepted");
      SMB.Core_NTLM.Validate_Final_Token (Accept_Completed, Status, Server_MIC);
      Assert (Status = SMB.Signature_Error, "missing mandatory SPNEGO MIC accepted");
      SMB.Core_NTLM.Validate_Final_Token (Accept_Completed, Status);
      Assert (Status = SMB.Ok, "valid SPNEGO accept-completed token");
      SMB.Core_NTLM.Validate_Final_Token (Empty_Token, Status);
      Assert (Status = SMB.Ok, "empty successful SPNEGO token");
      SMB.Core_NTLM.Validate_Final_Token (Nonminimal_Length, Status);
      Assert (Status /= SMB.Ok, "nonminimal DER length accepted");
      SMB.Core_NTLM.Validate_Final_Token (Requested_MIC, Status);
      Assert (Status /= SMB.Ok, "SPNEGO mechListMIC accepted");
      SMB.Core_NTLM.Validate_Final_Token (Duplicate_State, Status);
      Assert (Status /= SMB.Ok, "duplicate SPNEGO state accepted");
   end Test_Final_Spnego;

   procedure Test_Connection_Reserved is
      Negotiate : SMB.Bytes (11 .. 138) := (others => 0);
      Tree : SMB.Bytes (11 .. 90) := (others => 0);
      type Offset_Array is array (Positive range <>) of Natural;
      Offsets : constant Offset_Array := (70, 71, 124, 125, 126, 127);
      Info : SMB.Core_Protocol.Response_Info;
      Status : SMB.Core_Status;
   begin
      SMB.Wire.Put_U16 (Negotiate, 64, 65);
      SMB.Wire.Put_U16 (Negotiate, 66, 1);
      SMB.Wire.Put_U16 (Negotiate, 68, SMB.SMB2_Dialect_0210);
      SMB.Wire.Put_U32 (Negotiate, 96, 65_536);
      SMB.Wire.Put_U32 (Negotiate, 100, 65_536);
      for Offset of Offsets loop
         Negotiate (Negotiate'First + 70 .. Negotiate'First + 71) :=
           (others => 16#FF#);
         Negotiate (Negotiate'First + 124 .. Negotiate'First + 127) :=
           (others => 16#FF#);
         for Reserved in SMB.Byte loop
            Negotiate (Negotiate'First + Offset) := Reserved;
            SMB.Core_Protocol.Parse_Response
              (Negotiate, SMB.Core_Wire.Command_Code (0),
               SMB.Success, Info, Status);
            Assert
              (Status = SMB.Ok,
               "SMB2.1 connection reserved fields were not ignored");
            Assert
              (Info.Max_Read = 65_536 and then Info.Max_Write = 65_536,
               "NEGOTIATE reserved fields altered transfer limits");
         end loop;
      end loop;
      SMB.Core_Protocol.Parse_Response
        (Negotiate (Negotiate'First .. Negotiate'Last - 1),
         SMB.Core_Wire.Command_Code (0), SMB.Success, Info, Status);
      Assert (Status /= SMB.Ok, "NEGOTIATE accepted truncated response");
      SMB.Wire.Put_U16 (Negotiate, 68, 16#0311#);
      SMB.Core_Protocol.Parse_Response
        (Negotiate, SMB.Core_Wire.Command_Code (0),
         SMB.Success, Info, Status);
      Assert (Status /= SMB.Ok, "NEGOTIATE accepted unsupported dialect");
      SMB.Wire.Put_U16 (Negotiate, 68, SMB.SMB2_Dialect_0210);
      SMB.Wire.Put_U16 (Negotiate, 66, 0);
      SMB.Core_Protocol.Parse_Response
        (Negotiate, SMB.Core_Wire.Command_Code (0),
         SMB.Success, Info, Status);
      Assert (Status /= SMB.Ok, "NEGOTIATE accepted disabled signing");
      SMB.Wire.Put_U16 (Negotiate, 66, 1);
      SMB.Wire.Put_U16 (Negotiate, 120, 127);
      SMB.Wire.Put_U16 (Negotiate, 122, 1);
      SMB.Core_Protocol.Parse_Response
        (Negotiate, SMB.Core_Wire.Command_Code (0),
         SMB.Success, Info, Status);
      Assert (Status /= SMB.Ok, "NEGOTIATE accepted overlapping security buffer");

      SMB.Wire.Put_U16 (Tree, 64, 16);
      Tree (Tree'First + 66) := 1;
      SMB.Wire.Put_U32 (Tree, 36, 7);
      for Reserved in SMB.Byte loop
         Tree (Tree'First + 67) := Reserved;
         SMB.Core_Protocol.Parse_Response
           (Tree, SMB.Core_Wire.Command_Code (3),
            SMB.Success, Info, Status);
         Assert
           (Status = SMB.Ok and then Info.Tree_Id = 7,
            "TREE_CONNECT reserved byte changed acceptance or TreeId");
      end loop;
      SMB.Core_Protocol.Parse_Response
        (Tree (Tree'First .. Tree'Last - 1),
         SMB.Core_Wire.Command_Code (3), SMB.Success, Info, Status);
      Assert (Status /= SMB.Ok, "TREE_CONNECT accepted truncated response");
      Tree (Tree'First + 66) := 2;
      SMB.Core_Protocol.Parse_Response
        (Tree, SMB.Core_Wire.Command_Code (3), SMB.Success, Info, Status);
      Assert (Status /= SMB.Ok, "TREE_CONNECT accepted unsupported share type");
      Tree (Tree'First + 66) := 1;
      SMB.Wire.Put_U32 (Tree, 68, 16#8000#);
      SMB.Core_Protocol.Parse_Response
        (Tree, SMB.Core_Wire.Command_Code (3), SMB.Success, Info, Status);
      Assert (Status /= SMB.Ok, "TREE_CONNECT accepted encryption requirement");
      SMB.Wire.Put_U32 (Tree, 68, 0);
      SMB.Wire.Put_U32 (Tree, 36, 0);
      SMB.Core_Protocol.Parse_Response
        (Tree, SMB.Core_Wire.Command_Code (3), SMB.Success, Info, Status);
      Assert (Status /= SMB.Ok, "TREE_CONNECT accepted zero TreeId");
   end Test_Connection_Reserved;

   procedure Test_Teardown_Reserved is
      type Command_Array is array (Positive range <>) of
        SMB.Core_Wire.Command_Code;
      Commands : constant Command_Array := (2, 4, 6);
      Packet : SMB.Bytes (11 .. 134) := (others => 0);
      Info : SMB.Core_Protocol.Response_Info;
      Status : SMB.Core_Status;
   begin
      for Command of Commands loop
         declare
            Length : constant Positive := (if Command = 6 then 124 else 68);
            Structure : constant SMB.Word := (if Command = 6 then 60 else 4);
            Offset : constant Natural := (if Command = 6 then 68 else 66);
            Width : constant Positive := (if Command = 6 then 4 else 2);
         begin
            Packet := (others => 0);
            SMB.Wire.Put_U16 (Packet, 64, Structure);
            for Byte_Offset in 0 .. Width - 1 loop
               Packet
                 (Packet'First + Offset .. Packet'First + Offset + Width - 1) :=
                   (others => 16#FF#);
               for Reserved in SMB.Byte loop
                  Packet (Packet'First + Offset + Byte_Offset) := Reserved;
                  SMB.Core_Protocol.Parse_Response
                    (Packet (Packet'First .. Packet'First + Length - 1),
                     Command, SMB.Success, Info, Status);
                  Assert
                    (Status = SMB.Ok,
                     "SMB2.1 teardown reserved fields were not ignored");
               end loop;
            end loop;
            SMB.Core_Protocol.Parse_Response
              (Packet (Packet'First .. Packet'First + Length - 2),
               Command, SMB.Success, Info, Status);
            Assert (Status /= SMB.Ok, "teardown accepted truncated response");
            SMB.Wire.Put_U16 (Packet, 64, Structure + 1);
            SMB.Core_Protocol.Parse_Response
              (Packet (Packet'First .. Packet'First + Length - 1),
               Command, SMB.Success, Info, Status);
            Assert (Status /= SMB.Ok, "teardown accepted wrong structure size");
            if Command = 6 then
               SMB.Wire.Put_U16 (Packet, 64, Structure);
               SMB.Wire.Put_U16 (Packet, 66, 2);
               SMB.Core_Protocol.Parse_Response
                 (Packet, Command, SMB.Success, Info, Status);
               Assert
                 (Status /= SMB.Ok,
                  "CLOSE reserved fields bypassed unsupported-flags check");
            end if;
         end;
      end loop;
   end Test_Teardown_Reserved;

   procedure Test_Error_Reserved is
      Packet : SMB.Bytes (11 .. 85) := (others => 0);
      Info : SMB.Core_Protocol.Response_Info;
      Status : SMB.Core_Status;
      type Command_Array is array (Positive range <>) of
        SMB.Core_Wire.Command_Code;
      Commands : constant Command_Array := (5, 8, 14, 17);
   begin
      SMB.Wire.Put_U16 (Packet, 64, 9);
      SMB.Wire.Put_U32 (Packet, 68, 3);
      for Reserved in SMB.Byte loop
         Packet (Packet'First + 67) := Reserved;
         for Command of Commands loop
            SMB.Core_Protocol.Parse_Response
              (Packet, Command, SMB.Status_Access_Denied, Info, Status);
            Assert
              (Status = SMB.Ok, "SMB2.1 ERROR reserved byte was not ignored");
         end loop;
      end loop;
      Packet (Packet'First + 66) := 1;
      SMB.Core_Protocol.Parse_Response
        (Packet, SMB.Core_Wire.Command_Code (5),
         SMB.Status_Access_Denied, Info, Status);
      Assert
        (Status /= SMB.Ok, "SMB2.1 ERROR accepted nonzero ErrorContextCount");
      Packet (Packet'First + 66) := 0;
      SMB.Wire.Put_U32 (Packet, 68, 4);
      SMB.Core_Protocol.Parse_Response
        (Packet, SMB.Core_Wire.Command_Code (5),
         SMB.Status_Access_Denied, Info, Status);
      Assert (Status /= SMB.Ok, "ERROR accepted oversized ByteCount");
      SMB.Wire.Put_U32 (Packet, 68, SMB.DWord'Last);
      SMB.Core_Protocol.Parse_Response
        (Packet, SMB.Core_Wire.Command_Code (5),
         SMB.Status_Access_Denied, Info, Status);
      Assert (Status /= SMB.Ok, "ERROR accepted overflowing ByteCount");
      SMB.Wire.Put_U32 (Packet, 68, 0);
      SMB.Core_Protocol.Parse_Response
        (Packet (Packet'First .. Packet'First + 71),
         SMB.Core_Wire.Command_Code (5),
         SMB.Status_Access_Denied, Info, Status);
      Assert (Status = SMB.Ok, "ERROR rejected empty data with reserved byte");
      SMB.Core_Protocol.Parse_Response
        (Packet (Packet'First .. Packet'First + 70),
         SMB.Core_Wire.Command_Code (5),
         SMB.Status_Access_Denied, Info, Status);
      Assert (Status /= SMB.Ok, "ERROR accepted truncated body");
      SMB.Wire.Put_U16 (Packet, 64, 8);
      SMB.Core_Protocol.Parse_Response
        (Packet, SMB.Core_Wire.Command_Code (5),
         SMB.Status_Access_Denied, Info, Status);
      Assert (Status /= SMB.Ok, "ERROR accepted wrong structure size");
   end Test_Error_Reserved;

   procedure Test_Read_Reserved is
      Packet : SMB.Bytes (11 .. 92) := (others => 0);
      Info : SMB.Core_Protocol.Response_Info;
      Status : SMB.Core_Status;
      type Reserved_Array is array (Positive range <>) of SMB.DWord;
      Values : constant Reserved_Array :=
        (0, 1, 16#8000_0000#, SMB.DWord'Last);
   begin
      SMB.Wire.Put_U16 (Packet, 64, 17);
      Packet (Packet'First + 66) := 80;
      SMB.Wire.Put_U32 (Packet, 68, 2);
      Packet (Packet'First + 80 .. Packet'Last) := (16#AA#, 16#BB#);
      for Reserved in SMB.Byte loop
         for Reserved2 of Values loop
            Packet (Packet'First + 67) := Reserved;
            SMB.Wire.Put_U32 (Packet, 76, Reserved2);
            SMB.Core_Protocol.Parse_Response
              (Packet, SMB.Core_Wire.Command_Code (8),
               SMB.Success, Info, Status);
            Assert
              (Status = SMB.Ok and then Info.Data_Offset = 80
               and then Info.Data_Length = 2,
               "SMB2.1 READ reserved fields were not ignored");
         end loop;
      end loop;
      SMB.Wire.Put_U32 (Packet, 68, 3);
      SMB.Core_Protocol.Parse_Response
        (Packet, SMB.Core_Wire.Command_Code (8), SMB.Success, Info, Status);
      Assert (Status /= SMB.Ok, "ignored READ fields bypassed length check");
      SMB.Wire.Put_U32 (Packet, 68, 2);
      Packet (Packet'First + 66) := 79;
      SMB.Core_Protocol.Parse_Response
        (Packet, SMB.Core_Wire.Command_Code (8), SMB.Success, Info, Status);
      Assert (Status /= SMB.Ok, "ignored READ fields bypassed offset check");
      Packet (Packet'First + 66) := 80;
      SMB.Wire.Put_U16 (Packet, 64, 18);
      SMB.Core_Protocol.Parse_Response
        (Packet, SMB.Core_Wire.Command_Code (8), SMB.Success, Info, Status);
      Assert (Status /= SMB.Ok, "ignored READ fields bypassed structure check");
   end Test_Read_Reserved;

   procedure Test_Directory_Bounds is
      Count : Natural := 0;
      Prefix : constant := 8;
      type Length_Array is array (Positive range <>) of SMB.DWord;
      Lengths : constant Length_Array :=
        (0, 1, 2, 3, 4, 8, 9, 65_534, SMB.DWord'Last);

      procedure Check
        (Available : Natural;
         Name_Length, Next_Offset : SMB.DWord;
         High_Bound : Boolean) is
         Template : SMB.Bytes (0 .. 223) := (others => 0);
         First : constant Natural :=
           (if High_Bound then Natural'Last - (Prefix + Available - 1)
            else 11);
         Buffer : SMB.Bytes (First .. First + (Prefix + Available - 1)) :=
           (others => 0);
         Cursor : Natural := Prefix;
         Info : SMB.Core_Protocol.Directory_Info;
         Status : SMB.Core_Status;
         Expected : constant Boolean :=
           Available >= 104
           and then Name_Length > 0
           and then Name_Length mod 2 = 0
           and then SMB.QWord (Name_Length) <= SMB.QWord (Available - 104)
           and then
             (Next_Offset = 0
              or else
                (Next_Offset mod 8 = 0
                 and then SMB.QWord (Next_Offset) < SMB.QWord (Available)
                 and then SMB.QWord (Next_Offset) >=
                   104 + SMB.QWord (Name_Length)));
      begin
         SMB.Wire.Put_U32 (Template, 0, Next_Offset);
         SMB.Wire.Put_U32 (Template, 60, Name_Length);
         Template (104 .. 111) := (120, 0, 121, 0, 122, 0, 119, 0);
         if Available > 0 then
            Buffer (First + Prefix .. Buffer'Last) :=
              Template (0 .. Available - 1);
         end if;
         SMB.Core_Protocol.Parse_Directory_Entry
           (Buffer, Cursor, Info, Status);
         Count := Count + 1;
         Assert
           ((Status = SMB.Ok) = Expected,
            "directory bounds result mismatch: available"
            & Natural'Image (Available) & " name"
            & SMB.DWord'Image (Name_Length) & " next"
            & SMB.DWord'Image (Next_Offset));
         if Expected then
            Assert
              (Cursor =
                 (if Next_Offset = 0 then Buffer'Length
                  else Prefix + Natural (Next_Offset))
               and then Info.Next_Cursor = Cursor
               and then Info.Name_Offset = Prefix + 104
               and then Info.Name_Length = Natural (Name_Length),
               "directory bounds output mismatch");
         else
            Assert (Cursor = Prefix, "rejected directory record advanced cursor");
         end if;
      end Check;
      procedure Check_Name (Name : SMB.Bytes; Valid, High_Bound : Boolean) is
         Length : constant Positive := Prefix + 104 + Name'Length;
         First : constant Natural :=
           (if High_Bound then Natural'Last - (Length - 1) else 11);
         Buffer : SMB.Bytes (First .. First + (Length - 1)) := (others => 0);
         Cursor : Natural := Prefix;
         Info : SMB.Core_Protocol.Directory_Info;
         Status : SMB.Core_Status;
      begin
         SMB.Wire.Put_U32 (Buffer, Prefix + 60, SMB.DWord (Name'Length));
         Buffer (First + Prefix + 104 .. Buffer'Last) := Name;
         SMB.Core_Protocol.Parse_Directory_Entry (Buffer, Cursor, Info, Status);
         Count := Count + 1;
         Assert
           (Status = (if Valid then SMB.Ok else SMB.Invalid_Encoding),
            "directory name encoding outcome");
         Assert
           (Cursor = (if Valid then Length else Prefix),
            "directory name failure changed cursor");
         if Valid then
            Assert
              (Info.Name_Offset = Prefix + 104
               and then Info.Name_Length = Name'Length
               and then Info.Next_Cursor = Length,
               "valid directory name bounds changed");
         end if;
      end Check_Name;
   begin
      for High_Bound in Boolean loop
         Check_Name (Hex ("4100"), True, High_Bound);
         Check_Name (Hex ("00d800dc"), True, High_Bound);
         Check_Name (Hex ("ffdbffdf"), True, High_Bound);
         Check_Name (Hex ("41003dd800de4200"), True, High_Bound);
         Check_Name (Hex ("00d8"), False, High_Bound);
         Check_Name (Hex ("00dc"), False, High_Bound);
         Check_Name (Hex ("00d84100"), False, High_Bound);
         Check_Name (Hex ("410000004200"), False, High_Bound);
         for Available in 0 .. 112 loop
            Check (Available, 2, 0, High_Bound);
         end loop;
         for Page_Multiple in 1 .. 2 loop
            for Name_Length of Lengths loop
               for Next_Offset in 0 .. Page_Multiple * 112 + 8 loop
                  Check
                    (Page_Multiple * 112, Name_Length,
                     SMB.DWord (Next_Offset), High_Bound);
               end loop;
            end loop;
         end loop;
         Check (112, 2, SMB.DWord'Last, High_Bound);
      end loop;
      declare
         Chain : SMB.Bytes (0 .. 217) := (others => 0);
         Cursor : Natural := 0;
         Info : SMB.Core_Protocol.Directory_Info;
         Status : SMB.Core_Status;
      begin
         SMB.Wire.Put_U32 (Chain, 0, 112);
         SMB.Wire.Put_U32 (Chain, 60, 2);
         Chain (104 .. 105) := (120, 0);
         Chain (106 .. 111) := (others => 16#A5#);
         SMB.Wire.Put_U32 (Chain, 112 + 60, 2);
         Chain (216 .. 217) := (121, 0);
         SMB.Core_Protocol.Parse_Directory_Entry
           (Chain, Cursor, Info, Status);
         Assert
           (Status = SMB.Ok and then Cursor = 112
            and then Info.Name_Offset = 104 and then Info.Name_Length = 2,
            "aligned directory chain with nonzero padding rejected");
         SMB.Core_Protocol.Parse_Directory_Entry
           (Chain, Cursor, Info, Status);
         Assert
           (Status = SMB.Ok and then Cursor = Chain'Length
            and then Info.Name_Offset = 216 and then Info.Name_Length = 2,
            "unpadded terminal directory entry rejected");
      end;
      Ada.Text_IO.Put_Line
        ("directory boundary cases:" & Natural'Image (Count));
   end Test_Directory_Bounds;

   procedure Test_Core_Protocol is
      File_Id : constant SMB.Bytes (0 .. 15) := (others => 16#11#);
      Read_Body : SMB.Bytes (0 .. 48) := (others => 0);
      Create_Body : SMB.Bytes (0 .. 56) := (others => 0);
      Used : Natural;
      Status : SMB.Core_Status;
      Packet : SMB.Bytes (0 .. 79) := (others => 0);
      Negotiate_Packet : SMB.Bytes (0 .. 127) := (others => 0);
      Close_Packet : SMB.Bytes (0 .. 123) := (others => 0);
      Error_Packet : SMB.Bytes (0 .. 71) := (others => 0);
      Info : SMB.Core_Protocol.Response_Info;
      Directory : SMB.Bytes (0 .. 105) := (others => 0);
      Cursor : Natural := 0;
      Directory_Info : SMB.Core_Protocol.Directory_Info;
      Chunk, Pages, Entries : Natural;
   begin
      SMB.Core_Protocol.Build_Read
        (File_Id, 16#0102_0304_0506_0708#, 16#1234#,
         Read_Body, Used, Status);
      Assert (Status = SMB.Ok and then Used = 49, "bounded READ builder");
      Assert
        (Read_Body (4) = 16#34# and then Read_Body (5) = 16#12#
         and then Read_Body (6) = 0 and then Read_Body (7) = 0,
         "READ length wire offset");
      Assert
        (Read_Body (32) = 0 and then Read_Body (33) = 0
         and then Read_Body (34) = 0 and then Read_Body (35) = 0,
         "READ minimum-count wire offset");
      Assert (Read_Body (48) = 1, "READ dynamic buffer byte");
      SMB.Core_Protocol.Build_Create
        (SMB.Bytes'(1 .. 0 => 0), 0, 1, False,
         Create_Body, Used, Status);
      Assert
        (Status = SMB.Ok and then Used = 57
         and then Create_Body (0) = 57
         and then Create_Body (46) = 0 and then Create_Body (47) = 0
         and then Create_Body (40) = 16#40#
         and then Create_Body (56) = 0,
         "empty CREATE name padding");

      Negotiate_Packet (64) := 65;
      Negotiate_Packet (66) := 1;
      Negotiate_Packet (68) := 16#10#;
      Negotiate_Packet (69) := 2;
      Negotiate_Packet (80) := 16#78#;
      Negotiate_Packet (98) := 1;
      Negotiate_Packet (102) := 1;
      SMB.Core_Protocol.Parse_Response
        (Negotiate_Packet, SMB.Core_Wire.Command_Code (0),
         SMB.Success, Info, Status);
      Assert (Status = SMB.Ok, "negotiate response validation");
      Assert (Info.Max_Read = 65_536, "negotiate read-size clamping");
      Negotiate_Packet (124) := 1;
      SMB.Core_Protocol.Parse_Response
        (Negotiate_Packet, SMB.Core_Wire.Command_Code (0),
         SMB.Success, Info, Status);
      Assert (Status = SMB.Ok, "nonzero NEGOTIATE reserved DWORD rejected");
      Negotiate_Packet (124) := 0;

      Packet (64) := 17;
      Packet (66) := 80;
      Packet (68) := 0;
      Packet (69) := 0;
      Packet (70) := 0;
      Packet (71) := 0;
      SMB.Core_Protocol.Parse_Response
        (Packet, SMB.Core_Wire.Command_Code (8), SMB.Success, Info, Status);
      Assert (Status = SMB.Ok and then Info.Data_Length = 0,
              "zero-length READ response");
      Packet (76) := 1;
      SMB.Core_Protocol.Parse_Response
        (Packet, SMB.Core_Wire.Command_Code (8), SMB.Success, Info, Status);
      Assert (Status = SMB.Ok, "nonzero READ reserved DWORD rejected");
      Packet (76 .. 79) := (others => 0);
      Packet (68 .. 71) := (16#FF#, 16#FF#, 16#FF#, 16#FF#);
      SMB.Core_Protocol.Parse_Response
        (Packet, SMB.Core_Wire.Command_Code (8), SMB.Success, Info, Status);
      Assert (Status /= SMB.Ok, "oversized READ response length accepted");
      Packet (66) := 16#FF#;
      Packet (68 .. 71) := (others => 0);
      SMB.Core_Protocol.Parse_Response
        (Packet, SMB.Core_Wire.Command_Code (8), SMB.Success, Info, Status);
      Assert (Status /= SMB.Ok, "out-of-packet READ response offset accepted");

      Close_Packet (64) := 60;
      SMB.Core_Protocol.Parse_Response
        (Close_Packet, SMB.Core_Wire.Command_Code (6),
         SMB.Success, Info, Status);
      Assert (Status = SMB.Ok, "CLOSE response flags zero rejected");
      Close_Packet (66) := 1;
      SMB.Core_Protocol.Parse_Response
        (Close_Packet, SMB.Core_Wire.Command_Code (6),
         SMB.Success, Info, Status);
      Assert (Status = SMB.Ok, "CLOSE POSTQUERY_ATTRIB flag rejected");
      Close_Packet (66) := 2;
      SMB.Core_Protocol.Parse_Response
        (Close_Packet, SMB.Core_Wire.Command_Code (6),
         SMB.Success, Info, Status);
      Assert (Status /= SMB.Ok, "unsupported CLOSE response flag accepted");

      Error_Packet (64) := 9;
      SMB.Core_Protocol.Parse_Response
        (Error_Packet, SMB.Core_Wire.Command_Code (8),
         SMB.Status_End_Of_File, Info, Status);
      Assert (Status = SMB.Ok, "valid SMB2.1 error response rejected");
      Error_Packet (66) := 1;
      SMB.Core_Protocol.Parse_Response
        (Error_Packet, SMB.Core_Wire.Command_Code (8),
         SMB.Status_End_Of_File, Info, Status);
      Assert (Status /= SMB.Ok, "nonzero SMB2.1 ErrorContextCount accepted");
      Error_Packet (66) := 0;
      Error_Packet (67) := 1;
      SMB.Core_Protocol.Parse_Response
        (Error_Packet, SMB.Core_Wire.Command_Code (8),
         SMB.Status_End_Of_File, Info, Status);
      Assert (Status = SMB.Ok, "nonzero SMB2.1 error reserved byte rejected");
      SMB.Core_Protocol.Parse_Response
        (Error_Packet, SMB.Core_Wire.Command_Code (99),
         SMB.Status_End_Of_File, Info, Status);
      Assert
        (Status = SMB.Unsupported_Feature,
         "unknown command accepted through error response path");

      Directory (60) := 2;
      Directory (104) := Character'Pos ('x');
      Directory (105) := 0;
      SMB.Core_Protocol.Parse_Directory_Entry
        (Directory, Cursor, Directory_Info, Status);
      Assert
        (Status = SMB.Ok and then Cursor = Directory'Length
         and then Directory_Info.Name_Offset = 104
         and then Directory_Info.Name_Length = 2,
         "bounded directory entry parser");
      Directory (0 .. 3) := (16#FF#, 16#FF#, 16#FF#, 16#FF#);
      Cursor := 0;
      SMB.Core_Protocol.Parse_Directory_Entry
        (Directory, Cursor, Directory_Info, Status);
      Assert (Status /= SMB.Ok, "oversized directory next offset accepted");

      Pages := SMB.Core_Protocol.Maximum_Directory_Pages - 1;
      SMB.Core_Protocol.Count_Directory_Page (Pages, Status);
      Assert
        (Status = SMB.Ok
         and then Pages = SMB.Core_Protocol.Maximum_Directory_Pages,
         "directory page cap accepted final page");
      SMB.Core_Protocol.Count_Directory_Page (Pages, Status);
      Assert
        (Status = SMB.Resource_Limit
         and then Pages = SMB.Core_Protocol.Maximum_Directory_Pages,
         "directory page cap exceeded");
      Entries := SMB.Core_Protocol.Maximum_Directory_Entries - 1;
      SMB.Core_Protocol.Count_Directory_Entry (Entries, Status);
      Assert
        (Status = SMB.Ok
         and then Entries = SMB.Core_Protocol.Maximum_Directory_Entries,
         "directory entry cap accepted final entry");
      SMB.Core_Protocol.Count_Directory_Entry (Entries, Status);
      Assert
        (Status = SMB.Resource_Limit
         and then Entries = SMB.Core_Protocol.Maximum_Directory_Entries,
         "directory entry cap exceeded");

      SMB.Core_Protocol.Select_Transfer_Amount
        (65_536, 4_096, Chunk, Status);
      Assert
        (Status = SMB.Ok and then Chunk = 4_096,
         "bounded transfer chunk selection");
      SMB.Core_Protocol.Select_Transfer_Amount
        (1, 0, Chunk, Status);
      Assert
        (Status /= SMB.Ok and then Chunk = 0,
         "zero transfer limit accepted");
   end Test_Core_Protocol;

   --  Every request body byte for byte, with values whose bytes all differ,
   --  and the rejected arguments of each builder.
   procedure Test_Protocol_Builders is
      File_Id : constant SMB.Bytes :=
        Hex ("000102030405060708090a0b0c0d0e0f");
      Offset : constant SMB.QWord := 16#1122_3344_5566_7788#;
      Output : SMB.Bytes (0 .. 255);
      Used : Natural;
      Status : SMB.Core_Status;

      procedure Expect (Expected : SMB.Bytes; Label : String) is
      begin
         Assert
           (Status = SMB.Ok and then Used = Expected'Length
            and then Output (0 .. Used - 1) = Expected, Label);
      end Expect;

      procedure Expect_Failure (Failure : SMB.Core_Status; Label : String) is
      begin
         Assert (Status = Failure and then Used = 0, Label);
      end Expect_Failure;
   begin
      SMB.Core_Protocol.Build_Session_Setup
        (Hex ("010203"), Output, Used, Status);
      Expect
        (Hex ("1900" & "00" & "03" & "00000000" & "00000000" & "5800" & "0300"
              & "0000000000000000" & "010203"),
         "SESSION_SETUP request");
      declare
         Token : constant SMB.Bytes (1 .. 65_535) := (others => 16#5A#);
         Large : SMB.Bytes (0 .. 24 + 65_534);
      begin
         SMB.Core_Protocol.Build_Session_Setup (Token, Large, Used, Status);
         Assert
           (Status = SMB.Ok and then Used = Large'Length
            and then Large (14) = 16#FF# and then Large (15) = 16#FF#,
            "SESSION_SETUP with the largest token");
      end;

      SMB.Core_Protocol.Build_Tree_Connect
        (Hex ("41004200"), Output, Used, Status);
      Expect
        (Hex ("0900" & "0000" & "4800" & "0400" & "41004200"),
         "TREE_CONNECT request");
      SMB.Core_Protocol.Build_Tree_Connect
        (SMB.Bytes'(0 => 16#41#), Output, Used, Status);
      Expect_Failure (SMB.Invalid_Length, "odd TREE_CONNECT path");

      for Directory in Boolean loop
         SMB.Core_Protocol.Build_Create
           (Hex ("6100"), 16#8112_3489#, 16#0403_0201#, Directory,
            Output, Used, Status);
         Expect
           (Hex ("3900" & "00" & "00" & "02000000" & "0000000000000000"
                 & "0000000000000000" & "89341281"
                 & (if Directory then "10000000" else "00000000")
                 & "07000000" & "01020304"
                 & (if Directory then "01000000" else "40000000")
                 & "7800" & "0200" & "00000000" & "00000000" & "6100"),
            "CREATE request");
      end loop;
      SMB.Core_Protocol.Build_Create
        (SMB.Bytes'(0 => 16#61#), 0, 1, False, Output, Used, Status);
      Expect_Failure (SMB.Invalid_Length, "odd CREATE name");

      SMB.Core_Protocol.Build_Read
        (File_Id, Offset, 65_536, Output, Used, Status);
      Expect
        (Hex ("3100" & "00" & "00" & "00000100" & "8877665544332211")
         & File_Id
         & Hex ("00000000" & "00000000" & "00000000" & "0000" & "0000" & "01"),
         "READ request");

      SMB.Core_Protocol.Build_Write
        (File_Id, Offset, Hex ("aabbcc"), Output, Used, Status);
      Expect
        (Hex ("3100" & "7000" & "03000000" & "8877665544332211") & File_Id
         & Hex ("00000000" & "00000000" & "0000" & "0000" & "00000000"
                & "aabbcc"),
         "WRITE request");
      declare
         Data : constant SMB.Bytes (1 .. 65_536) := (others => 16#5A#);
         Large : SMB.Bytes (0 .. 48 + 65_535);
      begin
         SMB.Core_Protocol.Build_Write (File_Id, Offset, Data, Large, Used, Status);
         Assert
           (Status = SMB.Ok and then Used = Large'Length
            and then Large (4 .. 7) = Hex ("00000100"),
            "WRITE of the largest chunk");
         SMB.Core_Protocol.Build_Write
           (File_Id, Offset, Data (1 .. 258), Large, Used, Status);
         Assert
           (Status = SMB.Ok and then Used = 48 + 258
            and then Large (4 .. 7) = Hex ("02010000"),
            "WRITE length with a second byte");
      end;

      SMB.Core_Protocol.Build_Close (File_Id, Output (0 .. 23), Used, Status);
      Expect (Hex ("1800" & "0000" & "00000000") & File_Id, "CLOSE request");
      Output := (others => 16#EE#);
      SMB.Core_Protocol.Build_Close (File_Id, Output (0 .. 22), Used, Status);
      Assert
        (Status = SMB.Resource_Limit and then Used = 0
         and then (for all Index in 0 .. 22 => Output (Index) = 0),
         "CLOSE request one byte short");

      for Restart in Boolean loop
         SMB.Core_Protocol.Build_Query_Directory
           (File_Id, Restart, Output, Used, Status);
         Expect
           (Hex ("2100" & "25" & (if Restart then "01" else "00") & "00000000")
            & File_Id & Hex ("6000" & "0200" & "00000100" & "2a00"),
            "QUERY_DIRECTORY request");
      end loop;

      for Delete_File in Boolean loop
         SMB.Core_Protocol.Build_Disposition
           (File_Id, Delete_File, Output, Used, Status);
         Expect
           (Hex ("2100" & "01" & "0d" & "01000000" & "6000" & "0000" & "00000000")
            & File_Id & Hex (if Delete_File then "01" else "00"),
            "SET_INFO disposition request");
      end loop;

      SMB.Core_Protocol.Build_Rename
        (File_Id, Hex ("62006300"), Output, Used, Status);
      Expect
        (Hex ("2100" & "01" & "0a" & "18000000" & "6000" & "0000" & "00000000")
         & File_Id & Hex ("00000000000000000000000000000000" & "04000000"
                          & "62006300"),
         "SET_INFO rename request");
      SMB.Core_Protocol.Build_Rename
        (File_Id, SMB.Bytes'(0 => 16#62#), Output, Used, Status);
      Expect_Failure (SMB.Invalid_Length, "odd rename target");
   end Test_Protocol_Builders;

   --  Response fields each parser must check, with the status it reports.
   procedure Test_Protocol_Parsers is
      Info : SMB.Core_Protocol.Response_Info;
      Status : SMB.Core_Status;

      procedure Parse
        (Packet : SMB.Bytes; Command : Natural;
         Expected : SMB.Core_Status; Label : String) is
      begin
         SMB.Core_Protocol.Parse_Response
           (Packet, SMB.Core_Wire.Command_Code (Command), SMB.Success,
            Info, Status);
         Assert (Status = Expected, Label & ": " & Status'Image);
      end Parse;

      function Negotiate return SMB.Bytes is
         Packet : SMB.Bytes (0 .. 127) := (others => 0);
      begin
         Packet (64) := 65;
         Packet (66) := 1;
         Packet (68) := 16#10#;
         Packet (69) := 2;
         Packet (98) := 1;
         Packet (102) := 1;
         return Packet;
      end Negotiate;

      Packet : SMB.Bytes (0 .. 127);
      Session : SMB.Bytes (0 .. 71) := (others => 0);
      Tree : SMB.Bytes (0 .. 79) := (others => 0);
      Create : SMB.Bytes (0 .. 159) := (others => 0);
      Read : SMB.Bytes (0 .. 79) := (others => 0);
      Query : SMB.Bytes (0 .. 71) := (others => 0);
   begin
      Parse (Negotiate, 0, SMB.Ok, "NEGOTIATE reply");
      Packet := Negotiate;
      Packet (40) := 1;
      Parse (Packet, 0, SMB.Invalid_Protocol, "NEGOTIATE reply with a session");
      Packet := Negotiate;
      Packet (36) := 1;
      Parse (Packet, 0, SMB.Invalid_Protocol, "NEGOTIATE reply with a tree");
      Packet := Negotiate;
      Packet (88) := 16#08#;
      Parse (Packet, 0, SMB.Invalid_Protocol, "NEGOTIATE reply with a 3.x capability");
      Packet (88) := 16#01#;
      Parse (Packet, 0, SMB.Ok, "NEGOTIATE reply with the DFS capability");
      Packet := Negotiate;
      Packet (98) := 0;
      Parse (Packet, 0, SMB.Invalid_Value, "NEGOTIATE reply without a read size");
      Packet := Negotiate;
      Packet (102) := 0;
      Parse (Packet, 0, SMB.Invalid_Value, "NEGOTIATE reply without a write size");
      Packet := Negotiate;
      Packet (120) := 128;
      Packet (122) := 1;
      Parse (Packet, 0, SMB.Invalid_Offset, "NEGOTIATE token past the end");

      Session (64) := 9;
      Session (40) := 1;
      Parse (Session, 1, SMB.Ok, "SESSION_SETUP reply");
      Session (66) := 1;
      Parse (Session, 1, SMB.Invalid_Protocol, "SESSION_SETUP reply with flags");
      Session (66) := 0;
      Session (68) := 72;
      Session (70) := 1;
      Parse (Session, 1, SMB.Invalid_Offset, "SESSION_SETUP token past the end");
      Session (68) := 80;
      Session (70) := 0;
      Parse (Session, 1, SMB.Invalid_Offset, "SESSION_SETUP offset past the end");

      Tree (64) := 16;
      Tree (66) := 1;
      Tree (36) := 7;
      Tree (68) := 1;
      Parse (Tree, 3, SMB.Ok, "TREE_CONNECT reply with share flag 1");

      Create (64) := 89;
      Parse (Create (0 .. 151), 5, SMB.Ok, "CREATE reply");
      Create (66) := 1;
      Parse (Create (0 .. 151), 5, SMB.Unsupported_Feature, "CREATE oplock");
      Create (66) := 0;
      Create (67) := 1;
      Parse (Create (0 .. 151), 5, SMB.Unsupported_Feature, "CREATE flags");
      Create (67) := 0;
      Create (144) := 153;
      Parse (Create (0 .. 151), 5, SMB.Invalid_Offset, "CREATE contexts past the end");
      Create (144) := 152;
      Create (148) := 1;
      Parse (Create (0 .. 151), 5, SMB.Invalid_Offset, "CREATE contexts too long");
      Create (148) := 8;
      Parse (Create, 5, SMB.Unsupported_Feature, "CREATE contexts");

      Read (64) := 17;
      Read (66) := 80;
      Read (68) := 1;
      Parse (Read, 8, SMB.Invalid_Offset, "READ data past the end");

      Query (64) := 9;
      Query (66) := 72;
      Query (68) := 1;
      Parse (Query, 14, SMB.Invalid_Offset, "QUERY_DIRECTORY data past the end");

      Parse (Query (0 .. 63), 17, SMB.Invalid_Length, "SET_INFO reply without a body");
      Parse (Query, 99, SMB.Unsupported_Feature, "reply to an unknown command");

      --  Directory entries: name and short name lengths, and the next entry.
      declare
         function Entry_Of
           (Next : SMB.Byte; Name_Length : SMB.Byte;
            Short_Length : SMB.Byte := 0; Reserved : SMB.Byte := 0;
            Last : Natural := 111) return SMB.Bytes
         is
            Result : SMB.Bytes (0 .. Last) := (others => 0);
         begin
            Result (0) := Next;
            Result (60) := Name_Length;
            Result (68) := Short_Length;
            Result (69) := Reserved;
            for Index in 104 .. Last loop
               Result (Index) := (if Index mod 2 = 0 then 16#61# else 0);
            end loop;
            return Result;
         end Entry_Of;

         procedure Directory
           (Buffer : SMB.Bytes; Expected : SMB.Core_Status; Label : String)
         is
            Cursor : Natural := 0;
            Directory_Info : SMB.Core_Protocol.Directory_Info;
         begin
            SMB.Core_Protocol.Parse_Directory_Entry
              (Buffer, Cursor, Directory_Info, Status);
            Assert (Status = Expected, Label & ": " & Status'Image);
         end Directory;
      begin
         Directory (Entry_Of (0, 2, 24, 1), SMB.Ok, "short name of 24 bytes");
         Directory (Entry_Of (0, 2, 2), SMB.Ok, "short name of 2 bytes");
         Directory (Entry_Of (0, 2, 26), SMB.Invalid_Offset, "short name of 26 bytes");
         Directory (Entry_Of (0, 3), SMB.Invalid_Offset, "odd name length");
         Directory (Entry_Of (0, 10), SMB.Invalid_Offset, "name past the entry");
         Directory
           (Entry_Of (8, 2, Last => 223), SMB.Invalid_Offset,
            "next entry inside this one");
      end;
   end Test_Protocol_Parsers;

   procedure Test_Directory_Counters is
      Count : Natural;
      Status : SMB.Core_Status;
      Cases : Natural := 0;
   begin
      for Before in 0 .. SMB.Core_Protocol.Maximum_Directory_Pages loop
         Count := Before;
         SMB.Core_Protocol.Count_Directory_Page (Count, Status);
         Assert
           (Status = (if Before < SMB.Core_Protocol.Maximum_Directory_Pages
                      then SMB.Ok else SMB.Resource_Limit)
            and then Count = Natural'Min
              (Before + 1, SMB.Core_Protocol.Maximum_Directory_Pages),
            "exact directory page count outcome");
         Cases := Cases + 1;
      end loop;
      for Before in 0 .. SMB.Core_Protocol.Maximum_Directory_Entries loop
         Count := Before;
         SMB.Core_Protocol.Count_Directory_Entry (Count, Status);
         Assert
           (Status = (if Before < SMB.Core_Protocol.Maximum_Directory_Entries
                      then SMB.Ok else SMB.Resource_Limit)
            and then Count = Natural'Min
              (Before + 1, SMB.Core_Protocol.Maximum_Directory_Entries),
            "exact directory entry count outcome");
         Cases := Cases + 1;
      end loop;
      Assert (Cases = 104_098, "directory counter state space coverage");
      Ada.Text_IO.Put_Line
        ("AdaSMB directory counter tests passed:" & Cases'Image & " cases");
   end Test_Directory_Counters;

   procedure Test_Transfer_Progress is
      Lengths : constant array (Positive range <>) of Natural :=
        (0, 1, 2, SMB.Core_Protocol.Maximum_IO_Chunk - 1,
         SMB.Core_Protocol.Maximum_IO_Chunk,
         SMB.Core_Protocol.Maximum_IO_Chunk + 1, SMB.Maximum_Frame_Size);
      Amounts : constant array (Positive range <>) of Natural :=
        (0, 1, 2, SMB.Core_Protocol.Maximum_IO_Chunk - 1,
         SMB.Core_Protocol.Maximum_IO_Chunk);
      Offsets : constant array (Positive range <>) of SMB.QWord :=
        (0, 1,
         SMB.QWord'Last - SMB.QWord (SMB.Maximum_Frame_Size),
         SMB.QWord'Last - SMB.QWord (SMB.Maximum_Frame_Size) + 1,
         SMB.QWord'Last - SMB.QWord (SMB.Core_Protocol.Maximum_IO_Chunk),
         SMB.QWord'Last - SMB.QWord (SMB.Core_Protocol.Maximum_IO_Chunk) + 1,
         SMB.QWord'Last - 1, SMB.QWord'Last);
      Status, Expected : SMB.Core_Status;
      Position : SMB.QWord;
      Remaining, Amount : Natural;
      Cases : Natural := 0;
   begin
      for Total of Lengths loop
         for Limit of Amounts loop
            SMB.Core_Protocol.Select_Transfer_Amount
              (Total, Limit, Amount, Status);
            Assert
              (Status = (if Total > 0 and then Limit = 0
                         then SMB.Invalid_Value else SMB.Ok)
               and then Amount = Natural'Min (Total, Limit),
               "exact transfer amount outcome");
            Cases := Cases + 1;
         end loop;
         for Base of Offsets loop
            SMB.Core_Protocol.Check_Transfer_Range (Base, Total, Status);
            Assert
              (Status = (if Base + SMB.QWord (Total) < Base
                         then SMB.Invalid_Offset else SMB.Ok),
               "exact transfer range outcome");
            Cases := Cases + 1;
            for Requested of Amounts loop
               for Count of Amounts loop
                  for Require_Progress in Boolean loop
                     Position := Base;
                     Remaining := Total;
                     if Count > Natural'Min (Requested, Total)
                       or else (Require_Progress and then Requested > 0
                                and then Count = 0)
                     then
                        Expected := SMB.Invalid_Value;
                     elsif Base + SMB.QWord (Count) < Base then
                        Expected := SMB.Invalid_Offset;
                     else
                        Expected := SMB.Ok;
                     end if;
                     SMB.Core_Protocol.Advance_Transfer
                       (Position, Remaining, Requested, Count, Status,
                        Require_Progress);
                     Assert (Status = Expected, "exact transfer progress outcome");
                     if Status = SMB.Ok then
                        Assert
                          (Position = Base + SMB.QWord (Count)
                           and then Position >= Base
                           and then Remaining = Total - Count,
                           "valid transfer advances without wrapping");
                     else
                        Assert
                          (Position = Base and then Remaining = Total,
                           "failed transfer preserves offset and remainder");
                     end if;
                     Cases := Cases + 1;
                  end loop;
               end loop;
            end loop;
         end loop;
      end loop;
      Assert (Cases = 2_891, "transfer boundary matrix coverage");
      Ada.Text_IO.Put_Line
        ("AdaSMB transfer progress tests passed:" & Cases'Image & " cases");
   end Test_Transfer_Progress;

   procedure Test_Engine_Receipts is
      use type SMB.Core_Client.Directory_Stage;
      use type SMB.Core_Client.Metadata_Stage;
      use type SMB.Core_Client.Metadata_State_Snapshot;
      State : SMB.Engine.Engine_State;
      Foreign_State : SMB.Engine.Engine_State;
      Status : SMB.Core_Status;
      Nt_Status : SMB.DWord;
      Message_Id : SMB.QWord;
      Expected : SMB.Engine.Request_Expectation;
      Token : SMB.Engine.Handle_Token := (others => 0);
      Directory_Token : SMB.Engine.Handle_Token := (others => 0);
      Foreign_Token : SMB.Engine.Handle_Token := (others => 0);
      File_Id : constant SMB.Bytes (0 .. 15) :=
        (16#10#, 16#21#, 16#32#, 16#43#, 16#54#, 16#65#, 16#76#, 16#87#,
         16#98#, 16#A9#, 16#BA#, 16#CB#, 16#DC#, 16#ED#, 16#FE#, 16#0F#);
      Wrong_File_Id : constant SMB.Bytes (0 .. 15) := (others => 1);
      Coordinator : SMB.Core_Client.Operation;
      Directory_Create : SMB.Core_Client.Operation;
      Foreign_Create : SMB.Core_Client.Operation;
      Close_Coordinator : SMB.Core_Client.Operation;
      Coordinator_Packet : SMB.Bytes (0 .. 121) := (others => 0);
      Close_Packet : SMB.Bytes (0 .. 87) := (others => 0);
      Coordinator_Used : Natural;
      Coordinator_Token : SMB.Engine.Handle_Token := (others => 0);
      Rejected_Token : SMB.Engine.Handle_Token := (others => 0);
      Validated_File_Id : SMB.Bytes (0 .. 15) := (others => 0);
      Validated_Access : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
      Validated_Directory : Boolean := False;
      Session_Id : constant SMB.QWord := 16#1234#;
      Tree_Id : constant SMB.DWord := 16#1020_3040#;
      Key : SMB.Bytes (0 .. 15) := (others => 0);
      Reservation_Checks, Metadata_Mutations : Natural := 0;
      Final_Token : constant SMB.Bytes (0 .. 28) :=
        (16#A1#, 16#1B#, 16#30#, 16#19#,
         16#A0#, 16#03#, 16#0A#, 16#01#, 0,
         16#A3#, 16#12#, 16#04#, 16#10#,
         1, 0, 0, 0, 16#0A#, 16#FB#, 16#34#, 16#90#,
         16#3A#, 16#3E#, 16#4E#, 16#54#, 0, 0, 0, 0);

      procedure Prepare_Response
        (Packet : in out SMB.Bytes;
         Command : SMB.Core_Wire.Command_Code;
         Reply_Id : SMB.QWord;
         Reply_Tree_Id : SMB.DWord;
         Reply_Session_Id : SMB.QWord;
         Signed : Boolean) is
      begin
         SMB.Wire.Initialize_Header
           (Packet, SMB.Word (Command), Reply_Id, Reply_Tree_Id,
            Reply_Session_Id);
         SMB.Wire.Put_U32 (Packet, 16, (if Signed then 9 else 1));
      end Prepare_Response;

      procedure Check_Request_Metadata
        (Target : SMB.Engine.Engine_State;
         Metadata : SMB.Engine.Request_Expectation;
         Match_Tree, Match_Session : Boolean) is
         Changed : SMB.Engine.Request_Expectation;
      begin
         Assert
           (Metadata.Match_Tree = Match_Tree
            and then Metadata.Match_Session = Match_Session
            and then SMB.Engine.Pending_Request_Matches (Target, Metadata),
            "request reservation selected incorrect correlation flags");
         Reservation_Checks := Reservation_Checks + 1;
         for Field in 0 .. 11 loop
            Changed := Metadata;
            case Field is
               when 0 => Changed.Command := Changed.Command xor 1;
               when 1 => Changed.Message_Id := Changed.Message_Id xor 1;
               when 2 => Changed.Tree_Id := Changed.Tree_Id xor 1;
               when 3 => Changed.Session_Id := Changed.Session_Id xor 1;
               when 4 => Changed.Match_Tree := not Changed.Match_Tree;
               when 5 => Changed.Match_Session := not Changed.Match_Session;
               when 6 => Changed.Request_Signed := not Changed.Request_Signed;
               when 7 => Changed.Signed := not Changed.Signed;
               when 8 => Changed.Request_Amount :=
                 (if Changed.Request_Amount = 0 then 1 else 0);
               when 9 => Changed.Close_Token.Owner := Changed.Close_Token.Owner xor 1;
               when 10 => Changed.Close_Token.Epoch := Changed.Close_Token.Epoch xor 1;
               when 11 => Changed.Close_Token.Ticket := Changed.Close_Token.Ticket xor 1;
            end case;
            Assert
              (not SMB.Engine.Pending_Request_Matches (Target, Changed),
               "request metadata mismatch accepted at field" & Natural'Image (Field));
            Metadata_Mutations := Metadata_Mutations + 1;
         end loop;
      end Check_Request_Metadata;

      procedure Reconnect_Share
        (Target : in out SMB.Engine.Engine_State;
         Initialize_State : Boolean := True;
         Connect_Share_State : Boolean := True;
         Check_Requests : Boolean := False;
         Stop_At_Challenge : Boolean := False;
         Stop_At_Negotiate : Boolean := False) is
      begin
         if Initialize_State then
            SMB.Engine.Initialize (Target, Status);
            Assert (Status = SMB.Ok, "reinitialize after coordinator abort");
         end if;
         SMB.Engine.Mark_Connected (Target, Status);
         Assert (Status = SMB.Ok, "reconnect transport after coordinator abort");
         declare
            Response : SMB.Bytes (0 .. 127) := (others => 0);
         begin
            SMB.Engine.Begin_Request
              (Target, SMB.Core_Wire.Command_Code (0), False, False,
               Message_Id, Expected, Status);
            Assert (Status = SMB.Ok, "reconnect negotiate request");
            Assert (Message_Id = 0, "fresh negotiation did not start at message ID zero");
            if Check_Requests then
               Check_Request_Metadata (Target, Expected, False, False);
            end if;
            Prepare_Response
              (Response, SMB.Core_Wire.Command_Code (0), Message_Id, 0, 0,
               False);
            Response (64) := 65;
            Response (66) := 1;
            Response (68) := 16#10#;
            Response (69) := 2;
            Response (98) := 1;
            Response (102) := 1;
            SMB.Engine.Accept_Response (Target, Response, Nt_Status, Status);
            Assert (Status = SMB.Ok, "reconnect negotiate response");
            if Stop_At_Negotiate then
               return;
            end if;
            SMB.Engine.Mark_Negotiated (Target, 65_536, 65_536, Status);
            Assert (Status = SMB.Ok, "reconnect negotiated phase");
         end;
         declare
            Response : SMB.Bytes (0 .. 71) := (others => 0);
         begin
            SMB.Engine.Begin_Request
              (Target, SMB.Core_Wire.Command_Code (1), False, False,
               Message_Id, Expected, Status);
            Assert (Status = SMB.Ok, "reconnect challenge request");
            Assert (Message_Id = 1, "NEGOTIATE processing changed the request counter");
            if Check_Requests then
               Check_Request_Metadata (Target, Expected, False, False);
            end if;
            Prepare_Response
              (Response, SMB.Core_Wire.Command_Code (1), Message_Id,
               0, Session_Id, False);
            SMB.Wire.Put_U32
              (Response, 8, SMB.Status_More_Processing_Required);
            Response (64) := 9;
            SMB.Engine.Accept_Response (Target, Response, Nt_Status, Status);
            Assert (Status = SMB.Ok, "reconnect challenge response");
            if Stop_At_Challenge then
               return;
            end if;
            SMB.Engine.Install_Session_Key (Target, Session_Id, Key, Status);
            Assert (Status = SMB.Ok, "reconnect session key");
         end;
         declare
            Response : SMB.Bytes (0 .. 100) := (others => 0);
         begin
            SMB.Engine.Begin_Request
              (Target, SMB.Core_Wire.Command_Code (1), False, True,
               Message_Id, Expected, Status);
            Assert (Status = SMB.Ok, "reconnect final session request");
            Assert (Message_Id = 2, "challenge processing changed the request counter");
            if Check_Requests then
               Check_Request_Metadata (Target, Expected, False, True);
            end if;
            Prepare_Response
              (Response, SMB.Core_Wire.Command_Code (1), Message_Id,
               0, Session_Id, True);
            Response (64) := 9;
            SMB.Wire.Put_U16 (Response, 68, 72);
            SMB.Wire.Put_U16 (Response, 70, Final_Token'Length);
            for Index in Final_Token'Range loop
               Response (72 + Index) := Final_Token (Index);
            end loop;
            SMB.Wire.Sign (Response, Key);
            SMB.Engine.Accept_Response (Target, Response, Nt_Status, Status);
            Assert (Status = SMB.Ok, "reconnect signed session response");
            SMB.Engine.Mark_Authenticated (Target, Status);
            Assert (Status = SMB.Ok, "reconnect authenticated phase");
         end;
         if Connect_Share_State then
            declare
               Response : SMB.Bytes (0 .. 79) := (others => 0);
            begin
               SMB.Engine.Begin_Request
                 (Target, SMB.Core_Wire.Command_Code (3), True, True,
                  Message_Id, Expected, Status);
               Assert (Status = SMB.Ok, "reconnect tree connect request");
               Assert (Message_Id = 3, "authentication changed the request counter");
               if Check_Requests then
                  Check_Request_Metadata (Target, Expected, False, True);
               end if;
               Prepare_Response
                 (Response, SMB.Core_Wire.Command_Code (3), Message_Id,
                  Tree_Id, Session_Id, True);
               Response (64) := 16;
               Response (66) := 1;
               SMB.Wire.Sign (Response, Key);
               SMB.Engine.Accept_Response (Target, Response, Nt_Status, Status);
               Assert (Status = SMB.Ok, "reconnect tree connect response");
               SMB.Engine.Mark_Share_Connected (Target, Tree_Id, Status);
               Assert (Status = SMB.Ok, "reconnect share-connected phase");
            end;
         end if;
      end Reconnect_Share;

      procedure Reconnect_Share is
      begin
         Reconnect_Share (State);
      end Reconnect_Share;

      procedure Create_Directory_Handle
        (Target : in out SMB.Engine.Engine_State;
         Create_Operation : in out SMB.Core_Client.Operation;
         Result_Token : out SMB.Engine.Handle_Token;
         Is_Directory : Boolean := True;
         Access_Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
         Response_File_Id : SMB.Bytes := File_Id;
         Expected_Message_Id : SMB.QWord := SMB.QWord'Last)
      is
         Request : SMB.Bytes (0 .. 121) := (others => 0);
         Response : SMB.Bytes (0 .. 151) := (others => 0);
         Used : Natural;
      begin
         SMB.Core_Client.Prepare_Create
           (Create_Operation, Target, SMB.Bytes'(0, 0),
            Access_Mode, False, 1, Is_Directory,
            Request, Used, Status);
         Assert (Status = SMB.Ok and then Used = Request'Length,
                 "prepare directory test handle");
         if Expected_Message_Id /= SMB.QWord'Last then
            Assert
              (SMB.Wire.U64 (Request, 24) = Expected_Message_Id,
               "CREATE request skipped or reused a message ID");
         end if;
         SMB.Core_Client.Send_Succeeded (Create_Operation, Target, Status);
         Assert (Status = SMB.Ok, "acknowledge directory test CREATE");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (5),
            SMB.Wire.U64 (Request, 24), Tree_Id, Session_Id, True);
         Response (64) := 89;
         Response (128 .. 143) := Response_File_Id;
         SMB.Wire.Sign (Response, Key);
         SMB.Core_Client.Complete
           (Create_Operation, Target, Response, Nt_Status,
            Result_Token, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status = SMB.Success,
            "complete directory test CREATE");
      end Create_Directory_Handle;

      procedure Test_Authentication_Atomicity is
         use type SMB.Engine.Engine_State;
         Base, Target : SMB.Engine.Engine_State;
         Key_Failures, Authentication_Failures : Natural := 0;
         Invalid_Lengths : constant array (Positive range <>) of Natural :=
           (0, 15, 17);
         Replacement_Key : constant SMB.Bytes (0 .. 15) := (others => 16#A5#);

         procedure Reject_Key (Id : SMB.QWord; Input : SMB.Bytes) is
            Before : constant SMB.Engine.Engine_State := Target;
         begin
            SMB.Engine.Install_Session_Key (Target, Id, Input, Status);
            Assert
              (Status = SMB.Invalid_Value and then Target = Before,
               "rejected key installation changed state or consumed receipt");
            Key_Failures := Key_Failures + 1;
         end Reject_Key;

         procedure Reject_Authentication is
            Before : constant SMB.Engine.Engine_State := Target;
         begin
            SMB.Engine.Mark_Authenticated (Target, Status);
            Assert
              (Status = SMB.Invalid_State_Status and then Target = Before,
               "rejected authentication transition changed state or consumed receipt");
            Authentication_Failures := Authentication_Failures + 1;
         end Reject_Authentication;

         procedure Begin_Final_Request is
         begin
            SMB.Engine.Begin_Request
              (Target, 1, False, True, Message_Id, Expected, Status);
            Assert (Status = SMB.Ok, "reserve atomic authentication final request");
         end Begin_Final_Request;
      begin
         Reject_Key (Session_Id, Key);
         Reject_Authentication;
         Reconnect_Share (Base, Stop_At_Challenge => True);
         Target := Base;
         Reject_Authentication;
         Reject_Key (0, Key);
         Reject_Key (Session_Id xor 1, Key);
         for High_Bounds in Boolean loop
            for Length of Invalid_Lengths loop
               declare
                  First : constant Natural :=
                    (if High_Bounds then Natural'Last - Length else 1);
                  Input : constant SMB.Bytes (First .. First + Length - 1) :=
                    (others => 16#A5#);
               begin
                  Reject_Key (Session_Id, Input);
               end;
            end loop;
         end loop;
         SMB.Engine.Begin_Request
           (Target, 1, False, False, Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "reserve pending challenge atomicity fixture");
         Reject_Key (Session_Id, Key);
         Reject_Authentication;
         for High_Bounds in Boolean loop
            declare
               First : constant Natural :=
                 (if High_Bounds then Natural'Last - 15 else 1);
               Input : constant SMB.Bytes (First .. First + 15) := Key;
            begin
               Target := Base;
               SMB.Engine.Install_Session_Key (Target, Session_Id, Input, Status);
               Assert
                 (Status = SMB.Ok
                  and then SMB.Engine.Current_Phase (Target) = SMB.Engine.Negotiated
                  and then SMB.Engine.Current_Session_Id (Target) = Session_Id
                  and then SMB.Engine.Has_Signing_Key (Target)
                  and then SMB.Engine.Current_Signing_Key (Target) = Input
                  and then not SMB.Engine.Has_Validated_Response (Target),
                  "key installation retry lost challenge receipt or key bytes");
               Reject_Key (Session_Id, Replacement_Key);
               Reject_Authentication;
               Begin_Final_Request;
               Reject_Key (Session_Id, Replacement_Key);
               Reject_Authentication;
               declare
                  Response : SMB.Bytes (0 .. 71) := (others => 0);
               begin
                  Prepare_Response (Response, 1, Message_Id, 0, Session_Id, True);
                  SMB.Wire.Put_U32 (Response, 8, 16#C000_006D#);
                  Response (64) := 9;
                  SMB.Wire.Sign (Response, Key);
                  SMB.Engine.Accept_Response (Target, Response, Nt_Status, Status);
                  Assert
                    (Status = SMB.Ok and then Nt_Status = 16#C000_006D#
                     and then SMB.Engine.Has_Validated_Response (Target),
                     "accept signed authentication failure receipt fixture");
               end;
               Reject_Key (Session_Id, Replacement_Key);
               Reject_Authentication;
               Begin_Final_Request;
               declare
                  Response : SMB.Bytes (0 .. 100) := (others => 0);
               begin
                  Prepare_Response (Response, 1, Message_Id, 0, Session_Id, True);
                  Response (64) := 9;
                  SMB.Wire.Put_U16 (Response, 68, 72);
                  SMB.Wire.Put_U16 (Response, 70, Final_Token'Length);
                  Response (72 .. 100) := Final_Token;
                  SMB.Wire.Sign (Response, Key);
                  SMB.Engine.Accept_Response (Target, Response, Nt_Status, Status);
                  Assert (Status = SMB.Ok, "accept atomic authentication success receipt");
               end;
               Reject_Key (Session_Id, Replacement_Key);
               SMB.Engine.Mark_Authenticated (Target, Status);
               Assert
                 (Status = SMB.Ok
                  and then SMB.Engine.Current_Phase (Target) = SMB.Engine.Authenticated
                  and then SMB.Engine.Current_Session_Id (Target) = Session_Id
                  and then SMB.Engine.Current_Signing_Key (Target) = Input
                  and then not SMB.Engine.Has_Validated_Response (Target),
                  "authentication retry lost success receipt or changed key");
               Reject_Authentication;
            end;
         end loop;
         Assert (Key_Failures = 18 and then Authentication_Failures = 11,
                 "authentication failure atomicity coverage");
         Ada.Text_IO.Put_Line
           ("authentication failure atomicity: 29 rejected calls and 2 successful retries passed");
      end Test_Authentication_Atomicity;

      procedure Test_Request_Metadata is
         use type SMB.Engine.Engine_State;
         use type SMB.Engine.Request_Expectation;
         Base, Target, Authenticated_State : SMB.Engine.Engine_State;
         Handle : SMB.Engine.Handle_Token;
         Commands : constant array (Positive range <>) of
           SMB.Core_Wire.Command_Code := (2, 4, 5, 6, 8, 9, 14, 17);
         Poison : constant SMB.Engine.Request_Expectation :=
           (Command => SMB.Core_Wire.Command_Code'Last,
            Message_Id => SMB.QWord'Last,
            Tree_Id => SMB.DWord'Last,
            Session_Id => SMB.QWord'Last,
            Match_Tree | Match_Session | Request_Signed | Signed => True,
            Request_Amount => Natural'Last,
            Close_Token => (others => SMB.QWord'Last));
         Reservation : SMB.Engine.Request_Expectation;
         Reserved_Id : SMB.QWord;
         Result : SMB.Core_Status;
         Rejections : Natural := 0;

         procedure Reject
           (Command : SMB.Core_Wire.Command_Code;
            Request_Signed, Response_Signed : Boolean;
            Amount : Natural;
            Close_Token : SMB.Engine.Handle_Token;
            Expected_Status : SMB.Core_Status) is
            Before : constant SMB.Engine.Engine_State := Target;
         begin
            Assert (not SMB.Engine.Has_Validated_Response (Target),
                    "reservation rejection fixture retained a receipt");
            Reservation := Poison;
            Reserved_Id := SMB.QWord'Last;
            SMB.Engine.Begin_Request
              (Target, Command, Request_Signed, Response_Signed,
               Reserved_Id, Reservation, Result, Amount, Close_Token);
            Assert
              (Result = Expected_Status and then Target = Before
               and then Reserved_Id = 0
               and then Reservation = SMB.Engine.Request_Expectation'(others => <>),
               "rejected reservation retained outputs or changed existing state");
            Rejections := Rejections + 1;
         end Reject;
      begin
         Assert
           (not SMB.Engine.Pending_Request_Matches
              (Target, SMB.Engine.Request_Expectation'(others => <>)),
            "default expectation matched without a pending request");
         Reconnect_Share (Base, Check_Requests => True);
         declare
            Operation : SMB.Core_Client.Operation;
         begin
            Create_Directory_Handle (Base, Operation, Handle);
         end;
         for Command of Commands loop
            Target := Base;
            SMB.Engine.Begin_Request
              (Target, Command, True, True,
               Reserved_Id, Reservation, Result,
               Request_Amount => (if Command = 8 or Command = 9 then 1 else 0),
               Close_Token => (if Command = 6 then Handle else (others => 0)));
            Assert (Result = SMB.Ok, "reserve share-operation metadata fixture");
            Check_Request_Metadata (Target, Reservation, Command /= 2, True);
            Reject (Command, True, True, 1, Handle, SMB.Invalid_State_Status);
         end loop;
         Target := Base;
         Reject (SMB.Core_Wire.Command_Code'Last, True, True, 0,
                 (others => 0), SMB.Unsupported_Feature);
         Reject (5, False, True, 0, (others => 0), SMB.Invalid_State_Status);
         Reject (8, True, True, 0, (others => 0), SMB.Invalid_Value);
         Reject (6, True, True, 0, (others => 0), SMB.Invalid_Handle_Status);
         Reconnect_Share (Authenticated_State, Connect_Share_State => False);
         SMB.Engine.Begin_Request
           (Authenticated_State, 2, True, True, Reserved_Id, Reservation, Result);
         Assert (Result = SMB.Ok, "reserve authenticated LOGOFF metadata fixture");
         Check_Request_Metadata (Authenticated_State, Reservation, False, True);
         Assert
           (Reservation_Checks = 13 and then Metadata_Mutations = 156
            and then Rejections = 12,
            "request metadata coverage");
         Ada.Text_IO.Put_Line
           ("request metadata: 13 reservations, 156 field mutations and 12 rejected calls passed");
      end Test_Request_Metadata;

      procedure Test_Request_Receipt_Preservation is
         use type SMB.Engine.Engine_State;
         use type SMB.Engine.Request_Expectation;
         type Receipt_Kind is (Negotiate_Receipt, Challenge_Receipt, Create_Receipt);
         Rejections : Natural := 0;
      begin
         for Kind in Receipt_Kind loop
            declare
               Target, Base : SMB.Engine.Engine_State;
               Token : SMB.Engine.Handle_Token;
               Next_Id : SMB.QWord;

               procedure Reject
                 (Command : SMB.Core_Wire.Command_Code;
                  Failure : SMB.Core_Status;
                  Amount : Natural := 0) is
                  Before : constant SMB.Engine.Engine_State := Target;
                  Reserved_Id : SMB.QWord := SMB.QWord'Last;
                  Reservation : SMB.Engine.Request_Expectation :=
                    (Command => SMB.Core_Wire.Command_Code'Last,
                     Message_Id => SMB.QWord'Last,
                     Tree_Id => SMB.DWord'Last,
                     Session_Id => SMB.QWord'Last,
                     Match_Tree | Match_Session | Request_Signed | Signed => True,
                     Request_Amount => Natural'Last,
                     Close_Token => (others => SMB.QWord'Last));
               begin
                  Assert (SMB.Engine.Has_Validated_Response (Target),
                          "reservation preservation fixture has no receipt");
                  SMB.Engine.Begin_Request
                    (Target, Command, True, True, Reserved_Id, Reservation,
                     Status, Request_Amount => Amount);
                  Assert
                    (Status = Failure and then Target = Before
                     and then Reserved_Id = 0
                     and then Reservation =
                       SMB.Engine.Request_Expectation'(others => <>),
                     "rejected reservation consumed receipt or changed state/output");
                  Rejections := Rejections + 1;
               end Reject;

               procedure Consume_Receipt is
               begin
                  case Kind is
                     when Negotiate_Receipt =>
                        SMB.Engine.Mark_Negotiated (Target, 65_536, 65_536, Status);
                     when Challenge_Receipt =>
                        SMB.Engine.Install_Session_Key (Target, Session_Id, Key, Status);
                     when Create_Receipt =>
                        SMB.Engine.Register_Handle
                          (Target, File_Id, SMB.Engine.Read_Only, False, Token, Status);
                  end case;
               end Consume_Receipt;
            begin
               Reconnect_Share
                 (Target, Stop_At_Negotiate => Kind = Negotiate_Receipt,
                  Stop_At_Challenge => Kind = Challenge_Receipt);
               if Kind = Create_Receipt then
                  SMB.Engine.Begin_Request
                    (Target, 5, True, True, Message_Id, Expected, Status);
                  Assert (Status = SMB.Ok, "reserve CREATE receipt fixture");
                  declare
                     Response : SMB.Bytes (0 .. 151) := (others => 0);
                  begin
                     Prepare_Response
                       (Response, 5, Message_Id, Tree_Id, Session_Id, True);
                     Response (64) := 89;
                     Response (128 .. 143) := File_Id;
                     SMB.Wire.Sign (Response, Key);
                     SMB.Engine.Accept_Response (Target, Response, Nt_Status, Status);
                     Assert (Status = SMB.Ok and then Nt_Status = SMB.Success,
                             "accept CREATE receipt fixture");
                  end;
               end if;
               Base := Target;
               Next_Id := Message_Id + 1;
               Reject (SMB.Core_Wire.Command_Code'Last, SMB.Unsupported_Feature);
               Reject (0, SMB.Invalid_State_Status);
               if Kind = Create_Receipt then
                  Reject (8, SMB.Invalid_Value);
                  Reject
                    (8, SMB.Invalid_Value,
                     Amount => SMB.Core_Protocol.Maximum_IO_Chunk + 1);
                  Reject (6, SMB.Invalid_Handle_Status);
               end if;
               Consume_Receipt;
               Assert
                 (Status = SMB.Ok and then not SMB.Engine.Has_Validated_Response (Target),
                  "rejected reservation prevented receipt consumption retry");
               if Kind = Create_Receipt then
                  Assert
                    (Token.Owner = SMB.Engine.Current_Owner_Id (Target)
                     and then Token.Epoch = SMB.Engine.Current_Epoch (Target)
                     and then Token.Ticket /= 0,
                     "CREATE receipt retry did not register its handle");
               end if;
               Target := Base;
               SMB.Engine.Begin_Request
                 (Target,
                  (case Kind is
                     when Negotiate_Receipt => 0,
                     when Challenge_Receipt => 1,
                     when Create_Receipt => 17),
                  Kind = Create_Receipt, Kind = Create_Receipt,
                  Message_Id, Expected, Status);
               Assert
                 (Status = SMB.Ok and then Message_Id = Next_Id
                  and then Expected.Message_Id = Next_Id
                  and then SMB.Engine.Has_Pending_Request (Target)
                  and then not SMB.Engine.Has_Validated_Response (Target),
                  "new reservation skipped an ID or retained the old receipt");
               declare
                  Before : constant SMB.Engine.Engine_State := Target;
               begin
                  Consume_Receipt;
                  Assert
                    (Status =
                       (if Kind = Create_Receipt
                        then SMB.Invalid_State_Status else SMB.Invalid_Value)
                     and then Target = Before,
                     "superseded receipt remained usable");
                  if Kind = Create_Receipt then
                     Assert
                       (Token.Owner = 0 and then Token.Epoch = 0
                        and then Token.Ticket = 0,
                        "superseded CREATE receipt returned a handle");
                  end if;
               end;
            end;
         end loop;
         Assert (Rejections = 9, "reservation receipt preservation coverage");
         Ada.Text_IO.Put_Line
           ("reservation receipts: 9 rejections, 3 retries and 3 superseding requests passed");
      end Test_Request_Receipt_Preservation;

      procedure Test_Handle_Outcomes is
         Target : SMB.Engine.Engine_State;
         Tokens : array (SMB.Engine.Access_Kind, Boolean) of
           SMB.Engine.Handle_Token;
         Lengths : constant array (Positive range <>) of Natural := (0, 15, 17);
         Cases : Natural := 0;

         procedure Check
           (Input_Token : SMB.Engine.Handle_Token;
            Need_Read, Need_Write : Boolean;
            Length : Natural;
            High_Bound : Boolean;
            Expected_Status : SMB.Core_Status;
            Expected_Access : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
            Expected_Directory : Boolean := False)
         is
            First : constant Natural :=
              (if High_Bound then Natural'Last - (Natural'Max (Length, 1) - 1)
               else 11);
            Last : constant Natural :=
              (if Length = 0 then First - 1 else First + (Length - 1));
            Output_Id : SMB.Bytes (First .. Last) := (others => 16#A5#);
            Output_Access : SMB.Engine.Access_Kind := SMB.Engine.Read_Write;
            Output_Directory : Boolean := True;
            Result : SMB.Core_Status;
         begin
            SMB.Engine.Validate_Handle
              (Target, Input_Token, Need_Read, Need_Write,
               Output_Id, Output_Access, Output_Directory, Result);
            Cases := Cases + 1;
            Assert (Result = Expected_Status, "exact handle validation status");
            if Result = SMB.Ok then
               Assert
                 (Output_Id = File_Id and then Output_Access = Expected_Access
                  and then Output_Directory = Expected_Directory,
                  "handle validation changed successful outputs");
            else
               Assert
                 ((for all Byte of Output_Id => Byte = 0)
                  and then Output_Access = SMB.Engine.Read_Only
                  and then not Output_Directory,
                  "handle validation failure retained outputs");
            end if;
         end Check;
      begin
         Reconnect_Share (Target);
         for Access_Mode in SMB.Engine.Access_Kind loop
            for Is_Directory in Boolean loop
               declare
                  Create_Operation : SMB.Core_Client.Operation;
               begin
                  Create_Directory_Handle
                    (Target, Create_Operation, Tokens (Access_Mode, Is_Directory),
                     Is_Directory, Access_Mode);
               end;
               for Need_Read in Boolean loop
                  for Need_Write in Boolean loop
                     for High_Bound in Boolean loop
                        Check
                          (Tokens (Access_Mode, Is_Directory),
                           Need_Read, Need_Write, 16, High_Bound,
                           (if (Need_Read and Access_Mode = SMB.Engine.Write_Only)
                              or (Need_Write and Access_Mode = SMB.Engine.Read_Only)
                            then SMB.Invalid_Handle_Status else SMB.Ok),
                           Access_Mode, Is_Directory);
                     end loop;
                  end loop;
               end loop;
            end loop;
         end loop;
         for High_Bound in Boolean loop
            for Length of Lengths loop
               Check (Tokens (SMB.Engine.Read_Write, False), True, True,
                      Length, High_Bound, SMB.Invalid_Length);
               Check ((others => 0), False, False,
                      Length, High_Bound, SMB.Invalid_Length);
            end loop;
            for Fault in 0 .. 3 loop
               declare
                  Bad : SMB.Engine.Handle_Token :=
                    Tokens (SMB.Engine.Read_Write, False);
               begin
                  case Fault is
                     when 0 => Bad.Owner := Bad.Owner + 1;
                     when 1 => Bad.Epoch := Bad.Epoch + 1;
                     when 2 => Bad.Ticket := 0;
                     when 3 => Bad.Ticket := SMB.QWord'Last;
                  end case;
                  Check (Bad, True, True, 16, High_Bound,
                         SMB.Invalid_Handle_Status);
               end;
            end loop;
         end loop;
         declare
            Operation : SMB.Core_Client.Operation;
            Request : SMB.Bytes (0 .. 87) := (others => 0);
            Response : SMB.Bytes (0 .. 123) := (others => 0);
            Used : Natural;
            Ignored_Token : SMB.Engine.Handle_Token;
         begin
            SMB.Core_Client.Prepare_Close
              (Operation, Target, Tokens (SMB.Engine.Read_Write, False),
               Request, Used, Status);
            Assert (Status = SMB.Ok, "prepare handle outcome CLOSE");
            SMB.Core_Client.Send_Succeeded (Operation, Target, Status);
            Assert (Status = SMB.Ok, "send handle outcome CLOSE");
            Prepare_Response
              (Response, 6, SMB.Wire.U64 (Request, 24),
               Tree_Id, Session_Id, True);
            Response (64) := 60;
            SMB.Wire.Sign (Response, Key);
            SMB.Core_Client.Complete
              (Operation, Target, Response, Nt_Status, Ignored_Token, Status);
            Assert (Status = SMB.Ok and then Nt_Status = SMB.Success,
                    "complete handle outcome CLOSE");
         end;
         for High_Bound in Boolean loop
            Check (Tokens (SMB.Engine.Read_Write, False), False, False,
                   16, High_Bound, SMB.Invalid_Handle_Status);
         end loop;
         SMB.Engine.Invalidate (Target, Status);
         Assert (Status = SMB.Ok, "invalidate handle outcome state");
         for High_Bound in Boolean loop
            Check (Tokens (SMB.Engine.Read_Write, True), False, False,
                   16, High_Bound, SMB.Invalid_Handle_Status);
         end loop;
         Reconnect_Share (Target, Initialize_State => False);
         for High_Bound in Boolean loop
            Check (Tokens (SMB.Engine.Read_Write, True), False, False,
                   16, High_Bound, SMB.Invalid_Handle_Status);
         end loop;
         Assert (Cases = 74, "handle validation case coverage");
         Ada.Text_IO.Put_Line ("handle validation cases:" & Natural'Image (Cases));
      end Test_Handle_Outcomes;

      procedure Test_Handle_Capacity is
         use type SMB.Engine.Engine_State;
         use type SMB.Core_Client.Operation_Stage;
         Target : SMB.Engine.Engine_State;
         Tokens : array (1 .. SMB.Engine.Maximum_Handles) of
           SMB.Engine.Handle_Token;
         File_Ids : array (Tokens'Range) of SMB.Bytes (0 .. 15) :=
           (others => File_Id);
         Modes : array (Tokens'Range) of SMB.Engine.Access_Kind :=
           (others => SMB.Engine.Read_Only);
         Directories : array (Tokens'Range) of Boolean := (others => False);
         Middle : constant Positive := Tokens'Length / 2;
         Old_Token : SMB.Engine.Handle_Token;
         Output_Id : SMB.Bytes (0 .. 15);
         Output_Access : SMB.Engine.Access_Kind;
         Output_Directory : Boolean;
         Next_Id : SMB.QWord := 4;

         procedure Check_Handles (Closed : Natural := 0) is
         begin
            for Index in Tokens'Range loop
               SMB.Engine.Validate_Handle
                 (Target, Tokens (Index), False, False,
                  Output_Id, Output_Access, Output_Directory, Status);
               if Index = Closed then
                  Assert (Status = SMB.Invalid_Handle_Status,
                          "closed capacity handle remained valid");
               else
                  Assert
                    (Status = SMB.Ok and then Output_Id = File_Ids (Index)
                     and then Output_Access = Modes (Index)
                     and then Output_Directory = Directories (Index),
                     "capacity handling changed another handle's identity or contents");
               end if;
            end loop;
         end Check_Handles;
      begin
         Reconnect_Share (Target);
         for Index in Tokens'Range loop
            File_Ids (Index) (0) := SMB.Byte (Index mod 256);
            File_Ids (Index) (1) := SMB.Byte (Index / 256);
            Modes (Index) := SMB.Engine.Access_Kind'Val ((Index - 1) mod 3);
            Directories (Index) := Index mod 2 = 0;
            declare
               Operation : SMB.Core_Client.Operation;
            begin
               Create_Directory_Handle
                 (Target, Operation, Tokens (Index),
                  Is_Directory => Directories (Index),
                  Access_Mode => Modes (Index),
                  Response_File_Id => File_Ids (Index),
                  Expected_Message_Id => Next_Id);
            end;
            Next_Id := Next_Id + 1;
            Assert
              (Tokens (Index).Ticket = SMB.QWord (Index),
               "handle tickets did not advance exactly once per registration");
         end loop;
         SMB.Engine.Begin_Request
           (Target, 17, True, True, Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "reserve capacity receipt fixture");
         Assert (Message_Id = Next_Id, "registration changed the request counter");
         Next_Id := Next_Id + 1;
         declare
            Response : SMB.Bytes (0 .. 65) := (others => 0);
         begin
            Prepare_Response
              (Response, 17, Message_Id, Tree_Id, Session_Id, True);
            Response (64) := 2;
            SMB.Wire.Sign (Response, Key);
            SMB.Engine.Accept_Response (Target, Response, Nt_Status, Status);
            Assert
              (Status = SMB.Ok and then Nt_Status = SMB.Success
               and then SMB.Engine.Has_Validated_Response (Target),
               "accept capacity receipt fixture");
         end;
         declare
            use type SMB.Engine.Request_Expectation;
            Before : constant SMB.Engine.Engine_State := Target;
            Reserved_Id : SMB.QWord := SMB.QWord'Last;
            Reservation : SMB.Engine.Request_Expectation :=
              (Command => SMB.Core_Wire.Command_Code'Last, others => <>);
         begin
            SMB.Engine.Begin_Request
              (Target, 5, True, True, Reserved_Id, Reservation, Status);
            Assert
              (Status = SMB.Resource_Limit and then Target = Before
               and then Reserved_Id = 0
               and then Reservation = SMB.Engine.Request_Expectation'(others => <>),
               "capacity rejection consumed receipt or retained reservation outputs");
         end;
         declare
            Before : constant SMB.Engine.Engine_State := Target;
            Operation : SMB.Core_Client.Operation;
            Request : SMB.Bytes (0 .. 127) := (others => 16#A5#);
            Used : Natural;
         begin
            SMB.Core_Client.Prepare_Create
              (Operation, Target, SMB.Bytes'(0 => 65, 1 => 0),
               SMB.Engine.Read_Only, False, 1, False, Request, Used, Status);
            Assert
              (Status = SMB.Resource_Limit and then Used = 0
               and then SMB.Core_Client.Stage_Of (Operation) = SMB.Core_Client.Failed
               and then Target = Before
               and then (for all Byte of Request => Byte = 0),
               "full handle table changed state or prepared a request");
         end;
         Check_Handles;
         SMB.Engine.Discard_Response_Receipt (Target, Status);
         Assert
           (Status = SMB.Ok and then not SMB.Engine.Has_Validated_Response (Target),
            "discard capacity receipt before closing a handle");
         Old_Token := Tokens (Middle);
         declare
            Operation : SMB.Core_Client.Operation;
            Request : SMB.Bytes (0 .. 87);
            Response : SMB.Bytes (0 .. 123) := (others => 0);
            Used : Natural;
            Ignored_Token : SMB.Engine.Handle_Token;
         begin
            SMB.Core_Client.Prepare_Close
              (Operation, Target, Old_Token, Request, Used, Status);
            Assert (Status = SMB.Ok, "capacity CLOSE preparation");
            Assert
              (SMB.Wire.U64 (Request, 24) = Next_Id,
               "reservation rejection or receipt discard changed the request counter");
            Next_Id := Next_Id + 1;
            SMB.Core_Client.Send_Succeeded (Operation, Target, Status);
            Assert (Status = SMB.Ok, "capacity CLOSE send");
            Prepare_Response
              (Response, 6, SMB.Wire.U64 (Request, 24), Tree_Id, Session_Id, True);
            Response (64) := 60;
            SMB.Wire.Sign (Response, Key);
            SMB.Core_Client.Complete
              (Operation, Target, Response, Nt_Status, Ignored_Token, Status);
            Assert (Status = SMB.Ok, "capacity CLOSE completion");
         end;
         Check_Handles (Closed => Middle);
         File_Ids (Middle) (15) := File_Ids (Middle) (15) xor 1;
         Modes (Middle) := SMB.Engine.Read_Only;
         Directories (Middle) := False;
         declare
            Operation : SMB.Core_Client.Operation;
         begin
            Create_Directory_Handle
              (Target, Operation, Tokens (Middle),
               Is_Directory => Directories (Middle),
               Access_Mode => Modes (Middle),
               Response_File_Id => File_Ids (Middle),
               Expected_Message_Id => Next_Id);
         end;
         Next_Id := Next_Id + 1;
         Assert
           (Tokens (Middle).Ticket = SMB.QWord (SMB.Engine.Maximum_Handles) + 1,
            "slot reuse rewound or skipped the handle ticket counter");
         SMB.Engine.Validate_Handle
           (Target, Old_Token, False, False,
            Output_Id, Output_Access, Output_Directory, Status);
         Assert (Status = SMB.Invalid_Handle_Status,
                 "reused slot revived a stale token");
         Check_Handles;
         declare
            Disconnect_Response : SMB.Bytes (0 .. 67) := (others => 0);
            Connect_Response : SMB.Bytes (0 .. 79) := (others => 0);
            Operation : SMB.Core_Client.Operation;
            New_Token : SMB.Engine.Handle_Token;
         begin
            SMB.Engine.Begin_Request
              (Target, 4, True, True, Message_Id, Expected, Status);
            Assert (Status = SMB.Ok, "reserve ticket-preserving tree disconnect");
            Assert (Message_Id = Next_Id, "handle reuse changed the request counter");
            Next_Id := Next_Id + 1;
            Prepare_Response
              (Disconnect_Response, 4, Message_Id, Tree_Id, Session_Id, True);
            Disconnect_Response (64) := 4;
            SMB.Wire.Sign (Disconnect_Response, Key);
            SMB.Engine.Accept_Response
              (Target, Disconnect_Response, Nt_Status, Status);
            Assert
              (Status = SMB.Ok and then Nt_Status = SMB.Success
               and then SMB.Engine.Current_Phase (Target) = SMB.Engine.Authenticated
               and then not SMB.Engine.Has_Open_Handles (Target),
               "ticket fixture did not disconnect the old share");
            SMB.Engine.Begin_Request
              (Target, 3, True, True, Message_Id, Expected, Status);
            Assert (Status = SMB.Ok, "reserve ticket-preserving tree reconnect");
            Assert (Message_Id = Next_Id, "tree disconnect changed the request counter");
            Next_Id := Next_Id + 1;
            Prepare_Response
              (Connect_Response, 3, Message_Id, Tree_Id, Session_Id, True);
            Connect_Response (64) := 16;
            Connect_Response (66) := 1;
            SMB.Wire.Sign (Connect_Response, Key);
            SMB.Engine.Accept_Response
              (Target, Connect_Response, Nt_Status, Status);
            Assert
              (Status = SMB.Ok and then Nt_Status = SMB.Success,
               "accept ticket-preserving tree reconnect");
            SMB.Engine.Mark_Share_Connected (Target, Tree_Id, Status);
            Assert (Status = SMB.Ok, "restore the same tree ID");
            Create_Directory_Handle
              (Target, Operation, New_Token, Is_Directory => False,
               Expected_Message_Id => Next_Id);
            Next_Id := Next_Id + 1;
            Assert
              (New_Token.Owner = Tokens (1).Owner
               and then New_Token.Epoch = Tokens (1).Epoch
               and then New_Token.Ticket = SMB.QWord (SMB.Engine.Maximum_Handles) + 2,
               "share reconnection recycled handle tickets or changed identity");
            for Stale of Tokens loop
               SMB.Engine.Validate_Handle
                 (Target, Stale, False, False,
                  Output_Id, Output_Access, Output_Directory, Status);
               Assert
                 (Status = SMB.Invalid_Handle_Status
                  and then Output_Id = SMB.Bytes'(0 .. 15 => 0),
                  "share reconnection revived an old handle");
            end loop;
            SMB.Engine.Validate_Handle
              (Target, Old_Token, False, False,
               Output_Id, Output_Access, Output_Directory, Status);
            Assert (Status = SMB.Invalid_Handle_Status,
                    "share reconnection revived the previously closed handle");
            SMB.Engine.Validate_Handle
              (Target, New_Token, False, False,
               Output_Id, Output_Access, Output_Directory, Status);
            Assert
              (Status = SMB.Ok and then Output_Id = File_Id
               and then Output_Access = SMB.Engine.Read_Only
               and then not Output_Directory,
               "share reconnection lost the new handle");
         end;
         Ada.Text_IO.Put_Line
           ("handle capacity: 258 sequential tickets, slot reuse and share reconnect passed");
         Assert
           (Next_Id = SMB.QWord (SMB.Engine.Maximum_Handles) + 10,
            "request counter continuity coverage");
         Ada.Text_IO.Put_Line
           ("request IDs: 266 consecutive reservations across handle and share reuse passed");
      end Test_Handle_Capacity;

      procedure Test_Lifecycle_Atomicity is
         use type SMB.Engine.Engine_State;
         Target : SMB.Engine.Engine_State;
         Init_Failures, Connect_Failures : Natural := 0;

         procedure Reject_Initialize is
            Before : constant SMB.Engine.Engine_State := Target;
         begin
            SMB.Engine.Initialize (Target, Status);
            Assert
              (Status = SMB.Invalid_State_Status and then Target = Before,
               "rejected initialization changed state");
            Init_Failures := Init_Failures + 1;
         end Reject_Initialize;

         procedure Reject_Connect is
            Before : constant SMB.Engine.Engine_State := Target;
         begin
            SMB.Engine.Mark_Connected (Target, Status);
            Assert
              (Status = SMB.Invalid_State_Status and then Target = Before,
               "rejected transport transition changed state");
            Connect_Failures := Connect_Failures + 1;
         end Reject_Connect;
      begin
         Reject_Connect;
         SMB.Engine.Initialize (Target, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Engine.Current_Owner_Id (Target) /= 0
            and then SMB.Engine.Current_Epoch (Target) = 0
            and then SMB.Engine.Current_Max_Read (Target) = 0
            and then not SMB.Engine.Has_Validated_Response (Target),
            "lifecycle fixture initialization");
         SMB.Engine.Mark_Connected (Target, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Engine.Current_Phase (Target) =
              SMB.Engine.Transport_Connected,
            "lifecycle fixture transport transition");
         Reject_Initialize;
         Reject_Connect;
         SMB.Engine.Begin_Request
           (Target, 0, False, False, Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "lifecycle pending fixture");
         Reject_Initialize;
         Reject_Connect;
         SMB.Engine.Invalidate (Target, Status);
         Assert (Status = SMB.Ok, "lifecycle invalidate pending fixture");
         Reconnect_Share (Target, Stop_At_Challenge => True);
         Reject_Initialize;
         Reject_Connect;
         SMB.Engine.Invalidate (Target, Status);
         Assert (Status = SMB.Ok, "lifecycle invalidate challenge fixture");
         Reconnect_Share (Target, Connect_Share_State => False);
         Reject_Initialize;
         Reject_Connect;
         SMB.Engine.Invalidate (Target, Status);
         Assert (Status = SMB.Ok, "lifecycle invalidate authenticated fixture");
         Reconnect_Share (Target);
         Reject_Initialize;
         Reject_Connect;
         Assert (Init_Failures = 5 and then Connect_Failures = 6,
                 "lifecycle failure atomicity coverage");
         Ada.Text_IO.Put_Line
           ("lifecycle failure atomicity: 11 rejected calls passed");
      end Test_Lifecycle_Atomicity;

      procedure Test_Invalidation_Reset is
         type Fixture_Kind is
           (Default_State, Transport_State, Pending_Negotiate_State,
            Challenge_State, Authenticated_State, Share_Receipt_State,
            Pending_Async_State);
         Resets, Restarts : Natural := 0;

         procedure Check_Reset (Target : in out SMB.Engine.Engine_State) is
            Owner : constant SMB.QWord := SMB.Engine.Current_Owner_Id (Target);
            Epoch : constant SMB.QWord := SMB.Engine.Current_Epoch (Target);
         begin
            SMB.Engine.Invalidate (Target, Status);
            Assert
              (Status = SMB.Ok
               and then SMB.Engine.Current_Owner_Id (Target) = Owner
               and then SMB.Engine.Current_Epoch (Target) = Epoch + 1
               and then SMB.Engine.Current_Phase (Target) = SMB.Engine.Disconnected
               and then not SMB.Engine.Has_Open_Handles (Target)
               and then not SMB.Engine.Has_Pending_Request (Target)
               and then not SMB.Engine.Has_Validated_Response (Target)
               and then not SMB.Engine.Has_Signing_Key (Target)
               and then SMB.Engine.Signing_Key_Is_Zero (Target)
               and then SMB.Engine.Current_Session_Id (Target) = 0
               and then SMB.Engine.Current_Tree_Id (Target) = 0
               and then SMB.Engine.Current_Async_Id (Target) = 0
               and then SMB.Engine.Current_Max_Read (Target) = 0
               and then SMB.Engine.Current_Max_Write (Target) = 0
               and then SMB.Core_Protocol."="
                 (SMB.Engine.Current_Response_Info (Target),
                  SMB.Core_Protocol.Response_Info'(others => <>)),
               "invalidation did not reset context or advance the same owner's epoch");
            Resets := Resets + 1;
         end Check_Reset;
      begin
         for Kind in Fixture_Kind loop
            declare
               Target : SMB.Engine.Engine_State;
               Token : SMB.Engine.Handle_Token;
               Create_Operation : SMB.Core_Client.Operation;
            begin
               case Kind is
                  when Default_State => null;
                  when Transport_State | Pending_Negotiate_State =>
                     SMB.Engine.Initialize (Target, Status);
                     Assert (Status = SMB.Ok, "initialize invalidation fixture");
                     SMB.Engine.Mark_Connected (Target, Status);
                     Assert (Status = SMB.Ok, "connect invalidation fixture");
                     if Kind = Pending_Negotiate_State then
                        SMB.Engine.Begin_Request
                          (Target, 0, False, False, Message_Id, Expected, Status);
                        Assert
                          (Status = SMB.Ok and then SMB.Engine.Has_Pending_Request (Target),
                           "reserve invalidation fixture request");
                     end if;
                  when Challenge_State =>
                     Reconnect_Share (Target, Stop_At_Challenge => True);
                     Assert
                       (SMB.Engine.Has_Validated_Response (Target)
                        and then SMB.Engine.Current_Response_Info (Target).Session_Id /= 0,
                        "invalidation fixture needs challenge metadata");
                  when Authenticated_State =>
                     Reconnect_Share (Target, Connect_Share_State => False);
                     Assert
                       (SMB.Engine.Has_Signing_Key (Target)
                        and then not SMB.Engine.Signing_Key_Is_Zero (Target),
                        "invalidation fixture needs a nonzero key");
                  when Share_Receipt_State | Pending_Async_State =>
                     Reconnect_Share (Target);
                     Create_Directory_Handle
                       (Target, Create_Operation, Token, Is_Directory => False);
                     declare
                        Fixture_File_Id : SMB.Bytes (0 .. 15);
                        Fixture_Access : SMB.Engine.Access_Kind :=
                          SMB.Engine.Read_Write;
                        Fixture_Is_Directory : Boolean := True;
                     begin
                        SMB.Engine.Validate_Handle
                          (Target, Token, False, False, Fixture_File_Id,
                           Fixture_Access, Fixture_Is_Directory, Status);
                        Assert
                          (Status = SMB.Ok
                           and then SMB.Engine.Current_Max_Read (Target) /= 0
                           and then SMB.Engine.Current_Max_Write (Target) /= 0,
                           "invalidation fixture needs a live handle and limits");
                     end;
                     if Kind = Share_Receipt_State then
                        declare
                           Response : SMB.Bytes (0 .. 65) := (others => 0);
                        begin
                           SMB.Engine.Begin_Request
                             (Target, 17, True, True, Message_Id, Expected, Status);
                           Assert (Status = SMB.Ok, "reserve invalidation receipt");
                           Prepare_Response
                             (Response, 17, Message_Id, Tree_Id, Session_Id, True);
                           Response (64) := 2;
                           SMB.Wire.Sign (Response, Key);
                           SMB.Engine.Accept_Response (Target, Response, Nt_Status, Status);
                           Assert
                             (Status = SMB.Ok and then Nt_Status = SMB.Success
                              and then SMB.Engine.Has_Validated_Response (Target),
                              "accept invalidation receipt fixture");
                        end;
                     else
                        declare
                           Response : SMB.Bytes (0 .. 71) := (others => 0);
                           Is_Interim : Boolean;
                           Async_Id : constant SMB.QWord := 16#1122_3344_5566_7788#;
                        begin
                           SMB.Engine.Begin_Request
                             (Target, 8, True, True, Message_Id, Expected, Status,
                              Request_Amount => 1);
                           Assert (Status = SMB.Ok, "reserve invalidation async request");
                           Prepare_Response
                             (Response, 8, Message_Id, 0, Session_Id, False);
                           SMB.Wire.Put_U32 (Response, 8, SMB.Status_Pending);
                           SMB.Wire.Put_U32 (Response, 16, 3);
                           SMB.Wire.Put_U64 (Response, 32, Async_Id);
                           Response (64) := 9;
                           SMB.Engine.Inspect_Interim_Response
                             (Target, Response, Is_Interim, Status);
                           Assert
                             (Status = SMB.Ok and then Is_Interim
                              and then SMB.Engine.Has_Pending_Request (Target)
                              and then SMB.Engine.Current_Async_Id (Target) = Async_Id,
                              "invalidation fixture needs a pending async ID");
                        end;
                     end if;
               end case;
               Check_Reset (Target);
               if Kind = Default_State then
                  Check_Reset (Target);
                  declare
                     use type SMB.Engine.Engine_State;
                     Before : constant SMB.Engine.Engine_State := Target;
                  begin
                     SMB.Engine.Mark_Connected (Target, Status);
                     Assert
                       (Status = SMB.Invalid_State_Status and then Target = Before,
                        "invalidation fabricated an owner for an uninitialized state");
                  end;
               else
                  if Kind = Share_Receipt_State or else Kind = Pending_Async_State then
                     declare
                        Result_Id : SMB.Bytes (0 .. 15) := (others => 16#AA#);
                        Access_Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Write;
                        Is_Directory : Boolean := True;
                     begin
                        SMB.Engine.Validate_Handle
                          (Target, Token, True, False,
                           Result_Id, Access_Mode, Is_Directory, Status);
                        Assert
                          (Status = SMB.Invalid_Handle_Status
                           and then Result_Id = SMB.Bytes'(0 .. 15 => 0)
                           and then Access_Mode = SMB.Engine.Read_Only
                           and then not Is_Directory,
                           "invalidation retained a usable handle or its output");
                     end;
                  end if;
                  SMB.Engine.Mark_Connected (Target, Status);
                  Assert (Status = SMB.Ok, "reconnect invalidated owner");
                  SMB.Engine.Begin_Request
                    (Target, 0, False, False, Message_Id, Expected, Status);
                  Assert
                    (Status = SMB.Ok and then Message_Id = 0
                     and then Expected.Message_Id = 0
                     and then SMB.Engine.Pending_Request_Matches (Target, Expected),
                     "invalidation did not restart message IDs at zero");
                  Restarts := Restarts + 1;
               end if;
            end;
         end loop;
         Assert (Resets = 8 and then Restarts = 6, "invalidation reset coverage");
         Ada.Text_IO.Put_Line
           ("invalidation: 8 resets and 6 message-ID restarts passed");
      end Test_Invalidation_Reset;

      procedure Test_Owner_Allocation is
         use type SMB.Engine.Engine_State;
         Target, Other : SMB.Engine.Engine_State;
         Previous : SMB.QWord;

         procedure Allocate_Next (Value : in out SMB.Engine.Engine_State) is
         begin
            SMB.Engine.Initialize (Value, Status);
            Assert
              (Status = SMB.Ok
               and then SMB.Engine.Current_Owner_Id (Value) = Previous + 1
               and then SMB.Engine.Current_Owner_Id (Value) > Previous
               and then SMB.Engine.Current_Epoch (Value) = 0,
               "owner allocation skipped or reused an ID");
            Previous := SMB.Engine.Current_Owner_Id (Value);
         end Allocate_Next;
      begin
         SMB.Engine.Initialize (Target, Status);
         Assert (Status = SMB.Ok, "owner allocation initial fixture");
         Previous := SMB.Engine.Current_Owner_Id (Target);
         for Cycle in 1 .. 32 loop
            SMB.Engine.Mark_Connected (Target, Status);
            Assert (Status = SMB.Ok, "owner allocation connected fixture");
            declare
               Before : constant SMB.Engine.Engine_State := Target;
            begin
               SMB.Engine.Initialize (Target, Status);
               Assert
                 (Status = SMB.Invalid_State_Status and then Target = Before,
                  "owner allocation rejected initialization changed state");
            end;
            Allocate_Next (Other);
            SMB.Engine.Invalidate (Target, Status);
            Assert (Status = SMB.Ok, "owner allocation invalidate fixture");
            Allocate_Next (Target);
         end loop;
         Ada.Text_IO.Put_Line
           ("owner allocation: 65 successes and 32 rejected calls passed");
      end Test_Owner_Allocation;

      procedure Test_Receipt_Transitions is
         use type SMB.Engine.Engine_State;
         use type SMB.Core_Protocol.Response_Info;
         Target, Base : SMB.Engine.Engine_State;
         Create_Operation : SMB.Core_Client.Operation;
         Token : SMB.Engine.Handle_Token;
         Negotiation_Failures, Tree_Failures : Natural := 0;
         Discard_Failures, Discard_Successes : Natural := 0;
         Invalid_Limits : constant array (Positive range <>) of Natural :=
           (0, 1, 65_535, 65_537, SMB.Maximum_Frame_Size,
            SMB.Maximum_Frame_Size + 1, Natural'Last);

         procedure Reject_Negotiation
           (Read_Limit : Natural := 65_536;
            Write_Limit : Natural := 65_536) is
            Before : constant SMB.Engine.Engine_State := Target;
         begin
            SMB.Engine.Mark_Negotiated
              (Target, Read_Limit, Write_Limit, Status);
            Assert
              (Status = SMB.Invalid_Value and then Target = Before,
               "rejected negotiation changed state or status");
            Negotiation_Failures := Negotiation_Failures + 1;
         end Reject_Negotiation;

         procedure Reject_Tree (Id : SMB.DWord := Tree_Id) is
            Before : constant SMB.Engine.Engine_State := Target;
         begin
            SMB.Engine.Mark_Share_Connected (Target, Id, Status);
            Assert
              (Status = SMB.Invalid_State_Status and then Target = Before,
               "rejected tree transition changed state or status");
            Tree_Failures := Tree_Failures + 1;
         end Reject_Tree;

         procedure Check_Discard is
            Before : constant SMB.Engine.Engine_State := Target;
         begin
            SMB.Engine.Discard_Response_Receipt (Target, Status);
            if SMB.Engine.Has_Pending_Request (Before) then
               Assert
                 (Status = SMB.Invalid_State_Status and then Target = Before,
                  "rejected receipt discard changed state or status");
               Discard_Failures := Discard_Failures + 1;
            else
               Assert
                 (Status = SMB.Ok
                  and then not SMB.Engine.Has_Validated_Response (Target)
                  and then not SMB.Engine.Has_Pending_Request (Target)
                  and then SMB.Engine.Current_Response_Info (Target) =
                    SMB.Core_Protocol.Response_Info'(others => <>)
                  and then SMB.Engine.Current_Phase (Target) =
                    SMB.Engine.Current_Phase (Before)
                  and then SMB.Engine.Current_Owner_Id (Target) =
                    SMB.Engine.Current_Owner_Id (Before)
                  and then SMB.Engine.Current_Epoch (Target) =
                    SMB.Engine.Current_Epoch (Before)
                  and then SMB.Engine.Current_Session_Id (Target) =
                    SMB.Engine.Current_Session_Id (Before)
                  and then SMB.Engine.Current_Tree_Id (Target) =
                    SMB.Engine.Current_Tree_Id (Before)
                  and then SMB.Engine.Current_Max_Read (Target) =
                    SMB.Engine.Current_Max_Read (Before)
                  and then SMB.Engine.Current_Max_Write (Target) =
                    SMB.Engine.Current_Max_Write (Before)
                  and then SMB.Engine.Has_Signing_Key (Target) =
                    SMB.Engine.Has_Signing_Key (Before)
                  and then SMB.Engine.Current_Signing_Key (Target) =
                    SMB.Engine.Current_Signing_Key (Before),
                  "receipt discard lost connection context or retained info");
               Discard_Successes := Discard_Successes + 1;
            end if;
         end Check_Discard;
      begin
         Reject_Negotiation;
         Reject_Tree;
         Check_Discard;
         SMB.Engine.Initialize (Target, Status);
         Assert (Status = SMB.Ok, "receipt transition initialization");
         SMB.Engine.Mark_Connected (Target, Status);
         Assert (Status = SMB.Ok, "receipt transition transport");
         Reject_Negotiation;
         SMB.Engine.Begin_Request
           (Target, 0, False, False, Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "receipt transition pending negotiate");
         Reject_Negotiation;
         Check_Discard;
         SMB.Engine.Invalidate (Target, Status);
         Assert (Status = SMB.Ok, "receipt transition invalidate negotiate");
         Reconnect_Share (Target, Stop_At_Negotiate => True);
         Reject_Tree;
         for Limit of Invalid_Limits loop
            Reject_Negotiation (Read_Limit => Limit);
            Reject_Negotiation (Write_Limit => Limit);
         end loop;
         SMB.Engine.Mark_Negotiated (Target, 65_536, 65_536, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Engine.Current_Phase (Target) = SMB.Engine.Negotiated
            and then SMB.Engine.Current_Max_Read (Target) = 65_536
            and then SMB.Engine.Current_Max_Write (Target) = 65_536
            and then not SMB.Engine.Has_Validated_Response (Target),
            "negotiation retry lost valid receipt");
         Reject_Negotiation;
         Check_Discard;
         declare
            Cleared : constant SMB.Engine.Engine_State := Target;
         begin
            Check_Discard;
            Assert (Target = Cleared, "receipt discard is not idempotent");
         end;
         SMB.Engine.Invalidate (Target, Status);
         Assert (Status = SMB.Ok, "receipt transition invalidate negotiated");
         Reconnect_Share (Target, Connect_Share_State => False);
         Reject_Tree;
         Base := Target;
         for Is_Error in Boolean loop
            Target := Base;
            SMB.Engine.Begin_Request
              (Target, 3, True, True, Message_Id, Expected, Status);
            Assert (Status = SMB.Ok, "receipt transition pending tree connect");
            Reject_Tree;
            Check_Discard;
            declare
               Response : SMB.Bytes (0 .. (if Is_Error then 71 else 79)) :=
                 (others => 0);
               Expected_Status : constant SMB.DWord :=
                 (if Is_Error then 16#C000_0022# else SMB.Success);
            begin
               Prepare_Response
                 (Response, 3, Message_Id, Tree_Id, Session_Id, True);
               SMB.Wire.Put_U32 (Response, 8, Expected_Status);
               if Is_Error then
                  Response (64) := 9;
               else
                  Response (64) := 16;
                  Response (66) := 1;
               end if;
               SMB.Wire.Sign (Response, Key);
               SMB.Engine.Accept_Response (Target, Response, Nt_Status, Status);
               Assert
                 (Status = SMB.Ok and then Nt_Status = Expected_Status
                  and then SMB.Engine.Has_Validated_Response (Target),
                  "receipt transition tree response fixture");
            end;
            if Is_Error then
               Reject_Tree;
               Check_Discard;
            else
               Reject_Tree (0);
               Reject_Tree (Tree_Id xor 1);
               Reject_Negotiation;
               SMB.Engine.Mark_Share_Connected (Target, Tree_Id, Status);
               Assert
                 (Status = SMB.Ok
                  and then SMB.Engine.Current_Phase (Target) =
                    SMB.Engine.Share_Connected
                  and then SMB.Engine.Current_Tree_Id (Target) = Tree_Id
                  and then SMB.Engine.Current_Max_Read (Target) = 65_536
                  and then SMB.Engine.Current_Max_Write (Target) = 65_536
                  and then not SMB.Engine.Has_Validated_Response (Target),
                  "tree connection retry lost valid receipt or transfer limits");
               Reject_Tree;
               Create_Directory_Handle (Target, Create_Operation, Token);
               Check_Discard;
               declare
                  Actual_Id : SMB.Bytes (0 .. 15);
                  Actual_Access : SMB.Engine.Access_Kind;
                  Actual_Directory : Boolean;
               begin
                  SMB.Engine.Validate_Handle
                    (Target, Token, True, False, Actual_Id,
                     Actual_Access, Actual_Directory, Status);
                  Assert
                    (Status = SMB.Ok and then Actual_Id = File_Id
                     and then Actual_Access = SMB.Engine.Read_Only
                     and then Actual_Directory,
                     "receipt discard changed a live handle");
               end;
            end if;
         end loop;
         Assert
           (Negotiation_Failures = 19 and then Tree_Failures = 9
            and then Discard_Failures = 3 and then Discard_Successes = 5,
            "receipt transition coverage");
         Ada.Text_IO.Put_Line
           ("receipt transitions: 31 rejections, 5 discards and 2 retries passed");
      end Test_Receipt_Transitions;

      procedure Test_Handle_Failure_Atomicity is
         use type SMB.Engine.Engine_State;
         Target : SMB.Engine.Engine_State;
         First_Token, Second_Token : SMB.Engine.Handle_Token;
         Registration_Failures, Close_Failures : Natural := 0;
         Lengths : constant array (Positive range <>) of Natural := (0, 15, 17);

         procedure Reject_Registration
           (Input : SMB.Bytes;
            Expected_Status : SMB.Core_Status) is
            Before : constant SMB.Engine.Engine_State := Target;
            Output_Token : SMB.Engine.Handle_Token := (others => 16#A5#);
         begin
            SMB.Engine.Register_Handle
              (Target, Input, SMB.Engine.Read_Only, False, Output_Token, Status);
            Assert
              (Status = Expected_Status and then Target = Before
               and then Output_Token.Owner = 0 and then Output_Token.Epoch = 0
               and then Output_Token.Ticket = 0,
               "rejected registration changed state or retained a token");
            Registration_Failures := Registration_Failures + 1;
         end Reject_Registration;

         procedure Reject_Close
           (Input, Confirmation : SMB.Engine.Handle_Token) is
            Before : constant SMB.Engine.Engine_State := Target;
         begin
            SMB.Engine.Close_Handle (Target, Input, Status, Confirmation);
            Assert
              (Status = SMB.Invalid_Handle_Status and then Target = Before,
               "rejected CLOSE changed state or consumed its receipt");
            Close_Failures := Close_Failures + 1;
         end Reject_Close;
      begin
         Reject_Registration (SMB.Bytes'(1 .. 0 => 0), SMB.Invalid_State_Status);
         Reconnect_Share (Target);
         Reject_Registration (File_Id, SMB.Invalid_State_Status);
         SMB.Engine.Begin_Request
           (Target, 5, True, True, Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "atomic registration begin CREATE");
         Reject_Registration (File_Id, SMB.Invalid_State_Status);
         declare
            Response : SMB.Bytes (0 .. 151) := (others => 0);
         begin
            Prepare_Response (Response, 5, Message_Id, Tree_Id, Session_Id, True);
            Response (64) := 89;
            Response (128 .. 143) := File_Id;
            SMB.Wire.Sign (Response, Key);
            SMB.Engine.Accept_Response (Target, Response, Nt_Status, Status);
            Assert (Status = SMB.Ok, "atomic registration accept CREATE");
         end;
         for High_Bounds in Boolean loop
            for Length of Lengths loop
               declare
                  First : constant Natural :=
                    (if High_Bounds then Natural'Last - Length else 1);
                  Input : constant SMB.Bytes (First .. First + Length - 1) :=
                    (others => 16#A5#);
               begin
                  Reject_Registration (Input, SMB.Invalid_Length);
               end;
            end loop;
            for Last_Byte in Boolean loop
               declare
                  First : constant Natural :=
                    (if High_Bounds then Natural'Last - 16 else 1);
                  Input : SMB.Bytes (First .. First + 15) := File_Id;
                  Changed : constant Natural := First + (if Last_Byte then 15 else 0);
               begin
                  Input (Changed) := Input (Changed) xor 1;
                  Reject_Registration (Input, SMB.Invalid_Value);
               end;
            end loop;
         end loop;
         SMB.Engine.Register_Handle
           (Target, File_Id, SMB.Engine.Read_Only, False, First_Token, Status);
         Assert (Status = SMB.Ok, "registration failures consumed valid receipt");
         Reject_Registration (File_Id, SMB.Invalid_State_Status);
         declare
            Operation : SMB.Core_Client.Operation;
         begin
            Create_Directory_Handle
              (Target, Operation, Second_Token, Is_Directory => False);
         end;
         Reject_Close (First_Token, First_Token);
         SMB.Engine.Begin_Request
           (Target, 6, True, True, Message_Id, Expected, Status,
            Close_Token => First_Token);
         Assert (Status = SMB.Ok, "atomic CLOSE begin request");
         Reject_Close (First_Token, First_Token);
         declare
            Response : SMB.Bytes (0 .. 123) := (others => 0);
         begin
            Prepare_Response (Response, 6, Message_Id, Tree_Id, Session_Id, True);
            Response (64) := 60;
            SMB.Wire.Sign (Response, Key);
            SMB.Engine.Accept_Response (Target, Response, Nt_Status, Status);
            Assert (Status = SMB.Ok, "atomic CLOSE accept receipt");
         end;
         Reject_Close (First_Token, Second_Token);
         Reject_Close (Second_Token, Second_Token);
         for Field in 1 .. 4 loop
            declare
               Bad_Token : SMB.Engine.Handle_Token := First_Token;
            begin
               case Field is
                  when 1 => Bad_Token.Owner := Bad_Token.Owner + 1;
                  when 2 => Bad_Token.Epoch := Bad_Token.Epoch + 1;
                  when 3 => Bad_Token.Ticket := 0;
                  when 4 => Bad_Token.Ticket := SMB.QWord'Last;
               end case;
               Reject_Close (Bad_Token, Bad_Token);
            end;
         end loop;
         SMB.Engine.Close_Handle (Target, First_Token, Status, First_Token);
         Assert (Status = SMB.Ok, "CLOSE failures consumed valid receipt");
         Reject_Close (First_Token, First_Token);
         declare
            Output_Id : SMB.Bytes (0 .. 15);
            Output_Access : SMB.Engine.Access_Kind;
            Output_Directory : Boolean;
         begin
            SMB.Engine.Validate_Handle
              (Target, Second_Token, True, False,
               Output_Id, Output_Access, Output_Directory, Status);
            Assert (Status = SMB.Ok and then Output_Id = File_Id,
                    "CLOSE retry changed the other handle");
         end;
         Assert
           (Registration_Failures = 14 and then Close_Failures = 9,
            "handle failure atomicity coverage");
         Ada.Text_IO.Put_Line ("handle failure atomicity: 23 rejected calls passed");
      end Test_Handle_Failure_Atomicity;

      procedure Test_Connection_Coordinator is
         Operation, Tree_Operation, Disconnect_Operation,
           Tree_Error_Operation, Logoff_Error_Operation,
           Logoff_Operation, Successful_Disconnect_Operation,
           Authenticated_Logoff_Operation, Abort_Operation,
           Malformed_Operation, Bad_Signature_Operation,
           Bad_Correlation_Operation :
           SMB.Core_Connection.Connection_Operation;
         Rejected_Operation, Bounded_Operation :
           SMB.Core_Connection.Connection_Operation;
         Create_Operation : SMB.Core_Client.Operation;
         Token : SMB.Engine.Handle_Token;
         Guid : constant SMB.Bytes (4 .. 19) :=
           (16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
            16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#);
         Name : constant SMB.Bytes (9 .. 12) := (16#41#, 0, 16#42#, 0);
         Request : SMB.Bytes (0 .. 101) := (others => 0);
         Nonzero_Request : SMB.Bytes (5 .. 80) := (others => 0);
         Short_Request : SMB.Bytes (0 .. 74) := (others => 0);
         Response : SMB.Bytes (0 .. 127) := (others => 0);
         Used : Natural;
         Response_Status : SMB.Core_Status;
         Saved_Key : SMB.Bytes (0 .. 15);
         Checked_Id : SMB.Bytes (0 .. 15);
         Checked_Access : SMB.Engine.Access_Kind;
         Is_Directory : Boolean;
         Saved_State : SMB.Engine.Engine_State;
         Completed_State : SMB.Engine.Engine_State;
         Saved_Connection :
           SMB.Core_Connection.Connection_State_Snapshot;
         Completed_Connection :
           SMB.Core_Connection.Connection_State_Snapshot;
      begin
         SMB.Engine.Initialize (State, Status);
         Assert (Status = SMB.Ok, "connection coordinator initialize");
         SMB.Engine.Mark_Connected (State, Status);
         Assert (Status = SMB.Ok, "connection coordinator transport");
         SMB.Core_Connection.Prepare_Negotiate
           (Operation, State, Guid, Request, Used, Status);
         Assert
           (Status = SMB.Ok and then Used = 102
            and then SMB.Wire.U16 (Request, 12) = 0
            and then SMB.Wire.U16 (Request, 64) = 36
            and then SMB.Wire.U16 (Request, 66) = 1
            and then SMB.Wire.U16 (Request, 68) = 3
            and then SMB.Wire.U16 (Request, 70) = 0
            and then SMB.Wire.U32 (Request, 72) = 0
            and then Request (76 .. 91) = Guid
            and then SMB.Wire.U64 (Request, 92) = 0
            and then SMB.Wire.U16 (Request, 100) = SMB.SMB2_Dialect_0210,
            "connection NEGOTIATE packet fields and GUID");
         SMB.Core_Connection.Send_Succeeded (Operation, State, Status);
         Assert (Status = SMB.Ok, "acknowledge connection NEGOTIATE");
         Response := (others => 0);
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (0),
            SMB.Wire.U64 (Request, 24), 0, 0, False);
         Response (64) := 65;
         Response (66) := 1;
         SMB.Wire.Put_U16 (Response, 68, SMB.SMB2_Dialect_0210);
         SMB.Wire.Put_U32 (Response, 96, 100_000);
         SMB.Wire.Put_U32 (Response, 100, 32_768);
         SMB.Core_Connection.Complete
           (Operation, State, Response, Nt_Status, Response_Status);
         Assert
           (Response_Status = SMB.Ok and then Nt_Status = SMB.Success
            and then SMB.Engine.Current_Phase (State) = SMB.Engine.Negotiated
            and then SMB.Engine.Current_Max_Read (State) = 65_536
            and then SMB.Engine.Current_Max_Write (State) = 32_768,
            "NEGOTIATE response limits are clamped and committed");

         SMB.Engine.Invalidate (State, Status);
         Assert (Status = SMB.Ok, "cleanup negotiated test state");
         Reconnect_Share (State, Connect_Share_State => False);
         Saved_State := State;
         Saved_Connection :=
           SMB.Core_Connection.Snapshot_Of (Rejected_Operation);
         SMB.Core_Connection.Prepare_Tree_Connect
           (Rejected_Operation, State, SMB.Bytes'(1 .. 0 => 0), Request,
            Used, Status);
         Assert
           (Status /= SMB.Ok and then Used = 0
            and then SMB.Engine."=" (State, Saved_State)
            and then SMB.Core_Connection.Snapshot_Of
              (Rejected_Operation) = Saved_Connection,
            "empty TREE_CONNECT name preserves state");
         SMB.Core_Connection.Prepare_Tree_Connect
           (Rejected_Operation, State, SMB.Bytes'(0 => 1), Request, Used,
            Status);
         Assert
           (Status /= SMB.Ok and then Used = 0
            and then SMB.Engine."=" (State, Saved_State)
            and then SMB.Core_Connection.Snapshot_Of
              (Rejected_Operation) = Saved_Connection,
            "odd TREE_CONNECT name preserves state");
         SMB.Core_Connection.Prepare_Tree_Connect
           (Rejected_Operation, State, Name, Short_Request, Used, Status);
         Assert
           (Status /= SMB.Ok and then Used = 0
            and then SMB.Engine."=" (State, Saved_State)
            and then SMB.Core_Connection.Snapshot_Of
              (Rejected_Operation) = Saved_Connection,
            "short TREE_CONNECT output preserves state");
         SMB.Core_Connection.Prepare_Tree_Connect
           (Bounded_Operation, State, Name, Nonzero_Request, Used, Status);
         Assert
           (Status = SMB.Ok
            and then Used = Nonzero_Request'Length
            and then SMB.Wire.U16 (Nonzero_Request, 64) = 9
            and then Nonzero_Request
              (Nonzero_Request'First + 72 .. Nonzero_Request'First + 75) =
                Name,
            "nonzero-bound TREE_CONNECT output preserves packet");
         SMB.Core_Connection.Abort_Connection
           (Bounded_Operation, State, Status);
         Assert (Status = SMB.Ok, "abort nonzero-bound preparation fixture");
         Reconnect_Share (State, Connect_Share_State => False);
         Saved_State := State;
         Saved_Connection :=
           SMB.Core_Connection.Snapshot_Of (Rejected_Operation);
         SMB.Core_Connection.Prepare_Tree_Disconnect
           (Rejected_Operation, State, Request, Used, Status);
         Assert
           (Status /= SMB.Ok and then Used = 0
            and then SMB.Engine."=" (State, Saved_State)
            and then SMB.Core_Connection.Snapshot_Of
              (Rejected_Operation) = Saved_Connection,
            "wrong-phase TREE_DISCONNECT preparation preserves state");
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (3), True, True,
            Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "reserve unrelated connection request");
         Saved_State := State;
         SMB.Core_Connection.Prepare_Tree_Connect
           (Rejected_Operation, State, Name, Request, Used, Status);
         Assert
           (Status /= SMB.Ok and then Used = 0
            and then SMB.Engine."=" (State, Saved_State)
            and then SMB.Core_Connection.Snapshot_Of
              (Rejected_Operation) = Saved_Connection,
            "pending request rejects TREE_CONNECT preparation without damage");
         Response := (others => 0);
         Prepare_Response
           (Response (0 .. 79), SMB.Core_Wire.Command_Code (3),
            Message_Id, Tree_Id, Session_Id, True);
         Response (64) := 16;
         Response (66) := 1;
         SMB.Wire.Sign (Response (0 .. 79), Key);
         SMB.Engine.Accept_Response (State, Response (0 .. 79), Nt_Status,
                                     Status);
         Assert
           (Status = SMB.Ok and then SMB.Engine.Has_Validated_Response (State),
            "raw TREE_CONNECT success creates an unconsumed receipt");
         Saved_State := State;
         Saved_Connection :=
           SMB.Core_Connection.Snapshot_Of (Rejected_Operation);
         SMB.Core_Connection.Prepare_Tree_Connect
           (Rejected_Operation, State, Name, Request, Used, Status);
         Assert
           (Status /= SMB.Ok and then Used = 0
            and then SMB.Engine."=" (State, Saved_State)
            and then SMB.Core_Connection.Snapshot_Of
              (Rejected_Operation) = Saved_Connection,
            "validated receipt rejects TREE_CONNECT preparation");
         SMB.Engine.Discard_Response_Receipt (State, Status);
         SMB.Engine.Invalidate (State, Status);
         Assert (Status = SMB.Ok, "clear pending preparation fixture");
         Reconnect_Share (State, Connect_Share_State => False);
         SMB.Core_Connection.Prepare_Tree_Connect
           (Tree_Error_Operation, State, Name, Request, Used, Status);
         SMB.Core_Connection.Send_Succeeded
           (Tree_Error_Operation, State, Status);
         Response := (others => 0);
         Prepare_Response
           (Response (0 .. 71), SMB.Core_Wire.Command_Code (3),
            SMB.Wire.U64 (Request, 24), Tree_Id, Session_Id, True);
         SMB.Wire.Put_U32 (Response, 8, SMB.Status_Access_Denied);
         Response (64) := 9;
         SMB.Wire.Sign (Response (0 .. 71), Key);
         Saved_Key := SMB.Engine.Current_Signing_Key (State);
         SMB.Core_Connection.Complete
           (Tree_Error_Operation, State, Response (0 .. 71), Nt_Status,
            Response_Status);
         Assert
           (Response_Status = SMB.Ok
            and then Nt_Status = SMB.Status_Access_Denied
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Authenticated
            and then SMB.Engine.Current_Session_Id (State) = Session_Id
            and then SMB.Engine.Current_Tree_Id (State) = 0
            and then SMB.Engine.Current_Signing_Key (State) = Saved_Key
            and then not SMB.Engine.Has_Pending_Request (State)
            and then not SMB.Engine.Has_Validated_Response (State),
            "TREE_CONNECT denial consumes receipt and preserves authentication");
         SMB.Core_Connection.Prepare_Tree_Connect
           (Tree_Operation, State, Name, Request, Used, Status);
         Assert
           (Status = SMB.Ok and then Used = 76
            and then SMB.Wire.U16 (Request, 12) = 3
            and then SMB.Wire.U32 (Request, 16) = 8
            and then SMB.Wire.U16 (Request, 64) = 9
            and then SMB.Wire.U16 (Request, 66) = 0
            and then SMB.Wire.U16 (Request, 68) = 72
            and then SMB.Wire.U16 (Request, 70) = 4
            and then Request (72 .. 75) = Name
            and then SMB.Wire.Verify_Signature
              (Request (Request'First .. Request'First + Used - 1),
               SMB.Engine.Current_Signing_Key (State)),
            "signed TREE_CONNECT preserves nonzero-bound path bytes");
         Response := (others => 0);
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (3),
            SMB.Wire.U64 (Request, 24), Tree_Id, Session_Id, True);
         Response (64) := 16;
         Response (66) := 1;
         SMB.Wire.Sign (Response (0 .. 79), Key);
         Saved_State := State;
         Saved_Connection :=
           SMB.Core_Connection.Snapshot_Of (Tree_Operation);
         SMB.Core_Connection.Complete
           (Tree_Operation, State, Response (0 .. 79), Nt_Status,
            Response_Status);
         Assert
           (Response_Status = SMB.Invalid_State_Status and then Nt_Status = 0
            and then SMB.Engine."=" (State, Saved_State)
            and then SMB.Core_Connection.Snapshot_Of
              (Tree_Operation) = Saved_Connection,
            "TREE_CONNECT completion before send acknowledgement is rejected");
         SMB.Core_Connection.Send_Succeeded
           (Tree_Operation, State, Status);
         Assert (Status = SMB.Ok, "acknowledge TREE_CONNECT");
         SMB.Core_Connection.Complete
           (Tree_Operation, State, Response (0 .. 79), Nt_Status,
            Response_Status);
         Assert
           (Response_Status = SMB.Ok and then Nt_Status = SMB.Success
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Share_Connected
            and then SMB.Engine.Current_Tree_Id (State) = Tree_Id,
            "TREE_CONNECT commits wire tree identifier");
         Completed_State := State;
         Completed_Connection :=
           SMB.Core_Connection.Snapshot_Of (Tree_Operation);
         SMB.Core_Connection.Complete
           (Tree_Operation, State, Response (0 .. 71), Nt_Status,
            Response_Status);
         Assert
           (Response_Status = SMB.Invalid_State_Status and then Nt_Status = 0
            and then SMB.Engine."=" (State, Completed_State)
            and then SMB.Core_Connection.Snapshot_Of
              (Tree_Operation) = Completed_Connection,
            "duplicate TREE_CONNECT completion preserves state");

         Create_Directory_Handle
           (State, Create_Operation, Token, Is_Directory => False);
         Saved_Key := SMB.Engine.Current_Signing_Key (State);
         SMB.Core_Connection.Prepare_Logoff
           (Logoff_Error_Operation, State, Request, Used, Status);
         SMB.Core_Connection.Send_Succeeded
           (Logoff_Error_Operation, State, Status);
         Response := (others => 0);
         Prepare_Response
           (Response (0 .. 71), SMB.Core_Wire.Command_Code (2),
            SMB.Wire.U64 (Request, 24), 0, Session_Id, True);
         SMB.Wire.Put_U32 (Response, 8, SMB.Status_Access_Denied);
         Response (64) := 9;
         SMB.Wire.Sign (Response (0 .. 71), Key);
         SMB.Core_Connection.Complete
           (Logoff_Error_Operation, State, Response (0 .. 71), Nt_Status,
            Response_Status);
         SMB.Engine.Validate_Handle
           (State, Token, False, False, Checked_Id, Checked_Access,
            Is_Directory, Status);
         Assert
           (Response_Status = SMB.Ok
            and then Nt_Status = SMB.Status_Access_Denied
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Share_Connected
            and then SMB.Engine.Current_Session_Id (State) = Session_Id
            and then SMB.Engine.Current_Tree_Id (State) = Tree_Id
            and then SMB.Engine.Current_Signing_Key (State) = Saved_Key
            and then Status = SMB.Ok
            and then Checked_Id = File_Id
            and then Checked_Access = SMB.Engine.Read_Only
            and then not Is_Directory
            and then not SMB.Engine.Has_Pending_Request (State)
            and then not SMB.Engine.Has_Validated_Response (State),
            "LOGOFF denial consumes receipt and preserves handle/context");
         SMB.Core_Connection.Prepare_Tree_Disconnect
           (Disconnect_Operation, State, Request, Used, Status);
         Assert (Status = SMB.Ok and then Used = 68,
                 "prepare TREE_DISCONNECT");
         SMB.Core_Connection.Send_Succeeded
           (Disconnect_Operation, State, Status);
         Response := (others => 0);
         Prepare_Response
           (Response (0 .. 67), SMB.Core_Wire.Command_Code (4),
            SMB.Wire.U64 (Request, 24), Tree_Id, Session_Id, True);
         Response (64) := 9;
         SMB.Wire.Put_U32 (Response, 8, SMB.Status_Access_Denied);
         SMB.Wire.Sign (Response (0 .. 71), Key);
         SMB.Core_Connection.Complete
           (Disconnect_Operation, State, Response (0 .. 71), Nt_Status,
            Response_Status);
         SMB.Engine.Validate_Handle
           (State, Token, False, False, Checked_Id, Checked_Access,
            Is_Directory, Status);
         Assert
           (Response_Status = SMB.Ok and then
              Nt_Status = SMB.Status_Access_Denied
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Share_Connected
            and then SMB.Engine.Current_Session_Id (State) = Session_Id
            and then SMB.Engine.Current_Signing_Key (State) = Saved_Key
            and then SMB.Engine.Current_Tree_Id (State) = Tree_Id
            and then Status = SMB.Ok
            and then Checked_Id = File_Id
            and then Checked_Access = SMB.Engine.Read_Only
            and then not Is_Directory,
            "TREE_DISCONNECT denial consumes receipt and preserves handle");

         SMB.Core_Connection.Prepare_Logoff
           (Logoff_Operation, State, Request, Used, Status);
         Assert (Status = SMB.Ok and then Used = 68,
                 "LOGOFF accepted directly from share-connected");
         SMB.Core_Connection.Send_Succeeded
           (Logoff_Operation, State, Status);
         Response := (others => 0);
         Prepare_Response
           (Response (0 .. 67), SMB.Core_Wire.Command_Code (2),
            SMB.Wire.U64 (Request, 24), 0, Session_Id, True);
         Response (64) := 4;
         SMB.Wire.Sign (Response (0 .. 67), Key);
         SMB.Core_Connection.Complete
           (Logoff_Operation, State, Response (0 .. 67), Nt_Status,
            Response_Status);
         SMB.Engine.Validate_Handle
           (State, Token, False, False, Checked_Id, Checked_Access,
            Is_Directory, Status);
         Assert
           (Response_Status = SMB.Ok and then Nt_Status = SMB.Success
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected
            and then SMB.Engine.Current_Session_Id (State) = 0
            and then SMB.Engine.Current_Tree_Id (State) = 0
            and then SMB.Engine.Signing_Key_Is_Zero (State)
            and then not SMB.Engine.Has_Pending_Request (State)
            and then not SMB.Engine.Has_Validated_Response (State),
           "LOGOFF completion invalidates connection state");
         Assert
           (Status /= SMB.Ok,
            "LOGOFF invalidates open handles");

         Reconnect_Share (State);
         Create_Directory_Handle
           (State, Create_Operation, Token, Is_Directory => False);
         Saved_Key := SMB.Engine.Current_Signing_Key (State);
         SMB.Core_Connection.Prepare_Tree_Disconnect
           (Successful_Disconnect_Operation, State, Request, Used, Status);
         SMB.Core_Connection.Send_Succeeded
           (Successful_Disconnect_Operation, State, Status);
         Response := (others => 0);
         Prepare_Response
           (Response (0 .. 67), SMB.Core_Wire.Command_Code (4),
            SMB.Wire.U64 (Request, 24), Tree_Id, Session_Id, True);
         Response (64) := 4;
         SMB.Wire.Sign (Response (0 .. 67), Key);
         SMB.Core_Connection.Complete
           (Successful_Disconnect_Operation, State, Response (0 .. 67),
            Nt_Status, Response_Status);
         SMB.Engine.Validate_Handle
           (State, Token, False, False, Checked_Id, Checked_Access,
            Is_Directory, Status);
         Assert
           (Response_Status = SMB.Ok and then Nt_Status = SMB.Success
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Authenticated
            and then SMB.Engine.Current_Session_Id (State) = Session_Id
            and then SMB.Engine.Current_Signing_Key (State) = Saved_Key
            and then Status /= SMB.Ok,
            "successful TREE_DISCONNECT retains session/key and clears handles");
         SMB.Core_Connection.Prepare_Logoff
           (Authenticated_Logoff_Operation, State, Request, Used, Status);
         SMB.Core_Connection.Send_Succeeded
           (Authenticated_Logoff_Operation, State, Status);
         Response := (others => 0);
         Prepare_Response
           (Response (0 .. 67), SMB.Core_Wire.Command_Code (2),
            SMB.Wire.U64 (Request, 24), 0, Session_Id, True);
         Response (64) := 4;
         SMB.Wire.Sign (Response (0 .. 67), Key);
         SMB.Core_Connection.Complete
           (Authenticated_Logoff_Operation, State, Response (0 .. 67),
            Nt_Status, Response_Status);
         Assert
           (Response_Status = SMB.Ok and then Nt_Status = SMB.Success
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected
            and then SMB.Engine.Current_Session_Id (State) = 0
            and then SMB.Engine.Current_Tree_Id (State) = 0
            and then SMB.Engine.Signing_Key_Is_Zero (State)
            and then not SMB.Engine.Has_Pending_Request (State)
            and then not SMB.Engine.Has_Validated_Response (State),
           "normal LOGOFF follows TREE_DISCONNECT");

         declare
            Owner_Operation, Foreign_Operation, Fresh_Operation :
              SMB.Core_Connection.Connection_Operation;
            Owner_Packet, Foreign_Packet, Fresh_Packet :
              SMB.Bytes (0 .. 101) := (others => 0);
            Owner_Used, Foreign_Used, Fresh_Used : Natural;
            Owner_Id, Owner_Epoch : SMB.QWord;
            Owner_State_Before, Foreign_State_Before :
              SMB.Engine.Engine_State;
            Fresh_State_Before : SMB.Engine.Engine_State;
            Foreign_Connection_Before, Fresh_Connection_Before :
              SMB.Core_Connection.Connection_State_Snapshot;
            Owner_Connection_Before :
              SMB.Core_Connection.Connection_State_Snapshot;
            Owner_Response : SMB.Bytes (0 .. 79) := (others => 0);
         begin
            Reconnect_Share (State, Connect_Share_State => False);
            Reconnect_Share
              (Foreign_State, Connect_Share_State => False);
            Owner_Id := SMB.Engine.Current_Owner_Id (State);
            Owner_Epoch := SMB.Engine.Current_Epoch (State);
            SMB.Core_Connection.Prepare_Tree_Connect
              (Owner_Operation, State, Name, Owner_Packet, Owner_Used, Status);
            SMB.Core_Connection.Prepare_Tree_Connect
              (Foreign_Operation, Foreign_State, Name, Foreign_Packet,
               Foreign_Used, Status);
            Assert
              (Owner_Used = Foreign_Used
               and then SMB.Wire.U64 (Owner_Packet, 24) =
                 SMB.Wire.U64 (Foreign_Packet, 24)
               and then SMB.Engine.Current_Owner_Id (State) /=
                 SMB.Engine.Current_Owner_Id (Foreign_State),
              "foreign connection operations have colliding wire identifiers");
            Owner_State_Before := State;
            Foreign_State_Before := Foreign_State;
            Owner_Connection_Before :=
              SMB.Core_Connection.Snapshot_Of (Owner_Operation);
            Foreign_Connection_Before :=
              SMB.Core_Connection.Snapshot_Of (Foreign_Operation);
            SMB.Core_Connection.Send_Succeeded
              (Owner_Operation, Foreign_State, Status);
            Assert
              (Status = SMB.Invalid_State_Status
               and then SMB.Engine."=" (State, Owner_State_Before)
               and then SMB.Engine."=" (Foreign_State, Foreign_State_Before)
               and then SMB.Core_Connection.Snapshot_Of
                 (Owner_Operation) = Owner_Connection_Before
               and then SMB.Core_Connection.Snapshot_Of
                 (Foreign_Operation) = Foreign_Connection_Before,
              "foreign send rejection preserves both pending requests");
            SMB.Core_Connection.Send_Succeeded
              (Owner_Operation, State, Status);
            Prepare_Response
              (Owner_Response, SMB.Core_Wire.Command_Code (3),
               SMB.Wire.U64 (Owner_Packet, 24), Tree_Id, Session_Id, True);
            Owner_Response (64) := 16;
            Owner_Response (66) := 1;
            SMB.Wire.Sign (Owner_Response, Key);
            Owner_State_Before := State;
            Foreign_State_Before := Foreign_State;
            Owner_Connection_Before :=
              SMB.Core_Connection.Snapshot_Of (Owner_Operation);
            SMB.Core_Connection.Complete
              (Owner_Operation, Foreign_State, Owner_Response, Nt_Status,
               Response_Status);
            Assert
              (Response_Status = SMB.Invalid_State_Status
               and then SMB.Engine."=" (State, Owner_State_Before)
               and then SMB.Engine."=" (Foreign_State, Foreign_State_Before)
               and then SMB.Core_Connection.Snapshot_Of
                 (Owner_Operation) = Owner_Connection_Before
               and then SMB.Core_Connection.Snapshot_Of
                 (Foreign_Operation) = Foreign_Connection_Before,
              "foreign completion preserves colliding pending requests");
            SMB.Core_Connection.Abort_Connection
              (Owner_Operation, Foreign_State, Status);
            Assert
               (Status = SMB.Invalid_State_Status
               and then SMB.Engine."=" (Foreign_State, Foreign_State_Before)
               and then SMB.Core_Connection.Snapshot_Of
                 (Owner_Operation) = Owner_Connection_Before
               and then SMB.Core_Connection.Snapshot_Of
                 (Foreign_Operation) = Foreign_Connection_Before,
              "foreign abort preserves colliding pending request");

            SMB.Engine.Invalidate (State, Status);
            Assert (Status = SMB.Ok, "invalidate sent operation epoch");
            Reconnect_Share
              (State, Initialize_State => False,
               Connect_Share_State => False);
            SMB.Core_Connection.Prepare_Tree_Connect
              (Fresh_Operation, State, Name, Fresh_Packet, Fresh_Used, Status);
            Assert
              (SMB.Engine.Current_Owner_Id (State) = Owner_Id
               and then SMB.Engine.Current_Epoch (State) /= Owner_Epoch
               and then SMB.Wire.U64 (Fresh_Packet, 24) =
                 SMB.Wire.U64 (Owner_Packet, 24),
              "stale operation collides with current message ID in new epoch");
            Fresh_State_Before := State;
            Fresh_Connection_Before :=
              SMB.Core_Connection.Snapshot_Of (Fresh_Operation);
            Owner_Connection_Before :=
              SMB.Core_Connection.Snapshot_Of (Owner_Operation);
            SMB.Core_Connection.Complete
              (Owner_Operation, State, Owner_Response, Nt_Status,
               Response_Status);
            Assert
              (Response_Status = SMB.Invalid_State_Status
               and then SMB.Engine."=" (State, Fresh_State_Before)
               and then SMB.Core_Connection.Snapshot_Of
                 (Owner_Operation) = Owner_Connection_Before
               and then SMB.Core_Connection.Snapshot_Of
                 (Fresh_Operation) = Fresh_Connection_Before,
              "stale completion preserves new live connection request");
            SMB.Core_Connection.Abort_Connection
              (Owner_Operation, State, Status);
            Assert
               (Status = SMB.Invalid_State_Status
               and then SMB.Engine."=" (State, Fresh_State_Before)
               and then SMB.Core_Connection.Snapshot_Of
                 (Owner_Operation) = Owner_Connection_Before
               and then SMB.Core_Connection.Snapshot_Of
                 (Fresh_Operation) = Fresh_Connection_Before,
              "stale abort preserves new live connection request");
            SMB.Core_Connection.Abort_Connection
              (Fresh_Operation, State, Status);
            SMB.Core_Connection.Abort_Connection
              (Foreign_Operation, Foreign_State, Status);
         end;

         declare
            Wrong_Pending_Operation :
              SMB.Core_Connection.Connection_Operation;
            Wrong_Pending_Packet : SMB.Bytes (0 .. 75) := (others => 0);
            Wrong_Pending_Response : SMB.Bytes (0 .. 79) := (others => 0);
            Wrong_Pending_Id : SMB.QWord;
            Wrong_Pending_Expected : SMB.Engine.Request_Expectation;
            Wrong_Pending_State : SMB.Engine.Engine_State;
            Wrong_Pending_Connection :
              SMB.Core_Connection.Connection_State_Snapshot;
         begin
            Reconnect_Share (State, Connect_Share_State => False);
            SMB.Core_Connection.Prepare_Tree_Connect
              (Wrong_Pending_Operation, State, Name, Wrong_Pending_Packet,
               Used, Status);
            Assert (Status = SMB.Ok, "prepare wrong-pending fixture");
            SMB.Core_Connection.Send_Succeeded
              (Wrong_Pending_Operation, State, Status);
            Prepare_Response
              (Wrong_Pending_Response, SMB.Core_Wire.Command_Code (3),
               SMB.Wire.U64 (Wrong_Pending_Packet, 24), Tree_Id, Session_Id,
               True);
            Wrong_Pending_Response (64) := 16;
            Wrong_Pending_Response (66) := 1;
            SMB.Wire.Sign (Wrong_Pending_Response, Key);
            SMB.Engine.Accept_Response
              (State, Wrong_Pending_Response, Nt_Status, Status);
            Assert
              (Status = SMB.Ok and then SMB.Engine.Has_Validated_Response (State),
               "accept raw response before replacing pending expectation");
            SMB.Engine.Discard_Response_Receipt (State, Status);
            Assert (Status = SMB.Ok, "discard wrong-pending fixture receipt");
            SMB.Engine.Begin_Request
              (State, SMB.Core_Wire.Command_Code (3), True, True,
               Wrong_Pending_Id, Wrong_Pending_Expected, Status);
            Assert (Status = SMB.Ok, "begin unrelated pending request");
            Wrong_Pending_State := State;
            Wrong_Pending_Connection :=
              SMB.Core_Connection.Snapshot_Of (Wrong_Pending_Operation);
            SMB.Core_Connection.Complete
              (Wrong_Pending_Operation, State, Wrong_Pending_Response,
               Nt_Status, Response_Status);
            Assert
              (Response_Status = SMB.Invalid_State_Status
               and then Nt_Status = 0
               and then SMB.Engine."=" (State, Wrong_Pending_State)
               and then SMB.Core_Connection.Snapshot_Of
                 (Wrong_Pending_Operation) = Wrong_Pending_Connection,
              "wrong pending expectation rejects completion without damage");
            SMB.Core_Connection.Abort_Connection
              (Wrong_Pending_Operation, State, Status);
            Assert
              (Status = SMB.Invalid_State_Status
               and then SMB.Engine."=" (State, Wrong_Pending_State)
               and then SMB.Core_Connection.Snapshot_Of
                 (Wrong_Pending_Operation) = Wrong_Pending_Connection,
              "wrong pending expectation rejects abort without damage");
            SMB.Engine.Invalidate (State, Status);
            Assert (Status = SMB.Ok, "clear wrong-pending fixture state");
         end;

         Reconnect_Share (State);
         SMB.Core_Connection.Prepare_Tree_Disconnect
           (Abort_Operation, State, Request, Used, Status);
         SMB.Core_Connection.Abort_Connection
           (Abort_Operation, State, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected
            and then SMB.Core_Connection.Stage_Of (Abort_Operation) =
              SMB.Core_Connection.Failed,
            "matching TREE_DISCONNECT abort invalidates locally");

         Reconnect_Share (State);
         SMB.Core_Connection.Prepare_Tree_Disconnect
           (Malformed_Operation, State, Request, Used, Status);
         SMB.Core_Connection.Send_Succeeded
           (Malformed_Operation, State, Status);
         Response := (others => 0);
         Prepare_Response
           (Response (0 .. 67), SMB.Core_Wire.Command_Code (4),
            SMB.Wire.U64 (Request, 24), Tree_Id, Session_Id, True);
         SMB.Wire.Put_U16 (Response, 64, 5);
         SMB.Wire.Sign (Response (0 .. 67), Key);
         SMB.Core_Connection.Complete
           (Malformed_Operation, State, Response (0 .. 67), Nt_Status,
            Response_Status);
         Assert
           (Response_Status = SMB.Invalid_Protocol and then Nt_Status = 0
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected
            and then SMB.Core_Connection.Stage_Of (Malformed_Operation) =
              SMB.Core_Connection.Failed,
            "malformed signed TREE_DISCONNECT fails without retry");

         Reconnect_Share (State);
         SMB.Core_Connection.Prepare_Tree_Disconnect
           (Bad_Signature_Operation, State, Request, Used, Status);
         SMB.Core_Connection.Send_Succeeded
           (Bad_Signature_Operation, State, Status);
         Response := (others => 0);
         Prepare_Response
           (Response (0 .. 67), SMB.Core_Wire.Command_Code (4),
            SMB.Wire.U64 (Request, 24), Tree_Id, Session_Id, True);
         Response (64) := 4;
         SMB.Wire.Sign (Response (0 .. 67), Key);
         Response (48) := Response (48) xor 1;
         SMB.Core_Connection.Complete
           (Bad_Signature_Operation, State, Response (0 .. 67), Nt_Status,
            Response_Status);
         Assert
           (Response_Status = SMB.Signature_Error and then Nt_Status = 0
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected
            and then SMB.Core_Connection.Stage_Of
              (Bad_Signature_Operation) = SMB.Core_Connection.Failed,
            "bad TREE_DISCONNECT signature invalidates locally");

         Reconnect_Share (State);
         SMB.Core_Connection.Prepare_Tree_Disconnect
           (Bad_Correlation_Operation, State, Request, Used, Status);
         SMB.Core_Connection.Send_Succeeded
           (Bad_Correlation_Operation, State, Status);
         Response := (others => 0);
         Prepare_Response
           (Response (0 .. 67), SMB.Core_Wire.Command_Code (4),
            SMB.Wire.U64 (Request, 24), Tree_Id, Session_Id, True);
         Response (64) := 4;
         SMB.Wire.Sign (Response (0 .. 67), Key);
         SMB.Wire.Put_U64 (Response, 24, SMB.Wire.U64 (Request, 24) + 1);
         SMB.Wire.Sign (Response (0 .. 67), Key);
         SMB.Core_Connection.Complete
           (Bad_Correlation_Operation, State, Response (0 .. 67), Nt_Status,
            Response_Status);
         Assert
           (Response_Status /= SMB.Ok and then Nt_Status = 0
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected
            and then SMB.Core_Connection.Stage_Of
              (Bad_Correlation_Operation) = SMB.Core_Connection.Failed,
            "bad TREE_DISCONNECT correlation invalidates locally");
         SMB.Engine.Invalidate (State, Status);
      end Test_Connection_Coordinator;

      procedure Test_Connection_Edges is
         Guid : constant SMB.Bytes (0 .. 15) := (others => 16#5A#);
         Name : constant SMB.Bytes (0 .. 3) := (16#41#, 0, 16#42#, 0);
         Negotiate, Second_Negotiate, Tree_One, Disconnect :
           SMB.Core_Connection.Connection_Operation;
         Request : SMB.Bytes (0 .. 101);
         Response : SMB.Bytes (0 .. 127);
         Used : Natural;
         Response_Status : SMB.Core_Status;
      begin
         SMB.Engine.Initialize (State, Status);
         SMB.Engine.Mark_Connected (State, Status);
         Request := (others => 16#EE#);
         SMB.Core_Connection.Prepare_Negotiate
           (Negotiate, State, Guid, Request, Used, Status);
         Assert
           (Status = SMB.Ok and then Used = 102
            and then (for all Index in 48 .. 63 => Request (Index) = 0),
            "unsigned NEGOTIATE carries no signature");
         SMB.Core_Connection.Send_Succeeded (Negotiate, State, Status);
         Response := (others => 0);
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (0),
            SMB.Wire.U64 (Request, 24), 0, 0, False);
         Response (64) := 65;
         Response (66) := 1;
         SMB.Wire.Put_U16 (Response, 68, SMB.SMB2_Dialect_0210);
         SMB.Wire.Put_U32 (Response, 96, 65_536);
         SMB.Wire.Put_U32 (Response, 100, 65_536);
         SMB.Core_Connection.Complete
           (Negotiate, State, Response, Nt_Status, Response_Status);
         Assert (Response_Status = SMB.Ok, "edge NEGOTIATE completes");
         --  A connection negotiates once, and a rejected preparation leaves
         --  nothing of the caller's buffer behind.
         Request := (others => 16#EE#);
         SMB.Core_Connection.Prepare_Negotiate
           (Second_Negotiate, State, Guid, Request, Used, Status);
         Assert
           (Status = SMB.Invalid_State_Status and then Used = 0
            and then (for all Byte of Request => Byte = 0),
            "second NEGOTIATE is rejected and clears the output");
         SMB.Engine.Invalidate (State, Status);

         --  Tree id 1 is a tree id like any other.
         Reconnect_Share (State, Connect_Share_State => False);
         Request := (others => 16#EE#);
         SMB.Core_Connection.Prepare_Tree_Connect
           (Tree_One, State, SMB.Bytes'(0 => 1), Request, Used, Status);
         Assert
           (Status = SMB.Invalid_Length and then Used = 0
            and then (for all Byte of Request => Byte = 0),
            "odd TREE_CONNECT name clears the output");
         SMB.Core_Connection.Prepare_Tree_Connect
           (Tree_One, State, Name, Request (0 .. 74), Used, Status);
         Assert
           (Status = SMB.Resource_Limit and then Used = 0,
            "TREE_CONNECT output one byte short");
         SMB.Core_Connection.Prepare_Tree_Connect
           (Tree_One, State, Name, Request, Used, Status);
         SMB.Core_Connection.Send_Succeeded (Tree_One, State, Status);
         Response := (others => 0);
         Prepare_Response
           (Response (0 .. 79), SMB.Core_Wire.Command_Code (3),
            SMB.Wire.U64 (Request, 24), 1, Session_Id, True);
         Response (64) := 16;
         Response (66) := 1;
         SMB.Wire.Sign (Response (0 .. 79), Key);
         SMB.Core_Connection.Complete
           (Tree_One, State, Response (0 .. 79), Nt_Status, Response_Status);
         Assert
           (Response_Status = SMB.Ok
            and then SMB.Engine.Current_Tree_Id (State) = 1,
            "TREE_CONNECT to tree id 1");
         SMB.Core_Connection.Prepare_Tree_Disconnect
           (Disconnect, State, Request, Used, Status);
         Assert (Status = SMB.Ok, "TREE_DISCONNECT of tree id 1");
         SMB.Core_Connection.Abort_Connection (Disconnect, State, Status);
         SMB.Engine.Invalidate (State, Status);
      end Test_Connection_Edges;

      procedure Test_Directory_Coordinator is
         Directory_A, Directory_B :
           SMB.Core_Client.Directory_Enumeration;
         Zero_Directory, Error_Directory, Malformed_Directory,
           Bad_Signature_Directory :
           SMB.Core_Client.Directory_Enumeration;
         Query_A, Query_B : SMB.Bytes (0 .. 97) := (others => 0);
         Response : SMB.Bytes (0 .. 291) := (others => 0);
         Second_Response : SMB.Bytes (0 .. 177) := (others => 0);
         Terminal_Response : SMB.Bytes (0 .. 71) := (others => 0);
         Page_One : SMB.Bytes (0 .. 219) := (others => 0);
         Page_Two : SMB.Bytes (0 .. 105) := (others => 0);
         Bad_Page : SMB.Bytes (0 .. 105) := (others => 0);
         Short_Name : SMB.Bytes (0 .. 0) := (others => 0);
         Name : SMB.Bytes (0 .. 3) := (others => 0);
         Entry_Info : SMB.Core_Protocol.Directory_Info;
         Used, Name_Used : Natural;
         Owner : SMB.QWord;
         Epoch : SMB.QWord;

         procedure Make_Response
           (Target : SMB.Engine.Engine_State;
            Packet : in out SMB.Bytes;
            Request : SMB.Bytes;
            Page : SMB.Bytes;
            Response_Status : SMB.DWord := SMB.Success)
         is
            Key_Value : constant SMB.Bytes :=
              SMB.Engine.Current_Signing_Key (Target);
         begin
            Prepare_Response
              (Packet, SMB.Core_Wire.Command_Code (14),
               SMB.Wire.U64 (Request, 24), Tree_Id, Session_Id, True);
            SMB.Wire.Put_U32 (Packet, 8, Response_Status);
            SMB.Wire.Put_U16 (Packet, 64, 9);
            SMB.Wire.Put_U16
              (Packet, 66, (if Page'Length = 0 then 0 else 72));
            SMB.Wire.Put_U32 (Packet, 68, SMB.DWord (Page'Length));
            if Page'Length > 0 then
               Packet (72 .. 72 + Page'Length - 1) := Page;
            end if;
            SMB.Wire.Sign (Packet, Key_Value);
         end Make_Response;

         procedure Prepare_Directory_Request
           (Value : in out SMB.Core_Client.Directory_Enumeration;
            Target : in out SMB.Engine.Engine_State;
            Packet : in out SMB.Bytes)
         is
         begin
            SMB.Core_Client.Prepare_Directory_Query
              (Value, Target, Packet, Used, Status);
            Assert
              (Status = SMB.Ok and then Used = 98
               and then SMB.Wire.U16 (Packet, 12) = 14
               and then SMB.Wire.U64 (Packet, 24) > 0
               and then Packet (67) = 1
               and then Packet (72 .. 87) = File_Id
               and then SMB.Wire.U32 (Packet, 92) = 65_536
               and then SMB.Wire.Verify_Signature
                 (Packet, SMB.Engine.Current_Signing_Key (Target)),
               "signed first QUERY_DIRECTORY request fields");
         end Prepare_Directory_Request;
      begin
         Page_One (0 .. 3) := (112, 0, 0, 0);
         Page_One (60 .. 63) := (2, 0, 0, 0);
         Page_One (104 .. 105) := (97, 0);
         Page_One (112 + 60 .. 112 + 63) := (4, 0, 0, 0);
         Page_One (112 + 104 .. 112 + 107) := (98, 0, 99, 0);
         SMB.Wire.Put_U64 (Page_One, 40, 123);
         SMB.Wire.Put_U32 (Page_One, 56, 16#20#);
         SMB.Wire.Put_U64 (Page_One, 112 + 40, 456);
         SMB.Wire.Put_U32 (Page_One, 112 + 56, 16#10#);
         Page_Two (60 .. 63) := (2, 0, 0, 0);
         Page_Two (104 .. 105) := (100, 0);
         SMB.Wire.Put_U64 (Page_Two, 40, 789);
         SMB.Wire.Put_U32 (Page_Two, 56, 16#20#);
         Reconnect_Share (State);
         Reconnect_Share (Foreign_State);
         Create_Directory_Handle (State, Directory_Create, Directory_Token);
         Create_Directory_Handle
           (Foreign_State, Foreign_Create, Foreign_Token);
         SMB.Core_Client.Start_Directory
           (Directory_A, State, Directory_Token, Status);
         Assert (Status = SMB.Ok, "start first directory coordinator");
         SMB.Core_Client.Start_Directory
           (Directory_B, Foreign_State, Foreign_Token, Status);
         Assert (Status = SMB.Ok, "start colliding directory coordinator");

         Prepare_Directory_Request (Directory_A, State, Query_A);
         Prepare_Directory_Request (Directory_B, Foreign_State, Query_B);
         Assert (Query_A = Query_B, "directory expectations did not collide");
         Make_Response (Foreign_State, Response, Query_B, Page_One);
         SMB.Core_Client.Complete_Directory_Page
           (Directory_A, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine.Has_Pending_Request (State)
            and then SMB.Core_Client.Directory_Stage_Of (Directory_A) =
              SMB.Core_Client.Query_Prepared,
           "directory completion before send acknowledgement advanced");
         SMB.Core_Client.Directory_Send_Succeeded
           (Directory_A, State, Status);
         Assert (Status = SMB.Ok, "acknowledge first directory query");
         SMB.Core_Client.Directory_Send_Succeeded
           (Directory_B, Foreign_State, Status);
         Assert (Status = SMB.Ok, "acknowledge colliding directory query");
         SMB.Core_Client.Complete_Directory_Page
           (Directory_A, Foreign_State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine.Has_Pending_Request (Foreign_State)
            and then SMB.Engine.Has_Signing_Key (Foreign_State)
            and then SMB.Core_Client.Directory_Stage_Of (Directory_A) =
              SMB.Core_Client.Query_Sent,
           "foreign directory completion consumed colliding response");
         SMB.Core_Client.Abort_Directory
           (Directory_A, Foreign_State, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine.Has_Pending_Request (Foreign_State)
            and then SMB.Engine.Has_Signing_Key (Foreign_State),
           "foreign directory abort invalidated matching Engine");

         SMB.Core_Client.Complete_Directory_Page
           (Directory_A, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Core_Client.Directory_Stage_Of (Directory_A) =
              SMB.Core_Client.Page_Ready,
           "complete first directory page");
         SMB.Core_Client.Complete_Directory_Page
           (Directory_A, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Core_Client.Directory_Stage_Of (Directory_A) =
              SMB.Core_Client.Page_Ready,
           "duplicate directory page completion advanced");
         SMB.Core_Client.Complete_Directory_Page
           (Directory_B, Foreign_State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Core_Client.Directory_Stage_Of (Directory_B) =
              SMB.Core_Client.Page_Ready,
           "complete colliding directory page");
         SMB.Core_Client.Prepare_Directory_Query
           (Directory_A, State, Query_A, Used, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then not SMB.Engine.Has_Pending_Request (State),
           "query prepared before page drain");
         Response := (others => 0);

         SMB.Core_Client.Next_Directory_Entry
           (Directory_A, State, Name, Name_Used, Entry_Info, Status);
         Assert
           (Status = SMB.Ok and then Name (0 .. 1) = SMB.Bytes'(97, 0)
            and then Entry_Info.Size = 123,
           "owned page snapshot changed with caller packet");
         SMB.Core_Client.Next_Directory_Entry
           (Directory_B, State, Name, Name_Used, Entry_Info, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Core_Client.Directory_Cursor_Of (Directory_B) = 0
            and then SMB.Engine.Has_Signing_Key (State),
           "foreign directory entry extraction advanced");

         SMB.Core_Client.Next_Directory_Entry
           (Directory_B, Foreign_State, Short_Name, Name_Used,
            Entry_Info, Status);
         Assert
           (Status = SMB.Resource_Limit
            and then Name_Used = 0
            and then SMB.Core_Client.Directory_Cursor_Of (Directory_B) = 0
            and then SMB.Core_Client.Directory_Entry_Count_Of (Directory_B) = 0,
           "short directory name buffer advanced page");
         SMB.Core_Client.Next_Directory_Entry
           (Directory_B, Foreign_State, Name, Name_Used, Entry_Info, Status);
         Assert
           (Status = SMB.Ok and then Name_Used = 2
            and then Name (0 .. 1) = SMB.Bytes'(97, 0)
            and then Entry_Info.Size = 123
            and then Entry_Info.Attributes = 16#20#,
           "directory snapshot first entry");
         SMB.Core_Client.Next_Directory_Entry
           (Directory_B, Foreign_State, Name, Name_Used, Entry_Info, Status);
         Assert
           (Status = SMB.Ok and then Name_Used = 4
            and then Name = SMB.Bytes'(98, 0, 99, 0)
            and then Entry_Info.Size = 456
            and then Entry_Info.Attributes = 16#10#,
           "directory snapshot second entry");
         Assert
           (SMB.Core_Client.Directory_Stage_Of (Directory_B) =
              SMB.Core_Client.Query_Ready,
           "directory page did not drain");
         SMB.Core_Client.Prepare_Directory_Query
           (Directory_B, Foreign_State, Query_B, Used, Status);
         Assert
           (Status = SMB.Ok and then Used = 98 and then Query_B (67) = 0
            and then SMB.Wire.Verify_Signature
              (Query_B, SMB.Engine.Current_Signing_Key (Foreign_State)),
           "second QUERY_DIRECTORY restart or signature");
         SMB.Core_Client.Directory_Send_Succeeded
           (Directory_B, Foreign_State, Status);
         Assert (Status = SMB.Ok, "acknowledge second directory query");
         Make_Response (Foreign_State, Second_Response, Query_B, Page_Two);
         SMB.Core_Client.Complete_Directory_Page
           (Directory_B, Foreign_State, Second_Response, Nt_Status, Status);
         Assert (Status = SMB.Ok, "complete second directory page");
         SMB.Core_Client.Next_Directory_Entry
           (Directory_B, Foreign_State, Name, Name_Used, Entry_Info, Status);
         Assert
           (Status = SMB.Ok and then Name (0 .. 1) = SMB.Bytes'(100, 0)
            and then Entry_Info.Size = 789,
           "second-page directory entry");
         SMB.Core_Client.Prepare_Directory_Query
           (Directory_B, Foreign_State, Query_B, Used, Status);
         Assert (Status = SMB.Ok and then Query_B (67) = 0,
                 "terminal QUERY_DIRECTORY restart flag");
         SMB.Core_Client.Directory_Send_Succeeded
           (Directory_B, Foreign_State, Status);
         Assert (Status = SMB.Ok, "acknowledge terminal directory query");
         Make_Response
           (Foreign_State, Terminal_Response, Query_B, Page_Two (1 .. 0),
            SMB.Status_No_More_Files);
         SMB.Core_Client.Complete_Directory_Page
           (Directory_B, Foreign_State, Terminal_Response, Nt_Status, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status = SMB.Status_No_More_Files
            and then SMB.Core_Client.Directory_Stage_Of (Directory_B) =
              SMB.Core_Client.Directory_Finished
            and then not SMB.Engine.Has_Pending_Request (Foreign_State)
            and then not SMB.Engine.Has_Validated_Response (Foreign_State),
           "No_More_Files directory terminal");

         SMB.Core_Client.Start_Directory
           (Zero_Directory, Foreign_State, Foreign_Token, Status);
         Assert (Status = SMB.Ok, "start zero-data directory enumeration");
         SMB.Core_Client.Prepare_Directory_Query
           (Zero_Directory, Foreign_State, Query_B, Used, Status);
         SMB.Core_Client.Directory_Send_Succeeded
           (Zero_Directory, Foreign_State, Status);
         Make_Response
           (Foreign_State, Terminal_Response, Query_B, Page_Two (1 .. 0));
         SMB.Core_Client.Complete_Directory_Page
           (Zero_Directory, Foreign_State, Terminal_Response,
            Nt_Status, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status = SMB.Success
            and then SMB.Core_Client.Directory_Stage_Of (Zero_Directory) =
              SMB.Core_Client.Directory_Finished,
           "zero-data directory terminal");

         SMB.Core_Client.Start_Directory
           (Error_Directory, Foreign_State, Foreign_Token, Status);
         SMB.Core_Client.Prepare_Directory_Query
           (Error_Directory, Foreign_State, Query_B, Used, Status);
         SMB.Core_Client.Directory_Send_Succeeded
           (Error_Directory, Foreign_State, Status);
         Make_Response
           (Foreign_State, Terminal_Response, Query_B, Page_Two (1 .. 0),
            16#C000_0022#);
         SMB.Core_Client.Complete_Directory_Page
           (Error_Directory, Foreign_State, Terminal_Response,
            Nt_Status, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status = 16#C000_0022#
            and then SMB.Core_Client.Directory_Stage_Of (Error_Directory) =
              SMB.Core_Client.Directory_Finished
            and then SMB.Engine.Has_Signing_Key (Foreign_State)
            and then not SMB.Engine.Has_Pending_Request (Foreign_State),
           "valid directory NT error did not preserve healthy Engine");

         SMB.Core_Client.Start_Directory
           (Malformed_Directory, Foreign_State, Foreign_Token, Status);
         SMB.Core_Client.Prepare_Directory_Query
           (Malformed_Directory, Foreign_State, Query_B, Used, Status);
         SMB.Core_Client.Directory_Send_Succeeded
           (Malformed_Directory, Foreign_State, Status);
         Bad_Page (0 .. 3) := (1, 0, 0, 0);
         Bad_Page (60 .. 63) := (2, 0, 0, 0);
         Bad_Page (104 .. 105) := (120, 0);
         Make_Response (Foreign_State, Second_Response, Query_B, Bad_Page);
         SMB.Core_Client.Complete_Directory_Page
           (Malformed_Directory, Foreign_State, Second_Response,
            Nt_Status, Status);
         SMB.Core_Client.Next_Directory_Entry
           (Malformed_Directory, Foreign_State, Name, Name_Used,
            Entry_Info, Status);
         Assert
           (Status /= SMB.Ok
            and then SMB.Engine.Current_Phase (Foreign_State) =
              SMB.Engine.Disconnected
            and then SMB.Engine.Signing_Key_Is_Zero (Foreign_State)
            and then not SMB.Engine.Has_Pending_Request (Foreign_State)
            and then not SMB.Engine.Has_Validated_Response (Foreign_State),
           "malformed directory record did not invalidate Engine");

         Owner := SMB.Engine.Current_Owner_Id (State);
         Epoch := SMB.Engine.Current_Epoch (State);
         SMB.Engine.Invalidate (State, Status);
         Assert (Status = SMB.Ok, "invalidate stale directory context");
         Reconnect_Share (State, Initialize_State => False);
         Create_Directory_Handle (State, Directory_Create, Directory_Token);
         SMB.Core_Client.Abort_Directory (Directory_A, State, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine.Current_Owner_Id (State) = Owner
            and then SMB.Engine.Current_Epoch (State) /= Epoch
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Share_Connected
            and then SMB.Engine.Has_Signing_Key (State),
           "stale directory abort affected same-owner reconnected Engine");

         SMB.Core_Client.Start_Directory
           (Bad_Signature_Directory, State, Directory_Token, Status);
         SMB.Core_Client.Prepare_Directory_Query
           (Bad_Signature_Directory, State, Query_A, Used, Status);
         SMB.Core_Client.Directory_Send_Succeeded
           (Bad_Signature_Directory, State, Status);
         Make_Response (State, Second_Response, Query_A, Page_Two);
         Second_Response (48) := Second_Response (48) xor 1;
         SMB.Core_Client.Complete_Directory_Page
           (Bad_Signature_Directory, State, Second_Response,
            Nt_Status, Status);
         Assert
           (Status = SMB.Signature_Error
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected
            and then SMB.Engine.Signing_Key_Is_Zero (State)
            and then not SMB.Engine.Has_Pending_Request (State),
           "tampered directory response did not invalidate Engine");
      end Test_Directory_Coordinator;

      procedure Create_Transfer_Handle is
         Response : SMB.Bytes (0 .. 151) := (others => 0);
      begin
         SMB.Core_Client.Prepare_Create
           (Coordinator, State, SMB.Bytes'(0, 0), SMB.Engine.Read_Write,
            False, 1, False, Coordinator_Packet, Coordinator_Used, Status);
         Assert (Status = SMB.Ok, "prepare transfer test handle");
         SMB.Core_Client.Send_Succeeded (Coordinator, State, Status);
         Assert (Status = SMB.Ok, "acknowledge transfer test CREATE");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (5),
            SMB.Wire.U64 (Coordinator_Packet, 24),
            Tree_Id, Session_Id, True);
         Response (64) := 89;
         Response (128 .. 143) := File_Id;
         SMB.Wire.Sign (Response, Key);
         SMB.Core_Client.Complete
           (Coordinator, State, Response, Nt_Status,
            Coordinator_Token, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status = SMB.Success,
            "complete transfer test CREATE");
      end Create_Transfer_Handle;

      function Rejects_Negotiation return Boolean is
      begin
         SMB.Engine.Mark_Negotiated (State, 65_536, 65_536, Status);
         return Status /= SMB.Ok;
      end Rejects_Negotiation;

      function Rejects_Authentication return Boolean is
      begin
         SMB.Engine.Mark_Authenticated (State, Status);
         return Status /= SMB.Ok;
      end Rejects_Authentication;

      function Rejects_Tree_Connection return Boolean is
      begin
         SMB.Engine.Mark_Share_Connected (State, 1, Status);
         return Status /= SMB.Ok;
      end Rejects_Tree_Connection;

      function Rejects_Handle_Registration return Boolean is
      begin
         SMB.Engine.Register_Handle
           (State, File_Id, SMB.Engine.Read_Only, False, Token, Status);
         return Status /= SMB.Ok;
      end Rejects_Handle_Registration;
   begin
      SMB.Engine.Initialize (State, Status);
      Assert (Status = SMB.Ok, "engine initialization");
      SMB.Engine.Mark_Connected (State, Status);
      Assert (Status = SMB.Ok, "engine transport transition");
      SMB.Core_Client.Prepare_Close
        (Coordinator, State, (Owner => 0, Epoch => 0, Ticket => 1),
         Coordinator_Packet, Coordinator_Used, Status);
      Assert
        (Status /= SMB.Ok and then not SMB.Engine.Has_Pending_Request (State),
         "stale coordinator CLOSE token accepted");
      SMB.Core_Client.Prepare_Close
        (Coordinator, State,
         (Owner => SMB.Engine.Current_Owner_Id (State) + 1,
          Epoch => SMB.Engine.Current_Epoch (State), Ticket => 1),
         Coordinator_Packet, Coordinator_Used, Status);
      Assert
        (Status /= SMB.Ok and then not SMB.Engine.Has_Pending_Request (State),
         "foreign coordinator CLOSE token accepted");
      SMB.Engine.Install_Session_Key (State, Session_Id, Key, Status);
      Assert (Status /= SMB.Ok, "session key installed without a receipt");
      SMB.Engine.Close_Handle (State, Token, Status);
      Assert (Status /= SMB.Ok, "handle closed without a matching receipt");

      SMB.Engine.Initialize (State, Status);
      Assert
        (Status /= SMB.Ok
         and then SMB.Engine.Current_Phase (State) =
           SMB.Engine.Transport_Connected,
         "engine reinitialized an active connection");

      Assert (Rejects_Negotiation, "negotiation without receipt accepted");
      Assert (Rejects_Authentication, "authentication without receipt accepted");
      Assert (Rejects_Tree_Connection, "tree connection without receipt accepted");
      Assert (Rejects_Handle_Registration, "handle registration without receipt accepted");

      for Index in Key'Range loop
         Key (Index) := SMB.Byte (Index);
      end loop;
      Test_Request_Metadata;
      Test_Authentication_Atomicity;
      Test_Lifecycle_Atomicity;
      Test_Invalidation_Reset;
      Test_Owner_Allocation;
      Test_Receipt_Transitions;
      Test_Request_Receipt_Preservation;
      Test_Handle_Outcomes;
      Test_Handle_Capacity;
      Test_Handle_Failure_Atomicity;
      declare
         Response : SMB.Bytes (0 .. 127) := (others => 0);
      begin
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (0), False, False,
            Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "begin negotiate request");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (0), Message_Id, 0, 0, False);
         Response (64) := 65;
         Response (66) := 1;
         Response (68) := 16#10#;
         Response (69) := 2;
         Response (98) := 1;
         Response (102) := 1;
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status = SMB.Success,
            "accept negotiate receipt");
         SMB.Engine.Mark_Negotiated (State, 65_536, 65_536, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Engine.Current_Phase (State) = SMB.Engine.Negotiated,
            "consume negotiate receipt");
      end;

      declare
         Response : SMB.Bytes (0 .. 71) := (others => 0);
      begin
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (1), False, False,
            Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "begin challenge request");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (1), Message_Id,
            0, Session_Id, False);
         SMB.Wire.Put_U32
           (Response, 8, SMB.Status_More_Processing_Required);
         Response (64) := 9;
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Ok
            and then Nt_Status = SMB.Status_More_Processing_Required,
            "accept session challenge receipt");
         SMB.Engine.Install_Session_Key
           (State, Session_Id + 1, Key, Status);
         Assert
           (Status /= SMB.Ok
            and then SMB.Engine.Has_Validated_Response (State),
            "challenge receipt accepted with a different session id");
         SMB.Engine.Install_Session_Key (State, Session_Id, Key, Status);
         Assert (Status = SMB.Ok, "consume challenge receipt");
      end;

      declare
         Response : SMB.Bytes (0 .. 100) := (others => 0);
      begin
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (1), False, True,
            Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "begin final session setup request");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (1), Message_Id,
            0, Session_Id, True);
         Response (64) := 9;
         SMB.Wire.Put_U16 (Response, 68, 72);
         SMB.Wire.Put_U16 (Response, 70, Final_Token'Length);
         for Index in Final_Token'Range loop
            Response (72 + Index) := Final_Token (Index);
         end loop;
         SMB.Wire.Sign (Response, Key);
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status = SMB.Success,
            "accept signed final session setup");
         SMB.Engine.Mark_Authenticated (State, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Engine.Current_Phase (State) = SMB.Engine.Authenticated,
            "consume authenticated session receipt once");
      end;

      declare
         Response : SMB.Bytes (0 .. 79) := (others => 0);
      begin
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (3), True, True,
            Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "begin tree connect request");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (3), Message_Id,
            Tree_Id, Session_Id, True);
         Response (64) := 16;
         Response (66) := 1;
         SMB.Wire.Sign (Response, Key);
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert (Status = SMB.Ok, "accept tree connect receipt");
         SMB.Engine.Mark_Share_Connected (State, Tree_Id, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Engine.Current_Phase (State) = SMB.Engine.Share_Connected,
            "consume tree connect receipt");
      end;

      declare
         Response : SMB.Bytes (0 .. 151) := (others => 0);
      begin
         SMB.Core_Client.Prepare_Create
           (Coordinator, State, SMB.Bytes'(0, 0), SMB.Engine.Read_Write,
            True, 3, False, Coordinator_Packet, Coordinator_Used, Status);
         Assert (Status = SMB.Ok, "coordinator CREATE preparation");
         Assert
           (Coordinator_Packet (88 .. 91) =
              SMB.Bytes'
                (SMB.Core_Wire.U32_Byte
                   (SMB.Core_Client.Access_Mask
                      (SMB.Engine.Read_Write, True), 0),
                 SMB.Core_Wire.U32_Byte
                   (SMB.Core_Client.Access_Mask
                      (SMB.Engine.Read_Write, True), 1),
                 SMB.Core_Wire.U32_Byte
                   (SMB.Core_Client.Access_Mask
                      (SMB.Engine.Read_Write, True), 2),
                 SMB.Core_Wire.U32_Byte
                   (SMB.Core_Client.Access_Mask
                      (SMB.Engine.Read_Write, True), 3))
            and then Coordinator_Packet (104) = 16#40#
            and then Coordinator_Packet (100) = 3
            and then SMB.Core_Client.Create_Delete_Access_Of
              (Coordinator)
            and then SMB.Core_Client.Create_Disposition_Of
              (Coordinator) = 3,
            "CREATE wire mask, options, and input metadata");
         SMB.Core_Client.Send_Succeeded (Coordinator, State, Status);
         Assert (Status = SMB.Ok, "coordinator CREATE send acknowledgement");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (5),
            SMB.Wire.U64 (Coordinator_Packet, 24),
            Tree_Id, Session_Id, True);
         Response (64) := 89;
         Response (128 .. 143) := File_Id;
         SMB.Wire.Sign (Response, Key);
         SMB.Core_Client.Complete
           (Coordinator, State, Response, Nt_Status,
            Coordinator_Token, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status = SMB.Success
            and then SMB.Engine.Has_Open_Handles (State),
            "coordinator CREATE completion and handle registration");
         SMB.Engine.Validate_Handle
           (State, Coordinator_Token, False, False, Validated_File_Id,
            Validated_Access, Validated_Directory, Status);
         Assert
           (Status = SMB.Ok
            and then Validated_File_Id = File_Id
            and then Validated_Access = SMB.Engine.Read_Write
            and then not Validated_Directory,
            "CREATE input metadata registered on returned handle");
         declare
            Original : constant SMB.Bytes (1 .. 5) :=
              (16#11#, 16#22#, 16#33#, 16#44#, 16#55#);
            Mutable_Data : SMB.Bytes (11 .. 15) := Original;
            Write_Transfer : SMB.Core_Client.Transfer (5);
            Read_Transfer : SMB.Core_Client.Transfer (5);
            Boundary_Transfer : SMB.Core_Client.Transfer (1);
            Empty_Transfer : SMB.Core_Client.Transfer (0);
            Write_Packet : SMB.Bytes (0 .. 116) := (others => 0);
            Read_Packet : SMB.Bytes (0 .. 112) := (others => 0);
            Write_Response : SMB.Bytes (0 .. 79) := (others => 0);
            Read_Response : SMB.Bytes (0 .. 84) := (others => 0);
            Result : SMB.Bytes (Natural'Last - 4 .. Natural'Last) :=
              (others => 0);
            Invalid_Token : constant SMB.Engine.Handle_Token :=
              (Owner => 0, Epoch => 0, Ticket => 0);
            Used : Natural;
         begin
            SMB.Core_Client.Start_Read
              (Boundary_Transfer, State, Invalid_Token, 0, 1, Status);
            Assert
              (Status = SMB.Invalid_Handle_Status
               and then not SMB.Engine.Has_Pending_Request (State),
               "invalid transfer token reserved a request");
            SMB.Core_Client.Start_Write
              (Boundary_Transfer, State, Coordinator_Token,
               SMB.QWord'Last, SMB.Bytes'(1 => 16#AA#), Status);
            Assert
              (Status = SMB.Invalid_Offset
               and then not SMB.Engine.Has_Pending_Request (State),
               "overflowing transfer range reserved a request");

            SMB.Core_Client.Start_Write
              (Empty_Transfer, State, Coordinator_Token, 0,
               SMB.Bytes'(1 .. 0 => 0), Status);
            Assert
              (Status = SMB.Ok
               and then SMB.Core_Client.Transfer_Stage_Of (Empty_Transfer) =
                 SMB.Core_Client.Transfer_Finished
               and then SMB.Core_Client.Transfer_Completed_Of (Empty_Transfer) = 0
               and then not SMB.Engine.Has_Pending_Request (State),
               "empty WRITE must finish without reserving a request");

            SMB.Core_Client.Start_Write
              (Write_Transfer, State, Coordinator_Token, 100,
               Mutable_Data, Status);
            Assert (Status = SMB.Ok, "transfer WRITE start");
            Mutable_Data := (others => 0);
            SMB.Core_Client.Prepare_Next
              (Write_Transfer, State, Write_Packet, Used, Status);
            Assert
              (Status = SMB.Ok and then Used = 117
               and then Write_Packet (72 .. 79) =
                 SMB.Bytes'(100, 0, 0, 0, 0, 0, 0, 0)
               and then Write_Packet (112 .. 116) = Original,
               "WRITE snapshot and encoded initial offset");
            SMB.Core_Client.Transfer_Send_Succeeded
              (Write_Transfer, State, Status);
            Assert (Status = SMB.Ok, "transfer WRITE send acknowledgement");
            Prepare_Response
              (Write_Response, SMB.Core_Wire.Command_Code (9),
               SMB.Wire.U64 (Write_Packet, 24), Tree_Id, Session_Id, True);
            Write_Response (64) := 17;
            SMB.Wire.Put_U16 (Write_Response, 66, 1);
            SMB.Wire.Put_U32 (Write_Response, 68, 3);
            SMB.Wire.Put_U32 (Write_Response, 72, 1);
            SMB.Wire.Put_U16 (Write_Response, 76, 1);
            SMB.Wire.Put_U16 (Write_Response, 78, 1);
            SMB.Wire.Sign (Write_Response, Key);
            SMB.Core_Client.Complete_Write
              (Write_Transfer, State, Write_Response, Nt_Status, Status);
            Assert
              (Status = SMB.Ok and then Nt_Status = SMB.Success
               and then SMB.Core_Client.Transfer_Completed_Of
                 (Write_Transfer) = 3,
               "reserved WRITE response fields were not ignored");
            SMB.Core_Client.Complete_Write
              (Write_Transfer, State, Write_Response, Nt_Status, Status);
            Assert
              (Status = SMB.Invalid_State_Status
               and then SMB.Core_Client.Transfer_Completed_Of
                 (Write_Transfer) = 3,
               "duplicate WRITE completion advanced progress");
            SMB.Core_Client.Prepare_Next
              (Write_Transfer, State, Write_Packet, Used, Status);
            Assert
              (Status = SMB.Ok
               and then SMB.Core_Wire.Encoded_U64 (Write_Packet, 72) = 103
               and then Write_Packet (112 .. 113) =
                 SMB.Bytes'(16#44#, 16#55#),
               "partial WRITE continuation offset and original payload");
            SMB.Core_Client.Transfer_Send_Succeeded
              (Write_Transfer, State, Status);
            Prepare_Response
              (Write_Response, SMB.Core_Wire.Command_Code (9),
               SMB.Wire.U64 (Write_Packet, 24), Tree_Id, Session_Id, True);
            Write_Response (64) := 17;
            SMB.Wire.Put_U32 (Write_Response, 68, 2);
            SMB.Wire.Sign (Write_Response, Key);
            SMB.Core_Client.Complete_Write
              (Write_Transfer, State, Write_Response, Nt_Status, Status);
            Assert
              (Status = SMB.Ok
               and then SMB.Core_Client.Transfer_Stage_Of (Write_Transfer) =
                 SMB.Core_Client.Transfer_Finished,
               "WRITE transfer completion");

            SMB.Core_Client.Start_Write
              (Write_Transfer, State, Coordinator_Token, 100, Original, Status);
            SMB.Core_Client.Prepare_Next
              (Write_Transfer, State, Write_Packet, Used, Status);
            SMB.Core_Client.Transfer_Send_Succeeded
              (Write_Transfer, State, Status);
            Prepare_Response
              (Write_Response, SMB.Core_Wire.Command_Code (9),
               SMB.Wire.U64 (Write_Packet, 24), Tree_Id, Session_Id, True);
            Write_Response (64) := 17;
            SMB.Wire.Put_U32 (Write_Response, 68, 3);
            SMB.Wire.Sign (Write_Response, Key);
            SMB.Core_Client.Complete_Write
              (Write_Transfer, State, Write_Response, Nt_Status, Status);
            Assert (Status = SMB.Ok, "WRITE progress before NTSTATUS error");
            SMB.Core_Client.Prepare_Next
              (Write_Transfer, State, Write_Packet, Used, Status);
            SMB.Core_Client.Transfer_Send_Succeeded
              (Write_Transfer, State, Status);
            Prepare_Response
              (Write_Response, SMB.Core_Wire.Command_Code (9),
               SMB.Wire.U64 (Write_Packet, 24), Tree_Id, Session_Id, True);
            Write_Response (64) := 9;
            SMB.Wire.Put_U32 (Write_Response, 8, SMB.Status_Access_Denied);
            SMB.Wire.Sign (Write_Response, Key);
            SMB.Core_Client.Complete_Write
              (Write_Transfer, State, Write_Response, Nt_Status, Status);
            Assert
              (Status = SMB.Ok and then Nt_Status = SMB.Status_Access_Denied
               and then SMB.Core_Client.Transfer_Completed_Of (Write_Transfer) = 3
               and then SMB.Core_Client.Transfer_Remaining_Of (Write_Transfer) = 2
               and then SMB.Core_Client.Transfer_Stage_Of (Write_Transfer) =
                 SMB.Core_Client.Transfer_Finished
               and then SMB.Engine.Current_Phase (State) =
                 SMB.Engine.Share_Connected
               and then not SMB.Engine.Has_Validated_Response (State)
               and then not SMB.Engine.Has_Pending_Request (State),
               "NTSTATUS after partial WRITE advanced progress or kept receipt");

            SMB.Core_Client.Start_Read
              (Read_Transfer, State, Coordinator_Token, 200, 5, Status);
            Assert (Status = SMB.Ok, "transfer READ start");
            SMB.Core_Client.Prepare_Next
              (Read_Transfer, State, Read_Packet, Used, Status);
            SMB.Core_Client.Transfer_Send_Succeeded
              (Read_Transfer, State, Status);
            Prepare_Response
              (Read_Response, SMB.Core_Wire.Command_Code (8),
               SMB.Wire.U64 (Read_Packet, 24), Tree_Id, Session_Id, True);
            Read_Response (64) := 17;
            Read_Response (66) := 80;
            SMB.Wire.Put_U32 (Read_Response, 68, 5);
            Read_Response (80 .. 84) := Original;
            SMB.Wire.Sign (Read_Response, Key);
            SMB.Core_Client.Complete_Read
              (Read_Transfer, State, Read_Response, Nt_Status, Status);
            SMB.Core_Client.Copy_Read_Result
              (Read_Transfer, Result, Used, Status);
            Assert
              (Status = SMB.Ok and then Used = 5
               and then Result = Original,
               "validated READ bytes copied from transfer buffer");

            SMB.Core_Client.Start_Read
              (Read_Transfer, State, Coordinator_Token, 300, 5, Status);
            SMB.Core_Client.Prepare_Next
              (Read_Transfer, State, Read_Packet, Used, Status);
            SMB.Core_Client.Transfer_Send_Succeeded
              (Read_Transfer, State, Status);
            Read_Response := (others => 0);
            Prepare_Response
              (Read_Response, SMB.Core_Wire.Command_Code (8),
               SMB.Wire.U64 (Read_Packet, 24), Tree_Id, Session_Id, True);
            Read_Response (64) := 17;
            SMB.Wire.Put_U16 (Read_Response, 66, 80);
            SMB.Wire.Put_U32 (Read_Response, 68, 2);
            Read_Response (80 .. 81) := Original (1 .. 2);
            SMB.Wire.Sign (Read_Response, Key);
            SMB.Core_Client.Complete_Read
              (Read_Transfer, State, Read_Response, Nt_Status, Status);
            SMB.Core_Client.Copy_Read_Result
              (Read_Transfer, Result, Used, Status);
            Assert
              (Status = SMB.Ok and then Used = 2
               and then Result (Result'First .. Result'First + 1) =
                 Original (1 .. 2)
               and then
                 (for all Index in Result'First + 2 .. Result'Last =>
                    Result (Index) = 0)
               and then SMB.Core_Client.Transfer_Stage_Of (Read_Transfer) =
                 SMB.Core_Client.Transfer_Finished,
               "short READ terminates with validated prefix");

            SMB.Core_Client.Start_Read
              (Read_Transfer, State, Coordinator_Token, 400, 5, Status);
            SMB.Core_Client.Prepare_Next
              (Read_Transfer, State, Read_Packet, Used, Status);
            SMB.Core_Client.Transfer_Send_Succeeded
              (Read_Transfer, State, Status);
            Read_Response := (others => 0);
            Prepare_Response
              (Read_Response, SMB.Core_Wire.Command_Code (8),
               SMB.Wire.U64 (Read_Packet, 24), Tree_Id, Session_Id, True);
            Read_Response (64) := 17;
            SMB.Wire.Put_U16 (Read_Response, 66, 80);
            SMB.Wire.Sign (Read_Response, Key);
            SMB.Core_Client.Complete_Read
              (Read_Transfer, State, Read_Response, Nt_Status, Status);
            SMB.Core_Client.Copy_Read_Result
              (Read_Transfer, Result, Used, Status);
            Assert
              (Status = SMB.Ok and then Used = 0
               and then SMB.Core_Client.Transfer_Stage_Of (Read_Transfer) =
                 SMB.Core_Client.Transfer_Finished,
               "zero-length READ terminates without retry");

            SMB.Core_Client.Start_Read
              (Read_Transfer, State, Coordinator_Token, 500, 5, Status);
            SMB.Core_Client.Prepare_Next
              (Read_Transfer, State, Read_Packet, Used, Status);
            SMB.Core_Client.Transfer_Send_Succeeded
              (Read_Transfer, State, Status);
            Read_Response := (others => 0);
            Prepare_Response
              (Read_Response, SMB.Core_Wire.Command_Code (8),
               SMB.Wire.U64 (Read_Packet, 24), Tree_Id, Session_Id, True);
            SMB.Wire.Put_U32 (Read_Response, 8, SMB.Status_End_Of_File);
            Read_Response (64) := 9;
            SMB.Wire.Sign (Read_Response, Key);
            SMB.Core_Client.Complete_Read
              (Read_Transfer, State, Read_Response, Nt_Status, Status);
            Assert
              (Status = SMB.Ok and then Nt_Status = SMB.Status_End_Of_File
               and then SMB.Core_Client.Transfer_Completed_Of (Read_Transfer)
                 = 0
               and then SMB.Core_Client.Transfer_Stage_Of (Read_Transfer) =
                 SMB.Core_Client.Transfer_Finished
               and then SMB.Engine.Current_Phase (State) =
                 SMB.Engine.Share_Connected
               and then not SMB.Engine.Has_Pending_Request (State),
               "EOF READ finishes without progress or invalidation");

            SMB.Core_Client.Start_Read
              (Read_Transfer, State, Coordinator_Token, 550, 5, Status);
            SMB.Core_Client.Prepare_Next
              (Read_Transfer, State, Read_Packet, Used, Status);
            SMB.Core_Client.Transfer_Send_Succeeded
              (Read_Transfer, State, Status);
            Read_Response := (others => 0);
            Prepare_Response
              (Read_Response, SMB.Core_Wire.Command_Code (8),
               SMB.Wire.U64 (Read_Packet, 24), Tree_Id, Session_Id, True);
            SMB.Wire.Put_U32 (Read_Response, 8, SMB.Status_Access_Denied);
            Read_Response (64) := 9;
            SMB.Wire.Sign (Read_Response, Key);
            SMB.Core_Client.Complete_Read
              (Read_Transfer, State, Read_Response, Nt_Status, Status);
            Assert
              (Status = SMB.Ok and then Nt_Status = SMB.Status_Access_Denied
               and then SMB.Core_Client.Transfer_Completed_Of (Read_Transfer)
                 = 0
               and then SMB.Core_Client.Transfer_Stage_Of (Read_Transfer) =
                 SMB.Core_Client.Transfer_Finished
               and then SMB.Engine.Current_Phase (State) =
                 SMB.Engine.Share_Connected
               and then not SMB.Engine.Has_Pending_Request (State),
               "signed NTSTATUS READ error advanced or invalidated state");

            declare
               Large_Transfer : SMB.Core_Client.Transfer
                 (SMB.Core_Protocol.Maximum_IO_Chunk + 1);
               Large_Response : SMB.Bytes
                 (0 .. 79 + SMB.Core_Protocol.Maximum_IO_Chunk);
               Final_Response : SMB.Bytes (0 .. 80) := (others => 0);
               Large_Result : SMB.Bytes
                 (0 .. SMB.Core_Protocol.Maximum_IO_Chunk);
            begin
               SMB.Core_Client.Start_Read
                 (Large_Transfer, State, Coordinator_Token, 600,
                  SMB.Core_Protocol.Maximum_IO_Chunk + 1, Status);
               SMB.Core_Client.Prepare_Next
                 (Large_Transfer, State, Read_Packet, Used, Status);
               SMB.Core_Client.Transfer_Send_Succeeded
                 (Large_Transfer, State, Status);
               Large_Response := (others => 0);
               Prepare_Response
                 (Large_Response, SMB.Core_Wire.Command_Code (8),
                  SMB.Wire.U64 (Read_Packet, 24), Tree_Id, Session_Id, True);
               Large_Response (64) := 17;
               SMB.Wire.Put_U16 (Large_Response, 66, 80);
               SMB.Wire.Put_U32
                 (Large_Response, 68,
                  SMB.Core_Protocol.Maximum_IO_Chunk);
               for Index in 0 .. SMB.Core_Protocol.Maximum_IO_Chunk - 1 loop
                  Large_Response (80 + Index) := SMB.Byte (Index mod 256);
               end loop;
               SMB.Wire.Sign (Large_Response, Key);
               SMB.Core_Client.Complete_Read
                 (Large_Transfer, State, Large_Response, Nt_Status, Status);
               Assert
                 (Status = SMB.Ok
                  and then SMB.Core_Client.Transfer_Completed_Of
                    (Large_Transfer) =
                      SMB.Core_Protocol.Maximum_IO_Chunk
                  and then SMB.Core_Client.Transfer_Stage_Of
                    (Large_Transfer) = SMB.Core_Client.Ready,
                  "full READ chunk preserves remaining transfer");
               SMB.Core_Client.Prepare_Next
                 (Large_Transfer, State, Read_Packet, Used, Status);
               Assert
                 (Status = SMB.Ok
                  and then SMB.Core_Wire.Encoded_U64 (Read_Packet, 72) =
                    600 + SMB.Core_Protocol.Maximum_IO_Chunk,
                  "READ chunk continuation advances validated offset");
               SMB.Core_Client.Transfer_Send_Succeeded
                 (Large_Transfer, State, Status);
               Prepare_Response
                 (Final_Response, SMB.Core_Wire.Command_Code (8),
                  SMB.Wire.U64 (Read_Packet, 24), Tree_Id, Session_Id, True);
               Final_Response (64) := 17;
               SMB.Wire.Put_U16 (Final_Response, 66, 80);
               SMB.Wire.Put_U32 (Final_Response, 68, 1);
               Final_Response (80) := 16#AA#;
               SMB.Wire.Sign (Final_Response, Key);
               SMB.Core_Client.Complete_Read
                 (Large_Transfer, State, Final_Response, Nt_Status, Status);
               SMB.Core_Client.Copy_Read_Result
                 (Large_Transfer, Large_Result, Used, Status);
               Assert
                 (Status = SMB.Ok
                  and then Used =
                    SMB.Core_Protocol.Maximum_IO_Chunk + 1
                  and then Large_Result (0) = 0
                  and then Large_Result (255) = 255
                  and then Large_Result (SMB.Core_Protocol.Maximum_IO_Chunk)
                    = 16#AA#,
                  "multi-chunk READ result preserves accumulated prefix");

               SMB.Core_Client.Start_Read
                 (Large_Transfer, State, Coordinator_Token, 600,
                  SMB.Core_Protocol.Maximum_IO_Chunk + 1, Status);
               SMB.Core_Client.Prepare_Next
                 (Large_Transfer, State, Read_Packet, Used, Status);
               SMB.Core_Client.Transfer_Send_Succeeded
                 (Large_Transfer, State, Status);
               SMB.Wire.Put_U64
                 (Large_Response, 24, SMB.Wire.U64 (Read_Packet, 24));
               SMB.Wire.Sign (Large_Response, Key);
               SMB.Core_Client.Complete_Read
                 (Large_Transfer, State, Large_Response, Nt_Status, Status);
               Assert (Status = SMB.Ok, "READ progress before EOF");
               SMB.Core_Client.Prepare_Next
                 (Large_Transfer, State, Read_Packet, Used, Status);
               SMB.Core_Client.Transfer_Send_Succeeded
                 (Large_Transfer, State, Status);
               Prepare_Response
                 (Final_Response, SMB.Core_Wire.Command_Code (8),
                  SMB.Wire.U64 (Read_Packet, 24), Tree_Id, Session_Id, True);
               Final_Response (64) := 9;
               SMB.Wire.Put_U32 (Final_Response, 8, SMB.Status_End_Of_File);
               SMB.Wire.Sign (Final_Response, Key);
               SMB.Core_Client.Complete_Read
                 (Large_Transfer, State, Final_Response, Nt_Status, Status);
               Assert
                 (Status = SMB.Ok and then Nt_Status = SMB.Status_End_Of_File,
                  "EOF after a full READ chunk");
               SMB.Core_Client.Copy_Read_Result
                 (Large_Transfer, Large_Result, Used, Status);
               Assert
                 (Status = SMB.Ok
                  and then Used = SMB.Core_Protocol.Maximum_IO_Chunk
                  and then (for all Index in 0 .. Used - 1 =>
                    Large_Result (Index) = SMB.Byte (Index mod 256))
                  and then not SMB.Engine.Has_Pending_Request (State)
                  and then not SMB.Engine.Has_Validated_Response (State),
                  "EOF after progress lost the validated READ prefix");
            end;
         end;
         SMB.Core_Client.Complete
           (Coordinator, State, Response, Nt_Status,
            Rejected_Token, Status);
         Assert (Status /= SMB.Ok, "duplicate coordinator completion accepted");
         SMB.Core_Client.Prepare_Close
           (Close_Coordinator, State, Coordinator_Token,
            Close_Packet, Coordinator_Used, Status);
         Assert
           (Status = SMB.Ok,
            "coordinator CLOSE preparation " & SMB.Core_Status'Image (Status));
         Assert
           (Close_Packet (72 .. 87) = Validated_File_Id,
            "coordinator CLOSE encoded validated FileId");
         SMB.Core_Client.Complete
           (Close_Coordinator, State, Response, Nt_Status,
            Rejected_Token, Status);
         Assert (Status /= SMB.Ok, "coordinator response-before-send accepted");
         SMB.Core_Client.Send_Succeeded (Close_Coordinator, State, Status);
         Assert (Status = SMB.Ok, "coordinator CLOSE send acknowledgement");
         declare
            Close_Response : SMB.Bytes (0 .. 123) := (others => 0);
         begin
            Prepare_Response
              (Close_Response, SMB.Core_Wire.Command_Code (6),
               SMB.Wire.U64 (Close_Packet, 24),
               Tree_Id, Session_Id, True);
            Close_Response (64) := 60;
            SMB.Wire.Sign (Close_Response, Key);
            SMB.Core_Client.Complete
              (Close_Coordinator, State, Close_Response, Nt_Status,
               Coordinator_Token, Status);
            Assert
              (Status = SMB.Ok and then Nt_Status = SMB.Success
               and then not SMB.Engine.Has_Open_Handles (State),
               "coordinator CLOSE completion");
            SMB.Core_Client.Complete
              (Close_Coordinator, State, Close_Response, Nt_Status,
               Coordinator_Token, Status);
            Assert (Status /= SMB.Ok, "duplicate CLOSE completion accepted");
         end;
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (5), True, True,
            Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "begin create request");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (5), Message_Id,
            Tree_Id, Session_Id, True);
         Response (64) := 89;
         Response (128 .. 143) := File_Id;
         SMB.Wire.Sign (Response, Key);
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert (Status = SMB.Ok, "accept create receipt");
         SMB.Engine.Register_Handle
           (State, Wrong_File_Id, SMB.Engine.Read_Only, False, Token, Status);
         Assert
           (Status /= SMB.Ok,
            "wrong CREATE file id accepted");
         SMB.Engine.Register_Handle
           (State, File_Id, SMB.Engine.Read_Only, False, Token, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Engine.Has_Open_Handles (State),
            "register handle from matching create receipt");
         Assert (Rejects_Handle_Registration,
                 "create receipt was reusable for handle registration");
      end;

      declare
         Response : SMB.Bytes (0 .. 79) := (others => 0);
      begin
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (8), True, True,
            Message_Id, Expected, Status, Request_Amount => 1);
         Assert (Status = SMB.Ok, "begin signed read request");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (8), Message_Id,
            Tree_Id, Session_Id, True);
         Response (64) := 17;
         Response (66) := 80;
         SMB.Wire.Sign (Response, Key);
         Response (48) := Response (48) xor 1;
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Signature_Error
            and then Nt_Status = 0
            and then SMB.Engine.Current_Phase (State) = SMB.Engine.Disconnected
            and then not SMB.Engine.Has_Signing_Key (State)
            and then not SMB.Engine.Has_Pending_Request (State)
            and then not SMB.Engine.Has_Open_Handles (State),
            "tampered response did not invalidate session and handles");
      end;

      Reconnect_Share;
      SMB.Core_Client.Prepare_Create
        (Coordinator, State, SMB.Bytes'(0, 0), SMB.Engine.Read_Only,
         False, 1, False, Coordinator_Packet, Coordinator_Used, Status);
      Assert (Status = SMB.Ok, "coordinator prepare before abort");
      SMB.Core_Client.Abort_Operation (Coordinator, State, Status);
      Assert
        (Status = SMB.Ok
         and then not SMB.Engine.Has_Pending_Request (State)
         and then not SMB.Engine.Has_Signing_Key (State)
         and then SMB.Engine.Current_Phase (State) = SMB.Engine.Disconnected,
         "coordinator abort left request or session state");
      Reconnect_Share;
      SMB.Core_Client.Prepare_Create
        (Coordinator, State, SMB.Bytes'(0, 0), SMB.Engine.Read_Only,
         False, 1, False, Coordinator_Packet, Coordinator_Used, Status);
      Assert
        (Status = SMB.Ok and then SMB.Engine.Has_Pending_Request (State),
         "coordinator was not reusable after abort and reconnect");
      SMB.Core_Client.Abort_Operation (Coordinator, State, Status);
      Assert (Status = SMB.Ok, "abort reused coordinator request");

      Reconnect_Share;
      Create_Transfer_Handle;
      declare
         Transfer : SMB.Core_Client.Transfer (1);
         Packet : SMB.Bytes (0 .. 112) := (others => 0);
         Used : Natural;
      begin
         SMB.Core_Client.Start_Write
           (Transfer, State, Coordinator_Token, 0,
            SMB.Bytes'(0 => 16#AA#), Status);
         SMB.Core_Client.Prepare_Next
           (Transfer, State, Packet, Used, Status);
         Assert (Status = SMB.Ok, "prepare transfer for abort");
         SMB.Core_Client.Abort_Transfer (Transfer, State, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Core_Client.Transfer_Stage_Of (Transfer) =
              SMB.Core_Client.Transfer_Failed
            and then not SMB.Engine.Has_Pending_Request (State)
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected,
            "transfer abort retained request or session");
      end;

      Reconnect_Share;
      Create_Transfer_Handle;
      declare
         Transfer : SMB.Core_Client.Transfer (1);
         Packet : SMB.Bytes (0 .. 112) := (others => 0);
         Response : SMB.Bytes (0 .. 79) := (others => 0);
         Used : Natural;
      begin
         SMB.Core_Client.Start_Write
           (Transfer, State, Coordinator_Token, 0,
            SMB.Bytes'(0 => 16#AA#), Status);
         SMB.Core_Client.Prepare_Next
           (Transfer, State, Packet, Used, Status);
         SMB.Core_Client.Transfer_Send_Succeeded
           (Transfer, State, Status);
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (9),
            SMB.Wire.U64 (Packet, 24), Tree_Id, Session_Id, True);
         Response (64) := 17;
         SMB.Wire.Put_U32 (Response, 68, 0);
         SMB.Wire.Sign (Response, Key);
         SMB.Core_Client.Complete_Write
           (Transfer, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Invalid_Protocol
            and then Nt_Status = SMB.Success
            and then SMB.Core_Client.Transfer_Completed_Of (Transfer) = 0
            and then SMB.Core_Client.Transfer_Stage_Of (Transfer) =
              SMB.Core_Client.Transfer_Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected
            and then not SMB.Engine.Has_Open_Handles (State),
            "zero-count WRITE did not invalidate transfer state");
      end;

      Reconnect_Share;
      Create_Transfer_Handle;
      declare
         Transfer : SMB.Core_Client.Transfer (1);
         Packet : SMB.Bytes (0 .. 112) := (others => 0);
         Response : SMB.Bytes (0 .. 79) := (others => 0);
         Used : Natural;
      begin
         SMB.Core_Client.Start_Write
           (Transfer, State, Coordinator_Token, 0,
            SMB.Bytes'(0 => 16#AA#), Status);
         SMB.Core_Client.Prepare_Next
           (Transfer, State, Packet, Used, Status);
         SMB.Core_Client.Transfer_Send_Succeeded
           (Transfer, State, Status);
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (9),
            SMB.Wire.U64 (Packet, 24), Tree_Id, Session_Id, True);
         Response (64) := 17;
         SMB.Wire.Put_U32 (Response, 68, 2);
         SMB.Wire.Sign (Response, Key);
         SMB.Core_Client.Complete_Write
           (Transfer, State, Response, Nt_Status, Status);
         Assert
           (Status /= SMB.Ok
            and then SMB.Core_Client.Transfer_Completed_Of (Transfer) = 0
            and then SMB.Core_Client.Transfer_Stage_Of (Transfer) =
              SMB.Core_Client.Transfer_Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected
            and then not SMB.Engine.Has_Pending_Request (State),
            "over-count WRITE response advanced or kept the session");
      end;

      Reconnect_Share;
      Create_Transfer_Handle;
      declare
         Transfer : SMB.Core_Client.Transfer (1);
         Packet : SMB.Bytes (0 .. 112) := (others => 0);
         Response : SMB.Bytes (0 .. 80) := (others => 0);
         Used : Natural;
      begin
         SMB.Core_Client.Start_Read
           (Transfer, State, Coordinator_Token, 0, 1, Status);
         SMB.Core_Client.Prepare_Next
           (Transfer, State, Packet, Used, Status);
         SMB.Core_Client.Transfer_Send_Succeeded
           (Transfer, State, Status);
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (8),
            SMB.Wire.U64 (Packet, 24), Tree_Id, Session_Id, True);
         Response (64) := 17;
         SMB.Wire.Put_U16 (Response, 66, 80);
         SMB.Wire.Put_U32 (Response, 68, 1);
         Response (80) := 16#AA#;
         SMB.Wire.Sign (Response, Key);
         Response (48) := Response (48) xor 1;
         SMB.Core_Client.Complete_Read
           (Transfer, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Signature_Error
            and then SMB.Core_Client.Transfer_Completed_Of (Transfer) = 0
            and then SMB.Core_Client.Transfer_Stage_Of (Transfer) =
              SMB.Core_Client.Transfer_Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected
            and then not SMB.Engine.Has_Pending_Request (State),
            "tampered transfer response advanced progress or kept the session");
      end;
      Test_Directory_Coordinator;
      Test_Connection_Coordinator;
      Test_Connection_Edges;
      Reconnect_Share;
      declare
         Metadata : SMB.Core_Client.Metadata_Operation;
         False_Metadata : SMB.Core_Client.Metadata_Operation;
         Rename_Metadata : SMB.Core_Client.Metadata_Operation;
         Error_Metadata : SMB.Core_Client.Metadata_Operation;
         Malformed_Metadata : SMB.Core_Client.Metadata_Operation;
         Bad_Signature_Metadata : SMB.Core_Client.Metadata_Operation;
         Create_Op : SMB.Core_Client.Operation;
         File_Create_Op : SMB.Core_Client.Operation;
         Signature_Create_Op : SMB.Core_Client.Operation;
         Metadata_Token : SMB.Engine.Handle_Token;
         File_Token : SMB.Engine.Handle_Token;
         Signature_Token : SMB.Engine.Handle_Token;
         Request : SMB.Bytes (0 .. 96) := (others => 0);
         Rename_Request : SMB.Bytes (3 .. 122) := (others => 0);
         Short_Request : SMB.Bytes (0 .. 95) := (others => 0);
         Response : SMB.Bytes (0 .. 71) := (others => 0);
         Metadata_Used : Natural;
         Checked_Id : SMB.Bytes (0 .. 15);
         Checked_Access : SMB.Engine.Access_Kind;
         Checked_Directory : Boolean;
         Expected_Metadata : SMB.Engine.Request_Expectation;
         Before_Metadata_State : SMB.Engine.Engine_State;
         Before_Metadata_Context : SMB.Core_Client.Metadata_State_Snapshot;
         Before_Invalid_State : SMB.Engine.Engine_State;
         Before_Invalid_Context : SMB.Core_Client.Metadata_State_Snapshot;
         Name : constant SMB.Bytes (7 .. 10) := (16#41#, 0, 16#42#, 0);
         Odd_Name : constant SMB.Bytes (4 .. 6) := (16#41#, 0, 16#42#);
      begin
         Create_Directory_Handle (State, Create_Op, Metadata_Token);
         SMB.Core_Client.Prepare_Disposition
           (Metadata, State, Metadata_Token, True, Request,
            Metadata_Used, Status);
         Expected_Metadata :=
           (Command => SMB.Core_Wire.Command_Code (17),
            Message_Id => SMB.Wire.U64 (Request, 24),
            Tree_Id => Tree_Id,
            Session_Id => Session_Id,
            Match_Tree => True,
            Match_Session => True,
            Request_Signed => True,
            Signed => True,
            Request_Amount => 0,
            Close_Token => (others => 0));
         Assert
           (Status = SMB.Ok and then Metadata_Used = 97
            and then SMB.Core_Wire.Encoded_U16 (Request, 4) = 64
            and then SMB.Core_Wire.Encoded_U16 (Request, 6) = 1
            and then SMB.Core_Wire.Encoded_U16 (Request, 12) = 17
            and then SMB.Core_Wire.Encoded_U32 (Request, 16) = 8
            and then SMB.Core_Wire.Encoded_U32 (Request, 36) = Tree_Id
            and then SMB.Core_Wire.Encoded_U64 (Request, 40) = Session_Id
            and then SMB.Core_Wire.Encoded_U16 (Request, 64) = 33
            and then Request (66) = 1 and then Request (67) = 13
            and then SMB.Core_Wire.Encoded_U32 (Request, 68) = 1
            and then SMB.Core_Wire.Encoded_U16 (Request, 72) = 96
            and then SMB.Core_Wire.Encoded_U16 (Request, 74) = 0
            and then SMB.Core_Wire.Encoded_U32 (Request, 76) = 0
            and then Request (80 .. 95) = File_Id
            and then Request (96) = 1
            and then SMB.Engine.Pending_Request_Matches
              (State, Expected_Metadata),
            "SET_INFO disposition packet");
         Assert
           (SMB.Wire.Verify_Signature
              (Request, SMB.Engine.Current_Signing_Key (State)),
            "signed SET_INFO disposition request");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (17),
            SMB.Wire.U64 (Request, 24), Tree_Id, Session_Id, True);
         Before_Metadata_State := State;
         Before_Metadata_Context :=
           SMB.Core_Client.Metadata_Snapshot_Of (Metadata);
         SMB.Core_Client.Complete_Metadata
           (Metadata, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Core_Client.Metadata_Stage_Of (Metadata) =
              SMB.Core_Client.Metadata_Prepared
            and then SMB.Engine.Has_Pending_Request (State)
            and then SMB.Engine."=" (State, Before_Metadata_State)
            and then SMB.Core_Client.Metadata_Snapshot_Of (Metadata) =
              Before_Metadata_Context,
            "SET_INFO completion before acknowledgement made progress");
         SMB.Core_Client.Metadata_Send_Succeeded
           (Metadata, State, Status);
         Assert (Status = SMB.Ok, "SET_INFO send acknowledgement");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (17),
            SMB.Wire.U64 (Request, 24), Tree_Id, Session_Id, True);
         Response (64) := 2;
         SMB.Wire.Sign (Response, Key);
         SMB.Core_Client.Complete_Metadata
           (Metadata, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status = SMB.Success
            and then SMB.Core_Client.Metadata_Stage_Of (Metadata) =
              SMB.Core_Client.Metadata_Finished
            and then not SMB.Engine.Has_Pending_Request (State)
            and then not SMB.Engine.Has_Validated_Response (State),
            "SET_INFO completion status and receipt");
         SMB.Engine.Validate_Handle
           (State, Metadata_Token, False, False, Checked_Id,
            Checked_Access, Checked_Directory, Status);
         Assert
           (Status = SMB.Ok and then Checked_Id = File_Id
            and then Checked_Directory,
            "SET_INFO completion preserves handle");
         Before_Metadata_State := State;
         Before_Metadata_Context :=
           SMB.Core_Client.Metadata_Snapshot_Of (Metadata);
         SMB.Core_Client.Complete_Metadata
           (Metadata, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Core_Client.Metadata_Stage_Of (Metadata) =
              SMB.Core_Client.Metadata_Finished
            and then SMB.Engine."=" (State, Before_Metadata_State)
            and then SMB.Core_Client.Metadata_Snapshot_Of (Metadata) =
              Before_Metadata_Context,
            "SET_INFO duplicate completion made progress");
         SMB.Core_Client.Prepare_Disposition
           (False_Metadata, State, Metadata_Token, False, Request,
            Metadata_Used, Status);
         Assert (Status = SMB.Ok and then Request (96) = 0,
                 "SET_INFO disposition false");
         SMB.Core_Client.Metadata_Send_Succeeded
           (False_Metadata, State, Status);
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (17),
            SMB.Wire.U64 (Request, 24), Tree_Id, Session_Id, True);
         Response (64) := 2;
         SMB.Wire.Sign (Response, Key);
         SMB.Core_Client.Complete_Metadata
           (False_Metadata, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status = SMB.Success
            and then not SMB.Engine.Has_Pending_Request (State)
            and then not SMB.Engine.Has_Validated_Response (State),
            "SET_INFO false disposition completion");
         SMB.Core_Client.Prepare_Rename
           (Rename_Metadata, State, Metadata_Token, Name, Rename_Request,
            Metadata_Used, Status);
         Expected_Metadata :=
           (Command => SMB.Core_Wire.Command_Code (17),
            Message_Id => SMB.Wire.U64 (Rename_Request, 24),
            Tree_Id => Tree_Id,
            Session_Id => Session_Id,
            Match_Tree => True,
            Match_Session => True,
            Request_Signed => True,
            Signed => True,
            Request_Amount => 0,
            Close_Token => (others => 0));
         Assert
            (Status = SMB.Ok and then Metadata_Used = 120
            and then SMB.Core_Wire.Encoded_U16 (Rename_Request, 4) = 64
            and then SMB.Core_Wire.Encoded_U16 (Rename_Request, 6) = 1
            and then SMB.Core_Wire.Encoded_U16 (Rename_Request, 12) = 17
            and then SMB.Core_Wire.Encoded_U32 (Rename_Request, 16) = 8
            and then SMB.Core_Wire.Encoded_U32 (Rename_Request, 36) = Tree_Id
            and then SMB.Core_Wire.Encoded_U64 (Rename_Request, 40) =
              Session_Id
            and then SMB.Core_Wire.Encoded_U16 (Rename_Request, 64) = 33
            and then Rename_Request (Rename_Request'First + 66) = 1
            and then Rename_Request (Rename_Request'First + 67) = 10
            and then SMB.Core_Wire.Encoded_U32 (Rename_Request, 68) = 24
            and then SMB.Core_Wire.Encoded_U16 (Rename_Request, 72) = 96
            and then SMB.Core_Wire.Encoded_U16 (Rename_Request, 74) = 0
            and then SMB.Core_Wire.Encoded_U32 (Rename_Request, 76) = 0
            and then Rename_Request (Rename_Request'First + 80 ..
                                     Rename_Request'First + 95) = File_Id
            and then Rename_Request (Rename_Request'First + 96) = 0
            and then Rename_Request (Rename_Request'First + 97) = 0
            and then SMB.Core_Wire.Encoded_U16 (Rename_Request, 98) = 0
            and then SMB.Core_Wire.Encoded_U64 (Rename_Request, 104) = 0
            and then Rename_Request (Rename_Request'First + 66) = 1
            and then SMB.Wire.U32 (Rename_Request, 112) = 4
            and then Rename_Request (Rename_Request'First + 116 ..
                                     Rename_Request'First + 119) = Name
            and then SMB.Engine.Pending_Request_Matches
              (State, Expected_Metadata),
            "SET_INFO rename body and nonzero bounds");
         Assert
           (SMB.Wire.Verify_Signature
              (Rename_Request, SMB.Engine.Current_Signing_Key (State)),
            "signed SET_INFO rename request");
         SMB.Core_Client.Metadata_Send_Succeeded
           (Rename_Metadata, State, Status);
         Assert (Status = SMB.Ok, "SET_INFO rename acknowledgement");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (17),
            SMB.Wire.U64 (Rename_Request, 24), Tree_Id, Session_Id, True);
         Response (64) := 2;
         SMB.Wire.Sign (Response, Key);
         SMB.Core_Client.Complete_Metadata
           (Rename_Metadata, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status = SMB.Success
            and then SMB.Core_Client.Metadata_Stage_Of (Rename_Metadata) =
              SMB.Core_Client.Metadata_Finished,
            "SET_INFO rename completion");

         Create_Directory_Handle
           (State, File_Create_Op, File_Token, Is_Directory => False);
         SMB.Core_Client.Prepare_Disposition
           (Error_Metadata, State, File_Token, True, Request,
            Metadata_Used, Status);
         Assert (Status = SMB.Ok, "SET_INFO file disposition preparation");
         SMB.Core_Client.Metadata_Send_Succeeded
           (Error_Metadata, State, Status);
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (17),
            SMB.Wire.U64 (Request, 24), Tree_Id, Session_Id, True);
         SMB.Wire.Put_U32 (Response, 8, SMB.Status_Access_Denied);
         Response (64) := 9;
         SMB.Wire.Sign (Response, Key);
         SMB.Core_Client.Complete_Metadata
           (Error_Metadata, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Ok and then Nt_Status = SMB.Status_Access_Denied
            and then SMB.Core_Client.Metadata_Stage_Of (Error_Metadata) =
              SMB.Core_Client.Metadata_Finished
            and then not SMB.Engine.Has_Pending_Request (State)
            and then not SMB.Engine.Has_Validated_Response (State),
            "SET_INFO signed NTSTATUS preserves usable state");
         SMB.Engine.Validate_Handle
           (State, File_Token, False, False, Checked_Id,
            Checked_Access, Checked_Directory, Status);
         Assert
           (Status = SMB.Ok and then Checked_Id = File_Id
            and then Checked_Access = SMB.Engine.Read_Only
            and then not Checked_Directory,
            "SET_INFO file handle remains usable after NTSTATUS");

         Before_Invalid_State := State;
         Before_Invalid_Context :=
           SMB.Core_Client.Metadata_Snapshot_Of (Malformed_Metadata);
         SMB.Core_Client.Prepare_Rename
           (Malformed_Metadata, State, File_Token, Odd_Name, Rename_Request,
            Metadata_Used, Status);
         Assert
           (Status = SMB.Invalid_Length and then Metadata_Used = 0
            and then SMB.Core_Client.Metadata_Stage_Of (Malformed_Metadata) =
              SMB.Core_Client.Metadata_Idle
            and then SMB.Engine."=" (State, Before_Invalid_State)
            and then SMB.Core_Client.Metadata_Snapshot_Of
              (Malformed_Metadata) = Before_Invalid_Context,
            "SET_INFO odd rename rejected without progress");
         SMB.Core_Client.Prepare_Rename
           (Malformed_Metadata, State, File_Token, SMB.Bytes'(1 .. 0 => 0),
            Rename_Request, Metadata_Used, Status);
         Assert
           (Status = SMB.Invalid_Length and then Metadata_Used = 0
            and then SMB.Engine."=" (State, Before_Invalid_State)
            and then SMB.Core_Client.Metadata_Snapshot_Of
              (Malformed_Metadata) = Before_Invalid_Context,
                 "SET_INFO empty rename rejected");
         SMB.Core_Client.Prepare_Rename
           (Malformed_Metadata, State, File_Token, Name, Short_Request,
            Metadata_Used, Status);
         Assert
           (Status = SMB.Resource_Limit and then Metadata_Used = 0
            and then SMB.Engine."=" (State, Before_Invalid_State)
            and then SMB.Core_Client.Metadata_Snapshot_Of
              (Malformed_Metadata) = Before_Invalid_Context,
            "SET_INFO short output rejected");
         SMB.Core_Client.Prepare_Rename
           (Malformed_Metadata, State, File_Token, Name, Rename_Request,
            Metadata_Used, Status);
         SMB.Core_Client.Metadata_Send_Succeeded
           (Malformed_Metadata, State, Status);
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (17),
            SMB.Wire.U64 (Rename_Request, 24), Tree_Id, Session_Id, True);
         Response (64) := 3;
         SMB.Wire.Sign (Response, Key);
         SMB.Core_Client.Complete_Metadata
           (Malformed_Metadata, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Invalid_Protocol
            and then SMB.Core_Client.Metadata_Stage_Of (Malformed_Metadata) =
              SMB.Core_Client.Metadata_Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected,
            "SET_INFO malformed signed success invalidated state");
         SMB.Core_Client.Prepare_Disposition
           (Malformed_Metadata, State, File_Token, False, Request,
            Metadata_Used, Status);
         Assert (Status = SMB.Invalid_State_Status and then Metadata_Used = 0,
                 "SET_INFO failed operation cannot be retried");

         Reconnect_Share;
         Create_Directory_Handle
           (State, Signature_Create_Op, Signature_Token,
            Is_Directory => False);
         SMB.Core_Client.Prepare_Disposition
           (Bad_Signature_Metadata, State, Signature_Token, False, Request,
            Metadata_Used, Status);
         SMB.Core_Client.Metadata_Send_Succeeded
           (Bad_Signature_Metadata, State, Status);
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (17),
            SMB.Wire.U64 (Request, 24), Tree_Id, Session_Id, True);
         Response (64) := 2;
         SMB.Wire.Sign (Response, Key);
         Response (48) := Response (48) xor 1;
         SMB.Core_Client.Complete_Metadata
           (Bad_Signature_Metadata, State, Response, Nt_Status, Status);
         Assert
           (Status = SMB.Signature_Error
            and then SMB.Core_Client.Metadata_Stage_Of
              (Bad_Signature_Metadata) = SMB.Core_Client.Metadata_Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected,
            "SET_INFO tampered signature did not invalidate state");
         SMB.Core_Client.Prepare_Disposition
           (Bad_Signature_Metadata, State, Signature_Token, False, Request,
            Metadata_Used, Status);
         Assert
           (Status = SMB.Invalid_State_Status and then Metadata_Used = 0,
            "SET_INFO signature failure cannot be retried");
      end;
      declare
         Owner_Create : SMB.Core_Client.Operation;
         Foreign_Create : SMB.Core_Client.Operation;
         Owner_Metadata : SMB.Core_Client.Metadata_Operation;
         Foreign_Metadata : SMB.Core_Client.Metadata_Operation;
         Owner_Token : SMB.Engine.Handle_Token;
         Foreign_Metadata_Token : SMB.Engine.Handle_Token;
         Owner_Packet : SMB.Bytes (0 .. 96) := (others => 0);
         Foreign_Packet : SMB.Bytes (0 .. 96) := (others => 0);
         Metadata_Response : SMB.Bytes (0 .. 71) := (others => 0);
         Owner_Used : Natural;
         Foreign_Used : Natural;
         Owner_State_Before : SMB.Engine.Engine_State;
         Foreign_State_Before : SMB.Engine.Engine_State;
         Owner_Metadata_Before : SMB.Core_Client.Metadata_State_Snapshot;
         Foreign_Metadata_Before : SMB.Core_Client.Metadata_State_Snapshot;
         Owner_Id_Before : SMB.QWord;
         Owner_Epoch_Before : SMB.QWord;
      begin
         Reconnect_Share (State);
         Reconnect_Share (Foreign_State);
         Create_Directory_Handle
           (State, Owner_Create, Owner_Token, Is_Directory => False);
         Create_Directory_Handle
           (Foreign_State, Foreign_Create, Foreign_Metadata_Token,
            Is_Directory => False);
         SMB.Core_Client.Prepare_Disposition
           (Owner_Metadata, State, Owner_Token, False, Owner_Packet,
            Owner_Used, Status);
         Assert (Status = SMB.Ok, "SET_INFO owner context prepared");
         SMB.Core_Client.Prepare_Disposition
           (Foreign_Metadata, Foreign_State, Foreign_Metadata_Token, False,
            Foreign_Packet, Foreign_Used, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Wire.U64 (Owner_Packet, 24) =
              SMB.Wire.U64 (Foreign_Packet, 24),
            "SET_INFO foreign contexts have colliding request ids");
         Owner_State_Before := State;
         Foreign_State_Before := Foreign_State;
         Owner_Metadata_Before :=
           SMB.Core_Client.Metadata_Snapshot_Of (Owner_Metadata);
         Foreign_Metadata_Before :=
           SMB.Core_Client.Metadata_Snapshot_Of (Foreign_Metadata);
         SMB.Core_Client.Metadata_Send_Succeeded
           (Owner_Metadata, Foreign_State, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine."=" (State, Owner_State_Before)
            and then SMB.Engine."=" (Foreign_State, Foreign_State_Before)
            and then SMB.Core_Client.Metadata_Snapshot_Of (Owner_Metadata) =
              Owner_Metadata_Before
            and then SMB.Core_Client.Metadata_Snapshot_Of
              (Foreign_Metadata) = Foreign_Metadata_Before,
            "SET_INFO foreign send context caused no damage");

         SMB.Core_Client.Metadata_Send_Succeeded
           (Owner_Metadata, State, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Core_Client.Metadata_Stage_Of (Owner_Metadata) =
              SMB.Core_Client.Metadata_Sent,
            "SET_INFO owner context acknowledged");
         Prepare_Response
           (Metadata_Response, SMB.Core_Wire.Command_Code (17),
            SMB.Wire.U64 (Owner_Packet, 24), Tree_Id, Session_Id, True);
         Metadata_Response (64) := 2;
         SMB.Wire.Sign (Metadata_Response, Key);
         Owner_State_Before := State;
         Foreign_State_Before := Foreign_State;
         Owner_Metadata_Before :=
           SMB.Core_Client.Metadata_Snapshot_Of (Owner_Metadata);
         Foreign_Metadata_Before :=
           SMB.Core_Client.Metadata_Snapshot_Of (Foreign_Metadata);
         SMB.Core_Client.Complete_Metadata
           (Owner_Metadata, Foreign_State, Metadata_Response, Nt_Status,
            Status);
         Assert
           (Status = SMB.Invalid_State_Status and then Nt_Status = 0
            and then SMB.Engine."=" (State, Owner_State_Before)
            and then SMB.Engine."=" (Foreign_State, Foreign_State_Before)
            and then SMB.Core_Client.Metadata_Snapshot_Of (Owner_Metadata) =
              Owner_Metadata_Before
            and then SMB.Core_Client.Metadata_Snapshot_Of
              (Foreign_Metadata) = Foreign_Metadata_Before,
            "SET_INFO foreign completion context caused no damage");
         SMB.Core_Client.Abort_Metadata
           (Owner_Metadata, Foreign_State, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine."=" (State, Owner_State_Before)
            and then SMB.Engine."=" (Foreign_State, Foreign_State_Before)
            and then SMB.Core_Client.Metadata_Snapshot_Of (Owner_Metadata) =
              Owner_Metadata_Before
            and then SMB.Core_Client.Metadata_Snapshot_Of
              (Foreign_Metadata) = Foreign_Metadata_Before,
            "SET_INFO foreign abort context caused no damage");

         SMB.Engine.Accept_Response
           (State, Metadata_Response, Nt_Status, Status);
         Assert
           (Status = SMB.Ok
            and then SMB.Engine.Has_Validated_Response (State)
            and then not SMB.Engine.Has_Pending_Request (State),
            "SET_INFO receipt-preservation fixture response accepted");
         Owner_State_Before := State;
         Owner_Metadata_Before :=
           SMB.Core_Client.Metadata_Snapshot_Of (Owner_Metadata);
         SMB.Core_Client.Abort_Metadata
           (Owner_Metadata, State, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine."=" (State, Owner_State_Before)
            and then SMB.Core_Client.Metadata_Snapshot_Of (Owner_Metadata) =
              Owner_Metadata_Before,
            "SET_INFO abort preserves unrelated validated receipt");
         SMB.Engine.Discard_Response_Receipt (State, Status);
         Assert
           (Status = SMB.Ok
            and then not SMB.Engine.Has_Validated_Response (State),
            "SET_INFO receipt-preservation fixture receipt discarded");

         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (17), True, True,
            Message_Id, Expected, Status);
         Assert
           (Status = SMB.Ok
            and then Message_Id /= SMB.Wire.U64 (Owner_Packet, 24),
            "SET_INFO unrelated request has a different message id");
         Metadata_Response := (others => 0);
         Prepare_Response
           (Metadata_Response, SMB.Core_Wire.Command_Code (17),
            SMB.Wire.U64 (Owner_Packet, 24), Tree_Id, Session_Id, True);
         Metadata_Response (64) := 2;
         SMB.Wire.Sign (Metadata_Response, Key);
         Owner_State_Before := State;
         Owner_Metadata_Before :=
           SMB.Core_Client.Metadata_Snapshot_Of (Owner_Metadata);
         SMB.Core_Client.Complete_Metadata
           (Owner_Metadata, State, Metadata_Response, Nt_Status, Status);
         Assert
           (Status = SMB.Invalid_State_Status and then Nt_Status = 0
            and then SMB.Engine."=" (State, Owner_State_Before)
            and then SMB.Core_Client.Metadata_Snapshot_Of (Owner_Metadata) =
              Owner_Metadata_Before,
            "SET_INFO completion preserves unrelated pending request");
         SMB.Core_Client.Abort_Metadata
           (Owner_Metadata, State, Status);
         Assert
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine."=" (State, Owner_State_Before)
            and then SMB.Core_Client.Metadata_Snapshot_Of (Owner_Metadata) =
              Owner_Metadata_Before,
            "SET_INFO abort preserves unrelated pending request");

         Owner_Id_Before := SMB.Engine.Current_Owner_Id (State);
         Owner_Epoch_Before := SMB.Engine.Current_Epoch (State);
         SMB.Engine.Invalidate (State, Status);
         Assert (Status = SMB.Ok, "SET_INFO epoch fixture invalidated");
         Reconnect_Share (State, Initialize_State => False);
         Assert
           (SMB.Engine.Current_Owner_Id (State) = Owner_Id_Before
            and then SMB.Engine.Current_Epoch (State) /= Owner_Epoch_Before,
            "SET_INFO same owner reconnected in a new epoch");
         declare
            Fresh_Create : SMB.Core_Client.Operation;
            Fresh_Metadata : SMB.Core_Client.Metadata_Operation;
            Fresh_Token : SMB.Engine.Handle_Token;
            Fresh_Packet : SMB.Bytes (0 .. 96) := (others => 0);
            Fresh_Used : Natural;
            Fresh_State_Before : SMB.Engine.Engine_State;
            Fresh_Metadata_Before :
              SMB.Core_Client.Metadata_State_Snapshot;
            Old_Metadata_Context : constant
              SMB.Core_Client.Metadata_State_Snapshot :=
                SMB.Core_Client.Metadata_Snapshot_Of (Owner_Metadata);
         begin
            Create_Directory_Handle
              (State, Fresh_Create, Fresh_Token, Is_Directory => False);
            SMB.Core_Client.Prepare_Disposition
              (Fresh_Metadata, State, Fresh_Token, False, Fresh_Packet,
               Fresh_Used, Status);
            Assert
              (Status = SMB.Ok and then Fresh_Used = 97
               and then SMB.Wire.U64 (Fresh_Packet, 24) =
                 SMB.Wire.U64 (Owner_Packet, 24)
               and then SMB.Engine.Current_Owner_Id (State) = Owner_Id_Before
               and then SMB.Engine.Current_Epoch (State) /= Owner_Epoch_Before
               and then Old_Metadata_Context.Stage =
                 SMB.Core_Client.Metadata_Sent
               and then Old_Metadata_Context.Owner = Owner_Id_Before
               and then Old_Metadata_Context.Epoch = Owner_Epoch_Before
               and then SMB.Engine.Pending_Request_Matches
                 (State, Old_Metadata_Context.Expected),
              "SET_INFO stale metadata collides with live wire context");
            Metadata_Response := (others => 0);
            Prepare_Response
              (Metadata_Response, SMB.Core_Wire.Command_Code (17),
               SMB.Wire.U64 (Owner_Packet, 24), Tree_Id, Session_Id, True);
            Metadata_Response (64) := 2;
            SMB.Wire.Sign (Metadata_Response, Key);
            Fresh_State_Before := State;
            Fresh_Metadata_Before :=
              SMB.Core_Client.Metadata_Snapshot_Of (Fresh_Metadata);
            SMB.Core_Client.Complete_Metadata
              (Owner_Metadata, State, Metadata_Response, Nt_Status, Status);
            Assert
              (Status = SMB.Invalid_State_Status and then Nt_Status = 0
               and then SMB.Engine."=" (State, Fresh_State_Before)
               and then SMB.Core_Client.Metadata_Snapshot_Of
                 (Fresh_Metadata) = Fresh_Metadata_Before
               and then SMB.Core_Client.Metadata_Snapshot_Of
                 (Owner_Metadata) = Old_Metadata_Context,
              "SET_INFO stale completion preserves live new-epoch operation");
            SMB.Core_Client.Abort_Metadata
              (Owner_Metadata, State, Status);
            Assert
              (Status = SMB.Invalid_State_Status
               and then SMB.Engine."=" (State, Fresh_State_Before)
               and then SMB.Core_Client.Metadata_Snapshot_Of
                 (Fresh_Metadata) = Fresh_Metadata_Before
               and then SMB.Core_Client.Metadata_Snapshot_Of
                 (Owner_Metadata) = Old_Metadata_Context,
              "SET_INFO stale abort preserves live new-epoch operation");
         end;
         SMB.Engine.Invalidate (State, Status);
         Assert (Status = SMB.Ok, "SET_INFO state cleanup");
         SMB.Engine.Invalidate (Foreign_State, Status);
         Assert (Status = SMB.Ok, "SET_INFO foreign state cleanup");
      end;
   end Test_Engine_Receipts;

   procedure Test_Engine_Malformed_Close is
      State : SMB.Engine.Engine_State;
      Status : SMB.Core_Status;
      Nt_Status : SMB.DWord;
      Message_Id : SMB.QWord;
      Expected : SMB.Engine.Request_Expectation;
      Token : SMB.Engine.Handle_Token;
      Session_Id : constant SMB.QWord := 16#1234#;
      Tree_Id : constant SMB.DWord := 16#1020_3040#;
      Key : constant SMB.Bytes (0 .. 15) :=
        (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
      File_Id : constant SMB.Bytes (0 .. 15) := (others => 16#22#);
      Final_Token : constant SMB.Bytes (0 .. 28) :=
        (16#A1#, 16#1B#, 16#30#, 16#19#,
         16#A0#, 16#03#, 16#0A#, 16#01#, 0,
         16#A3#, 16#12#, 16#04#, 16#10#,
         1, 0, 0, 0, 16#0A#, 16#FB#, 16#34#, 16#90#,
         16#3A#, 16#3E#, 16#4E#, 16#54#, 0, 0, 0, 0);

      procedure Prepare_Response
        (Packet : in out SMB.Bytes;
         Command : SMB.Core_Wire.Command_Code;
         Reply_Id : SMB.QWord;
         Reply_Tree_Id : SMB.DWord;
         Reply_Session_Id : SMB.QWord;
         Signed : Boolean) is
      begin
         SMB.Wire.Initialize_Header
           (Packet, SMB.Word (Command), Reply_Id, Reply_Tree_Id,
            Reply_Session_Id);
         SMB.Wire.Put_U32 (Packet, 16, (if Signed then 9 else 1));
      end Prepare_Response;
   begin
      SMB.Engine.Initialize (State, Status);
      Assert (Status = SMB.Ok, "malformed CLOSE engine initialization");
      SMB.Engine.Mark_Connected (State, Status);
      Assert (Status = SMB.Ok, "malformed CLOSE transport transition");

      declare
         Response : SMB.Bytes (0 .. 127) := (others => 0);
      begin
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (0), False, False,
            Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE begin negotiate");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (0), Message_Id, 0, 0, False);
         Response (64) := 65;
         Response (66) := 1;
         Response (68) := 16#10#;
         Response (69) := 2;
         Response (96) := 1;
         Response (100) := 1;
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE accept negotiate");
         SMB.Engine.Mark_Negotiated (State, 1, 1, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE negotiate transition");
      end;

      declare
         Response : SMB.Bytes (0 .. 71) := (others => 0);
      begin
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (1), False, False,
            Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE begin challenge");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (1), Message_Id,
            0, Session_Id, False);
         SMB.Wire.Put_U32
           (Response, 8, SMB.Status_More_Processing_Required);
         Response (64) := 9;
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE accept challenge");
         SMB.Engine.Install_Session_Key (State, Session_Id, Key, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE install session key");
      end;

      declare
         Response : SMB.Bytes (0 .. 100) := (others => 0);
      begin
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (1), False, True,
            Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE begin final setup");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (1), Message_Id,
            0, Session_Id, True);
         Response (64) := 9;
         SMB.Wire.Put_U16 (Response, 68, 72);
         SMB.Wire.Put_U16 (Response, 70, Final_Token'Length);
         for Index in Final_Token'Range loop
            Response (72 + Index) := Final_Token (Index);
         end loop;
         SMB.Wire.Sign (Response, Key);
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE accept final setup");
         SMB.Engine.Mark_Authenticated (State, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE authenticate");
      end;

      declare
         Response : SMB.Bytes (0 .. 79) := (others => 0);
      begin
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (3), True, True,
            Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE begin tree connect");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (3), Message_Id,
            Tree_Id, Session_Id, True);
         Response (64) := 16;
         Response (66) := 1;
         SMB.Wire.Sign (Response, Key);
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE accept tree connect");
         SMB.Engine.Mark_Share_Connected (State, Tree_Id, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE share transition");
      end;

      declare
         Response : SMB.Bytes (0 .. 151) := (others => 0);
      begin
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (5), True, True,
            Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE begin CREATE");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (5), Message_Id,
            Tree_Id, Session_Id, True);
         Response (64) := 89;
         Response (128 .. 143) := File_Id;
         SMB.Wire.Sign (Response, Key);
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE accept CREATE");
         SMB.Engine.Register_Handle
           (State, File_Id, SMB.Engine.Read_Write, False, Token, Status);
         Assert (Status = SMB.Ok, "malformed CLOSE register handle");
      end;

      declare
         Response : SMB.Bytes (0 .. 123) := (others => 0);
      begin
         SMB.Engine.Begin_Request
           (State, SMB.Core_Wire.Command_Code (6), True, True,
            Message_Id, Expected, Status, Close_Token => Token);
         Assert (Status = SMB.Ok, "malformed CLOSE begin close");
         Prepare_Response
           (Response, SMB.Core_Wire.Command_Code (6), Message_Id,
            Tree_Id, Session_Id, True);
         Response (64) := 60;
         Response (66) := 2;
         SMB.Wire.Sign (Response, Key);
         SMB.Engine.Accept_Response (State, Response, Nt_Status, Status);
         Assert
           (Status /= SMB.Ok
            and then Nt_Status = 0
            and then SMB.Engine.Current_Phase (State) = SMB.Engine.Disconnected
            and then not SMB.Engine.Has_Pending_Request (State)
            and then not SMB.Engine.Has_Validated_Response (State)
            and then not SMB.Engine.Has_Open_Handles (State)
            and then not SMB.Engine.Has_Signing_Key (State)
            and then SMB.Engine.Signing_Key_Is_Zero (State),
            "signed malformed CLOSE did not fully invalidate Engine");
      end;
   end Test_Engine_Malformed_Close;

   procedure Test_Text_And_Wire is
      UTF8 : constant String :=
        Character'Val (16#E6#) & Character'Val (16#97#)
        & Character'Val (16#A5#) & Character'Val (16#F0#)
        & Character'Val (16#9F#) & Character'Val (16#98#)
        & Character'Val (16#80#);
      UTF16 : constant SMB.Bytes := SMB.Text.To_UTF16LE (UTF8);
      Packet : SMB.Bytes (0 .. 63) := (others => 0);
      Tree_Packet : SMB.Bytes (0 .. 63) := (others => 0);
      Key : constant SMB.Bytes (0 .. 15) := (others => 16#11#);
   begin
      Assert (UTF16'Length = 6, "UTF-16 surrogate conversion");
      Assert (SMB.Text.From_UTF16LE (UTF16) = UTF8, "UTF-16 round trip");
      SMB.Wire.Initialize_Header (Packet, SMB.Wire.Read_Command, 7);
      SMB.Wire.Put_U16 (Packet, 6, 1);
      SMB.Wire.Put_U32 (Packet, 16, 1);
      Assert (SMB.Wire.U64 (Packet, 24) = 7, "SMB message id");
      SMB.Wire.Initialize_Header
        (Tree_Packet, SMB.Wire.Read_Command, 11, 16#1122_3344#);
      Assert (SMB.Wire.U32 (Tree_Packet, 36) = 16#1122_3344#,
              "SMB tree id wire offset");
      Assert (SMB.Wire.U32 (Tree_Packet, 32) = 0,
              "SMB process id must not contain tree id");
      Assert (SMB.Wire.Validate_Header
        (Packet,
         (Command => SMB.Wire.Read_Command, Message_Id => 7,
          Tree_Id => 0, Session_Id => 0, Signed => False)) = 0,
        "SMB response header");
      SMB.Wire.Sign (Packet, Key);
      Assert (SMB.Wire.Verify_Signature (Packet, Key), "SMB signature");
      Packet (10) := Packet (10) xor 1;
      Assert (not SMB.Wire.Verify_Signature (Packet, Key),
              "tampered SMB signature");
      begin
         declare
            Ignored : constant SMB.Word := SMB.Wire.U16 (Packet, 63);
         begin
            Assert (Ignored = 0, "unreachable malformed wire value");
         end;
         raise Program_Error with "wire bounds check did not fire";
      exception
         when SMB.Protocol_Error => null;
      end;
      begin
         declare
            Ignored_Status : constant SMB.DWord := SMB.Wire.Validate_Header
              (Packet,
               (Command => SMB.Wire.Read_Command, Message_Id => 7,
                Tree_Id => 0, Session_Id => 0, Signed => True));
         begin
            Assert (Ignored_Status = 0, "unreachable unsigned SMB response");
         end;
         raise Program_Error with "unsigned SMB response was accepted";
      exception
         when SMB.Protocol_Error => null;
      end;
      begin
         declare
            Invalid_UTF8 : constant SMB.Bytes := SMB.Text.To_UTF16LE
              (Character'Val (16#C0#) & Character'Val (16#AF#));
         begin
            Assert (Invalid_UTF8'Length = 0, "unreachable invalid UTF-8");
         end;
         raise Program_Error with "overlong UTF-8 was accepted";
      exception
         when SMB.Protocol_Error => null;
      end;
      begin
         declare
            Invalid_UTF16 : constant String :=
              SMB.Text.From_UTF16LE (Hex ("00d8"));
         begin
            Assert (Invalid_UTF16'Length = 0, "unreachable UTF-16 surrogate");
         end;
         raise Program_Error with "unpaired UTF-16 surrogate was accepted";
      exception
         when SMB.Protocol_Error => null;
      end;
      begin
         declare
            Non_Ascii_User : constant String :=
              SMB.Text.NTLM_Username
                (Character'Val (16#E3#) & Character'Val (16#81#)
                 & Character'Val (16#82#));
         begin
            Assert (Non_Ascii_User'Length = 0, "unreachable NTLM username");
         end;
         raise Program_Error with "non-ASCII NTLM username was accepted";
      exception
         when SMB.Authentication_Error => null;
      end;
      declare
         Token : constant SMB.Bytes := SMB.NTLM.Negotiate_Token;
      begin
         Assert (Token'Length > 0, "SPNEGO token");
      end;
      declare
         Nonce : constant SMB.Bytes (0 .. 7) := (others => 0);
         Empty_Token : constant SMB.Bytes := SMB.Bytes'(1 .. 0 => 0);
      begin
         begin
            declare
               Invalid_Challenge : constant SMB.NTLM.Authentication_Result :=
                 SMB.NTLM.Authenticate
                   ("User", "Password", "Domain", Nonce, Empty_Token);
            begin
               Assert
                 (Invalid_Challenge.Security_Token'Length = 0,
                  "unreachable malformed SPNEGO token");
            end;
            raise Program_Error with "malformed SPNEGO token was accepted";
         exception
            when SMB.Protocol_Error => null;
         end;
      end;
   end Test_Text_And_Wire;

   procedure Expect_Protocol_Error
     (Action : not null access procedure; Message : String) is
   begin
      Expect_Error (Action, SMB.Protocol_Error'Identity, Message);
   end Expect_Protocol_Error;

   procedure Test_Wire_Facade is
      Packet : SMB.Bytes (0 .. 63) := (others => 0);
      Short : SMB.Bytes (0 .. 62) := (others => 0);
      Top : SMB.Bytes (Natural'Last - 63 .. Natural'Last) :=
        (others => 16#FF#);
      Key : constant SMB.Bytes (0 .. 15) := (others => 16#11#);

      function Response
        (Tree_Id : SMB.DWord; Session_Id : SMB.QWord) return SMB.Bytes
      is
         Result : SMB.Bytes (0 .. 63) := (others => 0);
      begin
         SMB.Wire.Initialize_Header
           (Result, SMB.Wire.Read_Command, 7, Tree_Id, Session_Id);
         SMB.Wire.Put_U16 (Result, 6, 1);
         SMB.Wire.Put_U32 (Result, 16, 1);
         return Result;
      end Response;

      function Validate
        (Data : SMB.Bytes; Tree_Id : SMB.DWord; Session_Id : SMB.QWord)
         return SMB.DWord
      is (SMB.Wire.Validate_Header
            (Data,
             (Command => SMB.Wire.Read_Command, Message_Id => 7,
              Tree_Id => Tree_Id, Session_Id => Session_Id,
              Signed => False)));

      procedure Read_U32 is
         Ignored : constant SMB.DWord := SMB.Wire.U32 (Packet, 61);
      begin
         null;
      end Read_U32;

      procedure Read_U64 is
         Ignored : constant SMB.QWord := SMB.Wire.U64 (Packet, 57);
      begin
         null;
      end Read_U64;

      procedure Write_U16 is
      begin
         SMB.Wire.Put_U16 (Packet, 63, 1);
      end Write_U16;

      procedure Write_U32 is
      begin
         SMB.Wire.Put_U32 (Packet, 61, 1);
      end Write_U32;

      procedure Write_U64 is
      begin
         SMB.Wire.Put_U64 (Packet, 57, 1);
      end Write_U64;

      procedure Initialize_Short is
      begin
         SMB.Wire.Initialize_Header (Short, SMB.Wire.Read_Command, 1);
      end Initialize_Short;

      procedure Other_Tree is
         Ignored : constant SMB.DWord := Validate (Response (2, 0), 1, 0);
      begin
         null;
      end Other_Tree;

      procedure Other_Session is
         Ignored : constant SMB.DWord := Validate (Response (0, 2), 0, 1);
      begin
         null;
      end Other_Session;
   begin
      Expect_Protocol_Error (Read_U32'Access, "U32 past the end was read");
      Expect_Protocol_Error (Read_U64'Access, "U64 past the end was read");
      Expect_Protocol_Error (Write_U16'Access, "U16 past the end was written");
      Expect_Protocol_Error (Write_U32'Access, "U32 past the end was written");
      Expect_Protocol_Error (Write_U64'Access, "U64 past the end was written");
      Expect_Protocol_Error
        (Initialize_Short'Access, "header in a 63-byte buffer was accepted");
      --  A header that fills the buffer up to Natural'Last has no body to
      --  clear, and the body's first index would overflow.
      SMB.Wire.Initialize_Header (Top, SMB.Wire.Read_Command, 9);
      Assert (SMB.Wire.U64 (Top, 24) = 9, "header ending at Natural'Last");
      Assert
        (Validate (Response (5, 9), 0, 0) = 0,
         "zero expected tree and session ids must not be compared");
      Assert
        (Validate (Response (5, 9), 5, 9) = 0,
         "matching tree and session ids");
      Expect_Protocol_Error (Other_Tree'Access, "wrong tree id was accepted");
      Expect_Protocol_Error
        (Other_Session'Access, "wrong session id was accepted");
      declare
         Failed : SMB.Bytes := Response (5, 9);
      begin
         SMB.Wire.Put_U32 (Failed, 8, 16#C0AB_CD22#);
         Assert (Validate (Failed, 5, 9) = 16#C0AB_CD22#,
                 "every byte of the NT status");
      end;
      SMB.Wire.Sign (Top, Key);
      Assert (SMB.Wire.Verify_Signature (Top, Key),
              "signature of a header ending at Natural'Last");
   end Test_Wire_Facade;
begin
   if Ada.Command_Line.Argument_Count > 0 then
      if Ada.Command_Line.Argument_Count /= 1
        or else (Ada.Command_Line.Argument (1) /= "transport-core"
                 and then Ada.Command_Line.Argument (1) /= "crypto-equality"
                 and then Ada.Command_Line.Argument (1) /= "transfer-progress"
                 and then Ada.Command_Line.Argument (1) /= "directory-counters"
                 and then Ada.Command_Line.Argument (1) /= "clock-core"
                 and then Ada.Command_Line.Argument (1) /= "path-contracts"
                 and then Ada.Command_Line.Argument (1) /= "utf-capacity"
                 and then Ada.Command_Line.Argument (1) /= "ntlm-uppercase"
                 and then Ada.Command_Line.Argument (1) /= "engine-receipts"
                 and then Ada.Command_Line.Argument (1) /= "auth-preflight"
                 and then Ada.Command_Line.Argument (1) /= "authentication"
                 and then Ada.Command_Line.Argument (1) /= "directory-bounds"
                 and then Ada.Command_Line.Argument (1) /= "read-reserved"
                 and then Ada.Command_Line.Argument (1) /= "error-reserved"
                 and then Ada.Command_Line.Argument (1) /= "teardown-reserved"
                 and then Ada.Command_Line.Argument (1) /= "connection-reserved"
                 and then Ada.Command_Line.Argument (1) /= "response-mutations"
                 and then Ada.Command_Line.Argument (1) /= "header-mutations"
                 and then Ada.Command_Line.Argument (1) /= "security-buffers"
                 and then Ada.Command_Line.Argument (1) /= "ntlm-maxlen"
                 and then Ada.Command_Line.Argument (1) /= "final-spnego"
                 and then Ada.Command_Line.Argument (1) /= "challenge-mutations"
                 and then Ada.Command_Line.Argument (1) /= "async-responses")
      then
         raise Program_Error with "unknown unit-test selection";
      end if;
      if Ada.Command_Line.Argument (1) = "crypto-equality" then
         Test_Crypto_Equality;
      elsif Ada.Command_Line.Argument (1) = "directory-counters" then
         Test_Directory_Counters;
      elsif Ada.Command_Line.Argument (1) = "transfer-progress" then
         Test_Transfer_Progress;
      elsif Ada.Command_Line.Argument (1) = "async-responses" then
         Async_Engine_Tests.Run;
         Ada.Text_IO.Put_Line ("AdaSMB async response tests passed");
      elsif Ada.Command_Line.Argument (1) = "challenge-mutations" then
         Challenge_Mutation_Tests;
      elsif Ada.Command_Line.Argument (1) = "final-spnego" then
         Test_Final_Spnego;
         Spnego_Mutation_Tests;
      elsif Ada.Command_Line.Argument (1) = "ntlm-maxlen" then
         Test_NTLM_Authenticate;
      elsif Ada.Command_Line.Argument (1) = "security-buffers" then
         Security_Buffer_Tests;
      elsif Ada.Command_Line.Argument (1) = "header-mutations" then
         Header_Mutation_Tests;
      elsif Ada.Command_Line.Argument (1) = "response-mutations" then
         Response_Mutation_Tests;
      elsif Ada.Command_Line.Argument (1) = "connection-reserved" then
         Test_Connection_Reserved;
         Ada.Text_IO.Put_Line ("AdaSMB connection reserved-field tests passed");
      elsif Ada.Command_Line.Argument (1) = "teardown-reserved" then
         Test_Teardown_Reserved;
         Ada.Text_IO.Put_Line ("AdaSMB teardown reserved-field tests passed");
      elsif Ada.Command_Line.Argument (1) = "error-reserved" then
         Test_Error_Reserved;
         Ada.Text_IO.Put_Line ("AdaSMB ERROR reserved-field tests passed");
      elsif Ada.Command_Line.Argument (1) = "read-reserved" then
         Test_Read_Reserved;
         Ada.Text_IO.Put_Line ("AdaSMB READ reserved-field tests passed");
      elsif Ada.Command_Line.Argument (1) = "directory-bounds" then
         Test_Directory_Bounds;
         Ada.Text_IO.Put_Line ("AdaSMB directory bounds tests passed");
      elsif Ada.Command_Line.Argument (1) = "authentication" then
         Test_Core_Client_Authentication;
         Ada.Text_IO.Put_Line ("AdaSMB authentication diagnostics passed");
      elsif Ada.Command_Line.Argument (1) = "auth-preflight" then
         Test_Authentication_Preflight;
         Ada.Text_IO.Put_Line ("AdaSMB authentication preflight tests passed");
      elsif Ada.Command_Line.Argument (1) = "engine-receipts" then
         Test_Engine_Receipts;
         Ada.Text_IO.Put_Line ("AdaSMB engine receipt tests passed");
      elsif Ada.Command_Line.Argument (1) = "utf-capacity" then
         Test_UTF_Capacity;
         Ada.Text_IO.Put_Line ("AdaSMB UTF capacity tests passed");
      elsif Ada.Command_Line.Argument (1) = "ntlm-uppercase" then
         Test_NTLM_Uppercase;
      elsif Ada.Command_Line.Argument (1) = "path-contracts" then
         Test_Path_Contracts;
         Ada.Text_IO.Put_Line ("AdaSMB path contract tests passed");
      elsif Ada.Command_Line.Argument (1) = "clock-core" then
         Test_Core_Clock;
         Ada.Text_IO.Put_Line ("AdaSMB clock core tests passed");
      else
         Test_Core_Transport;
         Ada.Text_IO.Put_Line ("AdaSMB transport core tests passed");
      end if;
      return;
   end if;
   declare
      Empty : SMB.Bytes (1 .. 0);
      Buffer : SMB.Bytes (11 .. 42);
   begin
      SMB.Entropy.Generate (Empty);
      SMB.Entropy.Generate (Buffer);
   end;
   Test_Crypto;
   Test_Crypto_Equality;
   Test_Authentication_Preflight;
   Test_Framing;
   Test_Core_Clock;
   Test_Path_Contracts;
   Test_UTF_Capacity;
   Test_NTLM_Uppercase;
   Test_Core_Transport;
   Test_Core_Wire;
   Test_Wire_Primitive_Boundaries;
   Test_NTLM_Authenticate;
   Test_Core_Client_Authentication;
   Test_Final_Spnego;
   Spnego_Mutation_Tests;
   Challenge_Mutation_Tests;
   Test_Core_Protocol;
   Test_Protocol_Builders;
   Test_Protocol_Parsers;
   Test_Transfer_Progress;
   Test_Directory_Counters;
   Response_Mutation_Tests;
   Header_Mutation_Tests;
   Security_Buffer_Tests;
   Test_Read_Reserved;
   Test_Error_Reserved;
   Test_Teardown_Reserved;
   Test_Connection_Reserved;
   Test_Directory_Bounds;
   Test_Engine_Malformed_Close;
   Test_Engine_Receipts;
   Async_Engine_Tests.Run;
   SMB.Heap_Owner_Tests.Run;
   Test_Text_And_Wire;
   Test_Wire_Facade;
   Ada.Text_IO.Put_Line ("AdaSMB unit tests passed");
end Test_Suite;
