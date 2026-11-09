with Test_Dialects;
with Ada.Environment_Variables;
with Ada.Exceptions;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with SMB;
with SMB.Client;

procedure Cleanup_Client is
   use type SMB.Byte;
   use type SMB.Bytes;
   use type SMB.DWord;

   function Env (Name : String) return String is
   begin
      return Ada.Environment_Variables.Value (Name);
   end Env;

   Proxy_Port : constant Positive :=
     Positive'Value (Env ("SMB_TEST_PORT"));
   Backend_Port : constant Positive :=
     Positive'Value (Env ("SMB_TEST_BACKEND_PORT"));
   Host : constant String := Env ("SMB_TEST_HOST");
   Share : constant String := Env ("SMB_TEST_SHARE");
   User : constant String := Env ("SMB_TEST_USER");
   Password : constant String := Env ("SMB_TEST_PASSWORD");
   Mode : constant String :=
     Ada.Environment_Variables.Value ("SMB_TEST_MODE", "");
   Reached_Create : Boolean := False;
   Client : SMB.Client.Connection;
begin
   SMB.Client.Connect (Client, Host, Proxy_Port, 5.0,
         Dialects => Test_Dialects.Policy);
   SMB.Client.Authenticate (Client, User, Password);
   SMB.Client.Connect_Share (Client, Share);
   if Mode = "handle-capacity" then
      declare
         Limit : constant Positive := 256;

         procedure Reject_Extra_Operations (File : SMB.Client.Handle) is
         begin
            for Action in 1 .. 8 loop
               declare
                  Data : constant SMB.Bytes := SMB.Client.Read (Client, File, 1024, 1);
               begin
                  if Data'Length /= 0
                    or else SMB.Client.Last_NT_Status (Client) /= SMB.Status_End_Of_File
                  then
                     raise Program_Error with "capacity test did not establish EOF status";
                  end if;
               end;
               begin
                  case Action is
                     when 1 .. 3 =>
                        declare
                           Extra : SMB.Client.Handle := SMB.Client.Open_File
                             (Client,
                              (if Action = 2 then "capacity-created.txt" else "fixture.txt"),
                              (if Action = 1 then SMB.Client.Read_Only
                               else SMB.Client.Read_Write),
                              (if Action = 1 then SMB.Client.Open_Existing
                               elsif Action = 2 then SMB.Client.Create_New
                               else SMB.Client.Truncate_Existing));
                        begin
                           SMB.Client.Close (Client, Extra);
                        end;
                     when 4 =>
                        declare
                           Entries : constant SMB.Client.Directory_Entry_Array :=
                             SMB.Client.List_Directory (Client);
                           pragma Unreferenced (Entries);
                        begin
                           null;
                        end;
                     when 5 => SMB.Client.Make_Directory (Client, "capacity-new-dir");
                     when 6 => SMB.Client.Rename
                       (Client, "fixture.txt", "capacity-renamed.txt");
                     when 7 => SMB.Client.Remove_File (Client, "fixture.txt");
                     when 8 => SMB.Client.Remove_Directory (Client, "capacity-retained-dir");
                  end case;
                  raise Program_Error with "full handle table accepted another operation";
               exception
                  when Error : SMB.Invalid_State =>
                     if Ada.Exceptions.Exception_Message (Error) /=
                       "SMB CREATE cannot start: RESOURCE_LIMIT"
                     then
                        raise;
                     end if;
               end;
               if not SMB.Client.Is_Connected (Client)
                 or else SMB.Client.Last_NT_Status (Client) /= SMB.Status_End_Of_File
                 or else SMB.Client.Read (Client, File, 0, 1) /= SMB.Bytes'(0 => 65)
               then
                  raise Program_Error with "capacity refusal damaged state or handle";
               end if;
            end loop;
         end Reject_Extra_Operations;

         procedure Fill (Depth : Positive) is
            File : SMB.Client.Handle :=
              SMB.Client.Open_File (Client, "fixture.txt", SMB.Client.Read_Only);
         begin
            if Depth < Limit then
               Fill (Depth + 1);
               if SMB.Client.Read (Client, File, 0, 1) /= SMB.Bytes'(0 => 65) then
                  raise Program_Error with "capacity refusal damaged an older handle";
               end if;
               SMB.Client.Close (Client, File);
            else
               Reject_Extra_Operations (File);
               SMB.Client.Close (Client, File);
               declare
                  Entries : constant SMB.Client.Directory_Entry_Array :=
                    SMB.Client.List_Directory (Client);
               begin
                  if Entries'Length = 0 then
                     raise Program_Error with "released slot did not allow enumeration";
                  end if;
               end;
               declare
                  Replacement : SMB.Client.Handle :=
                    SMB.Client.Open_File (Client, "fixture.txt", SMB.Client.Read_Only);
               begin
                  if SMB.Client.Read (Client, Replacement, 0, 1) /= SMB.Bytes'(0 => 65) then
                     raise Program_Error with "released slot did not allow a new file";
                  end if;
                  SMB.Client.Close (Client, Replacement);
               end;
            end if;
         end Fill;
      begin
         SMB.Client.Make_Directory (Client, "capacity-retained-dir");
         Fill (1);
         SMB.Client.Remove_Directory (Client, "capacity-retained-dir");
      end;
      SMB.Client.Disconnect (Client);
      Ada.Text_IO.Put_Line
        ("256 handles, eight preflight refusals, retained status and slot reuse passed");
   elsif Mode = "read-reserved-fields" then
      declare
         File : SMB.Client.Handle :=
           SMB.Client.Open_File
             (Client, "interrupted-read.bin", SMB.Client.Read_Only);
         Contents : constant SMB.Bytes :=
           SMB.Client.Read (Client, File, 0, 70_001);
      begin
         if Contents'Length /= 70_001
           or else not SMB.Client.Is_Connected (Client)
           or else
             (for some Index in Contents'Range =>
                Contents (Index) /= SMB.Byte ((Index - Contents'First) mod 251))
         then
            raise Program_Error with "READ reserved fields changed returned data";
         end if;
         if SMB.Client.Read (Client, File, 100, 1) /= SMB.Bytes'(0 => 100) then
            raise Program_Error with "READ reserved fields broke handle reuse";
         end if;
         SMB.Client.Close (Client, File);
      end;
      SMB.Client.Disconnect (Client);
      Ada.Text_IO.Put_Line
        ("signed READ reserved fields, exact data and handle reuse passed");
   elsif Mode = "error-reserved-field" then
      declare
         File : SMB.Client.Handle :=
           SMB.Client.Open_File (Client, "fixture.txt", SMB.Client.Read_Only);
      begin
         begin
            declare
               Missing : SMB.Client.Handle :=
                 SMB.Client.Open_File
                   (Client, "reserved-error-missing.bin", SMB.Client.Read_Only);
            begin
               SMB.Client.Close (Client, Missing);
               raise Program_Error with "missing file unexpectedly opened";
            end;
         exception
            when SMB.NT_Status_Error =>
               if SMB.Client.Last_NT_Status (Client) /=
                 SMB.Status_Object_Name_Not_Found
               then
                  raise Program_Error with "ERROR reserved byte lost NTSTATUS";
               end if;
         end;
         if not SMB.Client.Is_Connected (Client)
           or else SMB.Client.Read (Client, File, 0, 1) /= SMB.Bytes'(0 => 65)
         then
            raise Program_Error with "ERROR reserved byte broke handle reuse";
         end if;
         SMB.Client.Close (Client, File);
      end;
      SMB.Client.Disconnect (Client);
      Ada.Text_IO.Put_Line
        ("signed ERROR reserved byte, NTSTATUS and handle reuse passed");
   elsif Mode = "connection-reserved-fields" then
      declare
         File : SMB.Client.Handle :=
           SMB.Client.Open_File (Client, "fixture.txt", SMB.Client.Read_Only);
      begin
         if SMB.Client.Read (Client, File, 0, 1) /= SMB.Bytes'(0 => 65) then
            raise Program_Error with "connection reserved fields broke file access";
         end if;
         SMB.Client.Close (Client, File);
      end;
      SMB.Client.Disconnect (Client);
      Ada.Text_IO.Put_Line
        ("NEGOTIATE and signed TREE_CONNECT reserved fields passed");
   elsif Mode = "teardown-reserved-fields" then
      declare
         Closed_File : SMB.Client.Handle :=
           SMB.Client.Open_File (Client, "fixture.txt", SMB.Client.Read_Only);
      begin
         SMB.Client.Close (Client, Closed_File);
      end;
      declare
         Reopened_File : SMB.Client.Handle :=
           SMB.Client.Open_File (Client, "fixture.txt", SMB.Client.Read_Only);
      begin
         if not SMB.Client.Is_Connected (Client)
           or else
             SMB.Client.Read (Client, Reopened_File, 0, 1) /=
               SMB.Bytes'(0 => 65)
         then
            raise Program_Error with "CLOSE reserved fields broke connection reuse";
         end if;
         SMB.Client.Close (Client, Reopened_File);
      end;
      SMB.Client.Disconnect (Client);
      if SMB.Client.Is_Connected (Client) then
         raise Program_Error with "teardown reserved fields prevented disconnect";
      end if;
      Ada.Text_IO.Put_Line
        ("signed CLOSE/TREE_DISCONNECT/LOGOFF reserved fields passed");
   elsif Mode = "interrupted-read-after-progress" then
      declare
         Old_File : constant SMB.Client.Handle :=
           SMB.Client.Open_File (Client, "interrupted-read.bin",
                                 SMB.Client.Read_Only);
         Rejected : Boolean := False;
      begin
         begin
            declare
               Ignored : constant SMB.Bytes :=
                 SMB.Client.Read (Client, Old_File, 0, 70_001);
               pragma Unreferenced (Ignored);
            begin
               raise Program_Error with
                 "tampered response after partial READ was accepted";
            end;
         exception
            when SMB.Protocol_Error =>
               Rejected := True;
         end;
         if not Rejected or else SMB.Client.Is_Connected (Client) then
            raise Program_Error with
              "interrupted READ did not invalidate the client";
         end if;
      SMB.Client.Connect (Client, Host, Backend_Port, 5.0,
         Dialects => Test_Dialects.Policy);
      SMB.Client.Authenticate (Client, User, Password);
      SMB.Client.Connect_Share (Client, Share);
      declare
         File : SMB.Client.Handle :=
           SMB.Client.Open_File (Client, "fixture.txt", SMB.Client.Read_Only);
      begin
         if SMB.Client.Read (Client, File, 0, 1)'Length /= 1 then
            raise Program_Error with "reconnected client did not read data";
         end if;
         SMB.Client.Close (Client, File);
      end;
      begin
         declare
            Ignored : constant SMB.Bytes :=
              SMB.Client.Read (Client, Old_File, 0, 1);
            pragma Unreferenced (Ignored);
         begin
            raise Program_Error with
              "pre-disconnect handle remained usable after reconnect";
         end;
      exception
         when SMB.Invalid_State =>
            null;
      end;
      SMB.Client.Disconnect (Client);
      Ada.Text_IO.Put_Line
        ("interrupted READ cleanup and same-connection reconnect passed");
      end;
   elsif Mode = "lost-write-response-after-progress" then
      declare
         Path : constant String := "lost-write-response-after-progress.bin";
         Data : SMB.Bytes (0 .. 70_000) := (others => 0);
         File : constant SMB.Client.Handle :=
           SMB.Client.Open_File
             (Client, Path, SMB.Client.Read_Write, SMB.Client.Create_New);
         Transport_Failed : Boolean := False;
         Stale_Read_Rejected : Boolean := False;
         Stale_Write_Rejected : Boolean := False;
      begin
         for Index in Data'Range loop
            Data (Index) := SMB.Byte (Index mod 251);
         end loop;
         begin
            SMB.Client.Write (Client, File, 0, Data);
            raise Program_Error with "WRITE with lost response was accepted";
         exception
            when SMB.Transport_Error =>
               Transport_Failed := True;
         end;
         if not Transport_Failed or else SMB.Client.Is_Connected (Client) then
            raise Program_Error with
              "lost WRITE response did not invalidate the client";
         end if;
         begin
            declare
               Ignored : constant SMB.Bytes :=
                 SMB.Client.Read (Client, File, 0, 1);
               pragma Unreferenced (Ignored);
            begin
               raise Program_Error with
                 "stale handle READ was accepted after transport loss";
            end;
         exception
            when SMB.Invalid_State =>
               Stale_Read_Rejected := True;
         end;
         begin
            SMB.Client.Write (Client, File, 0, SMB.Bytes'(0 => 0));
            raise Program_Error with
              "stale handle WRITE was accepted after transport loss";
         exception
            when SMB.Invalid_State =>
               Stale_Write_Rejected := True;
         end;
         if not Stale_Read_Rejected or else not Stale_Write_Rejected then
            raise Program_Error with
              "stale handle operations were not rejected";
         end if;

         SMB.Client.Connect (Client, Host, Backend_Port, 5.0,
         Dialects => Test_Dialects.Policy);
         SMB.Client.Authenticate (Client, User, Password);
         SMB.Client.Connect_Share (Client, Share);
         declare
            Reopened : SMB.Client.Handle :=
              SMB.Client.Open_File (Client, Path, SMB.Client.Read_Only);
            Observed : constant SMB.Bytes :=
              SMB.Client.Read (Client, Reopened, 0, Data'Length);
         begin
            if Observed'Length /= Data'Length then
               raise Program_Error with
                 "server retained" & Natural'Image (Observed'Length)
                 & " of" & Natural'Image (Data'Length)
                 & " bytes after lost WRITE response";
            end if;
            for Index in Data'Range loop
               if Observed (Observed'First + Index) /= Data (Index) then
                  raise Program_Error with
                    "server WRITE content differs at offset"
                    & Natural'Image (Index);
               end if;
            end loop;
            SMB.Client.Close (Client, Reopened);
         end;
         SMB.Client.Remove_File (Client, Path);
         SMB.Client.Disconnect (Client);
         Ada.Text_IO.Put_Line
           ("lost WRITE response after progress and same-connection reconnect passed");
      end;
   elsif Mode in "directory-page-boundary" | "directory-page-overflow"
     | "directory-entry-boundary" | "directory-entry-overflow"
   then
      declare
         Overflow : constant Boolean := Mode in
           "directory-page-overflow" | "directory-entry-overflow";
         Old_File : SMB.Client.Handle := SMB.Client.Open_File
           (Client, "fixture.txt", SMB.Client.Read_Only);
         Rejected : Boolean := False;
      begin
         begin
            declare
               Entries : constant SMB.Client.Directory_Entry_Array :=
                 SMB.Client.List_Directory (Client);
            begin
               if Overflow then
                  raise Program_Error with "directory limit was not enforced";
               end if;
               if Entries'Length /= 1
                 or else Ada.Strings.Unbounded.To_String
                   (Entries (Entries'First).Name) /= "fixture.txt"
               then
                  raise Program_Error with "boundary listing lost its witness entry";
               end if;
            end;
         exception
            when Error : SMB.Protocol_Error =>
               if not Overflow or else Ada.Strings.Fixed.Index
                 (Ada.Exceptions.Exception_Message (Error), "RESOURCE_LIMIT") = 0
               then
                  raise;
               end if;
               Rejected := True;
         end;
         if Overflow then
            if not Rejected or else SMB.Client.Is_Connected (Client) then
               raise Program_Error with "directory exhaustion did not disconnect";
            end if;
            SMB.Client.Connect (Client, Host, Backend_Port, 5.0,
         Dialects => Test_Dialects.Policy);
            SMB.Client.Authenticate (Client, User, Password);
            SMB.Client.Connect_Share (Client, Share);
            declare
               Entries : constant SMB.Client.Directory_Entry_Array :=
                 SMB.Client.List_Directory (Client);
               Fresh : SMB.Client.Handle := SMB.Client.Open_File
                 (Client, "fixture.txt", SMB.Client.Read_Only);
            begin
               if Entries'Length < 2
                 or else SMB.Client.Read (Client, Fresh, 0, 1) /= SMB.Bytes'(0 => 65)
               then
                  raise Program_Error with "directory limit reconnect did not recover";
               end if;
               SMB.Client.Close (Client, Fresh);
            end;
            begin
               declare
                  Ignored : constant SMB.Bytes := SMB.Client.Read (Client, Old_File, 0, 1);
                  pragma Unreferenced (Ignored);
               begin
                  raise Program_Error with "directory limit left stale handle usable";
               end;
            exception
               when SMB.Invalid_State => null;
            end;
         else
            if not SMB.Client.Is_Connected (Client)
              or else SMB.Client.Read (Client, Old_File, 0, 1) /= SMB.Bytes'(0 => 65)
            then
               raise Program_Error with "boundary listing broke existing handle";
            end if;
            SMB.Client.Close (Client, Old_File);
         end if;
         if not SMB.Client.Is_Connected (Client) then
            raise Program_Error with "directory test lost the recovered connection";
         end if;
      end;
      SMB.Client.Disconnect (Client);
      Ada.Text_IO.Put_Line ("signed directory limit and recovery passed: " & Mode);
   elsif Mode in "malformed-signed-directory-second-page"
     | "dangling-signed-directory-second-page"
     | "signed-directory-unpaired-high" | "signed-directory-unpaired-low"
     | "signed-directory-high-nonlow" | "signed-directory-embedded-nul"
   then
      declare
         Rejected : Boolean := False;
      begin
         begin
            declare
               Ignored : constant SMB.Client.Directory_Entry_Array :=
                 SMB.Client.List_Directory (Client);
               pragma Unreferenced (Ignored);
            begin
               raise Program_Error with
                 "malformed second directory page was accepted";
            end;
         exception
            when Error : SMB.Protocol_Error =>
               if Mode in "signed-directory-unpaired-high"
                 | "signed-directory-unpaired-low"
                 | "signed-directory-high-nonlow"
                 | "signed-directory-embedded-nul"
               then
                  if Ada.Exceptions.Exception_Message (Error) /=
                    "cannot extract SMB directory entry: INVALID_ENCODING"
                  then
                     raise;
                  end if;
               end if;
               Rejected := True;
         end;
         if not Rejected or else SMB.Client.Is_Connected (Client) then
            raise Program_Error with
              "malformed directory page did not invalidate the client";
         end if;
      end;
      SMB.Client.Connect (Client, Host, Backend_Port, 5.0,
         Dialects => Test_Dialects.Policy);
      SMB.Client.Authenticate (Client, User, Password);
      SMB.Client.Connect_Share (Client, Share);
      declare
         Entries : constant SMB.Client.Directory_Entry_Array :=
           SMB.Client.List_Directory (Client);
         File : SMB.Client.Handle :=
           SMB.Client.Open_File (Client, "fixture.txt", SMB.Client.Read_Only);
      begin
         if Entries'Length < 2
           or else SMB.Client.Read (Client, File, 0, 1)'Length /= 1
         then
            raise Program_Error with
              "directory reconnect did not list and read from backend";
         end if;
         SMB.Client.Close (Client, File);
      end;
      SMB.Client.Disconnect (Client);
      Ada.Text_IO.Put_Line
        ("malformed signed directory page cleanup and reconnect passed");
   elsif Mode = "malformed-signed-set-info" then
      declare
         Rejected : Boolean := False;
      begin
         begin
            SMB.Client.Rename
              (Client, "set-info-source.txt", "set-info-renamed.txt");
            raise Program_Error with
              "malformed signed SET_INFO response was accepted";
         exception
            when SMB.Protocol_Error =>
               Rejected := True;
         end;
         if not Rejected or else SMB.Client.Is_Connected (Client) then
            raise Program_Error with
              "malformed SET_INFO response did not disconnect the client";
         end if;
      end;
      SMB.Client.Connect (Client, Host, Backend_Port, 5.0,
         Dialects => Test_Dialects.Policy);
      SMB.Client.Authenticate (Client, User, Password);
      SMB.Client.Connect_Share (Client, Share);
      declare
         Renamed : SMB.Client.Handle :=
           SMB.Client.Open_File
             (Client, "set-info-renamed.txt", SMB.Client.Read_Only);
         Contents : constant SMB.Bytes :=
           SMB.Client.Read (Client, Renamed, 0, 24);
         Fixture : SMB.Client.Handle :=
           SMB.Client.Open_File (Client, "fixture.txt", SMB.Client.Read_Only);
      begin
         if Contents'Length /= 24
           or else SMB.Client.Read (Client, Fixture, 0, 1)'Length /= 1
         then
            raise Program_Error with
              "SET_INFO reconnect could not read renamed file and fixture";
         end if;
         if Contents /= SMB.Bytes'(16#73#, 16#65#, 16#74#, 16#2D#,
             16#69#, 16#6E#, 16#66#, 16#6F#, 16#2D#, 16#72#, 16#65#,
             16#6E#, 16#61#, 16#6D#, 16#65#, 16#64#, 16#2D#, 16#63#,
             16#6F#, 16#6E#, 16#74#, 16#65#, 16#6E#, 16#74#)
         then
            raise Program_Error with "renamed SET_INFO fixture content differs";
         end if;
         SMB.Client.Close (Client, Renamed);
         SMB.Client.Close (Client, Fixture);
      end;
      SMB.Client.Disconnect (Client);
      Ada.Text_IO.Put_Line
        ("malformed signed SET_INFO response and remote rename effect passed");
   elsif Mode = "malformed-signed-tree-disconnect" then
      declare
         Old_File : constant SMB.Client.Handle :=
           SMB.Client.Open_File
             (Client, "fixture.txt", SMB.Client.Read_Only);
         Rejected : Boolean := False;
      begin
         begin
            SMB.Client.Disconnect (Client);
            raise Program_Error with
              "malformed signed TREE_DISCONNECT response was accepted";
         exception
            when SMB.Protocol_Error =>
               Rejected := True;
         end;
         if not Rejected or else SMB.Client.Is_Connected (Client) then
            raise Program_Error with
              "malformed TREE_DISCONNECT did not disconnect the client";
         end if;
         SMB.Client.Connect (Client, Host, Backend_Port, 5.0,
         Dialects => Test_Dialects.Policy);
         SMB.Client.Authenticate (Client, User, Password);
         SMB.Client.Connect_Share (Client, Share);
         begin
            declare
               Ignored : constant SMB.Bytes :=
                 SMB.Client.Read (Client, Old_File, 0, 1);
               pragma Unreferenced (Ignored);
            begin
               raise Program_Error with
                 "pre-disconnect handle remained usable after reconnect";
            end;
         exception
            when SMB.Invalid_State =>
               null;
         end;
      end;
      declare
         File : SMB.Client.Handle :=
           SMB.Client.Open_File
             (Client, "fixture.txt", SMB.Client.Read_Only);
      begin
         if SMB.Client.Read (Client, File, 0, 1)'Length /= 1 then
            raise Program_Error with
              "reconnected client did not read the TREE_DISCONNECT fixture";
         end if;
         SMB.Client.Close (Client, File);
      end;
      SMB.Client.Disconnect (Client);
      Ada.Text_IO.Put_Line
        ("malformed signed TREE_DISCONNECT cleanup and reconnect passed");
   else
      Reached_Create := True;
      begin
         declare
            File : SMB.Client.Handle :=
              SMB.Client.Open_File
                (Client, "malformed-create-reconnect-test.bin",
                 SMB.Client.Read_Write, SMB.Client.Create_New);
         begin
            SMB.Client.Close (Client, File);
            raise Program_Error with "malformed signed CREATE was accepted";
         end;
      exception
         when SMB.Protocol_Error =>
            null;
      end;
      if not Reached_Create or else SMB.Client.Is_Connected (Client) then
         raise Program_Error with "malformed CREATE did not invalidate the client";
      end if;
      SMB.Client.Connect (Client, Host, Backend_Port, 5.0,
         Dialects => Test_Dialects.Policy);
      SMB.Client.Authenticate (Client, User, Password);
      SMB.Client.Connect_Share (Client, Share);
      declare
         File : SMB.Client.Handle :=
           SMB.Client.Open_File (Client, "fixture.txt", SMB.Client.Read_Only);
      begin
         SMB.Client.Close (Client, File);
      end;
      SMB.Client.Disconnect (Client);
      Ada.Text_IO.Put_Line
        ("malformed signed CREATE cleanup and same-connection reconnect passed");
   end if;
exception
   when others =>
      SMB.Client.Disconnect (Client);
      raise;
end Cleanup_Client;
