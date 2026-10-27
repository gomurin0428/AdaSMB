with Ada.Environment_Variables;
with Ada.Real_Time;
with Ada.Text_IO;
with SMB;
with SMB.Client;

procedure Async_Client is
   use type SMB.Bytes;
   use type SMB.DWord;
   use type Ada.Real_Time.Time;
   Mode : constant String :=
     Ada.Environment_Variables.Value ("SMB_TEST_MODE");
   Host : constant String :=
     Ada.Environment_Variables.Value ("SMB_TEST_HOST");
   Port : constant Positive :=
     Positive'Value (Ada.Environment_Variables.Value ("SMB_TEST_PORT"));
   Backend_Port : constant Positive :=
     Positive'Value (Ada.Environment_Variables.Value ("SMB_TEST_BACKEND_PORT"));
   Share : constant String :=
     Ada.Environment_Variables.Value ("SMB_TEST_SHARE");
   User : constant String :=
     Ada.Environment_Variables.Value ("SMB_TEST_USER");
   Password : constant String :=
     Ada.Environment_Variables.Value ("SMB_TEST_PASSWORD");
   Client : SMB.Client.Connection;
begin
   SMB.Client.Connect (Client, Host, Port, (if Mode = "repeat-pending" then 0.5 else 5.0));
   SMB.Client.Authenticate (Client, User, Password);
   SMB.Client.Connect_Share (Client, Share);
   if Mode = "async-success" then
      declare
         Failed : Boolean := False;
      begin
         begin
            declare
               Missing : SMB.Client.Handle :=
                 SMB.Client.Open_File (Client, "async-no-such-file");
            begin
               SMB.Client.Close (Client, Missing);
            end;
         exception
            when SMB.NT_Status_Error => Failed := True;
         end;
         if not Failed or else
           SMB.Client.Last_NT_Status (Client) /= SMB.Status_Object_Name_Not_Found
         then
            raise Program_Error with "signed async missing-file error was not reported";
         end if;
      end;
      declare
         File : SMB.Client.Handle := SMB.Client.Open_File
           (Client, "async-response.bin", SMB.Client.Read_Write, SMB.Client.Create_New);
         Data : constant SMB.Bytes (0 .. 2) := (16#41#, 16#53#, 16#59#);
      begin
         SMB.Client.Write (Client, File, 0, Data);
         if SMB.Client.Read (Client, File, 0, Data'Length) /= Data then
            raise Program_Error with "async success READ content mismatch";
         end if;
         SMB.Client.Close (Client, File);
      end;
      declare
         Entries : constant SMB.Client.Directory_Entry_Array :=
           SMB.Client.List_Directory (Client);
      begin
         if Entries'Length = 0 then
            raise Program_Error with "async success directory listing is empty";
         end if;
      end;
      SMB.Client.Rename (Client, "async-response.bin", "async-renamed.bin");
      SMB.Client.Remove_File (Client, "async-renamed.bin");
      SMB.Client.Disconnect (Client);
      Ada.Text_IO.Put_Line ("async success workflow passed");
      return;
   end if;
   declare
      Old_File : constant SMB.Client.Handle :=
        SMB.Client.Open_File (Client, "fixture.txt", SMB.Client.Read_Only);
      Rejected : Boolean := False;
      Original_Status : constant SMB.DWord := SMB.Client.Last_NT_Status (Client);
      Started : Ada.Real_Time.Time;
   begin
      Started := Ada.Real_Time.Clock;
      begin
         declare
            Data : constant SMB.Bytes := SMB.Client.Read (Client, Old_File, 0, 1);
            pragma Unreferenced (Data);
         begin
            raise Program_Error with "async negative response was accepted";
         end;
      exception
         when SMB.Protocol_Error =>
            if Mode = "repeat-pending" then
               raise Program_Error with "repeated pending did not reach deadline";
            end if;
            Rejected := True;
         when SMB.Transport_Error =>
            if Mode /= "repeat-pending" then
               raise Program_Error with "unexpected transport failure";
            end if;
            Rejected := True;
      end;
      if Mode = "repeat-pending" then
         declare
            Elapsed : constant Duration :=
              Ada.Real_Time.To_Duration (Ada.Real_Time.Clock - Started);
         begin
            if Elapsed < 0.4 or else Elapsed > 2.0 then
               raise Program_Error with "async deadline was renewed or misapplied";
            end if;
         end;
      end if;
      if not Rejected or else SMB.Client.Is_Connected (Client) then
         raise Program_Error with "invalid async response did not disconnect";
      end if;
      if SMB.Client.Last_NT_Status (Client) /= Original_Status then
         raise Program_Error with "interim response changed public NTSTATUS";
      end if;
      SMB.Client.Connect (Client, Host, Backend_Port, 5.0);
      SMB.Client.Authenticate (Client, User, Password);
      SMB.Client.Connect_Share (Client, Share);
      begin
         declare
            Data : constant SMB.Bytes := SMB.Client.Read (Client, Old_File, 0, 1);
            pragma Unreferenced (Data);
         begin
            raise Program_Error with "stale handle survived async failure";
         end;
      exception
         when SMB.Invalid_State => null;
      end;
      declare
         File : SMB.Client.Handle :=
           SMB.Client.Open_File (Client, "fixture.txt", SMB.Client.Read_Only);
      begin
         if SMB.Client.Read (Client, File, 0, 1) /= SMB.Bytes'(0 => 16#41#) then
            raise Program_Error with "async recovery read mismatch";
         end if;
         SMB.Client.Close (Client, File);
      end;
   end;
   SMB.Client.Disconnect (Client);
   Ada.Text_IO.Put_Line ("async rejection and recovery passed: " & Mode);
end Async_Client;
