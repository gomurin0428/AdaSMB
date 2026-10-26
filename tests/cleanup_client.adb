with Ada.Environment_Variables;
with Ada.Text_IO;
with SMB;
with SMB.Client;

procedure Cleanup_Client is
   use type SMB.Byte;

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
   SMB.Client.Connect (Client, Host, Proxy_Port, 5.0);
   SMB.Client.Authenticate (Client, User, Password);
   SMB.Client.Connect_Share (Client, Share);
   if Mode = "interrupted-read-after-progress" then
      declare
         File : constant SMB.Client.Handle :=
           SMB.Client.Open_File (Client, "interrupted-read.bin",
                                 SMB.Client.Read_Only);
         Rejected : Boolean := False;
      begin
         begin
            declare
               Ignored : constant SMB.Bytes :=
                 SMB.Client.Read (Client, File, 0, 70_001);
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
      end;
      SMB.Client.Connect (Client, Host, Backend_Port, 5.0);
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
      SMB.Client.Disconnect (Client);
      Ada.Text_IO.Put_Line
        ("interrupted READ cleanup and same-connection reconnect passed");
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

         SMB.Client.Connect (Client, Host, Backend_Port, 5.0);
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
      SMB.Client.Connect (Client, Host, Backend_Port, 5.0);
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
