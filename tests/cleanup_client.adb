with Ada.Environment_Variables;
with Ada.Text_IO;
with SMB;
with SMB.Client;

procedure Cleanup_Client is
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
   Reached_Create : Boolean := False;
   Client : SMB.Client.Connection;
begin
   SMB.Client.Connect (Client, Host, Proxy_Port, 5.0);
   SMB.Client.Authenticate (Client, User, Password);
   SMB.Client.Connect_Share (Client, Share);
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
exception
   when others =>
      SMB.Client.Disconnect (Client);
      raise;
end Cleanup_Client;
