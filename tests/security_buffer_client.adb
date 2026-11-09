with Test_Dialects;
with Ada.Environment_Variables;
with Ada.Text_IO;
with SMB.Client;

procedure Security_Buffer_Client is
   use type SMB.Bytes;
   use type SMB.DWord;

   function Env (Name : String) return String renames Ada.Environment_Variables.Value;
   Mode : constant String := Env ("SMB_TEST_MODE");
   Negotiate : constant Boolean :=
     Mode in "negotiate-buffer-offset" | "negotiate-buffer-length";
   Final : constant Boolean :=
     Mode in "final-buffer-offset" | "final-buffer-length"
       | "final-spnego-mic" | "final-spnego-state"
       | "final-spnego-duplicate-state" | "final-spnego-missing-mic";
   Client : SMB.Client.Connection;
   Rejected : Boolean := False;

   procedure Authenticate is
   begin
      SMB.Client.Authenticate (Client, Env ("SMB_TEST_USER"), Env ("SMB_TEST_PASSWORD"));
   end Authenticate;
begin
   if not Negotiate then
      SMB.Client.Connect
        (Client, Env ("SMB_TEST_HOST"), Positive'Value (Env ("SMB_TEST_PORT")), 5.0,
         Dialects => Test_Dialects.Policy);
   end if;
   begin
      if Negotiate then
         SMB.Client.Connect
           (Client, Env ("SMB_TEST_HOST"), Positive'Value (Env ("SMB_TEST_PORT")), 5.0,
         Dialects => Test_Dialects.Policy);
      else
         Authenticate;
      end if;
   exception
      when SMB.Protocol_Error =>
         if Final then
            raise;
         end if;
         Rejected := True;
      when SMB.Authentication_Error =>
         if not Final then
            raise;
         end if;
         Rejected := True;
   end;
   if not Rejected or else SMB.Client.Is_Connected (Client)
     or else SMB.Client.Last_NT_Status (Client) /= 0
     or else SMB.Client.Last_Unverified_Authentication_Status (Client) /= 0
   then
      raise Program_Error with "security-buffer failure did not reject and clear state";
   end if;
   SMB.Client.Connect
     (Client, Env ("SMB_TEST_HOST"), Positive'Value (Env ("SMB_TEST_BACKEND_PORT")), 5.0,
         Dialects => Test_Dialects.Policy);
   Authenticate;
   SMB.Client.Connect_Share (Client, Env ("SMB_TEST_SHARE"));
   declare
      File : SMB.Client.Handle := SMB.Client.Open_File (Client, "fixture.txt");
   begin
      if SMB.Client.Read (Client, File, 0, 1) /= SMB.Bytes'(0 => 65) then
         raise Program_Error with "security-buffer recovery data mismatch";
      end if;
      SMB.Client.Close (Client, File);
   end;
   SMB.Client.Disconnect (Client);
   Ada.Text_IO.Put_Line ("security-buffer rejection and recovery passed: " & Mode);
end Security_Buffer_Client;
