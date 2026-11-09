with Test_Dialects;
with Ada.Environment_Variables;
with Ada.Exceptions;
with Ada.Strings.Fixed;
with Ada.Text_IO;
with SMB;
with SMB.Client;

procedure Auth_Diagnostic_Client is
   use type SMB.DWord;
   function Env (Name : String) return String is
     (Ada.Environment_Variables.Value (Name));
   Client : SMB.Client.Connection;
   Mode : constant String := Env ("SMB_TEST_MODE");
   Rejected : Boolean := False;
begin
   SMB.Client.Connect
     (Client, Env ("SMB_TEST_HOST"), Positive'Value (Env ("SMB_TEST_PORT")),
         Dialects => Test_Dialects.Policy);
   begin
      SMB.Client.Authenticate
        (Client, Env ("SMB_TEST_USER"), Env ("SMB_TEST_PASSWORD"));
   exception
      when E : SMB.Authentication_Error =>
         Rejected := True;
         if Mode = "unsigned-auth-error" then
            if SMB.Client.Last_Unverified_Authentication_Status (Client) /=
              16#C000_006D#
              or else Ada.Strings.Fixed.Index
                (Ada.Exceptions.Exception_Message (E), "unverified") = 0
            then
               raise Program_Error with "missing unverified authentication hint";
            end if;
         elsif SMB.Client.Last_Unverified_Authentication_Status (Client) /= 0 then
            raise Program_Error with "unexpected unverified authentication hint";
         end if;
   end;
   if not Rejected or else SMB.Client.Is_Connected (Client)
     or else SMB.Client.Last_NT_Status (Client) /= SMB.Success
   then
      raise Program_Error with "unverified authentication trusted or connected";
   end if;
   SMB.Client.Connect
     (Client, Env ("SMB_TEST_HOST"),
      Positive'Value (Env ("SMB_TEST_BACKEND_PORT")),
         Dialects => Test_Dialects.Policy);
   if SMB.Client.Last_Unverified_Authentication_Status (Client) /= 0 then
      raise Program_Error with "reconnect retained unverified hint";
   end if;
   SMB.Client.Authenticate
     (Client, Env ("SMB_TEST_USER"), Env ("SMB_TEST_PASSWORD"));
   SMB.Client.Connect_Share (Client, Env ("SMB_TEST_SHARE"));
   SMB.Client.Disconnect (Client);
   Ada.Text_IO.Put_Line ("authentication diagnostic and recovery passed: " & Mode);
end Auth_Diagnostic_Client;
