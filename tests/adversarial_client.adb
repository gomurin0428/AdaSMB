with Test_Dialects;
with Ada.Environment_Variables;
with Ada.Exceptions;
with Ada.Strings.Fixed;
with Ada.Text_IO;
with SMB;
with SMB.Client;

procedure Adversarial_Client is
   Mode : constant String := Ada.Environment_Variables.Value ("SMB_TEST_MODE");
   Host : constant String := Ada.Environment_Variables.Value ("SMB_TEST_HOST");
   Port : constant Positive :=
     Positive'Value (Ada.Environment_Variables.Value ("SMB_TEST_PORT"));
   function Is_Early_Failure return Boolean is
   begin
      return Mode in
        "truncated" | "oversized" | "wrong-correlation-negotiate"
        | "dribble-timeout";
   end Is_Early_Failure;
   --  An SMB 3.1.1 NEGOTIATE response altered on the way: the keys then
   --  differ from the server's, and the signed final SESSION_SETUP
   --  response fails its signature check, so Authenticate must raise
   --  Authentication_Error ("server did not complete signed SMB
   --  authentication").
   function Is_Negotiate_Tamper return Boolean is
     (Mode'Length > 10
      and then Mode (Mode'First .. Mode'First + 9) = "negotiate-");
begin
   declare
      Client : SMB.Client.Connection;
      Rejected : Boolean := False;
   begin
      if Is_Early_Failure then
         begin
            SMB.Client.Connect (Client, Host, Port, 2.0,
         Dialects => Test_Dialects.Policy);
         exception
            when E : SMB.Transport_Error =>
               if Mode = "dribble-timeout"
                 and then Ada.Strings.Fixed.Index
                   (Ada.Exceptions.Exception_Message (E), "timed out") = 0
               then
                  raise Program_Error with "dribble peer did not trigger timeout";
               end if;
               Rejected := True;
            when SMB.Protocol_Error =>
               Rejected := True;
         end;
         SMB.Client.Disconnect (Client);
      else
         declare
            Authenticated : Boolean := False;
         begin
            begin
               SMB.Client.Connect (Client, Host, Port, 5.0,
         Dialects => Test_Dialects.Policy);
               SMB.Client.Authenticate
                 (Client,
                  Ada.Environment_Variables.Value ("SMB_TEST_USER"),
                  Ada.Environment_Variables.Value ("SMB_TEST_PASSWORD"));
               Authenticated := True;
               SMB.Client.Connect_Share
                 (Client, Ada.Environment_Variables.Value ("SMB_TEST_SHARE"));
            exception
               when SMB.Protocol_Error =>
                  if Is_Negotiate_Tamper and then Authenticated then
                     raise Program_Error with
                       "tampered NEGOTIATE was not caught by authentication";
                  elsif not Is_Negotiate_Tamper and then not Authenticated then
                     raise Program_Error with
                       "authenticated-path proxy failed before authentication";
                  end if;
                  Rejected := True;
               when E : SMB.Authentication_Error =>
                  if not Is_Negotiate_Tamper then
                     raise;
                  end if;
                  Ada.Text_IO.Put_Line
                    ("authentication rejected: "
                     & Ada.Exceptions.Exception_Message (E));
                  Rejected := True;
            end;
            if Is_Negotiate_Tamper and then SMB.Client.Is_Connected (Client) then
               raise Program_Error with
                 "connection stayed open after a tampered NEGOTIATE";
            end if;
            SMB.Client.Disconnect (Client);
         end;
      end if;
      if not Rejected then
         raise Program_Error with "adversarial SMB response was accepted: " & Mode;
      end if;
   end;
   Ada.Text_IO.Put_Line ("adversarial case rejected: " & Mode);
end Adversarial_Client;
