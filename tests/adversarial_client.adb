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
                  if not Authenticated then
                     raise Program_Error with
                       "authenticated-path proxy failed before authentication";
                  end if;
                  Rejected := True;
            end;
            SMB.Client.Disconnect (Client);
         end;
      end if;
      if not Rejected then
         raise Program_Error with "adversarial SMB response was accepted: " & Mode;
      end if;
   end;
   Ada.Text_IO.Put_Line ("adversarial case rejected: " & Mode);
end Adversarial_Client;
