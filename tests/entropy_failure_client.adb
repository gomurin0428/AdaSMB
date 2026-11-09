with Test_Dialects;
with Ada.Environment_Variables;
with Ada.Exceptions;
with Ada.Text_IO;
with Authentication_Test_Support;
with SMB.Client;

procedure Entropy_Failure_Client is
   use type Ada.Exceptions.Exception_Id;
   use type SMB.Bytes;
   use type SMB.DWord;
   use type Authentication_Test_Support.Failure_Kind;

   function Env (Name : String) return String renames Ada.Environment_Variables.Value;
   On_Call : constant Positive := Positive'Value (Env ("SMB_TEST_ENTROPY_CALL"));
   Kind : constant Authentication_Test_Support.Failure_Kind :=
     Authentication_Test_Support.Failure_Kind'Value (Env ("SMB_TEST_ENTROPY_KIND"));
   Expected : constant Ada.Exceptions.Exception_Id :=
     (if Kind = Authentication_Test_Support.State_Failure then SMB.Invalid_State'Identity
      elsif Kind = Authentication_Test_Support.Authentication_Failure or On_Call = 2
        then SMB.Authentication_Error'Identity
      else SMB.Protocol_Error'Identity);
   Client : SMB.Client.Connection;
   Rejected : Boolean := False;

   procedure Authenticate is
   begin
      SMB.Client.Authenticate (Client, Env ("SMB_TEST_USER"), Env ("SMB_TEST_PASSWORD"));
   end Authenticate;
begin
   if On_Call > 2 then
      raise Program_Error with "unsupported entropy injection point";
   end if;
   Authentication_Test_Support.Configure (On_Call, Kind);
   begin
      SMB.Client.Connect
        (Client, Env ("SMB_TEST_HOST"), Positive'Value (Env ("SMB_TEST_PORT")), 5.0,
         Entropy => Authentication_Test_Support.Generate'Access,
         Dialects => Test_Dialects.Policy);
      if On_Call = 2 then
         Authenticate;
      end if;
   exception
      when E : others =>
         if Ada.Exceptions.Exception_Identity (E) /= Expected then
            raise;
         end if;
         Rejected := True;
   end;
   if not Rejected or else SMB.Client.Is_Connected (Client)
     or else SMB.Client.Last_NT_Status (Client) /= 0
     or else SMB.Client.Last_Unverified_Authentication_Status (Client) /= 0
     or else Authentication_Test_Support.Calls /= On_Call
   then
      raise Program_Error with "entropy failure did not reject and clear state";
   end if;
   begin
      Authenticate;
      raise Program_Error with "authentication continued without reconnection";
   exception
      when SMB.Invalid_State => null;
   end;
   Ada.Text_IO.Put_Line ("entropy failure checkpoint");
   Ada.Text_IO.Flush;
   if Ada.Text_IO.Get_Line /= "failure-observed" then
      raise Program_Error with "missing entropy failure observation";
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
         raise Program_Error with "entropy failure recovery data mismatch";
      end if;
      SMB.Client.Close (Client, File);
   end;
   SMB.Client.Disconnect (Client);
   if SMB.Client.Is_Connected (Client)
     or else Authentication_Test_Support.Calls /= On_Call
   then
      raise Program_Error with "recovery retained failed callback or connection";
   end if;
   Ada.Text_IO.Put_Line
     ("entropy failure and default-source recovery passed: call"
      & Positive'Image (On_Call) & " "
      & Authentication_Test_Support.Failure_Kind'Image (Kind));
end Entropy_Failure_Client;
