with Ada.Environment_Variables;
with Ada.Text_IO;
with SMB.Client;

procedure Response_Mutation_Client is
   use type SMB.Bytes;

   function Env (Name : String) return String renames Ada.Environment_Variables.Value;
   Mode : constant String := Env ("SMB_TEST_MODE");
   Writing : constant Boolean :=
     Mode in "signed-write-zero" | "signed-write-over-request"
       | "signed-write-structure" | "signed-write-truncated";
   Client : SMB.Client.Connection;

   procedure Connect (Port : Positive) is
   begin
      SMB.Client.Connect (Client, Env ("SMB_TEST_HOST"), Port, 5.0);
      SMB.Client.Authenticate (Client, Env ("SMB_TEST_USER"), Env ("SMB_TEST_PASSWORD"));
      SMB.Client.Connect_Share (Client, Env ("SMB_TEST_SHARE"));
   end Connect;
begin
   Connect (Positive'Value (Env ("SMB_TEST_PORT")));
   declare
      Old_File : constant SMB.Client.Handle := SMB.Client.Open_File
        (Client, (if Writing then "mutation-write.bin" else "fixture.txt"),
         (if Writing then SMB.Client.Read_Write else SMB.Client.Read_Only));
      Rejected : Boolean := False;
   begin
      begin
         if Writing then
            SMB.Client.Write (Client, Old_File, 0, SMB.Bytes'(0 => 66));
         else
            declare
               Data : constant SMB.Bytes := SMB.Client.Read (Client, Old_File, 0, 1);
               pragma Unreferenced (Data);
            begin
               null;
            end;
         end if;
      exception
         when SMB.Protocol_Error => Rejected := True;
      end;
      if not Rejected or else SMB.Client.Is_Connected (Client) then
         raise Program_Error with "signed IO mutation was not rejected and disconnected";
      end if;
      Connect (Positive'Value (Env ("SMB_TEST_BACKEND_PORT")));
      declare
         File : SMB.Client.Handle := SMB.Client.Open_File
           (Client, (if Writing then "mutation-write.bin" else "fixture.txt"),
            SMB.Client.Read_Only);
      begin
         if SMB.Client.Read (Client, File, 0, 1) /=
           SMB.Bytes'(0 => (if Writing then 66 else 65))
         then
            raise Program_Error with "reconnected data or remote WRITE effect mismatch";
         end if;
         SMB.Client.Close (Client, File);
      end;
      begin
         declare
            Data : constant SMB.Bytes := SMB.Client.Read (Client, Old_File, 0, 1);
            pragma Unreferenced (Data);
         begin
            raise Program_Error with "stale pre-disconnect handle accepted";
         end;
      exception
         when SMB.Invalid_State => null;
      end;
      if not SMB.Client.Is_Connected (Client) then
         raise Program_Error with "stale handle rejection destroyed recovered connection";
      end if;
   end;
   SMB.Client.Disconnect (Client);
   Ada.Text_IO.Put_Line ("signed response mutation and recovery passed: " & Mode);
end Response_Mutation_Client;
