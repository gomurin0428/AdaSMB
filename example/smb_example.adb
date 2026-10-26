with Ada.Command_Line;
with Ada.Environment_Variables;
with Ada.Text_IO;
with SMB;
with SMB.Client;

procedure SMB_Example is
   use type SMB.Client.Access_Mode;
   use type SMB.QWord;

   function Environment (Name, Default : String := "") return String is
   begin
      if Ada.Environment_Variables.Exists (Name) then
         return Ada.Environment_Variables.Value (Name);
      end if;
      return Default;
   end Environment;

   Host : constant String :=
     (if Ada.Command_Line.Argument_Count >= 1
      then Ada.Command_Line.Argument (1) else "127.0.0.1");
   Share : constant String :=
     (if Ada.Command_Line.Argument_Count >= 2
      then Ada.Command_Line.Argument (2) else "public");
   Path : constant String :=
     (if Ada.Command_Line.Argument_Count >= 3
      then Ada.Command_Line.Argument (3) else "README.txt");
   User : constant String := Environment ("SMB_USER");
   Domain : constant String := Environment ("SMB_DOMAIN", "WORKGROUP");
   Password : constant String := Environment ("SMB_PASSWORD");
begin
   if User'Length = 0 or else Password'Length = 0 then
      raise Program_Error with "SMB_USER and SMB_PASSWORD must be set";
   end if;

   declare
      Client : SMB.Client.Connection;
   begin
      SMB.Client.Connect (Client, Host);
      SMB.Client.Authenticate
        (Client, User, Password, Domain);
      SMB.Client.Connect_Share (Client, Share);
      declare
         File : SMB.Client.Handle :=
           SMB.Client.Open_File (Client, Path, SMB.Client.Read_Only);
         Offset : SMB.QWord := 0;
      begin
         loop
            declare
               Data : constant SMB.Bytes :=
                 SMB.Client.Read (Client, File, Offset, 65_536);
            begin
               exit when Data'Length = 0;
               for Byte of Data loop
                  Ada.Text_IO.Put (Character'Val (Integer (Byte)));
               end loop;
               Offset := Offset + SMB.QWord (Data'Length);
            end;
         end loop;
         SMB.Client.Close (Client, File);
      end;
      SMB.Client.Disconnect (Client);
   end;
end SMB_Example;
