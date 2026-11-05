package body Engine_Fixtures is
   use type SMB.DWord;

   procedure Assert (Condition : Boolean; Message : String) is
   begin
      if not Condition then
         raise Program_Error with Message;
      end if;
   end Assert;

   procedure Setup_Share
     (State : in out SMB.Engine.Engine_State;
      Message_Id : out SMB.QWord;
      Expected : out SMB.Engine.Request_Expectation;
      Status : out SMB.Core_Status;
      Stop_At : Fixture_Stage := Shared;
      Session : SMB.QWord := Session_Id;
      Reconnect : Boolean := False;
      Maximum_Read, Maximum_Write : Natural := 65_536) is
   begin
      Message_Id := 0;
      Expected := (others => <>);
      SMB.Engine.Invalidate (State, Status);
      Assert (Status = SMB.Ok, "async fixture reset");
      if not Reconnect then
         SMB.Engine.Initialize (State, Status);
         Assert (Status = SMB.Ok, "async fixture engine initialization");
      end if;
      SMB.Engine.Mark_Connected (State, Status);
      Assert (Status = SMB.Ok, "async fixture transport connection");
      if Stop_At = Connected then
         return;
      end if;
      declare
         Packet : SMB.Bytes (0 .. 127) := (others => 0);
         Nt_Status : SMB.DWord;
      begin
         SMB.Engine.Begin_Request
           (State, 0, False, False, Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "async fixture negotiate request");
         SMB.Wire.Initialize_Header (Packet, 0, Message_Id, 0, 0);
         SMB.Wire.Put_U32 (Packet, 16, 1);
         Packet (64) := 65;
         Packet (66) := 1;
         Packet (68) := 16#10#;
         Packet (69) := 2;
         SMB.Wire.Put_U32 (Packet, 96, SMB.DWord (Maximum_Read));
         SMB.Wire.Put_U32 (Packet, 100, SMB.DWord (Maximum_Write));
         SMB.Engine.Accept_Response (State, Packet, Nt_Status, Status);
      end;
      Assert
        (Status = SMB.Ok,
         "async fixture negotiate response: " & SMB.Core_Status'Image (Status));
      SMB.Engine.Mark_Negotiated
        (State, Maximum_Read, Maximum_Write, Status);
      Assert (Status = SMB.Ok, "async fixture negotiation state");
      if Stop_At = Negotiated then
         return;
      end if;
      declare
         Packet : SMB.Bytes (0 .. 71) := (others => 0);
         Nt_Status : SMB.DWord;
      begin
         SMB.Engine.Begin_Request
           (State, 1, False, False, Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "async fixture challenge request");
         SMB.Wire.Initialize_Header
           (Packet, 1, Message_Id, 0, Session);
         SMB.Wire.Put_U32 (Packet, 16, 1);
         SMB.Wire.Put_U32 (Packet, 8, SMB.Status_More_Processing_Required);
         Packet (64) := 9;
         SMB.Engine.Accept_Response (State, Packet, Nt_Status, Status);
         Assert
           (Status = SMB.Ok
            and then Nt_Status = SMB.Status_More_Processing_Required,
            "async fixture challenge response");
         SMB.Engine.Install_Session_Key (State, Session, Key, Status);
         Assert (Status = SMB.Ok, "async fixture signing key");
      end;
      if Stop_At = Keyed then
         return;
      end if;
      declare
         Packet : SMB.Bytes (0 .. 100) := (others => 0);
         Nt_Status : SMB.DWord;
      begin
         SMB.Engine.Begin_Request
           (State, 1, False, True, Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "async fixture authenticate request");
         SMB.Wire.Initialize_Header
           (Packet, 1, Message_Id, 0, Session);
         SMB.Wire.Put_U32 (Packet, 16, 9);
         Packet (64) := 9;
         SMB.Wire.Put_U16 (Packet, 68, 72);
         SMB.Wire.Put_U16 (Packet, 70, Final_Token'Length);
         for Index in Final_Token'Range loop
            Packet (72 + Index) := Final_Token (Index);
         end loop;
         SMB.Wire.Sign (Packet, Key);
         SMB.Engine.Accept_Response (State, Packet, Nt_Status, Status);
         Assert
           (Status = SMB.Ok,
            "async fixture signed authentication: "
            & SMB.Core_Status'Image (Status));
         SMB.Engine.Mark_Authenticated (State, Status);
         Assert (Status = SMB.Ok, "async fixture authenticated state");
      end;
      if Stop_At = Authenticated then
         return;
      end if;
      declare
         Packet : SMB.Bytes (0 .. 79) := (others => 0);
         Nt_Status : SMB.DWord;
      begin
         SMB.Engine.Begin_Request
           (State, 3, True, True, Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "async fixture tree request");
         SMB.Wire.Initialize_Header
           (Packet, 3, Message_Id, Tree_Id, Session);
         SMB.Wire.Put_U32 (Packet, 16, 9);
         Packet (64) := 16;
         Packet (66) := 1;
         SMB.Wire.Sign (Packet, Key);
         SMB.Engine.Accept_Response (State, Packet, Nt_Status, Status);
         Assert (Status = SMB.Ok, "async fixture signed tree response");
         SMB.Engine.Mark_Share_Connected (State, Tree_Id, Status);
         Assert (Status = SMB.Ok, "async fixture share state");
      end;
   end Setup_Share;

   function Signed_Response
     (Command : SMB.Wire.Command_Code;
      Message_Id : SMB.QWord;
      Last : Natural;
      Structure : SMB.Word;
      Body_Bytes : SMB.Bytes := (1 .. 0 => 0);
      Session : SMB.QWord := Session_Id) return SMB.Bytes
   is
      Packet : SMB.Bytes (0 .. Last) := (others => 0);
   begin
      SMB.Wire.Initialize_Header
        (Packet, Command, Message_Id, Tree_Id, Session);
      SMB.Wire.Put_U32 (Packet, 16, 9);
      SMB.Wire.Put_U16 (Packet, 64, Structure);
      for Index in Body_Bytes'Range loop
         Packet (66 + Index - Body_Bytes'First) := Body_Bytes (Index);
      end loop;
      SMB.Wire.Sign (Packet, Key);
      return Packet;
   end Signed_Response;

   procedure Open_Handle
     (State : in out SMB.Engine.Engine_State;
      Token : out SMB.Engine.Handle_Token;
      Access_Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
      Directory : Boolean := False)
   is
      Message_Id : SMB.QWord;
      Expected : SMB.Engine.Request_Expectation;
      Status : SMB.Core_Status;
      Nt_Status : SMB.DWord;
      Body_Bytes : SMB.Bytes (66 .. 143) := (others => 0);
   begin
      SMB.Engine.Begin_Request
        (State, 5, True, True, Message_Id, Expected, Status);
      Assert (Status = SMB.Ok, "CREATE request for a handle");
      Body_Bytes (128 .. 143) := File_Id;
      SMB.Engine.Accept_Response
        (State, Signed_Response (5, Message_Id, 151, 89, Body_Bytes),
         Nt_Status, Status);
      Assert (Status = SMB.Ok, "CREATE response for a handle");
      SMB.Engine.Register_Handle
        (State, File_Id, Access_Mode, Directory, Token, Status);
      Assert (Status = SMB.Ok, "register the handle");
   end Open_Handle;

   procedure Close_Open_Handle
     (State : in out SMB.Engine.Engine_State;
      Token : SMB.Engine.Handle_Token)
   is
      Message_Id : SMB.QWord;
      Expected : SMB.Engine.Request_Expectation;
      Status : SMB.Core_Status;
      Nt_Status : SMB.DWord;
   begin
      SMB.Engine.Begin_Request
        (State, 6, True, True, Message_Id, Expected, Status,
         Close_Token => Token);
      Assert (Status = SMB.Ok, "CLOSE request for the handle");
      SMB.Engine.Accept_Response
        (State, Signed_Response (6, Message_Id, 123, 60), Nt_Status, Status);
      Assert (Status = SMB.Ok, "CLOSE response for the handle");
      SMB.Engine.Close_Handle (State, Token, Status, Close_Token => Token);
      Assert (Status = SMB.Ok, "close the handle");
   end Close_Open_Handle;
end Engine_Fixtures;
