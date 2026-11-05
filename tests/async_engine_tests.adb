with SMB;
with SMB.Core_Wire;
with SMB.Engine;
with SMB.Wire;

package body Async_Engine_Tests is
   use type SMB.Core_Status;
   use type SMB.DWord;
   use type SMB.Byte;
   use type SMB.Engine.Phase;
   use type SMB.QWord;
   use type SMB.Core_Wire.Command_Code;

   Session_Id : constant SMB.QWord := 16#1234#;
   Tree_Id : constant SMB.DWord := 16#1020_3040#;
   Async_Id : constant SMB.QWord := 16#0102_0304_0506_0708#;
   Key : constant SMB.Bytes (0 .. 15) :=
     (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
   Invalidation_Check : Natural := 0;
   Final_Token : constant SMB.Bytes (0 .. 28) :=
     (16#A1#, 16#1B#, 16#30#, 16#19#,
      16#A0#, 16#03#, 16#0A#, 16#01#, 0,
      16#A3#, 16#12#, 16#04#, 16#10#,
      1, 0, 0, 0, 16#0A#, 16#FB#, 16#34#, 16#90#,
      16#3A#, 16#3E#, 16#4E#, 16#54#, 0, 0, 0, 0);

   procedure Assert (Condition : Boolean; Message : String) is
   begin
      if not Condition then
         raise Program_Error with Message;
      end if;
   end Assert;

   --  How far Setup_Share takes the engine.
   type Fixture_Stage is (Connected, Negotiated, Keyed, Authenticated, Shared);

   procedure Setup_Share
     (State : in out SMB.Engine.Engine_State;
      Message_Id : out SMB.QWord;
      Expected : out SMB.Engine.Request_Expectation;
      Status : out SMB.Core_Status;
      Stop_At : Fixture_Stage := Shared;
      Session : SMB.QWord := Session_Id) is
   begin
      Message_Id := 0;
      Expected := (others => <>);
      SMB.Engine.Invalidate (State, Status);
      Assert (Status = SMB.Ok, "async fixture reset");
      SMB.Engine.Initialize (State, Status);
      Assert (Status = SMB.Ok, "async fixture engine initialization");
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
         Packet (98) := 1;
         Packet (102) := 1;
         SMB.Engine.Accept_Response (State, Packet, Nt_Status, Status);
      end;
      Assert
        (Status = SMB.Ok,
         "async fixture negotiate response: " & SMB.Core_Status'Image (Status));
      SMB.Engine.Mark_Negotiated (State, 65_536, 65_536, Status);
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

   procedure Start_Read
     (State : in out SMB.Engine.Engine_State;
      Message_Id : out SMB.QWord;
      Expected : out SMB.Engine.Request_Expectation;
      Status : out SMB.Core_Status) is
   begin
      SMB.Engine.Begin_Request
        (State, 8, True, True, Message_Id, Expected, Status,
         Request_Amount => 1);
      Assert (Status = SMB.Ok, "async fixture READ request");
   end Start_Read;

   function Pending_Response
     (Message_Id, Reply_Session, Reply_Async : SMB.QWord;
      Byte_Count : SMB.DWord := 0;
      Credit : SMB.Word := 1;
      Command : SMB.Wire.Command_Code := 8) return SMB.Bytes is
      Packet : SMB.Bytes (0 .. 71) := (others => 0);
   begin
      SMB.Wire.Initialize_Header
        (Packet, Command, Message_Id, 0, Reply_Session);
      SMB.Wire.Put_U16 (Packet, 14, Credit);
      SMB.Wire.Put_U32 (Packet, 8, SMB.Status_Pending);
      SMB.Wire.Put_U32 (Packet, 16, 3);
      SMB.Wire.Put_U64 (Packet, 32, Reply_Async);
      SMB.Wire.Put_U16 (Packet, 64, 9);
      Packet (66) := 0;
      SMB.Wire.Put_U32 (Packet, 68, Byte_Count);
      return Packet;
   end Pending_Response;

   function Final_Response
     (Message_Id, Reply_Session, Reply_Async : SMB.QWord;
      Signed : Boolean := True) return SMB.Bytes is
      Packet : SMB.Bytes (0 .. 80) := (others => 0);
   begin
      SMB.Wire.Initialize_Header
        (Packet, 8, Message_Id, Tree_Id, Reply_Session);
      SMB.Wire.Put_U16 (Packet, 14, 0);
      SMB.Wire.Put_U32 (Packet, 16, (if Signed then 11 else 3));
      SMB.Wire.Put_U64 (Packet, 32, Reply_Async);
      SMB.Wire.Put_U16 (Packet, 64, 17);
      Packet (66) := 80;
      SMB.Wire.Put_U32 (Packet, 68, 1);
      Packet (80) := 16#41#;
      if Signed then
         SMB.Wire.Sign (Packet, Key);
      end if;
      return Packet;
   end Final_Response;

   procedure Check_Invalidated
     (State : SMB.Engine.Engine_State;
      Expected_Status, Actual_Status : SMB.Core_Status) is
   begin
      Invalidation_Check := Invalidation_Check + 1;
      Assert
        (Actual_Status = Expected_Status
         and then SMB.Engine.Current_Phase (State) = SMB.Engine.Disconnected
         and then SMB.Engine.Current_Async_Id (State) = 0
         and then not SMB.Engine.Has_Pending_Request (State)
         and then not SMB.Engine.Has_Signing_Key (State)
         and then not SMB.Engine.Has_Validated_Response (State)
         and then not SMB.Engine.Has_Open_Handles (State)
         and then SMB.Engine.Signing_Key_Is_Zero (State),
         "async invalidation check" & Natural'Image (Invalidation_Check)
         & " status=" & SMB.Core_Status'Image (Actual_Status)
         & " phase=" & SMB.Engine.Phase'Image
           (SMB.Engine.Current_Phase (State))
         & " async=" & SMB.QWord'Image
           (SMB.Engine.Current_Async_Id (State))
         & " pending=" & Boolean'Image
           (SMB.Engine.Has_Pending_Request (State))
         & " key=" & Boolean'Image (SMB.Engine.Has_Signing_Key (State))
         & " receipt=" & Boolean'Image
           (SMB.Engine.Has_Validated_Response (State))
         & " handles=" & Boolean'Image
           (SMB.Engine.Has_Open_Handles (State))
         & " zero-key=" & Boolean'Image
           (SMB.Engine.Signing_Key_Is_Zero (State)));
   end Check_Invalidated;

   --  A signed response to the pending request: header, structure size, and
   --  Body_Bytes written from offset 66.
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
      Token : out SMB.Engine.Handle_Token)
   is
      File_Id : constant SMB.Bytes (0 .. 15) := (others => 16#3C#);
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
        (State, File_Id, SMB.Engine.Read_Only, False, Token, Status);
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

   --  Requests that the phase, the signing flags or the arguments rule out,
   --  interim responses for every command that can go asynchronous, and
   --  responses that exceed what was requested.
   procedure Run_State_Checks is
      State : SMB.Engine.Engine_State;
      Message_Id : SMB.QWord;
      Expected : SMB.Engine.Request_Expectation;
      Status : SMB.Core_Status;
      Nt_Status : SMB.DWord;
      Is_Interim : Boolean;
      Token : SMB.Engine.Handle_Token;
      Packet : SMB.Bytes (0 .. 71);

      procedure Reject_Request
        (Command : SMB.Core_Wire.Command_Code;
         Request_Signed, Response_Signed : Boolean;
         Expected_Status : SMB.Core_Status;
         Label : String;
         Amount : Natural := 0;
         Close : SMB.Engine.Handle_Token := (others => 0))
      is
         Before : constant SMB.Engine.Engine_State := State;
      begin
         SMB.Engine.Begin_Request
           (State, Command, Request_Signed, Response_Signed, Message_Id,
            Expected, Status, Amount, Close);
         Assert
           (Status = Expected_Status and then SMB.Engine."=" (State, Before),
            Label & ": " & SMB.Core_Status'Image (Status));
      end Reject_Request;

      type Command_List is array (Positive range <>) of SMB.Core_Wire.Command_Code;
      Async_Commands : constant Command_List := (2, 4, 5, 6, 9, 14, 17);
   begin
      Setup_Share (State, Message_Id, Expected, Status, Stop_At => Connected);
      Reject_Request
        (0, True, False, SMB.Invalid_State_Status, "signed NEGOTIATE");
      Reject_Request
        (0, False, True, SMB.Invalid_State_Status,
         "NEGOTIATE expecting a signature");
      Reject_Request
        (1, False, False, SMB.Invalid_State_Status,
         "SESSION_SETUP before NEGOTIATE");
      Setup_Share (State, Message_Id, Expected, Status, Stop_At => Negotiated);
      Reject_Request
        (1, True, False, SMB.Invalid_State_Status, "signed SESSION_SETUP");
      Reject_Request
        (1, False, True, SMB.Invalid_State_Status,
         "SESSION_SETUP expecting a signature without a key");
      Reject_Request
        (3, True, True, SMB.Invalid_State_Status,
         "TREE_CONNECT before authentication");
      Reject_Request
        (2, True, True, SMB.Invalid_State_Status,
         "LOGOFF before authentication");
      Setup_Share (State, Message_Id, Expected, Status, Stop_At => Authenticated);
      Reject_Request
        (3, False, True, SMB.Invalid_State_Status, "unsigned TREE_CONNECT");
      Reject_Request
        (3, True, False, SMB.Invalid_State_Status,
         "TREE_CONNECT with an unsigned reply");
      Reject_Request
        (2, False, True, SMB.Invalid_State_Status, "unsigned LOGOFF");
      Reject_Request
        (2, True, False, SMB.Invalid_State_Status,
         "LOGOFF with an unsigned reply");
      Setup_Share (State, Message_Id, Expected, Status);
      Reject_Request (9, True, True, SMB.Invalid_Value, "WRITE of nothing");
      Open_Handle (State, Token);
      Reject_Request
        (6, True, True, SMB.Invalid_Handle_Status, "CLOSE for another owner",
         Close => (Owner => Token.Owner + 1, Epoch => Token.Epoch,
                   Ticket => Token.Ticket));
      Reject_Request
        (6, True, True, SMB.Invalid_Handle_Status, "CLOSE for another epoch",
         Close => (Owner => Token.Owner, Epoch => Token.Epoch + 1,
                   Ticket => Token.Ticket));
      Reject_Request
        (6, True, True, SMB.Invalid_Handle_Status, "CLOSE for ticket 0",
         Close => (Owner => Token.Owner, Epoch => Token.Epoch, Ticket => 0));
      Reject_Request
        (6, True, True, SMB.Invalid_Handle_Status,
         "CLOSE for a ticket never issued",
         Close => (Owner => Token.Owner, Epoch => Token.Epoch,
                   Ticket => Token.Ticket + 1));
      Close_Open_Handle (State, Token);
      Reject_Request
        (6, True, True, SMB.Invalid_Handle_Status, "CLOSE for a closed handle",
         Close => Token);

      for Command of Async_Commands loop
         Setup_Share (State, Message_Id, Expected, Status);
         if Command = 6 then
            Open_Handle (State, Token);
         end if;
         SMB.Engine.Begin_Request
           (State, Command, True, True, Message_Id, Expected, Status,
            Request_Amount => (if Command = 9 then 1 else 0),
            Close_Token => (if Command = 6 then Token else (others => 0)));
         Assert (Status = SMB.Ok, "request for an interim response");
         Packet := Pending_Response
           (Message_Id, Session_Id, Async_Id,
            Command => SMB.Wire.Command_Code (Command));
         SMB.Engine.Inspect_Interim_Response
           (State, Packet, Is_Interim, Status);
         Assert
           (Status = SMB.Ok and then Is_Interim,
            "interim response for command"
            & SMB.Core_Wire.Command_Code'Image (Command));
      end loop;
      Setup_Share (State, Message_Id, Expected, Status, Stop_At => Authenticated);
      SMB.Engine.Begin_Request
        (State, 3, True, True, Message_Id, Expected, Status);
      Packet := Pending_Response
        (Message_Id, Session_Id, Async_Id, Command => 3);
      SMB.Engine.Inspect_Interim_Response (State, Packet, Is_Interim, Status);
      Check_Invalidated (State, SMB.Unsupported_Feature, Status);
      Setup_Share (State, Message_Id, Expected, Status);
      Packet := Pending_Response (Message_Id + 1, Session_Id, Async_Id);
      SMB.Engine.Inspect_Interim_Response (State, Packet, Is_Interim, Status);
      Check_Invalidated (State, SMB.Invalid_State_Status, Status);
      Setup_Share (State, Message_Id, Expected, Status);
      Start_Read (State, Message_Id, Expected, Status);
      Packet := Pending_Response (Message_Id, Session_Id, Async_Id);
      SMB.Engine.Inspect_Interim_Response
        (State, Packet (0 .. 63), Is_Interim, Status);
      Check_Invalidated (State, SMB.Invalid_Protocol, Status);
      Setup_Share (State, Message_Id, Expected, Status);
      Start_Read (State, Message_Id, Expected, Status);
      Packet := Pending_Response (Message_Id, Session_Id, Async_Id);
      SMB.Engine.Inspect_Interim_Response
        (State, Packet (0 .. 69), Is_Interim, Status);
      Check_Invalidated (State, SMB.Invalid_Protocol, Status);
      Setup_Share (State, Message_Id, Expected, Status);
      Start_Read (State, Message_Id, Expected, Status);
      Packet := Pending_Response (Message_Id, Session_Id, Async_Id);
      SMB.Wire.Put_U16 (Packet, 64, 8);
      SMB.Engine.Inspect_Interim_Response (State, Packet, Is_Interim, Status);
      Check_Invalidated (State, SMB.Invalid_Protocol, Status);
      Setup_Share (State, Message_Id, Expected, Status);
      Start_Read (State, Message_Id, Expected, Status);
      Packet := Pending_Response (Message_Id, Session_Id, Async_Id);
      Packet (66) := 1;
      SMB.Engine.Inspect_Interim_Response (State, Packet, Is_Interim, Status);
      Check_Invalidated (State, SMB.Invalid_Protocol, Status);

      --  A WRITE reply may count at most the bytes requested, and a READ
      --  reply may carry at most the bytes requested.
      Setup_Share (State, Message_Id, Expected, Status);
      SMB.Engine.Begin_Request
        (State, 9, True, True, Message_Id, Expected, Status, Request_Amount => 1);
      SMB.Engine.Accept_Response
        (State, Signed_Response (9, Message_Id, 79, 17, (0, 0, 1, 0, 0, 0)),
         Nt_Status, Status);
      Assert (Status = SMB.Ok, "one-byte WRITE reply");
      for Count in SMB.Byte range 1 .. 3 loop
         Setup_Share (State, Message_Id, Expected, Status);
         SMB.Engine.Begin_Request
           (State, 9, True, True, Message_Id, Expected, Status,
            Request_Amount => 2);
         SMB.Engine.Accept_Response
           (State,
            Signed_Response (9, Message_Id, 79, 17, (0, 0, Count, 0, 0, 0)),
            Nt_Status, Status);
         if Count <= 2 then
            Assert (Status = SMB.Ok, "WRITE reply within the request");
         else
            Check_Invalidated (State, SMB.Invalid_Value, Status);
         end if;
      end loop;
      for Length in SMB.Byte range 1 .. 3 loop
         Setup_Share (State, Message_Id, Expected, Status);
         SMB.Engine.Begin_Request
           (State, 8, True, True, Message_Id, Expected, Status,
            Request_Amount => 2);
         SMB.Engine.Accept_Response
           (State,
            Signed_Response
              (8, Message_Id, 79 + Natural (Length), 17,
               (80, 0, Length, 0, 0, 0)),
            Nt_Status, Status);
         if Length <= 2 then
            Assert (Status = SMB.Ok, "READ reply within the request");
         else
            Check_Invalidated (State, SMB.Invalid_Value, Status);
         end if;
      end loop;

      --  A final SESSION_SETUP reply needs the MIC of the security token.
      Setup_Share (State, Message_Id, Expected, Status, Stop_At => Keyed);
      SMB.Engine.Begin_Request
        (State, 1, False, True, Message_Id, Expected, Status);
      SMB.Engine.Accept_Response
        (State, Signed_Response (1, Message_Id, 71, 9), Nt_Status, Status);
      Check_Invalidated (State, SMB.Invalid_Protocol, Status);

      --  Padding after the security token does not move the token.
      Setup_Share (State, Message_Id, Expected, Status, Stop_At => Keyed);
      SMB.Engine.Begin_Request
        (State, 1, False, True, Message_Id, Expected, Status);
      declare
         Padded : SMB.Bytes (0 .. 108) := (others => 0);
      begin
         SMB.Wire.Initialize_Header (Padded, 1, Message_Id, 0, Session_Id);
         SMB.Wire.Put_U32 (Padded, 16, 9);
         Padded (64) := 9;
         SMB.Wire.Put_U16 (Padded, 68, 72);
         SMB.Wire.Put_U16 (Padded, 70, Final_Token'Length);
         for Index in Final_Token'Range loop
            Padded (72 + Index) := Final_Token (Index);
         end loop;
         SMB.Wire.Sign (Padded, Key);
         SMB.Engine.Accept_Response (State, Padded, Nt_Status, Status);
         Assert (Status = SMB.Ok, "security token followed by padding");
         SMB.Engine.Mark_Authenticated (State, Status);
         Assert (Status = SMB.Ok, "authenticated after a padded reply");
      end;

      --  Session id 1 is a session id like any other.
      Setup_Share (State, Message_Id, Expected, Status, Session => 1);
      Assert (SMB.Engine.Current_Session_Id (State) = 1, "session id 1");
   end Run_State_Checks;

   procedure Run is
      State : SMB.Engine.Engine_State;
      Message_Id : SMB.QWord;
      Expected : SMB.Engine.Request_Expectation;
      Status : SMB.Core_Status;
      Nt_Status : SMB.DWord;
      Is_Interim : Boolean;
      Packet : SMB.Bytes (0 .. 71);
   begin
      Setup_Share (State, Message_Id, Expected, Status);
      Start_Read (State, Message_Id, Expected, Status);
      Packet := Pending_Response (Message_Id, Session_Id, Async_Id);
      SMB.Engine.Inspect_Interim_Response (State, Packet, Is_Interim, Status);
      Assert
        (Status = SMB.Ok and then Is_Interim
         and then SMB.Engine.Has_Pending_Request (State)
         and then SMB.Engine.Current_Async_Id (State) = Async_Id
         and then not SMB.Engine.Has_Validated_Response (State)
         and then SMB.Engine.Current_Phase (State) = SMB.Engine.Share_Connected
         and then SMB.Engine.Current_Session_Id (State) = Session_Id
         and then SMB.Engine.Current_Tree_Id (State) = Tree_Id
         and then SMB.Engine.Has_Signing_Key (State),
         "valid interim did not retain authenticated operation state");
      Packet := Pending_Response
        (Message_Id, Session_Id, Async_Id, Credit => 0);
      SMB.Engine.Inspect_Interim_Response (State, Packet, Is_Interim, Status);
      Assert
        (Status = SMB.Ok and then Is_Interim
         and then SMB.Engine.Current_Async_Id (State) = Async_Id
         and then SMB.Engine.Has_Pending_Request (State)
         and then not SMB.Engine.Has_Validated_Response (State),
         "same-ID interim repeat changed operation state");
      declare
         Final : constant SMB.Bytes :=
           Final_Response (Message_Id, Session_Id, Async_Id);
      begin
         SMB.Engine.Inspect_Interim_Response
           (State, Final, Is_Interim, Status);
         Assert
           (Status = SMB.Ok and then not Is_Interim
            and then SMB.Engine.Current_Async_Id (State) = Async_Id
            and then SMB.Engine.Has_Pending_Request (State)
            and then not SMB.Engine.Has_Validated_Response (State),
            "final response inspection changed pending state");
         SMB.Engine.Accept_Response (State, Final, Nt_Status, Status);
      end;
      Assert
        (Status = SMB.Ok and then Nt_Status = SMB.Success
         and then SMB.Engine.Current_Async_Id (State) = 0
         and then not SMB.Engine.Has_Pending_Request (State)
         and then SMB.Engine.Response_Receipt_Matches (State, 8, 0, True, False),
         "valid async final did not complete the operation");

      Setup_Share (State, Message_Id, Expected, Status);
      declare
         Final : constant SMB.Bytes :=
           Final_Response (Message_Id, Session_Id, Async_Id);
      begin
         SMB.Engine.Accept_Response (State, Final, Nt_Status, Status);
      end;
      Check_Invalidated (State, SMB.Invalid_State_Status, Status);

      Setup_Share (State, Message_Id, Expected, Status);
      Start_Read (State, Message_Id, Expected, Status);
      declare
         Final : SMB.Bytes := Final_Response (Message_Id, Session_Id, Async_Id);
      begin
         SMB.Wire.Put_U16 (Final, 14, 1);
         SMB.Wire.Sign (Final, Key);
         SMB.Engine.Accept_Response (State, Final, Nt_Status, Status);
      end;
      Check_Invalidated (State, SMB.Unsupported_Feature, Status);

      Setup_Share (State, Message_Id, Expected, Status);
      Start_Read (State, Message_Id, Expected, Status);
      Packet := Pending_Response (Message_Id, Session_Id, Async_Id);
      SMB.Wire.Put_U16 (Packet, 12, 9);
      SMB.Engine.Inspect_Interim_Response (State, Packet, Is_Interim, Status);
      Check_Invalidated (State, SMB.Correlation_Error, Status);

      Setup_Share (State, Message_Id, Expected, Status);
      Start_Read (State, Message_Id, Expected, Status);
      Packet := Pending_Response (Message_Id, Session_Id, Async_Id);
      SMB.Engine.Inspect_Interim_Response (State, Packet, Is_Interim, Status);
      Assert (Status = SMB.Ok and then Is_Interim, "async command fixture");
      declare
         Final : SMB.Bytes := Final_Response (Message_Id, Session_Id, Async_Id);
      begin
         SMB.Wire.Put_U16 (Final, 12, 9);
         SMB.Wire.Sign (Final, Key);
         SMB.Engine.Accept_Response (State, Final, Nt_Status, Status);
      end;
      Check_Invalidated (State, SMB.Correlation_Error, Status);

      Setup_Share (State, Message_Id, Expected, Status);
      Start_Read (State, Message_Id, Expected, Status);
      Packet := Pending_Response (Message_Id, Session_Id, Async_Id);
      SMB.Engine.Inspect_Interim_Response (State, Packet, Is_Interim, Status);
      declare
         Final : SMB.Bytes := Final_Response (Message_Id, Session_Id, 0);
      begin
         SMB.Wire.Put_U16 (Final, 14, 1);
         SMB.Wire.Put_U32 (Final, 16, 9);
         SMB.Wire.Put_U32 (Final, 36, Tree_Id);
         SMB.Wire.Sign (Final, Key);
         SMB.Engine.Accept_Response (State, Final, Nt_Status, Status);
      end;
      Check_Invalidated (State, SMB.Invalid_Protocol, Status);

      Setup_Share (State, Message_Id, Expected, Status);
      Start_Read (State, Message_Id, Expected, Status);
      Packet := Pending_Response (Message_Id, Session_Id, 0);
      SMB.Engine.Inspect_Interim_Response (State, Packet, Is_Interim, Status);
      Check_Invalidated (State, SMB.Correlation_Error, Status);

      Setup_Share (State, Message_Id, Expected, Status);
      Start_Read (State, Message_Id, Expected, Status);
      Packet := Pending_Response (Message_Id, Session_Id, Async_Id);
      SMB.Engine.Inspect_Interim_Response (State, Packet, Is_Interim, Status);
      Assert (Status = SMB.Ok and then Is_Interim, "async ID fixture");
      Packet := Pending_Response (Message_Id, Session_Id, Async_Id + 1);
      SMB.Engine.Inspect_Interim_Response (State, Packet, Is_Interim, Status);
      Check_Invalidated (State, SMB.Correlation_Error, Status);

      Setup_Share (State, Message_Id, Expected, Status);
      Start_Read (State, Message_Id, Expected, Status);
      Packet := Pending_Response (Message_Id + 1, Session_Id, Async_Id);
      SMB.Engine.Inspect_Interim_Response (State, Packet, Is_Interim, Status);
      Check_Invalidated (State, SMB.Correlation_Error, Status);

      Setup_Share (State, Message_Id, Expected, Status);
      Start_Read (State, Message_Id, Expected, Status);
      Packet := Pending_Response (Message_Id, Session_Id + 1, Async_Id);
      SMB.Engine.Inspect_Interim_Response (State, Packet, Is_Interim, Status);
      Check_Invalidated (State, SMB.Correlation_Error, Status);

      Setup_Share (State, Message_Id, Expected, Status);
      Start_Read (State, Message_Id, Expected, Status);
      Packet := Pending_Response (Message_Id, Session_Id, Async_Id, 1);
      SMB.Engine.Inspect_Interim_Response (State, Packet, Is_Interim, Status);
      Check_Invalidated (State, SMB.Invalid_Protocol, Status);

      Setup_Share (State, Message_Id, Expected, Status);
      Start_Read (State, Message_Id, Expected, Status);
      Packet := Pending_Response (Message_Id, Session_Id, Async_Id);
      SMB.Engine.Inspect_Interim_Response (State, Packet, Is_Interim, Status);
      declare
         Final : constant SMB.Bytes := Final_Response
           (Message_Id, Session_Id, Async_Id + 1);
      begin
         SMB.Engine.Accept_Response (State, Final, Nt_Status, Status);
      end;
      Check_Invalidated (State, SMB.Correlation_Error, Status);

      Setup_Share (State, Message_Id, Expected, Status);
      Start_Read (State, Message_Id, Expected, Status);
      Packet := Pending_Response (Message_Id, Session_Id, Async_Id);
      SMB.Engine.Inspect_Interim_Response (State, Packet, Is_Interim, Status);
      declare
         Final : constant SMB.Bytes := Final_Response
           (Message_Id + 1, Session_Id, Async_Id);
      begin
         SMB.Engine.Accept_Response (State, Final, Nt_Status, Status);
      end;
      Check_Invalidated (State, SMB.Correlation_Error, Status);

      Setup_Share (State, Message_Id, Expected, Status);
      Start_Read (State, Message_Id, Expected, Status);
      Packet := Pending_Response (Message_Id, Session_Id, Async_Id);
      SMB.Engine.Inspect_Interim_Response (State, Packet, Is_Interim, Status);
      declare
         Final : constant SMB.Bytes := Final_Response
           (Message_Id, Session_Id + 1, Async_Id);
      begin
         SMB.Engine.Accept_Response (State, Final, Nt_Status, Status);
      end;
      Check_Invalidated (State, SMB.Correlation_Error, Status);

      Setup_Share (State, Message_Id, Expected, Status);
      Start_Read (State, Message_Id, Expected, Status);
      Packet := Pending_Response (Message_Id, Session_Id, Async_Id);
      SMB.Engine.Inspect_Interim_Response (State, Packet, Is_Interim, Status);
      declare
         Final : constant SMB.Bytes := Final_Response
           (Message_Id, Session_Id, Async_Id, Signed => False);
      begin
         SMB.Engine.Accept_Response (State, Final, Nt_Status, Status);
      end;
      Check_Invalidated (State, SMB.Signature_Error, Status);

      Setup_Share (State, Message_Id, Expected, Status);
      Start_Read (State, Message_Id, Expected, Status);
      Packet := Pending_Response (Message_Id, Session_Id, Async_Id);
      SMB.Engine.Inspect_Interim_Response (State, Packet, Is_Interim, Status);
      declare
         Final : SMB.Bytes := Final_Response (Message_Id, Session_Id, Async_Id);
      begin
         Final (48) := Final (48) xor 1;
         SMB.Engine.Accept_Response (State, Final, Nt_Status, Status);
      end;
      Check_Invalidated (State, SMB.Signature_Error, Status);
      Run_State_Checks;
   end Run;
end Async_Engine_Tests;
