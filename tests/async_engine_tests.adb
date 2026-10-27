with SMB;
with SMB.Engine;
with SMB.Wire;

package body Async_Engine_Tests is
   use type SMB.Core_Status;
   use type SMB.DWord;
   use type SMB.Byte;
   use type SMB.Engine.Phase;
   use type SMB.QWord;

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

   procedure Setup_Share
     (State : in out SMB.Engine.Engine_State;
      Message_Id : out SMB.QWord;
      Expected : out SMB.Engine.Request_Expectation;
      Status : out SMB.Core_Status) is
   begin
      SMB.Engine.Invalidate (State, Status);
      Assert (Status = SMB.Ok, "async fixture reset");
      SMB.Engine.Initialize (State, Status);
      Assert (Status = SMB.Ok, "async fixture engine initialization");
      SMB.Engine.Mark_Connected (State, Status);
      Assert (Status = SMB.Ok, "async fixture transport connection");
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
      declare
         Packet : SMB.Bytes (0 .. 71) := (others => 0);
         Nt_Status : SMB.DWord;
      begin
         SMB.Engine.Begin_Request
           (State, 1, False, False, Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "async fixture challenge request");
         SMB.Wire.Initialize_Header
           (Packet, 1, Message_Id, 0, Session_Id);
         SMB.Wire.Put_U32 (Packet, 16, 1);
         SMB.Wire.Put_U32 (Packet, 8, SMB.Status_More_Processing_Required);
         Packet (64) := 9;
         SMB.Engine.Accept_Response (State, Packet, Nt_Status, Status);
         Assert
           (Status = SMB.Ok
            and then Nt_Status = SMB.Status_More_Processing_Required,
            "async fixture challenge response");
         SMB.Engine.Install_Session_Key (State, Session_Id, Key, Status);
         Assert (Status = SMB.Ok, "async fixture signing key");
      end;
      declare
         Packet : SMB.Bytes (0 .. 100) := (others => 0);
         Nt_Status : SMB.DWord;
      begin
         SMB.Engine.Begin_Request
           (State, 1, False, True, Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "async fixture authenticate request");
         SMB.Wire.Initialize_Header
           (Packet, 1, Message_Id, 0, Session_Id);
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
      declare
         Packet : SMB.Bytes (0 .. 79) := (others => 0);
         Nt_Status : SMB.DWord;
      begin
         SMB.Engine.Begin_Request
           (State, 3, True, True, Message_Id, Expected, Status);
         Assert (Status = SMB.Ok, "async fixture tree request");
         SMB.Wire.Initialize_Header
           (Packet, 3, Message_Id, Tree_Id, Session_Id);
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
      Credit : SMB.Word := 1) return SMB.Bytes is
      Packet : SMB.Bytes (0 .. 71) := (others => 0);
   begin
      SMB.Wire.Initialize_Header (Packet, 8, Message_Id, 0, Reply_Session);
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
   end Run;
end Async_Engine_Tests;
