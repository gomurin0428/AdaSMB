with SMB.Core_Protocol;
with SMB.Core_Request;

package body SMB.Core_Resize
  with SPARK_Mode
is
   pragma Unevaluated_Use_Of_Old (Allow);
   Header_Length : constant Natural := SMB.Core_Wire.Header_Size;

   --  The executable part of In_Flight, but for the stage and the pending
   --  request.
   function Context_Valid
     (Value : Resize_Operation;
      State : SMB.Engine.Engine_State) return Boolean
   with Post =>
     (if Context_Valid'Result then
        Value.Owner = SMB.Engine.Current_Owner_Id (State)
        and then Value.Epoch = SMB.Engine.Current_Epoch (State)
        and then Value.Expected.Command = Set_Info_Command
        and then Value.Expected.Signed
        and then Value.Expected.Request_Signed
        and then SMB.Engine.Current_Phase (State) =
          SMB.Engine.Share_Connected
        and then SMB.Engine.Handle_Matches
          (State, Value.Token, Value.File_Id, Value.Access_Mode,
           Value.Directory))
   is
      Id : SMB.Bytes (0 .. 15) := (others => 0);
      Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
      Is_Directory : Boolean := False;
      S : SMB.Core_Status;
   begin
      --  The expectation comes from Begin_Request in Prepare, and
      --  Validate_Handle rejects the other states the same way, so no
      --  pairing of these can be told apart.
      if Value.Expected.Command /= Set_Info_Command
        or else not Value.Expected.Signed
        or else not Value.Expected.Request_Signed
        or else Value.Owner /= SMB.Engine.Current_Owner_Id (State)
        or else Value.Epoch /= SMB.Engine.Current_Epoch (State)
        or else SMB.Engine.Current_Phase (State) /=
          SMB.Engine.Share_Connected
      then
         --  Only for an operation never prepared, or from before the
         --  connection was reset; every caller also requires the
         --  operation's own request pending, which neither can have.
         return False;
      end if;
      SMB.Engine.Validate_Handle
        --  Prepare took only a handle that may write, and a token's handle
        --  does not change, so asking for write access here adds nothing.
        (State, Value.Token, False, False, Id, Mode, Is_Directory, S);
      --  A token's handle does not change while its request is in flight,
      --  and a failed lookup clears its outputs, so every pairing of these
      --  fails the same way.
      if S /= SMB.Ok
        or else Id /= Value.File_Id
        or else Mode /= Value.Access_Mode
        or else Is_Directory /= Value.Directory
      then
         return False;
      end if;
      pragma Assert
        (for all Index in Value.File_Id'Range =>
           Id (Index) = Value.File_Id (Index));
      pragma Assert
        (SMB.Engine.Handle_Matches_Equivalent
           (State, Value.Token, Id, Value.File_Id, Mode, Is_Directory));
      return True;
   end Context_Valid;

   procedure Prepare
     (Value : in out Resize_Operation;
      State : in out SMB.Engine.Engine_State;
      Token : SMB.Engine.Handle_Token;
      Size : SMB.QWord;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   is
      Id : SMB.Bytes (0 .. 15) := (others => 0);
      Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
      Dir : Boolean := False;
      S : SMB.Core_Status;
      Body_Buffer : SMB.Bytes (0 .. Request_Size - Header_Length - 1);
      Body_Used : Natural;
      Message : SMB.QWord;
      Expected : SMB.Engine.Request_Expectation;
      Before_Begin : constant SMB.Engine.Engine_State := State with Ghost;
   begin
      Output := (others => 0);
      Used := 0;
      if Value.Stage /= Resize_Idle
        or else SMB.Engine.Current_Phase (State) /=
          SMB.Engine.Share_Connected
        or else SMB.Engine.Has_Pending_Request (State)
        or else SMB.Engine.Has_Validated_Response (State)
        or else Token.Owner /= SMB.Engine.Current_Owner_Id (State)
        or else Token.Epoch /= SMB.Engine.Current_Epoch (State)
        or else Token.Ticket = 0
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      SMB.Engine.Validate_Handle
        (State, Token, False, True, Id, Mode, Dir, S);
      if S /= SMB.Ok then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      if Size > Maximum_Size then
         Status := SMB.Invalid_Value;
         return;
      end if;
      if Output'Length < Request_Size then
         Status := SMB.Resource_Limit;
         return;
      end if;
      SMB.Core_Protocol.Build_End_Of_File
        (Id, Size, Body_Buffer, Body_Used, S);
      if S /= SMB.Ok then
         Status := S;
         return;
      end if;
      pragma Assert (Body_Used = Body_Buffer'Length);
      Output (Output'First + Header_Length ..
              Output'First + (Request_Size - 1)) := Body_Buffer;
      pragma Assert
        (for all Index in 0 .. Body_Buffer'Length - 1 =>
           Output (Output'First + Header_Length + Index) =
             Body_Buffer (Index));
      SMB.Engine.Begin_Request
        (State, Set_Info_Command, True, True, Message, Expected, S);
      if S /= SMB.Ok then
         Status := S;
         return;
      end if;
      pragma Assert
        (SMB.Engine.Handle_Matches_In_States
           (Before_Begin, State, Token, Id, Mode, Dir));
      SMB.Core_Request.Prepare_Header (Output, Expected, S);
      pragma Assert (S = SMB.Ok);
      SMB.Core_Request.Sign_Packet
        (Output, Request_Size, SMB.Engine.Current_Signing_Key (State),
         SMB.Engine.Current_Signing (State),
         SMB.Engine.Current_SMB3_Signing_Key (State), S);
      Value.Stage := Resize_Prepared;
      Value.Owner := SMB.Engine.Current_Owner_Id (State);
      Value.Epoch := SMB.Engine.Current_Epoch (State);
      Value.Token := Token;
      Value.File_Id := Id;
      Value.Access_Mode := Mode;
      Value.Directory := Dir;
      Value.Expected := Expected;
      Value.Size := Size;
      Used := Request_Size;
      Status := SMB.Ok;
   end Prepare;

   procedure Send_Succeeded
     (Value : in out Resize_Operation;
      State : SMB.Engine.Engine_State;
      Status : out SMB.Core_Status) is
   begin
      if Value.Stage /= Resize_Prepared
        or else not Context_Valid (Value, State)
        or else not SMB.Engine.Pending_Request_Matches
          (State, Value.Expected)
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      Value.Stage := Resize_Sent;
      Status := SMB.Ok;
   end Send_Succeeded;

   procedure Complete
     (Value : in out Resize_Operation;
      State : in out SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Nt_Status : out SMB.DWord;
      Status : out SMB.Core_Status)
   is
      Accept_Status, Receipt_Status : SMB.Core_Status;
      Before_Accept : constant SMB.Engine.Engine_State := State with Ghost;
   begin
      Nt_Status := 0;
      if Value.Stage /= Resize_Sent
        or else not Context_Valid (Value, State)
        or else not SMB.Engine.Pending_Request_Matches
          (State, Value.Expected)
        or else SMB.Engine.Has_Validated_Response (State)
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      SMB.Engine.Accept_Response (State, Packet, Nt_Status, Accept_Status);
      if Accept_Status /= SMB.Ok then
         --  Accept_Response has invalidated the connection. It reports
         --  Invalid_State_Status only without a matching pending request,
         --  which the checks above rule out; the postcondition keeps that
         --  status for a call that changed nothing.
         Value.Stage := Resize_Failed;
         Status :=
           (if Accept_Status = SMB.Invalid_State_Status
            then SMB.Invalid_Protocol else Accept_Status);
         return;
      end if;
      pragma Assert
        (SMB.Engine.Handle_Matches_In_States
           (Before_Accept, State, Value.Token, Value.File_Id,
            Value.Access_Mode, Value.Directory));
      declare
         Before_Discard : constant SMB.Engine.Engine_State := State
         with Ghost;
      begin
         SMB.Engine.Discard_Response_Receipt (State, Receipt_Status);
         pragma Assert (Receipt_Status = SMB.Ok);
         pragma Assert
           (SMB.Engine.Handle_Matches_In_States
              (Before_Discard, State, Value.Token, Value.File_Id,
               Value.Access_Mode, Value.Directory));
      end;
      Value.Stage := Resize_Finished;
      Status := SMB.Ok;
   end Complete;

   procedure Abort_Resize
     (Value : in out Resize_Operation;
      State : in out SMB.Engine.Engine_State;
      Status : out SMB.Core_Status) is
      S : SMB.Core_Status;
   begin
      --  A pending request that matches the operation's own is in flight,
      --  so the stage test adds nothing a test can see; the postcondition
      --  needs it.
      if Value.Stage not in Resize_Prepared | Resize_Sent
        or else not Context_Valid (Value, State)
        or else not SMB.Engine.Pending_Request_Matches
          (State, Value.Expected)
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      SMB.Engine.Invalidate (State, S);
      Value.Stage := Resize_Failed;
      Status := S;
   end Abort_Resize;
end SMB.Core_Resize;
