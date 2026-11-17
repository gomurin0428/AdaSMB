with SMB.AES;
with SMB.Core_Negotiate;

package body SMB.Core_Query
  with SPARK_Mode
is
   pragma Unevaluated_Use_Of_Old (Allow);
   Header_Length : constant Natural := SMB.Core_Wire.Header_Size;

   --  The header and signing steps are those of SMB.Core_Client and
   --  SMB.Core_Connection, each of which keeps its own copy as well.
   procedure Prepare_Header
     (Packet : in out SMB.Bytes;
      Expected : SMB.Engine.Request_Expectation;
      Status : out SMB.Core_Status)
   with Pre => Packet'Length <= SMB.Maximum_Frame_Size,
     Post =>
       (if Packet'Length >= Header_Length then Status = SMB.Ok)
       and then (if Status = SMB.Ok then
          SMB.Core_Wire.Encoded_U16 (Packet, 4) =
            SMB.Word (Header_Length)
          and then SMB.Core_Wire.Encoded_U16 (Packet, 12) =
            SMB.Word (Expected.Command)
          and then SMB.Core_Wire.Encoded_U32 (Packet, 16) =
            (if Expected.Request_Signed then 8 else 0)
          and then SMB.Core_Wire.Encoded_U64 (Packet, 24) =
            Expected.Message_Id
          and then SMB.Core_Wire.Encoded_U32 (Packet, 36) =
            Expected.Tree_Id
          and then SMB.Core_Wire.Encoded_U64 (Packet, 40) =
            Expected.Session_Id
          and then
            (for all Index in Packet'Range =>
               (if Index - Packet'First >= Header_Length then
                  Packet (Index) = Packet'Old (Index))))
   is
      Field_Status : SMB.Core_Status;
   begin
      --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: Prepare checks the output length first
      if Packet'Length < Header_Length then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Status := SMB.Invalid_Length;
         return;
      end if;
      SMB.Core_Wire.Initialize_Header
        (Packet, Expected.Command, Expected.Message_Id,
         Expected.Tree_Id, Expected.Session_Id, 1, Field_Status);
      --  adamutant:disable-next-line ConditionalExpression: a header fits the packet, so the write succeeds
      if Field_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Status := Field_Status;
         return;
      end if;
      --  adamutant:disable-next-line ConditionalExpression: every QUERY_INFO is signed
      if Expected.Request_Signed then
         SMB.Core_Wire.Write_U32 (Packet, 16, 8, Field_Status);
         --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: a header fits the packet, so the write succeeds
         if Field_Status /= SMB.Ok then
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
            Status := Field_Status;
            return;
         end if;
      end if;
      Status := SMB.Ok;
   end Prepare_Header;

   --  Signs with HMAC-SHA256 and Key for SMB 2.1, and with AES-128-CMAC or
   --  AES-128-GMAC, as Signing says, and SMB3_Key for 3.1.1.
   procedure Sign_Packet
     (Packet : in out SMB.Bytes;
      Used : Natural;
      Key : SMB.Bytes;
      Signing : SMB.Core_Negotiate.Signing_Id;
      SMB3_Key : SMB.AES.Key_128;
      Status : out SMB.Core_Status)
   with Pre =>
     Packet'Length <= SMB.Maximum_Frame_Size
     and then Key'Length > 0
     and then Key'Length <= SMB.Maximum_Frame_Size
     and then Used <= Packet'Length
     and then Used >= Header_Length,
     Post =>
       Status = SMB.Ok
       and then
         (for all Index in Packet'Range =>
            (if Index < Packet'First + 48
               or else Index > Packet'First + 63
             then Packet (Index) = Packet'Old (Index)))
       and then SMB.Core_Wire.Encoded_U16 (Packet, 4) =
         SMB.Core_Wire.Encoded_U16 (Packet'Old, 4)
       and then SMB.Core_Wire.Encoded_U16 (Packet, 12) =
         SMB.Core_Wire.Encoded_U16 (Packet'Old, 12)
       and then SMB.Core_Wire.Encoded_U32 (Packet, 16) =
         SMB.Core_Wire.Encoded_U32 (Packet'Old, 16)
       and then SMB.Core_Wire.Encoded_U64 (Packet, 24) =
         SMB.Core_Wire.Encoded_U64 (Packet'Old, 24)
       and then SMB.Core_Wire.Encoded_U32 (Packet, 36) =
         SMB.Core_Wire.Encoded_U32 (Packet'Old, 36)
       and then SMB.Core_Wire.Encoded_U64 (Packet, 40) =
         SMB.Core_Wire.Encoded_U64 (Packet'Old, 40)
   is
   begin
      case Signing is
         when SMB.Core_Negotiate.HMAC_SHA256 =>
            SMB.Core_Wire.Sign
              (Packet
                 (Packet'First .. Packet'First + (Used - 1)), Key, Status);
         when SMB.Core_Negotiate.AES_CMAC | SMB.Core_Negotiate.AES_GMAC =>
            SMB.Core_Wire.Sign_SMB3
              (Packet
                 (Packet'First .. Packet'First + (Used - 1)), SMB3_Key,
               Signing, Status);
      end case;
   end Sign_Packet;

   --  The executable part of In_Flight, but for the stage and the pending
   --  request.
   function Context_Valid
     (Value : Query_Operation;
      State : SMB.Engine.Engine_State) return Boolean
   with Post =>
     (if Context_Valid'Result then
        Value.Owner = SMB.Engine.Current_Owner_Id (State)
        and then Value.Epoch = SMB.Engine.Current_Epoch (State)
        and then Value.Expected.Command = Query_Info_Command
        and then Value.Expected.Signed
        and then Value.Expected.Request_Signed
        and then SMB.Engine.Current_Phase (State) =
          SMB.Engine.Share_Connected
        and then SMB.Engine.Handle_Matches
          (State, Value.Token, Value.File_Id, Value.Access_Mode,
           Value.Directory))
   is
      --  adamutant:disable-next-line NumericLiteral: Validate_Handle sets every out parameter
      Id : SMB.Bytes (0 .. 15) := (others => 0);
      Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
      --  adamutant:disable-next-line BooleanLiteral: Validate_Handle sets every out parameter
      Is_Directory : Boolean := False;
      S : SMB.Core_Status;
   begin
      --  The expectation comes from Begin_Request in Prepare, and
      --  Validate_Handle rejects the other states the same way, so no
      --  pairing of these can be told apart.
      --  adamutant:disable LogicalOperator
      --  adamutant:disable-next-line ConditionalExpression: as above
      if Value.Expected.Command /= Query_Info_Command
        or else not Value.Expected.Signed
        or else not Value.Expected.Request_Signed
        or else Value.Owner /= SMB.Engine.Current_Owner_Id (State)
        or else Value.Epoch /= SMB.Engine.Current_Epoch (State)
        or else SMB.Engine.Current_Phase (State) /=
          SMB.Engine.Share_Connected
      --  adamutant:enable LogicalOperator
      then
         --  Only for an operation never prepared, or from before the
         --  connection was reset; every caller also requires the
         --  operation's own request pending, which neither can have.
         --  adamutant:disable-next-line StatementDeletion, BooleanLiteral: as above
         return False;
      end if;
      SMB.Engine.Validate_Handle
        (State, Value.Token, False, False, Id, Mode, Is_Directory, S);
      --  A token's handle does not change while its request is in flight,
      --  and a failed lookup clears its outputs, so every pairing of these
      --  fails the same way.
      --  adamutant:disable LogicalOperator
      --  adamutant:disable-next-line ConditionalExpression: as above
      if S /= SMB.Ok
        or else Id /= Value.File_Id
        or else Mode /= Value.Access_Mode
        or else Is_Directory /= Value.Directory
      --  adamutant:enable LogicalOperator
      then
         --  adamutant:disable-next-line BooleanLiteral, StatementDeletion: unreachable, as above
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
     (Value : in out Query_Operation;
      State : in out SMB.Engine.Engine_State;
      Token : SMB.Engine.Handle_Token;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   is
      --  adamutant:disable-next-line NumericLiteral: Validate_Handle sets every out parameter
      Id : SMB.Bytes (0 .. 15) := (others => 0);
      Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
      --  adamutant:disable-next-line BooleanLiteral: Validate_Handle sets every out parameter
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
      if Value.Stage /= Query_Idle
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
        (State, Token, False, False, Id, Mode, Dir, S);
      if S /= SMB.Ok then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      if Output'Length < Request_Size then
         Status := SMB.Resource_Limit;
         return;
      end if;
      SMB.Core_Protocol.Build_Query_Information
        (Id, Body_Buffer, Body_Used, S);
      --  adamutant:disable-next-line ConditionalExpression: the builder cannot fail on a buffer of its size
      if S /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Status := S;
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
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
        (State, Query_Info_Command, True, True, Message, Expected, S);
      --  adamutant:disable-next-line ConditionalExpression: the checks above leave Begin_Request nothing to reject short of 2**64 requests
      if S /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Status := S;
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         return;
      end if;
      pragma Assert
        (SMB.Engine.Handle_Matches_In_States
           (Before_Begin, State, Token, Id, Mode, Dir));
      Prepare_Header (Output, Expected, S);
      pragma Assert (S = SMB.Ok);
      Sign_Packet
        (Output, Request_Size, SMB.Engine.Current_Signing_Key (State),
         SMB.Engine.Current_Signing (State),
         SMB.Engine.Current_SMB3_Signing_Key (State), S);
      Value.Stage := Query_Prepared;
      Value.Owner := SMB.Engine.Current_Owner_Id (State);
      Value.Epoch := SMB.Engine.Current_Epoch (State);
      Value.Token := Token;
      Value.File_Id := Id;
      Value.Access_Mode := Mode;
      Value.Directory := Dir;
      Value.Expected := Expected;
      --  An idle operation's result is zero already, but the postcondition
      --  needs it stated.
      --  adamutant:disable-next-line StatementDeletion: as above
      Value.Result := (others => <>);
      Used := Request_Size;
      Status := SMB.Ok;
   end Prepare;

   procedure Send_Succeeded
     (Value : in out Query_Operation;
      State : SMB.Engine.Engine_State;
      Status : out SMB.Core_Status) is
   begin
      if Value.Stage /= Query_Prepared
        or else not Context_Valid (Value, State)
        or else not SMB.Engine.Pending_Request_Matches
          (State, Value.Expected)
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      Value.Stage := Query_Sent;
      Status := SMB.Ok;
   end Send_Succeeded;

   procedure Fail
     (Value : in out Query_Operation;
      State : in out SMB.Engine.Engine_State;
      Failure : SMB.Core_Status;
      Status : out SMB.Core_Status)
   with Pre => Failure /= SMB.Ok
     and then Failure /= SMB.Invalid_State_Status,
     Post => Status /= SMB.Ok
       and then Status /= SMB.Invalid_State_Status
       and then Stage_Of (Value) = Query_Failed
       and then Same_Request (Snapshot_Of (Value), Snapshot_Of (Value)'Old)
       and then Result_Of (Value) = Result_Of (Value)'Old
       and then SMB.Engine.Current_Phase (State) = SMB.Engine.Disconnected
       and then not SMB.Engine.Has_Pending_Request (State)
   is
      S : SMB.Core_Status;
   begin
      SMB.Engine.Invalidate (State, S);
      Value.Stage := Query_Failed;
      --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: Invalidate fails only after 2**64 reconnections
      Status := (if S = SMB.Ok then Failure else S);
   end Fail;

   procedure Complete
     (Value : in out Query_Operation;
      State : in out SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Nt_Status : out SMB.DWord;
      Status : out SMB.Core_Status)
   is
      Accept_Status, Receipt_Status : SMB.Core_Status;
      Info : SMB.Core_Protocol.Response_Info;
      Before_Accept : constant SMB.Engine.Engine_State := State with Ghost;
   begin
      Nt_Status := 0;
      if Value.Stage /= Query_Sent
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
         Value.Stage := Query_Failed;
         Status :=
           --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: as above
           (if Accept_Status = SMB.Invalid_State_Status
            then SMB.Invalid_Protocol else Accept_Status);
         return;
      end if;
      pragma Assert
        (SMB.Engine.Handle_Matches_In_States
           (Before_Accept, State, Value.Token, Value.File_Id,
            Value.Access_Mode, Value.Directory));
      Info := SMB.Engine.Current_Response_Info (State);
      if Nt_Status = SMB.Success then
         if Info.Data_Length /=
           SMB.Core_Protocol.Network_Open_Information_Size
         then
            Fail (Value, State, SMB.Invalid_Protocol, Status);
            return;
         end if;
         Value.Result :=
           SMB.Core_Protocol.Network_Open_Information
             (Packet, Info.Data_Offset);
      else
         --  Prepare left the result zero, but the postcondition needs it
         --  stated.
         --  adamutant:disable-next-line StatementDeletion: as above
         Value.Result := (others => <>);
      end if;
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
      Value.Stage := Query_Finished;
      Status := SMB.Ok;
   end Complete;

   procedure Abort_Query
     (Value : in out Query_Operation;
      State : in out SMB.Engine.Engine_State;
      Status : out SMB.Core_Status) is
      S : SMB.Core_Status;
   begin
      --  A pending request that matches the operation's own is in flight,
      --  so the stage test adds nothing a test can see; the postcondition
      --  needs it.
      --  adamutant:disable LogicalOperator
      if Value.Stage not in Query_Prepared | Query_Sent
        or else not Context_Valid (Value, State)
        or else not SMB.Engine.Pending_Request_Matches
          (State, Value.Expected)
      --  adamutant:enable LogicalOperator
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      SMB.Engine.Invalidate (State, S);
      Value.Stage := Query_Failed;
      Status := S;
   end Abort_Query;
end SMB.Core_Query;
