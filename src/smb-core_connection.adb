package body SMB.Core_Connection
  with SPARK_Mode
is
   pragma Unevaluated_Use_Of_Old (Allow);

   Header_Length : constant Natural := SMB.Core_Wire.Header_Size;

   function Command_Of
     (Kind : Connection_Kind) return SMB.Core_Wire.Command_Code is
     (case Kind is
        when Negotiate => 0,
        when Tree_Connect => 3,
        when Tree_Disconnect => 4,
        when Logoff => 2,
        --  adamutant:disable-next-line NumericLiteral: no caller asks for No_Connection
        when No_Connection => 0);

   function Body_Length
     (Kind : Connection_Kind;
      Path_Length : Natural) return Natural
   with Pre => Path_Length <= SMB.Core_Protocol.Maximum_Name_Bytes,
     Post =>
       Body_Length'Result =
         (case Kind is
            when Negotiate => 38,
            when Tree_Connect => 8 + Path_Length,
            when Tree_Disconnect | Logoff => 4,
            when No_Connection => 0)
     and then Body_Length'Result <=
       SMB.Maximum_Frame_Size - Header_Length
   is
   begin
      return
        (case Kind is
           when Negotiate => 38,
           when Tree_Connect => 8 + Path_Length,
           when Tree_Disconnect | Logoff => 4,
           --  adamutant:disable-next-line NumericLiteral: no caller asks for No_Connection
           when No_Connection => 0);
   end Body_Length;

   function Signed_Kind (Kind : Connection_Kind) return Boolean is
     (Kind /= Negotiate and then Kind /= No_Connection);

   function Body_Matches_Kind
      (Kind : Connection_Kind;
      Guid : SMB.Bytes;
      Path_Length : Natural;
      Buffer : SMB.Bytes) return Boolean is
      (case Kind is
        when Negotiate =>
          Buffer'Length = 38
          and then SMB.Core_Wire.Encoded_U16 (Buffer, 0) = 36
          and then SMB.Core_Wire.Encoded_U16 (Buffer, 2) = 1
          and then SMB.Core_Wire.Encoded_U16 (Buffer, 4) = 3
          and then SMB.Core_Wire.Encoded_U16 (Buffer, 6) = 0
          and then SMB.Core_Wire.Encoded_U32 (Buffer, 8) = 0
          and then
            (for all Index in 0 .. 15 =>
               Buffer (12 + Index) = Guid (Guid'First + Index))
          and then SMB.Core_Wire.Encoded_U64 (Buffer, 28) = 0
          and then SMB.Core_Wire.Encoded_U16
            (Buffer, 36) = SMB.SMB2_Dialect_0210,
        when Tree_Connect =>
          Buffer'Length = 8 + Path_Length
          and then Path_Length > 0
          and then Path_Length mod 2 = 0
          and then SMB.Core_Wire.Encoded_U16 (Buffer, 0) = 9
          and then SMB.Core_Wire.Encoded_U16 (Buffer, 2) = 0
          and then SMB.Core_Wire.Encoded_U16 (Buffer, 4) = 72
          and then SMB.Core_Wire.Encoded_U16 (Buffer, 6) =
            SMB.Word (Path_Length),
        when Tree_Disconnect | Logoff =>
          Path_Length = 0
          and then Buffer'Length = 4
          and then SMB.Core_Wire.Encoded_U16 (Buffer, 0) = 4
          and then SMB.Core_Wire.Encoded_U16 (Buffer, 2) = 0,
        when No_Connection => False)
   with
     Ghost,
     Pre => Guid'Length = 16
       and then Buffer'First = 0
       and then Buffer'Last < SMB.Maximum_Frame_Size - Header_Length
       and then Path_Length <= SMB.Core_Protocol.Maximum_Name_Bytes;

   function Phase_Matches
     (Kind : Connection_Kind;
      State : SMB.Engine.Engine_State) return Boolean is
     (case Kind is
        when Negotiate =>
          --  adamutant:disable-next-line LogicalOperator: SMB.Engine.Begin_Request rejects the same states with the same status
          SMB.Engine.Current_Phase (State) =
            SMB.Engine.Transport_Connected
          and then SMB.Engine.Current_Session_Id (State) = 0
          and then SMB.Engine.Current_Tree_Id (State) = 0
          and then not SMB.Engine.Has_Signing_Key (State),
        when Tree_Connect =>
          SMB.Engine.Current_Phase (State) = SMB.Engine.Authenticated
          --  adamutant:disable-next-line LogicalOperator: SMB.Engine.Begin_Request rejects the same states with the same status
          and then SMB.Engine.Current_Tree_Id (State) = 0,
        when Tree_Disconnect =>
          SMB.Engine.Current_Phase (State) =
            SMB.Engine.Share_Connected
          --  adamutant:disable-next-line LogicalOperator: SMB.Engine.Begin_Request rejects the same states with the same status
          and then SMB.Engine.Current_Tree_Id (State) /= 0,
        when Logoff =>
          SMB.Engine.Current_Phase (State) =
            SMB.Engine.Authenticated
          or else SMB.Engine.Current_Phase (State) =
            SMB.Engine.Share_Connected,
        --  adamutant:disable-next-line BooleanLiteral: every caller rules out No_Connection first
        when No_Connection => False);

   function Preparation_Context_Matches
     (Snapshot : Connection_State_Snapshot;
      State : SMB.Engine.Engine_State;
      Kind : Connection_Kind) return Boolean is
     --  adamutant:disable-next-line LogicalOperator: Prepare checks the stage first, and SMB.Engine.Begin_Request rejects the same states with the same status
     (Snapshot.Stage = Idle
      and then Kind /= No_Connection
      and then Snapshot.Kind = No_Connection
      --  adamutant:disable-next-line NumericLiteral: owner 1 belongs to the first engine of a process, which no test can pick
      and then SMB.Engine.Current_Owner_Id (State) /= 0
      and then Phase_Matches (Kind, State)
      and then not SMB.Engine.Has_Pending_Request (State)
      and then not SMB.Engine.Has_Validated_Response (State)
      and then
        (Kind = Negotiate or else SMB.Engine.Has_Signing_Key (State)));

   function Continuation_Context_Matches
     (Snapshot : Connection_State_Snapshot;
      State : SMB.Engine.Engine_State) return Boolean is
     --  adamutant:disable-next-line LogicalOperator: every caller checks the stage first
     (Snapshot.Stage in Prepared | Sent
      and then Snapshot.Kind /= No_Connection
      and then Phase_Matches (Snapshot.Kind, State)
      and then Snapshot.Owner = SMB.Engine.Current_Owner_Id (State)
      and then Snapshot.Epoch = SMB.Engine.Current_Epoch (State)
      and then Snapshot.Starting_Phase =
        SMB.Engine.Current_Phase (State)
      and then Snapshot.Starting_Session_Id =
        SMB.Engine.Current_Session_Id (State)
      and then Snapshot.Starting_Tree_Id =
        SMB.Engine.Current_Tree_Id (State)
      and then Snapshot.Expected.Command = Command_Of (Snapshot.Kind)
      and then Snapshot.Expected.Request_Signed =
        Signed_Kind (Snapshot.Kind)
      and then Snapshot.Expected.Signed = Signed_Kind (Snapshot.Kind)
      and then
        --  adamutant:disable-next-line ConditionalExpression: Begin_Request leaves the tree id of a LOGOFF expectation at 0
        (if Snapshot.Kind = Logoff then
           Snapshot.Expected.Tree_Id = 0
         else True)
      and then SMB.Engine.Pending_Request_Matches
        (State, Snapshot.Expected)
      and then not SMB.Engine.Has_Validated_Response (State));

   function Packet_Guid_Matches
     (Packet, Guid : SMB.Bytes) return Boolean is
     (for all Index in 0 .. 15 =>
        Packet (Packet'First + 76 + Index) = Guid (Guid'First + Index))
   with Ghost,
     Pre => Packet'Length >= 92 and then Guid'Length = 16;

   function Packet_Matches_Prepared
     (Value : Connection_Operation;
      State : SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Used : Natural) return Boolean is
     (Value.Stage = Prepared
      and then Value.Kind /= No_Connection
      and then Value.Path_Length <=
        SMB.Core_Protocol.Maximum_Name_Bytes
      and then Packet'Length <= SMB.Maximum_Frame_Size
      and then Used >= Header_Length
      and then Used <= Packet'Length
      and then Used =
        Header_Length + Body_Length (Value.Kind, Value.Path_Length)
      and then SMB.Engine.Pending_Request_Matches
        (State, Value.Expected)
      and then Value.Expected.Command = Command_Of (Value.Kind)
      and then Value.Expected.Request_Signed = Signed_Kind (Value.Kind)
      and then Value.Expected.Signed = Signed_Kind (Value.Kind)
      and then SMB.Core_Wire.Encoded_U16 (Packet, 4) =
        SMB.Word (Header_Length)
      and then SMB.Core_Wire.Encoded_U16 (Packet, 6) = 1
      and then SMB.Core_Wire.Encoded_U16 (Packet, 12) =
        SMB.Word (Value.Expected.Command)
      and then SMB.Core_Wire.Encoded_U16 (Packet, 14) = 1
      and then SMB.Core_Wire.Encoded_U32 (Packet, 16) =
        (if Value.Expected.Request_Signed then 8 else 0)
      and then SMB.Core_Wire.Encoded_U32 (Packet, 20) = 0
      and then SMB.Core_Wire.Encoded_U64 (Packet, 24) =
        Value.Expected.Message_Id
      and then SMB.Core_Wire.Encoded_U32 (Packet, 36) =
        Value.Expected.Tree_Id
      and then SMB.Core_Wire.Encoded_U64 (Packet, 40) =
        Value.Expected.Session_Id
      and then
        (case Value.Kind is
           when Negotiate =>
             Packet'Length >= Header_Length + 38
             and then SMB.Core_Wire.Encoded_U16
               (Packet, Header_Length) = 36
             and then SMB.Core_Wire.Encoded_U16
               (Packet, Header_Length + 2) = 1
             and then SMB.Core_Wire.Encoded_U16
               (Packet, Header_Length + 4) = 3
             and then SMB.Core_Wire.Encoded_U16
               (Packet, Header_Length + 6) = 0
             and then SMB.Core_Wire.Encoded_U32
               (Packet, Header_Length + 8) = 0
             and then SMB.Core_Wire.Encoded_U64
               (Packet, Header_Length + 28) = 0
             and then SMB.Core_Wire.Encoded_U16
               (Packet, Header_Length + 36) = SMB.SMB2_Dialect_0210
             and then Value.Expected.Tree_Id = 0
             and then Value.Expected.Session_Id = 0
             and then Packet_Guid_Matches (Packet, Value.Guid),
           when Tree_Connect =>
             Packet'Length >= Header_Length + 8 + Value.Path_Length
             and then SMB.Core_Wire.Encoded_U16
               (Packet, Header_Length) = 9
             and then SMB.Core_Wire.Encoded_U16
               (Packet, Header_Length + 2) = 0
             and then SMB.Core_Wire.Encoded_U16
               (Packet, Header_Length + 4) = 72
             and then SMB.Core_Wire.Encoded_U16
               (Packet, Header_Length + 6) =
                 SMB.Word (Value.Path_Length)
             and then Value.Expected.Tree_Id = 0,
           when Tree_Disconnect =>
             Packet'Length >= Header_Length + 4
             and then SMB.Core_Wire.Encoded_U16
               (Packet, Header_Length) = 4
             and then SMB.Core_Wire.Encoded_U16
               (Packet, Header_Length + 2) = 0
             and then Value.Expected.Tree_Id /= 0,
           when Logoff =>
             Packet'Length >= Header_Length + 4
             and then SMB.Core_Wire.Encoded_U16
               (Packet, Header_Length) = 4
             and then SMB.Core_Wire.Encoded_U16
               (Packet, Header_Length + 2) = 0
             and then Value.Expected.Tree_Id = 0,
           when No_Connection => False));

   procedure Clear_Output (Output : out SMB.Bytes)
   with Post =>
     (for all Index in Output'Range => Output (Index) = 0)
   is
   begin
      Output := (others => 0);
   end Clear_Output;

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
          and then SMB.Core_Wire.Encoded_U16 (Packet, 6) = 1
          and then SMB.Core_Wire.Encoded_U16 (Packet, 12) =
            SMB.Word (Expected.Command)
          and then SMB.Core_Wire.Encoded_U16 (Packet, 14) = 1
          and then SMB.Core_Wire.Encoded_U32 (Packet, 16) =
            (if Expected.Request_Signed then 8 else 0)
          and then SMB.Core_Wire.Encoded_U32 (Packet, 20) = 0
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
      if Expected.Request_Signed then
         SMB.Core_Wire.Write_U32 (Packet, 16, 8, Field_Status);
         --  adamutant:disable-next-line ConditionalExpression: a header fits the packet, so the write succeeds
         if Field_Status /= SMB.Ok then
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
            Status := Field_Status;
            return;
         end if;
      end if;
      Status := SMB.Ok;
   end Prepare_Header;

   procedure Sign_Packet
     (Packet : in out SMB.Bytes;
      Used : Natural;
      Key : SMB.Bytes;
     Status : out SMB.Core_Status)
   with Pre =>
     Packet'Length <= SMB.Maximum_Frame_Size
     and then Key'Length > 0
     and then Key'Length <= SMB.Maximum_Frame_Size
     and then Used <= Packet'Length
     and then Used >= Header_Length,
     Post =>
       Status = SMB.Ok
       and then (if Status = SMB.Ok then
          (for all Index in Packet'Range =>
             (if Index < Packet'First + 48
                or else Index > Packet'First + 63
              then Packet (Index) = Packet'Old (Index)))
          and then SMB.Core_Wire.Encoded_U16 (Packet, 4) =
            SMB.Core_Wire.Encoded_U16 (Packet'Old, 4)
          and then SMB.Core_Wire.Encoded_U16 (Packet, 6) =
            SMB.Core_Wire.Encoded_U16 (Packet'Old, 6)
          and then SMB.Core_Wire.Encoded_U16 (Packet, 12) =
            SMB.Core_Wire.Encoded_U16 (Packet'Old, 12)
          and then SMB.Core_Wire.Encoded_U16 (Packet, 14) =
            SMB.Core_Wire.Encoded_U16 (Packet'Old, 14)
          and then SMB.Core_Wire.Encoded_U32 (Packet, 16) =
            SMB.Core_Wire.Encoded_U32 (Packet'Old, 16)
          and then SMB.Core_Wire.Encoded_U32 (Packet, 20) =
            SMB.Core_Wire.Encoded_U32 (Packet'Old, 20)
          and then SMB.Core_Wire.Encoded_U64 (Packet, 24) =
            SMB.Core_Wire.Encoded_U64 (Packet'Old, 24)
          and then SMB.Core_Wire.Encoded_U32 (Packet, 36) =
            SMB.Core_Wire.Encoded_U32 (Packet'Old, 36)
          and then SMB.Core_Wire.Encoded_U64 (Packet, 40) =
            SMB.Core_Wire.Encoded_U64 (Packet'Old, 40)
        else Packet = Packet'Old)
   is
   begin
      --  adamutant:disable-next-line ConditionalExpression, EqualityOperator, LogicalOperator: the precondition already bounds Used
      if Used < Header_Length or else Used > Packet'Length then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Status := SMB.Invalid_Length;
         return;
      end if;
      SMB.Core_Wire.Sign
        (Packet
           (Packet'First .. Packet'First + (Used - 1)), Key, Status);
   end Sign_Packet;

   procedure Fail_Connection
     (Value : in out Connection_Operation;
      State : in out SMB.Engine.Engine_State;
      Failure : SMB.Core_Status;
      Status : out SMB.Core_Status)
   with
     Pre => Failure /= SMB.Ok,
     Post =>
       Status /= SMB.Ok
       and then Status =
         (if SMB.Engine.Current_Epoch (State)'Old = SMB.QWord'Last
          then SMB.Counter_Exhausted
          else Failure)
       and then Stage_Of (Value) = Failed
       and then Same_Identity
         (Snapshot_Of (Value)'Old, Snapshot_Of (Value))
       and then Invalidated (State)
   is
      Invalidate_Status : SMB.Core_Status;
   begin
      --  Only the defensive branches above call this, and no input reaches
      --  them.
      --  adamutant:disable all
      SMB.Engine.Invalidate (State, Invalidate_Status);
      Value.Stage := Failed;
      Status :=
        (if Invalidate_Status = SMB.Ok then Failure else Invalidate_Status);
      --  adamutant:enable all
   end Fail_Connection;

   procedure Lemma_Body_Copy (Source, Packet : SMB.Bytes)
   with Ghost,
     Pre => Source'Length in 4 .. SMB.Maximum_Frame_Size - Header_Length
       and then Packet'Length <= SMB.Maximum_Frame_Size
       and then Packet'Length >= Header_Length + Source'Length
       and then
         (for all Index in 0 .. Source'Length - 1 =>
            Packet (Packet'First + Header_Length + Index) =
              Source (Source'First + Index)),
     Post =>
       SMB.Core_Wire.Encoded_U16 (Packet, 64) =
         SMB.Core_Wire.Encoded_U16 (Source, 0)
       and then SMB.Core_Wire.Encoded_U16 (Packet, 66) =
         SMB.Core_Wire.Encoded_U16 (Source, 2)
       and then
         (if Source'Length >= 8 then
            SMB.Core_Wire.Encoded_U16 (Packet, 68) =
              SMB.Core_Wire.Encoded_U16 (Source, 4)
            and then SMB.Core_Wire.Encoded_U16 (Packet, 70) =
              SMB.Core_Wire.Encoded_U16 (Source, 6))
       and then
         (if Source'Length >= 38 then
            SMB.Core_Wire.Encoded_U32 (Packet, 72) =
              SMB.Core_Wire.Encoded_U32 (Source, 8)
            and then SMB.Core_Wire.Encoded_U64 (Packet, 92) =
              SMB.Core_Wire.Encoded_U64 (Source, 28)
            and then SMB.Core_Wire.Encoded_U16 (Packet, 100) =
              SMB.Core_Wire.Encoded_U16 (Source, 36))
   is
   begin
      null;
   end Lemma_Body_Copy;

   procedure Lemma_Copies_Compose
     (Source, Middle, Target : SMB.Bytes;
      Middle_Offset, Target_Offset : Natural)
   with Ghost,
     Pre => Source'Length in 1 .. SMB.Maximum_Frame_Size
       and then Middle'Length <= SMB.Maximum_Frame_Size
       and then Target'Length <= SMB.Maximum_Frame_Size
       and then Middle_Offset <= Middle'Length
       and then Source'Length <= Middle'Length - Middle_Offset
       and then Target_Offset <= Target'Length
       and then Source'Length <= Target'Length - Target_Offset
       and then
         (for all Index in 0 .. Source'Length - 1 =>
            Middle (Middle'First + Middle_Offset + Index) =
              Source (Source'First + Index))
       and then
         (for all Index in 0 .. Source'Length - 1 =>
            Target (Target'First + Target_Offset + Index) =
              Middle (Middle'First + Middle_Offset + Index)),
     Post =>
       (for all Index in 0 .. Source'Length - 1 =>
          Target (Target'First + Target_Offset + Index) =
            Source (Source'First + Index))
   is
   begin
      null;
   end Lemma_Copies_Compose;

   procedure Capture_Guid (Source : SMB.Bytes; Target : out SMB.Bytes)
   with Pre => Source'Length = 16 and then Target'Length = 16,
     Post => Target = Source
       and then
         (for all Index in 0 .. 15 =>
            Target (Target'First + Index) = Source (Source'First + Index))
   is
   begin
      Target := Source;
   end Capture_Guid;

   procedure Prepare
     (Value : in out Connection_Operation;
      State : in out SMB.Engine.Engine_State;
      Kind : Connection_Kind;
      Guid : SMB.Bytes;
      Path_Length : Natural;
      Body_Buffer : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with
     Pre =>
       Kind /= No_Connection
     and then Guid'Length = 16
     and then Path_Length <=
       SMB.Core_Protocol.Maximum_Name_Bytes
     and then Body_Buffer'First = 0
     and then Body_Buffer'Last < SMB.Maximum_Frame_Size - Header_Length
     and then Body_Buffer'Length = Body_Length (Kind, Path_Length)
     and then Output'Length <= SMB.Maximum_Frame_Size
     and then Body_Matches_Kind
       (Kind, Guid, Path_Length, Body_Buffer),
     Post =>
       Used <= Output'Length
       and then
         (if not Preparation_Context_Matches
                 (Snapshot_Of (Value), State, Kind)'Old
               or else Output'Length < Header_Length + Body_Buffer'Length
          then Status /= SMB.Ok
            and then Snapshot_Of (Value) = Snapshot_Of (Value)'Old
            and then State = State'Old
            and then Used = 0)
       and then
         (if Status = SMB.Ok then
            Used = Header_Length + Body_Buffer'Length)
       and then (if Status = SMB.Ok then Value.Stage = Prepared)
       and then (if Status = SMB.Ok then Value.Kind = Kind)
       and then (if Status = SMB.Ok then Value.Path_Length = Path_Length)
       and then
         (if Status = SMB.Ok then Value.Expected.Command = Command_Of (Kind))
       and then
         (if Status = SMB.Ok then
            Value.Expected.Request_Signed = Signed_Kind (Kind))
       and then
         (if Status = SMB.Ok then Value.Expected.Signed = Signed_Kind (Kind))
       and then (if Status = SMB.Ok then Value.Guid = Guid)
       and then
         (if Status = SMB.Ok then
            SMB.Engine.Connection_Context_Equivalent (State'Old, State))
       and then
         (if Status = SMB.Ok then
            Continuation_Context_Matches (Snapshot_Of (Value), State))
       and then
         (if Status = SMB.Ok then
            Packet_Matches_Prepared (Value, State, Output, Used))
       and then
         (if Status = SMB.Ok then
            (for all Index in 0 .. Body_Buffer'Length - 1 =>
               Output (Output'First + Header_Length + Index) =
                 Body_Buffer (Body_Buffer'First + Index)))
       and then
         (if Status = SMB.Counter_Exhausted then
            Snapshot_Of (Value) = Snapshot_Of (Value)'Old
            and then State = State'Old
            and then Used = 0)
   is
      Snapshot : constant Connection_State_Snapshot :=
        Snapshot_Of (Value);
      State_At_Entry : constant SMB.Engine.Engine_State := State with Ghost;
      Message : SMB.QWord;
      Expected : SMB.Engine.Request_Expectation;
      Begin_Status : SMB.Core_Status;
      Field_Status : SMB.Core_Status;
      Need : constant Natural := Header_Length + Body_Buffer'Length;
   begin
      Clear_Output (Output);
      Used := 0;
      if Value.Stage /= Idle
        or else not Preparation_Context_Matches (Snapshot, State, Kind)
        or else Output'Length < Need
        --  adamutant:disable-next-line NumericLiteral: Prepare_Tree_Connect rejects empty and odd names first
        or else (Kind = Tree_Connect and then Path_Length = 0)
        --  adamutant:disable-next-line EqualityOperator: Prepare_Tree_Connect rejects empty and odd names first
        or else (Kind = Tree_Connect and then Path_Length mod 2 /= 0)
      then
         Status := (if Value.Stage /= Idle
           or else not Preparation_Context_Matches (Snapshot, State, Kind)
           then SMB.Invalid_State_Status else SMB.Resource_Limit);
         --  adamutant:disable-next-line ConditionalExpression: Prepare_Tree_Connect rejects empty and odd names first
         if Kind = Tree_Connect
           --  adamutant:disable-next-line all: unreachable, as above
           and then (Path_Length = 0 or else Path_Length mod 2 /= 0)
         then
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
            Status := SMB.Invalid_Length;
         end if;
         pragma Assert (State = State_At_Entry);
         pragma Assert (Snapshot_Of (Value) = Snapshot);
         return;
      end if;
      pragma Assert (Need <= Output'Length);
      pragma Assert (Preparation_Context_Matches (Snapshot, State, Kind));
      pragma Assert (Output'Last - Output'First >= Header_Length);
      pragma Assert (Output'First <= Output'Last - Header_Length);
      SMB.Engine.Begin_Request
        (State, Command_Of (Kind), Signed_Kind (Kind), Signed_Kind (Kind),
         Message, Expected, Begin_Status);
      --  adamutant:disable-next-line ConditionalExpression: Begin_Request fails only on a pending request, rejected above, or after 2**64 requests
      if Begin_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Status := Begin_Status;
         pragma Assert (State = State_At_Entry);
         pragma Assert (Snapshot_Of (Value) = Snapshot);
         return;
      end if;
      pragma Assert (Message = Expected.Message_Id);
      --  adamutant:disable-next-line ConditionalExpression: Begin_Request guarantees it, as asserted above
      if Message /= Expected.Message_Id then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Value.Expected := Expected;
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Value.Kind := Kind;
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Fail_Connection
           (Value, State, SMB.Invalid_State_Status, Status);
         return;
      end if;
      Value.Kind := Kind;
      Value.Owner := SMB.Engine.Current_Owner_Id (State);
      Value.Epoch := SMB.Engine.Current_Epoch (State);
      Value.Starting_Phase := SMB.Engine.Current_Phase (State);
      Value.Starting_Session_Id := SMB.Engine.Current_Session_Id (State);
      Value.Starting_Tree_Id := SMB.Engine.Current_Tree_Id (State);
      Value.Expected := Expected;
      Value.Path_Length := Path_Length;
      --  adamutant:disable-next-line ConditionalExpression: both branches capture the same GUID
      if Kind = Negotiate then
         Capture_Guid (Body_Buffer (12 .. 27), Value.Guid);
         Lemma_Copies_Compose (Guid, Body_Buffer, Value.Guid, 12, 0);
      else
         --  adamutant:disable-next-line StatementDeletion: an Idle operation already holds the zero GUID passed here
         Capture_Guid (Guid, Value.Guid);
      end if;
      pragma Assert (Value.Guid = Guid);
      pragma Assert
        (if Kind = Negotiate then
           (for all Index in 0 .. 15 =>
              Body_Buffer (12 + Index) = Value.Guid (Index)));
      Value.Stage := Prepared;
      pragma Assert (Value.Kind = Kind);
      pragma Assert (Value.Path_Length = Path_Length);
      pragma Assert (Value.Expected = Expected);
      pragma Assert
        (Preparation_Context_Matches (Snapshot, State_At_Entry, Kind));
      pragma Assert (Continuation_Context_Matches (Snapshot_Of (Value), State));
      pragma Assert
        (SMB.Engine.Connection_Context_Equivalent (State_At_Entry, State));
      Prepare_Header (Output, Expected, Field_Status);
      pragma Assert (Field_Status = SMB.Ok);
      --  adamutant:disable-next-line ConditionalExpression: Prepare_Header succeeds, as asserted above
      if Field_Status = SMB.Ok then
         Output (Output'First + Header_Length ..
                 Output'First + (Need - 1)) :=
           Body_Buffer;
         Used := Need;
         Lemma_Body_Copy (Body_Buffer, Output);
         --  adamutant:disable-next-line ConditionalExpression: the branch holds only a lemma
         if Kind = Negotiate then
            Lemma_Copies_Compose (Value.Guid, Body_Buffer, Output, 12, 76);
            pragma Assert (Packet_Guid_Matches (Output, Value.Guid));
         end if;
         pragma Assert (Packet_Matches_Prepared (Value, State, Output, Used));
         pragma Assert
           (for all Index in 0 .. Body_Buffer'Length - 1 =>
              Output (Output'First + Header_Length + Index) =
                Body_Buffer (Body_Buffer'First + Index));
         if Expected.Request_Signed then
            declare
               Before_Signing : constant SMB.Bytes := Output with Ghost;
            begin
               pragma Assert
                 (for all Index in 0 .. Body_Buffer'Length - 1 =>
                    Before_Signing (Before_Signing'First + 64 + Index) =
                      Body_Buffer (Body_Buffer'First + Index));
               Sign_Packet
                 (Output, Used, SMB.Engine.Current_Signing_Key (State),
                  Field_Status);
               Lemma_Copies_Compose
                 (Body_Buffer, Before_Signing, Output, 64, 64);
               Lemma_Body_Copy (Body_Buffer, Output);
            end;
         end if;
      end if;
      pragma Assert (Field_Status = SMB.Ok);
      --  adamutant:disable-next-line ConditionalExpression: signing succeeds, as asserted above
      if Field_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Fail_Connection (Value, State, Field_Status, Status);
         --  adamutant:disable-next-line StatementDeletion, NumericLiteral: unreachable, as above
         Used := 0;
         return;
      end if;
      --  adamutant:disable-next-line StatementDeletion: Used is already Need
      Used := Need;
      Status := SMB.Ok;
      pragma Assert (Value.Kind = Kind);
      pragma Assert
        (if Kind = Negotiate then Packet_Guid_Matches (Output, Value.Guid));
      pragma Assert (Value.Guid = Guid);
      pragma Assert
        (for all Index in 0 .. Body_Buffer'Length - 1 =>
           Output (Output'First + Header_Length + Index) =
             Body_Buffer (Body_Buffer'First + Index));
      pragma Assert (Packet_Matches_Prepared (Value, State, Output, Used));
      pragma Assert_And_Cut
        (Status = SMB.Ok
         and then Used <= Output'Length
         and then Used = Header_Length + Body_Buffer'Length
         and then Preparation_Context_Matches (Snapshot, State_At_Entry, Kind)
         and then Value.Stage = Prepared
         and then Value.Kind = Kind
         and then Value.Path_Length = Path_Length
         and then Value.Expected.Command = Command_Of (Kind)
         and then Value.Expected.Request_Signed = Signed_Kind (Kind)
         and then Value.Expected.Signed = Signed_Kind (Kind)
         and then Value.Guid = Guid
         and then SMB.Engine.Connection_Context_Equivalent
           (State_At_Entry, State)
         and then Continuation_Context_Matches (Snapshot_Of (Value), State)
         and then Packet_Matches_Prepared (Value, State, Output, Used)
         and then
           (for all Index in 0 .. Body_Buffer'Length - 1 =>
              Output (Output'First + Header_Length + Index) =
                Body_Buffer (Body_Buffer'First + Index)));
   end Prepare;

   procedure Prepare_Negotiate
     (Value : in out Connection_Operation;
      State : in out SMB.Engine.Engine_State;
      Guid : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
      Body_Buffer : SMB.Bytes (0 .. 37);
      Body_Used : Natural;
      Build_Status : SMB.Core_Status;
   begin
      SMB.Core_Protocol.Build_Negotiate
        (Guid, Body_Buffer, Body_Used, Build_Status);
      --  adamutant:disable-next-line ConditionalExpression: the body buffer always fits a NEGOTIATE body
      if Build_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Clear_Output (Output);
         --  adamutant:disable-next-line StatementDeletion, NumericLiteral: unreachable, as above
         Used := 0;
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Status := Build_Status;
         return;
      end if;
      Prepare
        (Value, State, Negotiate, Guid, 0,
         Body_Buffer (0 .. Body_Used - 1),
               Output, Used, Status);
      --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: the branch holds only a lemma
      if Status = SMB.Ok then
         Lemma_Copies_Compose (Guid, Body_Buffer, Output, 12, 76);
      end if;
   end Prepare_Negotiate;

   procedure Prepare_Tree_Connect
     (Value : in out Connection_Operation;
      State : in out SMB.Engine.Engine_State;
      Name : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
      State_At_Entry : constant SMB.Engine.Engine_State := State with Ghost;
      Snapshot_At_Entry : constant Connection_State_Snapshot :=
        Snapshot_Of (Value) with Ghost;
      Body_Buffer : SMB.Bytes
        (0 .. 7 + SMB.Core_Protocol.Maximum_Name_Bytes);
      Body_Used : Natural;
      Build_Status : SMB.Core_Status;
   begin
      if Name'Length = 0 or else Name'Length mod 2 /= 0 then
         Clear_Output (Output);
         Used := 0;
         Status := SMB.Invalid_Length;
         return;
      end if;
      SMB.Core_Protocol.Build_Tree_Connect
        (Name, Body_Buffer, Body_Used, Build_Status);
      --  adamutant:disable-next-line ConditionalExpression: the name was checked and the body buffer fits it
      if Build_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Clear_Output (Output);
         --  adamutant:disable-next-line StatementDeletion, NumericLiteral: unreachable, as above
         Used := 0;
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Status := Build_Status;
         return;
      end if;
      Prepare
        --  adamutant:disable-next-line NumericLiteral: only NEGOTIATE uses the GUID
        (Value, State, Tree_Connect, SMB.Bytes'(0 .. 15 => 0),
         Name'Length, Body_Buffer (0 .. Body_Used - 1), Output, Used,
         Status);
      pragma Assert
        (if not Preparation_Context_Matches
              (Snapshot_At_Entry, State_At_Entry, Tree_Connect)
            or else Output'Length < Header_Length + 8 + Name'Length
            or else Status = SMB.Counter_Exhausted
         then
            Status /= SMB.Ok
            and then Snapshot_Of (Value) = Snapshot_At_Entry
            and then State = State_At_Entry
            and then Used = 0);
      if Status = SMB.Ok then
         Lemma_Copies_Compose (Name, Body_Buffer, Output, 8, 72);
         pragma Assert
           (for all Index in 0 .. Name'Length - 1 =>
              Output (Output'First + Header_Length + 8 + Index) =
                Name (Name'First + Index));
         pragma Assert_And_Cut
           (Status = SMB.Ok
            and then Name'Length > 0
            and then Name'Length mod 2 = 0
            and then Used <= Output'Length
            and then Used = Header_Length + 8 + Name'Length
            and then Preparation_Context_Matches
              (Snapshot_At_Entry, State_At_Entry, Tree_Connect)
            and then Stage_Of (Value) = Prepared
            and then Kind_Of (Value) = Tree_Connect
            and then SMB.Engine.Connection_Context_Equivalent
              (State_At_Entry, State)
            and then Continuation_Context_Matches (Snapshot_Of (Value), State)
            and then Packet_Matches_Prepared (Value, State, Output, Used)
            and then Snapshot_Of (Value).Path_Length = Name'Length
            and then
              (for all Index in 0 .. Name'Length - 1 =>
                 Output (Output'First + Header_Length + 8 + Index) =
                   Name (Name'First + Index)));
      else
         pragma Assert_And_Cut
           (Status /= SMB.Ok
            and then Name'Length > 0
            and then Name'Length mod 2 = 0
            and then Used <= Output'Length
            and then
              (if not Preparation_Context_Matches
                    (Snapshot_At_Entry, State_At_Entry, Tree_Connect)
                  or else Output'Length < Header_Length + 8 + Name'Length
                  or else Status = SMB.Counter_Exhausted
               then
                 Snapshot_Of (Value) = Snapshot_At_Entry
                 and then State = State_At_Entry
                 and then Used = 0));
      end if;
   end Prepare_Tree_Connect;

   procedure Prepare_Tree_Disconnect
     (Value : in out Connection_Operation;
      State : in out SMB.Engine.Engine_State;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
      Body_Buffer : SMB.Bytes (0 .. 3);
      Body_Used : Natural;
      Build_Status : SMB.Core_Status;
   begin
      SMB.Core_Protocol.Build_Simple
        (Body_Buffer, Body_Used, Build_Status);
      --  adamutant:disable-next-line ConditionalExpression: the body buffer always fits a four-byte body
      if Build_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Clear_Output (Output);
         --  adamutant:disable-next-line StatementDeletion, NumericLiteral: unreachable, as above
         Used := 0;
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Status := Build_Status;
         return;
      end if;
      Prepare
        --  adamutant:disable-next-line NumericLiteral: only NEGOTIATE uses the GUID
        (Value, State, Tree_Disconnect, SMB.Bytes'(0 .. 15 => 0), 0,
         Body_Buffer (0 .. Body_Used - 1), Output, Used, Status);
   end Prepare_Tree_Disconnect;

   procedure Prepare_Logoff
     (Value : in out Connection_Operation;
      State : in out SMB.Engine.Engine_State;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
      Body_Buffer : SMB.Bytes (0 .. 3);
      Body_Used : Natural;
      Build_Status : SMB.Core_Status;
   begin
      SMB.Core_Protocol.Build_Simple
        (Body_Buffer, Body_Used, Build_Status);
      --  adamutant:disable-next-line ConditionalExpression: the body buffer always fits a four-byte body
      if Build_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Clear_Output (Output);
         --  adamutant:disable-next-line StatementDeletion, NumericLiteral: unreachable, as above
         Used := 0;
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Status := Build_Status;
         return;
      end if;
      Prepare
        --  adamutant:disable-next-line NumericLiteral: only NEGOTIATE uses the GUID
        (Value, State, Logoff, SMB.Bytes'(0 .. 15 => 0), 0,
         Body_Buffer (0 .. Body_Used - 1), Output, Used, Status);
   end Prepare_Logoff;

   procedure Send_Succeeded
     (Value : in out Connection_Operation;
      State : SMB.Engine.Engine_State;
      Status : out SMB.Core_Status) is
      Old : constant Connection_State_Snapshot := Snapshot_Of (Value);
   begin
      if Value.Stage /= Prepared
        or else not Continuation_Context_Matches
        ((Kind => Value.Kind, Stage => Prepared, Owner => Value.Owner,
          Epoch => Value.Epoch, Starting_Phase => Value.Starting_Phase,
          Starting_Session_Id => Value.Starting_Session_Id,
          Starting_Tree_Id => Value.Starting_Tree_Id,
          Expected => Value.Expected, Guid => Value.Guid,
          Path_Length => Value.Path_Length), State)
      then
         Status := SMB.Invalid_State_Status;
         pragma Assert (Snapshot_Of (Value) = Old);
         return;
      end if;
      Value.Stage := Sent;
      Status := SMB.Ok;
   end Send_Succeeded;

   procedure Complete
     (Value : in out Connection_Operation;
      State : in out SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Nt_Status : out SMB.DWord;
      Status : out SMB.Core_Status) is
      Accept_Status : SMB.Core_Status;
      Receipt_Status : SMB.Core_Status;
      Mark_Status : SMB.Core_Status;
      Info : SMB.Core_Protocol.Response_Info;
      Old : constant Connection_State_Snapshot := Snapshot_Of (Value);
      State_At_Entry : constant SMB.Engine.Engine_State := State
        with Ghost;
      Before_Mark : SMB.Engine.Engine_State with Ghost;
   begin
      Nt_Status := 0;
      if Value.Stage /= Sent
        or else not Continuation_Context_Matches (Old, State)
      then
         Status := SMB.Invalid_State_Status;
         pragma Assert (Snapshot_Of (Value) = Old);
         return;
      end if;
      SMB.Engine.Accept_Response (State, Packet, Nt_Status, Accept_Status);
      if Accept_Status /= SMB.Ok then
         Value.Stage := Failed;
         Status := Accept_Status;
         return;
      end if;
      if Nt_Status /= SMB.Success then
         pragma Assert
           (SMB.Engine.Connection_Context_Equivalent (State_At_Entry, State));
         declare
            Before_Discard : constant SMB.Engine.Engine_State := State
              with Ghost;
         begin
            SMB.Engine.Discard_Response_Receipt (State, Receipt_Status);
            --  adamutant:disable-next-line ConditionalExpression: the response accepted above is still held
            if Receipt_Status /= SMB.Ok then
               --  adamutant:disable-next-line StatementDeletion: unreachable, as above
               Fail_Connection (Value, State, Receipt_Status, Status);
               return;
            end if;
            --  adamutant:disable-next-line StatementDeletion: a ghost lemma
            SMB.Engine.Lemma_Connection_Context_Transitive
              (State_At_Entry, Before_Discard, State);
         end;
         pragma Assert (not SMB.Engine.Has_Validated_Response (State));
         Value.Stage := Finished;
         Status := SMB.Ok;
         return;
      end if;
      Before_Mark := State;
      if Value.Kind = Negotiate then
         Info := SMB.Engine.Current_Response_Info (State);
         SMB.Engine.Mark_Negotiated
           (State, Info.Max_Read, Info.Max_Write, Mark_Status);
         --  adamutant:disable-next-line ConditionalExpression: the phase and limits were checked when the response was accepted
         if Mark_Status /= SMB.Ok then
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
            Fail_Connection (Value, State, Mark_Status, Status);
            return;
         end if;
         pragma Assert (not SMB.Engine.Has_Validated_Response (State));
      elsif Value.Kind = Tree_Connect then
         Info := SMB.Engine.Current_Response_Info (State);
         SMB.Engine.Mark_Share_Connected
           (State, Info.Tree_Id, Mark_Status);
         --  adamutant:disable-next-line ConditionalExpression: the phase and tree id were checked when the response was accepted
         if Mark_Status /= SMB.Ok then
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
            Fail_Connection (Value, State, Mark_Status, Status);
            return;
         end if;
         pragma Assert (not SMB.Engine.Has_Validated_Response (State));
      else
         pragma Assert (not SMB.Engine.Has_Validated_Response (State));
      end if;
      --  adamutant:disable-next-line ConditionalExpression: the branch holds only a lemma
      if Value.Kind in Negotiate | Tree_Connect then
         --  adamutant:disable-next-line StatementDeletion: a ghost lemma
         SMB.Engine.Lemma_Handle_Table_Transitive
           (State_At_Entry, Before_Mark, State);
      end if;
      Value.Stage := Finished;
      Status := SMB.Ok;
   end Complete;

   procedure Abort_Connection
     (Value : in out Connection_Operation;
      State : in out SMB.Engine.Engine_State;
      Status : out SMB.Core_Status) is
      Old : constant Connection_State_Snapshot := Snapshot_Of (Value);
      Invalidate_Status : SMB.Core_Status;
   begin
      if not Continuation_Context_Matches
        ((Kind => Value.Kind, Stage => Value.Stage, Owner => Value.Owner,
          Epoch => Value.Epoch, Starting_Phase => Value.Starting_Phase,
          Starting_Session_Id => Value.Starting_Session_Id,
          Starting_Tree_Id => Value.Starting_Tree_Id,
          Expected => Value.Expected, Guid => Value.Guid,
          Path_Length => Value.Path_Length), State)
        or else Value.Stage not in Prepared | Sent
      then
         Status := SMB.Invalid_State_Status;
         pragma Assert (Snapshot_Of (Value) = Old);
         return;
      end if;
      SMB.Engine.Invalidate (State, Invalidate_Status);
      Value.Stage := Failed;
      Status := Invalidate_Status;
   end Abort_Connection;

   function Stage_Of
     (Value : Connection_Operation) return Connection_Stage is
     (Value.Stage);

   function Kind_Of
     (Value : Connection_Operation) return Connection_Kind is
     (Value.Kind);

   function Snapshot_Of
     (Value : Connection_Operation) return Connection_State_Snapshot is
     ((Kind => Value.Kind,
       Stage => Value.Stage,
       Owner => Value.Owner,
       Epoch => Value.Epoch,
       Starting_Phase => Value.Starting_Phase,
       Starting_Session_Id => Value.Starting_Session_Id,
       Starting_Tree_Id => Value.Starting_Tree_Id,
       Expected => Value.Expected,
       Guid => Value.Guid,
       Path_Length => Value.Path_Length));

   function Expected_Of
     (Value : Connection_Operation) return SMB.Engine.Request_Expectation is
     (Value.Expected);
end SMB.Core_Connection;
