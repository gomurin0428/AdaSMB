with SMB.Core_Protocol;
with SMB.Core_Wire;
with SMB.Engine;

package SMB.Core_Connection
  with SPARK_Mode
is
   pragma Unevaluated_Use_Of_Old (Allow);
   use type SMB.Byte;
   use type SMB.Word;
   use type SMB.DWord;
   use type SMB.QWord;
   use type SMB.Engine.Phase;
   use type SMB.Engine.Engine_State;
   use type SMB.Engine.Request_Expectation;
   use type SMB.Core_Wire.Command_Code;

   type Connection_Kind is
     (No_Connection, Negotiate, Tree_Connect, Tree_Disconnect, Logoff);
   type Connection_Stage is (Idle, Prepared, Sent, Finished, Failed);

   type Connection_State_Snapshot is record
      Kind : Connection_Kind := No_Connection;
      Stage : Connection_Stage := Idle;
      Owner, Epoch : SMB.QWord := 0;
      Starting_Phase : SMB.Engine.Phase := SMB.Engine.Disconnected;
      Starting_Session_Id : SMB.QWord := 0;
      Starting_Tree_Id : SMB.DWord := 0;
      Expected : SMB.Engine.Request_Expectation;
      Guid : SMB.Bytes (0 .. 15) := (others => 0);
      Path_Length : Natural := 0;
   end record;

   type Connection_Operation is limited private;

   function Same_Identity
     (Left, Right : Connection_State_Snapshot) return Boolean is
     (Left.Kind = Right.Kind
      and then Left.Owner = Right.Owner
      and then Left.Epoch = Right.Epoch
      and then Left.Starting_Phase = Right.Starting_Phase
      and then Left.Starting_Session_Id = Right.Starting_Session_Id
      and then Left.Starting_Tree_Id = Right.Starting_Tree_Id
      and then Left.Expected = Right.Expected
      and then Left.Guid = Right.Guid
      and then Left.Path_Length = Right.Path_Length)
   with Ghost;

   function Invalidated (State : SMB.Engine.Engine_State) return Boolean is
     (SMB.Engine.Current_Phase (State) = SMB.Engine.Disconnected
      and then not SMB.Engine.Has_Pending_Request (State)
      and then not SMB.Engine.Has_Validated_Response (State)
      and then not SMB.Engine.Has_Open_Handles (State)
      and then not SMB.Engine.Has_Signing_Key (State)
      and then SMB.Engine.Signing_Key_Is_Zero (State)
      and then SMB.Engine.Current_Session_Id (State) = 0
      and then SMB.Engine.Current_Tree_Id (State) = 0)
   with Ghost;

   function Stage_Of
     (Value : Connection_Operation) return Connection_Stage;
   function Kind_Of
     (Value : Connection_Operation) return Connection_Kind;
   function Snapshot_Of
     (Value : Connection_Operation) return Connection_State_Snapshot;
   function Expected_Of
     (Value : Connection_Operation) return SMB.Engine.Request_Expectation
   with Ghost;

   function Preparation_Context_Matches
     (Snapshot : Connection_State_Snapshot;
      State : SMB.Engine.Engine_State;
      Kind : Connection_Kind) return Boolean;
   function Continuation_Context_Matches
     (Snapshot : Connection_State_Snapshot;
      State : SMB.Engine.Engine_State) return Boolean;
   function Packet_Matches_Prepared
     (Value : Connection_Operation;
      State : SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Used : Natural) return Boolean
   with Ghost,
     Pre => Packet'Length <= SMB.Maximum_Frame_Size
       and then Snapshot_Of (Value).Path_Length <=
         SMB.Core_Protocol.Maximum_Name_Bytes;

   procedure Prepare_Negotiate
     (Value : in out Connection_Operation;
      State : in out SMB.Engine.Engine_State;
      Guid : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with
     Pre => Guid'Length = 16
       and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if not Preparation_Context_Matches
               (Snapshot_Of (Value)'Old, State'Old, Negotiate)
             or else Output'Length < SMB.Core_Wire.Header_Size + 38
          then Status /= SMB.Ok
            and then Snapshot_Of (Value) = Snapshot_Of (Value)'Old
            and then State = State'Old
            and then Used = 0)
       and then
         (if Status = SMB.Counter_Exhausted then
            Snapshot_Of (Value) = Snapshot_Of (Value)'Old
            and then State = State'Old
            and then Used = 0)
       and then
         (if Status = SMB.Ok then
            Stage_Of (Value) = Prepared
            and then Kind_Of (Value) = Negotiate
            and then SMB.Engine.Connection_Context_Equivalent
              (State'Old, State)
            and then Continuation_Context_Matches (Snapshot_Of (Value), State)
            and then Used = SMB.Core_Wire.Header_Size + 38
            and then Packet_Matches_Prepared (Value, State, Output, Used)
            and then
              (for all Index in 0 .. 15 =>
                 Output (Output'First + 76 + Index) =
                   Guid (Guid'First + Index))
            and then
              (for all Index in 0 .. 15 =>
                 Snapshot_Of (Value).Guid (Index) =
                   Guid (Guid'First + Index))
            and then Snapshot_Of (Value).Path_Length = 0);

   procedure Prepare_Tree_Connect
     (Value : in out Connection_Operation;
      State : in out SMB.Engine.Engine_State;
      Name : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with
     Pre => Name'Length <= SMB.Core_Protocol.Maximum_Name_Bytes
       and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if Name'Length = 0
               or else Name'Length mod 2 /= 0
               or else Output'Length <
                 SMB.Core_Wire.Header_Size + 8 + Name'Length
               or else not Preparation_Context_Matches
                 (Snapshot_Of (Value)'Old, State'Old, Tree_Connect)
          then Status /= SMB.Ok
            and then Snapshot_Of (Value) = Snapshot_Of (Value)'Old
            and then State = State'Old
            and then Used = 0)
       and then
         (if Status = SMB.Counter_Exhausted then
            Snapshot_Of (Value) = Snapshot_Of (Value)'Old
            and then State = State'Old
            and then Used = 0)
       and then
         (if Status = SMB.Ok then
            Stage_Of (Value) = Prepared
            and then Kind_Of (Value) = Tree_Connect
            and then SMB.Engine.Connection_Context_Equivalent
              (State'Old, State)
            and then Continuation_Context_Matches (Snapshot_Of (Value), State)
            and then Used = SMB.Core_Wire.Header_Size + 8 + Name'Length
            and then Packet_Matches_Prepared (Value, State, Output, Used)
            and then Snapshot_Of (Value).Path_Length = Name'Length
            and then
              (for all Index in 0 .. Name'Length - 1 =>
                 Output
                   (Output'First + SMB.Core_Wire.Header_Size + 8 + Index) =
                     Name (Name'First + Index)));

   procedure Prepare_Tree_Disconnect
     (Value : in out Connection_Operation;
      State : in out SMB.Engine.Engine_State;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with
     Pre => Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if Output'Length < SMB.Core_Wire.Header_Size + 4
               or else not Preparation_Context_Matches
                 (Snapshot_Of (Value)'Old, State'Old, Tree_Disconnect)
          then Status /= SMB.Ok
            and then Snapshot_Of (Value) = Snapshot_Of (Value)'Old
            and then State = State'Old
            and then Used = 0)
       and then
         (if Status = SMB.Counter_Exhausted then
            Snapshot_Of (Value) = Snapshot_Of (Value)'Old
            and then State = State'Old
            and then Used = 0)
       and then
         (if Status = SMB.Ok then
            Stage_Of (Value) = Prepared
            and then Kind_Of (Value) = Tree_Disconnect
            and then SMB.Engine.Connection_Context_Equivalent
              (State'Old, State)
            and then Continuation_Context_Matches (Snapshot_Of (Value), State)
            and then Used = SMB.Core_Wire.Header_Size + 4
            and then Packet_Matches_Prepared (Value, State, Output, Used));

   procedure Prepare_Logoff
     (Value : in out Connection_Operation;
      State : in out SMB.Engine.Engine_State;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with
     Pre => Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if Output'Length < SMB.Core_Wire.Header_Size + 4
               or else not Preparation_Context_Matches
                 (Snapshot_Of (Value)'Old, State'Old, Logoff)
          then Status /= SMB.Ok
            and then Snapshot_Of (Value) = Snapshot_Of (Value)'Old
            and then State = State'Old
            and then Used = 0)
       and then
         (if Status = SMB.Counter_Exhausted then
            Snapshot_Of (Value) = Snapshot_Of (Value)'Old
            and then State = State'Old
            and then Used = 0)
       and then
         (if Status = SMB.Ok then
            Stage_Of (Value) = Prepared
            and then Kind_Of (Value) = Logoff
            and then SMB.Engine.Connection_Context_Equivalent
              (State'Old, State)
            and then Continuation_Context_Matches (Snapshot_Of (Value), State)
            and then Used = SMB.Core_Wire.Header_Size + 4
            and then Snapshot_Of (Value).Expected.Tree_Id = 0
            and then Packet_Matches_Prepared (Value, State, Output, Used));

   procedure Send_Succeeded
     (Value : in out Connection_Operation;
      State : SMB.Engine.Engine_State;
      Status : out SMB.Core_Status)
   with Post =>
     Same_Identity (Snapshot_Of (Value)'Old, Snapshot_Of (Value))
     and then (if Status = SMB.Ok then
        Stage_Of (Value) = Sent
        and then Stage_Of (Value)'Old = Prepared
        and then Continuation_Context_Matches
          (Snapshot_Of (Value), State))
     and then
       (if Status = SMB.Invalid_State_Status then
          Snapshot_Of (Value) = Snapshot_Of (Value)'Old);

   procedure Complete
     (Value : in out Connection_Operation;
      State : in out SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Nt_Status : out SMB.DWord;
      Status : out SMB.Core_Status)
   with
     Pre => Packet'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Same_Identity (Snapshot_Of (Value)'Old, Snapshot_Of (Value))
       and then (if Stage_Of (Value)'Old /= Sent
             or else not Continuation_Context_Matches
               (Snapshot_Of (Value)'Old, State'Old)
        then Status = SMB.Invalid_State_Status
          and then Snapshot_Of (Value) = Snapshot_Of (Value)'Old
          and then State = State'Old
          and then Nt_Status = 0)
       and then
         (if Status = SMB.Ok then
            Stage_Of (Value) = Finished
            and then Stage_Of (Value)'Old = Sent
            and then not SMB.Engine.Has_Pending_Request (State)
            and then not SMB.Engine.Has_Validated_Response (State)
            and then
              (if Nt_Status /= SMB.Success then
                 SMB.Engine.Connection_Context_Equivalent (State'Old, State)
               else
                 (if Kind_Of (Value) /= Logoff then
                    SMB.Engine.Current_Owner_Id (State) =
                      SMB.Engine.Current_Owner_Id (State'Old)
                    and then SMB.Engine.Current_Epoch (State) =
                      SMB.Engine.Current_Epoch (State'Old))
                 and then
                   (if Kind_Of (Value) in Negotiate | Tree_Connect then
                      SMB.Engine.Handle_Table_Equivalent (State'Old, State)
                      and then SMB.Engine.Current_Signing_Key (State) =
                        SMB.Engine.Current_Signing_Key (State'Old)
                      and then SMB.Engine.Has_Signing_Key (State) =
                        SMB.Engine.Has_Signing_Key (State'Old))
                 and then
                   (case Kind_Of (Value) is
                      when Negotiate =>
                        Packet'Length >= 128
                        and then SMB.Engine.Current_Phase (State) =
                          SMB.Engine.Negotiated
                        and then SMB.Engine.Current_Session_Id (State) = 0
                        and then SMB.Engine.Current_Tree_Id (State) = 0
                        and then SMB.Engine.Current_Max_Read (State) in
                          1 .. SMB.Core_Protocol.Maximum_IO_Chunk
                        and then SMB.Engine.Current_Max_Write (State) in
                          1 .. SMB.Core_Protocol.Maximum_IO_Chunk
                        and then SMB.Engine.Current_Max_Read (State) =
                          Natural (SMB.DWord'Min
                            (SMB.Core_Protocol.Maximum_IO_Chunk,
                             SMB.Core_Wire.Encoded_U32 (Packet, 96)))
                        and then SMB.Engine.Current_Max_Write (State) =
                          Natural (SMB.DWord'Min
                            (SMB.Core_Protocol.Maximum_IO_Chunk,
                             SMB.Core_Wire.Encoded_U32 (Packet, 100))),
                      when Tree_Connect =>
                        Packet'Length >= 80
                        and then SMB.Engine.Current_Phase (State) =
                          SMB.Engine.Share_Connected
                        and then SMB.Engine.Current_Tree_Id (State) /= 0
                        and then SMB.Engine.Current_Tree_Id (State) =
                          SMB.Core_Wire.Encoded_U32 (Packet, 36)
                        and then SMB.Engine.Current_Session_Id (State) =
                          SMB.Engine.Current_Session_Id (State'Old),
                      when Tree_Disconnect =>
                        SMB.Engine.Current_Phase (State) =
                          SMB.Engine.Authenticated
                        and then SMB.Engine.Current_Tree_Id (State) = 0
                        and then not SMB.Engine.Has_Open_Handles (State)
                        and then SMB.Engine.Current_Session_Id (State) =
                          SMB.Engine.Current_Session_Id (State'Old)
                        and then SMB.Engine.Current_Signing_Key (State) =
                          SMB.Engine.Current_Signing_Key (State'Old)
                        and then SMB.Engine.Has_Signing_Key (State) =
                          SMB.Engine.Has_Signing_Key (State'Old),
                      when Logoff => Invalidated (State),
                      when No_Connection => False)))
       and then
         (if Stage_Of (Value)'Old = Sent
               and then Continuation_Context_Matches
                 (Snapshot_Of (Value)'Old, State'Old)
               and then Status /= SMB.Ok
          then Stage_Of (Value) = Failed and then Invalidated (State));

   procedure Abort_Connection
     (Value : in out Connection_Operation;
      State : in out SMB.Engine.Engine_State;
      Status : out SMB.Core_Status)
   with Post =>
     Same_Identity (Snapshot_Of (Value)'Old, Snapshot_Of (Value))
     and then (if Snapshot_Of (Value)'Old.Stage not in Prepared | Sent
           or else not Continuation_Context_Matches
             (Snapshot_Of (Value)'Old, State'Old)
      then Status = SMB.Invalid_State_Status
        and then Snapshot_Of (Value) = Snapshot_Of (Value)'Old
        and then State = State'Old)
     and then
       (if Snapshot_Of (Value)'Old.Stage in Prepared | Sent
             and then Continuation_Context_Matches
               (Snapshot_Of (Value)'Old, State'Old)
        then
          Stage_Of (Value) = Failed
          and then Invalidated (State));

private
   type Connection_Operation is limited record
      Kind : Connection_Kind := No_Connection;
      Stage : Connection_Stage := Idle;
      Owner, Epoch : SMB.QWord := 0;
      Starting_Phase : SMB.Engine.Phase := SMB.Engine.Disconnected;
      Starting_Session_Id : SMB.QWord := 0;
      Starting_Tree_Id : SMB.DWord := 0;
      Expected : SMB.Engine.Request_Expectation;
      Guid : SMB.Bytes (0 .. 15) := (others => 0);
      Path_Length : Natural := 0;
   end record;
end SMB.Core_Connection;
