with SMB.Core_Wire;
with SMB.Engine;
with SMB.Spec.FSCC;
with SMB.Spec.SMB2;

--  SET_INFO FileEndOfFileInformation on an open handle (MS-SMB2 2.2.39 and
--  2.2.40, MS-FSCC FileEndOfFileInformation): one request that sets the
--  file's size, truncating or extending it. The handle must have been
--  opened for writing. An operation goes from Resize_Idle to
--  Resize_Prepared and Resize_Sent, and ends Resize_Finished or
--  Resize_Failed, as SMB.Core_Query's operations do.
package SMB.Core_Resize
  with SPARK_Mode
is
   use type SMB.Word;
   use type SMB.DWord;
   use type SMB.QWord;
   use type SMB.Byte;
   use type SMB.Core_Wire.Command_Code;
   use type SMB.Engine.Phase;
   use type SMB.Engine.Access_Kind;
   use type SMB.Engine.Engine_State;
   use type SMB.Engine.Handle_Token;
   use type SMB.Engine.Request_Expectation;
   pragma Unevaluated_Use_Of_Old (Allow);

   type Resize_Stage is
     (Resize_Idle, Resize_Prepared, Resize_Sent, Resize_Finished,
      Resize_Failed);
   type Resize_Operation is limited private;

   Set_Info_Command : constant SMB.Core_Wire.Command_Code := 17;
   Request_Size : constant Natural := SMB.Core_Wire.Header_Size + 40;
   --  EndOfFile is a signed 64-bit count of bytes.
   Maximum_Size : constant SMB.QWord := 2 ** 63 - 1;

   subtype File_Id_Bytes is SMB.Bytes (0 .. 15);
   type Resize_Snapshot is record
      Stage : Resize_Stage;
      Owner, Epoch : SMB.QWord;
      Token : SMB.Engine.Handle_Token;
      File_Id : File_Id_Bytes;
      Access_Mode : SMB.Engine.Access_Kind;
      Directory : Boolean;
      Expected : SMB.Engine.Request_Expectation;
      Size : SMB.QWord;
   end record;

   function Snapshot_Of (Value : Resize_Operation) return Resize_Snapshot;
   --  Left and Right are of the same request; the stage may differ.
   function Same_Request (Left, Right : Resize_Snapshot) return Boolean is
     (Left.Owner = Right.Owner
      and then Left.Epoch = Right.Epoch
      and then Left.Token = Right.Token
      and then Left.File_Id = Right.File_Id
      and then Left.Access_Mode = Right.Access_Mode
      and then Left.Directory = Right.Directory
      and then Left.Expected = Right.Expected
      and then Left.Size = Right.Size);
   function Stage_Of (Value : Resize_Operation) return Resize_Stage is
     (Snapshot_Of (Value).Stage);

   --  Prepare can start: an idle operation, no request in flight on a
   --  connected share, and Token a live handle of this connection that may
   --  write.
   function Can_Prepare
     (Snapshot : Resize_Snapshot;
      State : SMB.Engine.Engine_State;
      Token : SMB.Engine.Handle_Token) return Boolean
   with Ghost;

   --  The request is in flight, on the handle it was prepared for.
   function In_Flight
     (Snapshot : Resize_Snapshot;
      State : SMB.Engine.Engine_State) return Boolean
   with Ghost;

   --  The first Used bytes of Packet are the operation's signed request.
   function Packet_Matches
     (Snapshot : Resize_Snapshot;
      State : SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Used : Natural) return Boolean
   with Ghost, Pre => Packet'Length <= SMB.Maximum_Frame_Size;

   procedure Prepare
     (Value : in out Resize_Operation;
      State : in out SMB.Engine.Engine_State;
      Token : SMB.Engine.Handle_Token;
      Size : SMB.QWord;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with
     Pre => Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if not Can_Prepare (Snapshot_Of (Value), State, Token)'Old
          then Status = SMB.Invalid_State_Status
          elsif Size > Maximum_Size then Status = SMB.Invalid_Value)
       and then
         (if Status = SMB.Ok then
            Can_Prepare (Snapshot_Of (Value), State, Token)'Old
            and then Size <= Maximum_Size
            and then Used = Request_Size
            and then Stage_Of (Value) = Resize_Prepared
            and then Snapshot_Of (Value).Token = Token
            and then Snapshot_Of (Value).Size = Size
            and then Snapshot_Of (Value).Owner =
              SMB.Engine.Current_Owner_Id (State)
            and then Snapshot_Of (Value).Epoch =
              SMB.Engine.Current_Epoch (State)
            and then Packet_Matches (Snapshot_Of (Value), State, Output, Used)
            and then SMB.Engine.Pending_Request_Matches
              (State, Snapshot_Of (Value).Expected)
            and then SMB.Engine.Handle_Matches
              (State'Old, Token, Snapshot_Of (Value).File_Id,
               Snapshot_Of (Value).Access_Mode,
               Snapshot_Of (Value).Directory)
            and then SMB.Engine.Handle_Matches_In_States
              (State'Old, State, Token, Snapshot_Of (Value).File_Id,
               Snapshot_Of (Value).Access_Mode,
               Snapshot_Of (Value).Directory)
          else Snapshot_Of (Value) = Snapshot_Of (Value)'Old
            and then State = State'Old
            and then Used = 0);

   procedure Send_Succeeded
     (Value : in out Resize_Operation;
      State : SMB.Engine.Engine_State;
      Status : out SMB.Core_Status)
   with
     Post =>
       (if Status = SMB.Ok then
          Stage_Of (Value)'Old = Resize_Prepared
          and then Stage_Of (Value) = Resize_Sent
          and then Same_Request (Snapshot_Of (Value), Snapshot_Of (Value)'Old)
          and then In_Flight (Snapshot_Of (Value), State)
        else Status = SMB.Invalid_State_Status
          and then Snapshot_Of (Value) = Snapshot_Of (Value)'Old);

   --  Takes the response. An error status from the server also finishes
   --  the operation, for the caller to report. Otherwise the call either
   --  changes nothing and reports Invalid_State_Status, or fails the
   --  operation and invalidates the connection: no response is taken
   --  without its checks.
   procedure Complete
     (Value : in out Resize_Operation;
      State : in out SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Nt_Status : out SMB.DWord;
      Status : out SMB.Core_Status)
   with
     Pre => Packet'Length <= SMB.Maximum_Frame_Size,
     Post =>
       (if not In_Flight (Snapshot_Of (Value), State)'Old
           or else SMB.Engine.Has_Validated_Response (State)'Old
        then Status = SMB.Invalid_State_Status
          and then Snapshot_Of (Value) = Snapshot_Of (Value)'Old
          and then State = State'Old
          and then Nt_Status = 0)
       and then
         (if Status = SMB.Ok then
            In_Flight (Snapshot_Of (Value), State)'Old
            and then Stage_Of (Value) = Resize_Finished
            and then Same_Request
              (Snapshot_Of (Value), Snapshot_Of (Value)'Old)
            and then Nt_Status = SMB.Core_Wire.Header_Nt_Status (Packet)
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Share_Connected
            and then SMB.Engine.Current_Owner_Id (State) =
              Snapshot_Of (Value).Owner
            and then SMB.Engine.Current_Epoch (State) =
              Snapshot_Of (Value).Epoch
            and then not SMB.Engine.Has_Pending_Request (State)
            and then not SMB.Engine.Has_Validated_Response (State)
            and then SMB.Engine.Handle_Matches
              (State, Snapshot_Of (Value).Token, Snapshot_Of (Value).File_Id,
               Snapshot_Of (Value).Access_Mode,
               Snapshot_Of (Value).Directory)
          elsif Status = SMB.Invalid_State_Status then
            Snapshot_Of (Value) = Snapshot_Of (Value)'Old
            and then State = State'Old
            and then Nt_Status = 0
          else Stage_Of (Value) = Resize_Failed
            and then Same_Request
              (Snapshot_Of (Value), Snapshot_Of (Value)'Old)
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected
            and then not SMB.Engine.Has_Pending_Request (State));

   --  Gives up on a prepared or sent request: the connection cannot tell
   --  its response from a later one, so it is invalidated.
   procedure Abort_Resize
     (Value : in out Resize_Operation;
      State : in out SMB.Engine.Engine_State;
      Status : out SMB.Core_Status)
   with
     Post =>
       (if Status = SMB.Invalid_State_Status then
          Snapshot_Of (Value) = Snapshot_Of (Value)'Old
          and then State = State'Old
        else Stage_Of (Value)'Old in Resize_Prepared | Resize_Sent
          and then Stage_Of (Value) = Resize_Failed
          and then Same_Request (Snapshot_Of (Value), Snapshot_Of (Value)'Old)
          and then SMB.Engine.Current_Phase (State) =
            SMB.Engine.Disconnected
          and then not SMB.Engine.Has_Pending_Request (State));

private
   type Resize_Operation is limited record
      Stage : Resize_Stage := Resize_Idle;
      Owner, Epoch : SMB.QWord := 0;
      Token : SMB.Engine.Handle_Token := (others => 0);
      File_Id : File_Id_Bytes := (others => 0);
      Access_Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
      Directory : Boolean := False;
      Expected : SMB.Engine.Request_Expectation;
      Size : SMB.QWord := 0;
   end record;

   function Snapshot_Of (Value : Resize_Operation) return Resize_Snapshot is
     ((Stage => Value.Stage,
       Owner => Value.Owner,
       Epoch => Value.Epoch,
       Token => Value.Token,
       File_Id => Value.File_Id,
       Access_Mode => Value.Access_Mode,
       Directory => Value.Directory,
       Expected => Value.Expected,
       Size => Value.Size));

   function Can_Prepare
     (Snapshot : Resize_Snapshot;
      State : SMB.Engine.Engine_State;
      Token : SMB.Engine.Handle_Token) return Boolean is
     (Snapshot.Stage = Resize_Idle
      and then SMB.Engine.Current_Phase (State) =
        SMB.Engine.Share_Connected
      and then not SMB.Engine.Has_Pending_Request (State)
      and then not SMB.Engine.Has_Validated_Response (State)
      and then Token.Owner = SMB.Engine.Current_Owner_Id (State)
      and then Token.Epoch = SMB.Engine.Current_Epoch (State)
      and then Token.Ticket /= 0
      and then SMB.Engine.Valid_Handle (State, Token, False, True));

   function In_Flight
     (Snapshot : Resize_Snapshot;
      State : SMB.Engine.Engine_State) return Boolean is
     (Snapshot.Stage = Resize_Sent
      and then Snapshot.Expected.Command = Set_Info_Command
      and then Snapshot.Expected.Request_Signed
      and then Snapshot.Expected.Signed
      and then Snapshot.Owner = SMB.Engine.Current_Owner_Id (State)
      and then Snapshot.Epoch = SMB.Engine.Current_Epoch (State)
      and then SMB.Engine.Current_Phase (State) =
        SMB.Engine.Share_Connected
      and then SMB.Engine.Handle_Matches
        (State, Snapshot.Token, Snapshot.File_Id, Snapshot.Access_Mode,
         Snapshot.Directory)
      and then SMB.Engine.Pending_Request_Matches
        (State, Snapshot.Expected));

   function Packet_Matches
     (Snapshot : Resize_Snapshot;
      State : SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Used : Natural) return Boolean is
     (Snapshot.Stage = Resize_Prepared
      and then Snapshot.Owner = SMB.Engine.Current_Owner_Id (State)
      and then Snapshot.Epoch = SMB.Engine.Current_Epoch (State)
      and then Snapshot.Token.Owner = Snapshot.Owner
      and then Snapshot.Token.Epoch = Snapshot.Epoch
      and then Snapshot.Token.Ticket /= 0
      and then SMB.Engine.Pending_Request_Matches (State, Snapshot.Expected)
      and then Snapshot.Expected.Command = Set_Info_Command
      and then Snapshot.Expected.Request_Signed
      and then Snapshot.Expected.Signed
      and then Used = Request_Size
      and then Used <= Packet'Length
      and then SMB.Core_Wire.Encoded_U16 (Packet, 4) =
        SMB.Word (SMB.Core_Wire.Header_Size)
      and then SMB.Core_Wire.Encoded_U16 (Packet, 12) =
        SMB.Word (Set_Info_Command)
      and then SMB.Core_Wire.Encoded_U32 (Packet, 16) = 8
      and then SMB.Core_Wire.Encoded_U64 (Packet, 24) =
        Snapshot.Expected.Message_Id
      and then SMB.Core_Wire.Encoded_U32 (Packet, 36) =
        Snapshot.Expected.Tree_Id
      and then SMB.Core_Wire.Encoded_U64 (Packet, 40) =
        Snapshot.Expected.Session_Id
      and then SMB.Core_Wire.Encoded_U16 (Packet, 64) = 33
      and then Packet (Packet'First + 66) = 1
      and then Packet (Packet'First + 67) = 20
      and then SMB.Core_Wire.Encoded_U32 (Packet, 68) = 8
      and then SMB.Core_Wire.Encoded_U16 (Packet, 72) = 96
      and then
        (for all Index in 74 .. 79 => Packet (Packet'First + Index) = 0)
      and then
        (for all Index in 0 .. 15 =>
           Packet (Packet'First + 80 + Index) = Snapshot.File_Id (Index))
      and then SMB.Core_Wire.Encoded_U64 (Packet, 96) = Snapshot.Size
      --  The body, as the specifications give this client's SET_INFO with
      --  FileEndOfFileInformation.
      and then SMB.Spec.SMB2.Is_Set_Info_Request
        (Packet (Packet'First + SMB.Core_Wire.Header_Size
                 .. Packet'First + (Used - 1)),
         SMB.Spec.SMB2.Client_Set_Info
           (SMB.Spec.FSCC.File_End_Of_File_Information, 8,
            Snapshot.File_Id),
         Packet (Packet'First + 96 .. Packet'First + (Used - 1)))
      and then SMB.Spec.FSCC.Is_End_Of_File_Information
        (Packet (Packet'First + 96 .. Packet'First + (Used - 1)),
         Snapshot.Size)
      --  The header, as the specification gives this client's request:
      --  every byte but the Signature, which signing fills in.
      and then SMB.Spec.SMB2.Is_Sync_Header
        (Packet,
         (SMB.Spec.SMB2.Request_Header
            (Command => SMB.Spec.SMB2.Set_Info,
             Credit_Charge => Snapshot.Expected.Credit_Charge,
             Credit_Request => Snapshot.Expected.Credit_Request,
             Flags => SMB.Spec.SMB2.Flags_Signed,
             Message_Id => Snapshot.Expected.Message_Id,
             Tree_Id => Snapshot.Expected.Tree_Id,
             Session_Id => Snapshot.Expected.Session_Id)
          with delta Signature =>
            Packet (Packet'First + 48 .. Packet'First + 63))));
end SMB.Core_Resize;
