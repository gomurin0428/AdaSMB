with SMB.Core_Protocol;
with SMB.Core_Wire;
with SMB.Engine;

--  QUERY_INFO on an open handle (MS-SMB2 2.2.37 and 2.2.38): one request for
--  FileNetworkOpenInformation, whose response gives the file's times, sizes
--  and attributes. An operation goes from Query_Idle to Query_Prepared and
--  Query_Sent, and ends Query_Finished or Query_Failed, as the metadata
--  operations of SMB.Core_Client do. Any handle will do: every access mode
--  the client opens with includes FILE_READ_ATTRIBUTES.
package SMB.Core_Query
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
   use type SMB.Core_Protocol.File_Information;
   pragma Unevaluated_Use_Of_Old (Allow);

   type Query_Stage is
     (Query_Idle, Query_Prepared, Query_Sent, Query_Finished, Query_Failed);
   type Query_Operation is limited private;

   Query_Info_Command : constant SMB.Core_Wire.Command_Code := 16;
   Request_Size : constant Natural := SMB.Core_Wire.Header_Size + 41;

   subtype File_Id_Bytes is SMB.Bytes (0 .. 15);
   type Query_Snapshot is record
      Stage : Query_Stage;
      Owner, Epoch : SMB.QWord;
      Token : SMB.Engine.Handle_Token;
      File_Id : File_Id_Bytes;
      Access_Mode : SMB.Engine.Access_Kind;
      Directory : Boolean;
      Expected : SMB.Engine.Request_Expectation;
      --  What a successful response gave; all zero until then.
      Result : SMB.Core_Protocol.File_Information;
   end record;

   function Snapshot_Of (Value : Query_Operation) return Query_Snapshot;
   --  Left and Right are of the same request; the stage and result may
   --  differ.
   function Same_Request (Left, Right : Query_Snapshot) return Boolean is
     (Left.Owner = Right.Owner
      and then Left.Epoch = Right.Epoch
      and then Left.Token = Right.Token
      and then Left.File_Id = Right.File_Id
      and then Left.Access_Mode = Right.Access_Mode
      and then Left.Directory = Right.Directory
      and then Left.Expected = Right.Expected);
   function Stage_Of (Value : Query_Operation) return Query_Stage is
     (Snapshot_Of (Value).Stage);
   function Result_Of
     (Value : Query_Operation) return SMB.Core_Protocol.File_Information is
     (Snapshot_Of (Value).Result);

   --  Prepare can start: an idle operation, no request in flight on a
   --  connected share, and Token a live handle of this connection.
   function Can_Prepare
     (Snapshot : Query_Snapshot;
      State : SMB.Engine.Engine_State;
      Token : SMB.Engine.Handle_Token) return Boolean
   with Ghost;

   --  The request is in flight, on the handle it was prepared for.
   function In_Flight
     (Snapshot : Query_Snapshot;
      State : SMB.Engine.Engine_State) return Boolean
   with Ghost;

   --  The first Used bytes of Packet are the operation's signed request.
   function Packet_Matches
     (Snapshot : Query_Snapshot;
      State : SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Used : Natural) return Boolean
   with Ghost, Pre => Packet'Length <= SMB.Maximum_Frame_Size;

   procedure Prepare
     (Value : in out Query_Operation;
      State : in out SMB.Engine.Engine_State;
      Token : SMB.Engine.Handle_Token;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with
     Pre => Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if not Can_Prepare (Snapshot_Of (Value), State, Token)'Old
          then Status = SMB.Invalid_State_Status)
       and then
         (if Status = SMB.Ok then
            Can_Prepare (Snapshot_Of (Value), State, Token)'Old
            and then Used = Request_Size
            and then Stage_Of (Value) = Query_Prepared
            and then Snapshot_Of (Value).Token = Token
            and then Snapshot_Of (Value).Owner =
              SMB.Engine.Current_Owner_Id (State)
            and then Snapshot_Of (Value).Epoch =
              SMB.Engine.Current_Epoch (State)
            and then Result_Of (Value) =
              SMB.Core_Protocol.File_Information'(others => <>)
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
     (Value : in out Query_Operation;
      State : SMB.Engine.Engine_State;
      Status : out SMB.Core_Status)
   with
     Post =>
       (if Status = SMB.Ok then
          Stage_Of (Value)'Old = Query_Prepared
          and then Stage_Of (Value) = Query_Sent
          and then Same_Request (Snapshot_Of (Value), Snapshot_Of (Value)'Old)
          and then Result_Of (Value) = Result_Of (Value)'Old
          and then In_Flight (Snapshot_Of (Value), State)
        else Status = SMB.Invalid_State_Status
          and then Snapshot_Of (Value) = Snapshot_Of (Value)'Old);

   --  Takes the response. An error status from the server also finishes
   --  the operation, with Result_Of left zero, for the caller to report.
   --  Otherwise the call either changes nothing and reports
   --  Invalid_State_Status, or fails the operation and invalidates the
   --  connection: no response is taken without its checks.
   procedure Complete
     (Value : in out Query_Operation;
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
            and then Stage_Of (Value) = Query_Finished
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
            and then
              (if Nt_Status = SMB.Success then
                 Packet'Length >= 72
                 and then SMB.Core_Wire.Encoded_U32 (Packet, 68) =
                   SMB.Core_Protocol.Network_Open_Information_Size
                 and then Natural (SMB.Core_Wire.Encoded_U16 (Packet, 66))
                   >= 72
                 and then Natural (SMB.Core_Wire.Encoded_U16 (Packet, 66))
                   + SMB.Core_Protocol.Network_Open_Information_Size
                   <= Packet'Length
                 and then Result_Of (Value) =
                   SMB.Core_Protocol.Network_Open_Information
                     (Packet,
                      Natural (SMB.Core_Wire.Encoded_U16 (Packet, 66)))
               else Result_Of (Value) =
                 SMB.Core_Protocol.File_Information'(others => <>))
          elsif Status = SMB.Invalid_State_Status then
            Snapshot_Of (Value) = Snapshot_Of (Value)'Old
            and then State = State'Old
            and then Nt_Status = 0
          else Stage_Of (Value) = Query_Failed
            and then Same_Request
              (Snapshot_Of (Value), Snapshot_Of (Value)'Old)
            and then Result_Of (Value) = Result_Of (Value)'Old
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected
            and then not SMB.Engine.Has_Pending_Request (State));

   --  Gives up on a prepared or sent request: the connection cannot tell
   --  its response from a later one, so it is invalidated.
   procedure Abort_Query
     (Value : in out Query_Operation;
      State : in out SMB.Engine.Engine_State;
      Status : out SMB.Core_Status)
   with
     Post =>
       (if Status = SMB.Invalid_State_Status then
          Snapshot_Of (Value) = Snapshot_Of (Value)'Old
          and then State = State'Old
        else Stage_Of (Value)'Old in Query_Prepared | Query_Sent
          and then Stage_Of (Value) = Query_Failed
          and then Same_Request (Snapshot_Of (Value), Snapshot_Of (Value)'Old)
          and then Result_Of (Value) = Result_Of (Value)'Old
          and then SMB.Engine.Current_Phase (State) =
            SMB.Engine.Disconnected
          and then not SMB.Engine.Has_Pending_Request (State));

private
   type Query_Operation is limited record
      Stage : Query_Stage := Query_Idle;
      Owner, Epoch : SMB.QWord := 0;
      Token : SMB.Engine.Handle_Token := (others => 0);
      File_Id : File_Id_Bytes := (others => 0);
      Access_Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
      Directory : Boolean := False;
      Expected : SMB.Engine.Request_Expectation;
      Result : SMB.Core_Protocol.File_Information;
   end record;

   function Snapshot_Of (Value : Query_Operation) return Query_Snapshot is
     ((Stage => Value.Stage,
       Owner => Value.Owner,
       Epoch => Value.Epoch,
       Token => Value.Token,
       File_Id => Value.File_Id,
       Access_Mode => Value.Access_Mode,
       Directory => Value.Directory,
       Expected => Value.Expected,
       Result => Value.Result));

   function Can_Prepare
     (Snapshot : Query_Snapshot;
      State : SMB.Engine.Engine_State;
      Token : SMB.Engine.Handle_Token) return Boolean is
     (Snapshot.Stage = Query_Idle
      and then SMB.Engine.Current_Phase (State) =
        SMB.Engine.Share_Connected
      and then not SMB.Engine.Has_Pending_Request (State)
      and then not SMB.Engine.Has_Validated_Response (State)
      and then Token.Owner = SMB.Engine.Current_Owner_Id (State)
      and then Token.Epoch = SMB.Engine.Current_Epoch (State)
      and then Token.Ticket /= 0
      and then SMB.Engine.Valid_Handle (State, Token, False, False));

   function In_Flight
     (Snapshot : Query_Snapshot;
      State : SMB.Engine.Engine_State) return Boolean is
     (Snapshot.Stage = Query_Sent
      and then Snapshot.Expected.Command = Query_Info_Command
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
     (Snapshot : Query_Snapshot;
      State : SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Used : Natural) return Boolean is
     (Snapshot.Stage = Query_Prepared
      and then Snapshot.Owner = SMB.Engine.Current_Owner_Id (State)
      and then Snapshot.Epoch = SMB.Engine.Current_Epoch (State)
      and then Snapshot.Token.Owner = Snapshot.Owner
      and then Snapshot.Token.Epoch = Snapshot.Epoch
      and then Snapshot.Token.Ticket /= 0
      and then SMB.Engine.Pending_Request_Matches (State, Snapshot.Expected)
      and then Snapshot.Expected.Command = Query_Info_Command
      and then Snapshot.Expected.Request_Signed
      and then Snapshot.Expected.Signed
      and then Used = Request_Size
      and then Used <= Packet'Length
      and then SMB.Core_Wire.Encoded_U16 (Packet, 4) =
        SMB.Word (SMB.Core_Wire.Header_Size)
      and then SMB.Core_Wire.Encoded_U16 (Packet, 12) =
        SMB.Word (Query_Info_Command)
      and then SMB.Core_Wire.Encoded_U32 (Packet, 16) = 8
      and then SMB.Core_Wire.Encoded_U64 (Packet, 24) =
        Snapshot.Expected.Message_Id
      and then SMB.Core_Wire.Encoded_U32 (Packet, 36) =
        Snapshot.Expected.Tree_Id
      and then SMB.Core_Wire.Encoded_U64 (Packet, 40) =
        Snapshot.Expected.Session_Id
      and then SMB.Core_Wire.Encoded_U16 (Packet, 64) = 41
      and then Packet (Packet'First + 66) = 1
      and then Packet (Packet'First + 67) =
        SMB.Core_Protocol.Network_Open_Information_Class
      and then SMB.Core_Wire.Encoded_U32 (Packet, 68) =
        SMB.Core_Protocol.Network_Open_Information_Size
      and then
        (for all Index in 72 .. 87 => Packet (Packet'First + Index) = 0)
      and then
        (for all Index in 0 .. 15 =>
           Packet (Packet'First + 88 + Index) = Snapshot.File_Id (Index))
      and then Packet (Packet'First + 104) = 0);
end SMB.Core_Query;
