with SMB.Core_Auth;
with SMB.Core_Protocol;
with SMB.Core_Wire;
with SMB.Engine;

package SMB.Core_Client
  with SPARK_Mode
is
   use type SMB.DWord;
   use type SMB.Word;
   use type SMB.QWord;
   use type SMB.Byte;
   use type SMB.Core_Wire.Command_Code;
   use type SMB.Engine.Access_Kind;
   use type SMB.Engine.Phase;
   use type SMB.Core_Protocol.Response_Info;
   pragma Unevaluated_Use_Of_Old (Allow);
   type Operation_Kind is (No_Operation, Create_Operation, Close_Operation);
   type Operation_Stage is (Idle, Prepared, Sent, Finished, Failed);

   type Operation is limited private;

   type Transfer_Kind is (Read_Transfer, Write_Transfer);
   type Transfer_Stage is (Ready, Transfer_Prepared, Transfer_Sent,
                           Transfer_Finished, Transfer_Failed);
   subtype Transfer_Capacity is
     Natural range 0 .. SMB.Maximum_Frame_Size;
   type Transfer
     (Capacity : Transfer_Capacity) is limited private;

   type Authentication_Stage is
     (Authentication_Ready,
      Negotiate_Prepared,
      Negotiate_Sent,
      Challenge_Received,
      Authenticate_Prepared,
      Authenticate_Sent,
      Authentication_Finished,
      Authentication_Failed);
   type Authentication is limited private;
   Authentication_Request_Size : constant Natural :=
     SMB.Core_Wire.Header_Size + 24 + SMB.Core_Auth.Maximum_Security_Token;

   function Authentication_Stage_Of
     (Value : Authentication) return Authentication_Stage;
   function Authentication_Session_Id_Of
     (Value : Authentication) return SMB.QWord;
   function Authentication_Challenge_Length_Of
     (Value : Authentication) return Natural;
   function Authentication_Challenge_Byte_Of
     (Value : Authentication; Index : Natural) return SMB.Byte
   with Pre => Index < Authentication_Challenge_Length_Of (Value)
       and then Index < SMB.Core_Auth.Maximum_Security_Token;
   function Authentication_Buffer_Of
     (Value : Authentication) return SMB.Bytes
   with Ghost;
   function Authentication_Expected_Of
     (Value : Authentication)
       return SMB.Engine.Request_Expectation
   with Ghost;
   function Authentication_Owner_Of
     (Value : Authentication) return SMB.QWord
   with Ghost;
   function Authentication_Epoch_Of
     (Value : Authentication) return SMB.QWord
   with Ghost;
   function Authentication_Context_Matches
     (Value : Authentication;
      State : SMB.Engine.Engine_State) return Boolean;
   function Authentication_Packet_Matches
     (Value : Authentication;
      State : SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Used : Natural) return Boolean
   with Pre => Packet'Length <= SMB.Maximum_Frame_Size;

   procedure Prepare_Negotiate
     (Value : in out Authentication;
      State : in out SMB.Engine.Engine_State;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with
     Pre => Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (Status /= SMB.Ok
          or else
            (Authentication_Stage_Of (Value) = Negotiate_Prepared
             and then Authentication_Packet_Matches (Value, State, Output, Used)));

   procedure Authentication_Send_Succeeded
     (Value : in out Authentication;
      State : SMB.Engine.Engine_State;
      Status : out SMB.Core_Status)
   with
     Post =>
     (if Status = SMB.Ok then
           (Authentication_Stage_Of (Value) in
             Negotiate_Sent | Authenticate_Sent
           and then Authentication_Stage_Of (Value)'Old in
             Negotiate_Prepared | Authenticate_Prepared
           and then Authentication_Context_Matches (Value, State)
           and then Authentication_Owner_Of (Value) =
             Authentication_Owner_Of (Value)'Old
           and then Authentication_Epoch_Of (Value) =
             Authentication_Epoch_Of (Value)'Old
           and then Authentication_Owner_Of (Value)'Old =
             SMB.Engine.Current_Owner_Id (State)'Old
           and then Authentication_Epoch_Of (Value)'Old =
             SMB.Engine.Current_Epoch (State)'Old
           and then Authentication_Session_Id_Of (Value) =
             Authentication_Session_Id_Of (Value)'Old
           and then SMB.Engine."=" (Authentication_Expected_Of (Value),
             Authentication_Expected_Of (Value)'Old)));

   procedure Complete_Challenge
     (Value : in out Authentication;
      State : in out SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Nt_Status : out SMB.DWord;
      Status : out SMB.Core_Status)
   with
     Pre => Packet'Length <= SMB.Maximum_Frame_Size,
     Post =>
       (if Status = SMB.Ok and then
           Nt_Status = SMB.Status_More_Processing_Required
        then
          Authentication_Stage_Of (Value)'Old = Negotiate_Sent
          and then Authentication_Owner_Of (Value)'Old =
            SMB.Engine.Current_Owner_Id (State)'Old
          and then Authentication_Epoch_Of (Value)'Old =
            SMB.Engine.Current_Epoch (State)'Old
          and then Authentication_Context_Matches (Value, State)
          and then Authentication_Owner_Of (Value) =
            Authentication_Owner_Of (Value)'Old
          and then Authentication_Epoch_Of (Value) =
            Authentication_Epoch_Of (Value)'Old
          and then Authentication_Stage_Of (Value) = Challenge_Received
          and then Authentication_Challenge_Length_Of (Value) <=
            SMB.Core_Auth.Maximum_Security_Token
          and then Authentication_Challenge_Length_Of (Value) =
            SMB.Engine.Current_Response_Info (State).Data_Length
          and then Authentication_Session_Id_Of (Value) /= 0
          and then Authentication_Session_Id_Of (Value) =
            SMB.Engine.Current_Response_Info (State).Session_Id
          and then not SMB.Engine.Has_Pending_Request (State)
          and then SMB.Engine.Response_Receipt_Matches
            (State, 1, Nt_Status, False, False)
          and then
            (if Authentication_Challenge_Length_Of (Value) = 0
             then True
             else
               Packet'Length >= 72
               and then SMB.Engine.Current_Response_Info (State).Data_Offset =
                 Natural (SMB.Core_Wire.Encoded_U16 (Packet, 68))
               and then SMB.Engine.Current_Response_Info (State).Data_Length =
                 Natural (SMB.Core_Wire.Encoded_U16 (Packet, 70))
               and then
               (for all Index in
                  0 .. Authentication_Challenge_Length_Of (Value) - 1 =>
                    Authentication_Challenge_Byte_Of (Value, Index) =
                      Packet
                        (Packet'First
                         + (Natural
                           (SMB.Core_Wire.Encoded_U16 (Packet, 68))
                            + Index))))
        elsif Status = SMB.Invalid_State_Status
          and then
            (Authentication_Stage_Of (Value)'Old /= Negotiate_Sent
             or else Authentication_Owner_Of (Value)'Old /=
               SMB.Engine.Current_Owner_Id (State)'Old
             or else Authentication_Epoch_Of (Value)'Old /=
               SMB.Engine.Current_Epoch (State)'Old
             or else Authentication_Expected_Of (Value)'Old.Command /= 1
             or else Authentication_Expected_Of (Value)'Old.Request_Signed
             or else Authentication_Expected_Of (Value)'Old.Signed
             or else Authentication_Expected_Of (Value)'Old.Session_Id /= 0
             or else not SMB.Engine.Pending_Request_Matches
               (State'Old, Authentication_Expected_Of (Value)'Old))
        then
          Authentication_Stage_Of (Value) =
            Authentication_Stage_Of (Value)'Old
          and then Authentication_Owner_Of (Value) =
            Authentication_Owner_Of (Value)'Old
          and then Authentication_Epoch_Of (Value) =
            Authentication_Epoch_Of (Value)'Old
          and then Authentication_Session_Id_Of (Value) =
            Authentication_Session_Id_Of (Value)'Old
          and then Authentication_Challenge_Length_Of (Value) =
            Authentication_Challenge_Length_Of (Value)'Old
          and then Authentication_Buffer_Of (Value) =
            Authentication_Buffer_Of (Value)'Old
          and then SMB.Engine."=" (Authentication_Expected_Of (Value),
            Authentication_Expected_Of (Value)'Old)
          and then SMB.Engine.Current_Owner_Id (State) =
            SMB.Engine.Current_Owner_Id (State)'Old
          and then SMB.Engine.Current_Epoch (State) =
            SMB.Engine.Current_Epoch (State)'Old
          and then SMB.Engine.Current_Phase (State) =
            SMB.Engine.Current_Phase (State)'Old
          and then SMB.Engine.Current_Session_Id (State) =
            SMB.Engine.Current_Session_Id (State)'Old
          and then SMB.Engine.Has_Pending_Request (State) =
            SMB.Engine.Has_Pending_Request (State)'Old
          and then SMB.Engine.Has_Validated_Response (State) =
            SMB.Engine.Has_Validated_Response (State)'Old
          and then SMB.Engine.Has_Signing_Key (State) =
            SMB.Engine.Has_Signing_Key (State)'Old
          and then SMB.Engine.Current_Response_Info (State) =
            SMB.Engine.Current_Response_Info (State)'Old
        else True);

   procedure Prepare_Authenticate
     (Value : in out Authentication;
      State : in out SMB.Engine.Engine_State;
      User, Password, Domain : String;
      Nonce : SMB.Bytes;
      Current_Filetime : SMB.QWord;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with
     Pre => Output'Length <= SMB.Maximum_Frame_Size
       and then Nonce'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
        (if Status = SMB.Ok then
            Authentication_Stage_Of (Value)'Old = Challenge_Received
             and then Authentication_Owner_Of (Value)'Old =
               SMB.Engine.Current_Owner_Id (State)'Old
             and then Authentication_Epoch_Of (Value)'Old =
               SMB.Engine.Current_Epoch (State)'Old
             and then Authentication_Context_Matches (Value, State)
             and then Authentication_Owner_Of (Value) =
               Authentication_Owner_Of (Value)'Old
             and then Authentication_Epoch_Of (Value) =
               Authentication_Epoch_Of (Value)'Old
             and then Authentication_Session_Id_Of (Value) =
               Authentication_Session_Id_Of (Value)'Old
             and then Authentication_Stage_Of (Value) = Authenticate_Prepared
              and then SMB.Engine.Has_Signing_Key (State)
              and then SMB.Engine.Current_Session_Id (State) =
                Authentication_Session_Id_Of (Value)
              and then Authentication_Packet_Matches
                (Value, State, Output, Used)
         elsif Status = SMB.Invalid_State_Status
           and then
             (Authentication_Stage_Of (Value)'Old /= Challenge_Received
              or else Authentication_Owner_Of (Value)'Old /=
                SMB.Engine.Current_Owner_Id (State)'Old
              or else Authentication_Epoch_Of (Value)'Old /=
                SMB.Engine.Current_Epoch (State)'Old)
         then
            Authentication_Stage_Of (Value) =
              Authentication_Stage_Of (Value)'Old
            and then Authentication_Owner_Of (Value) =
              Authentication_Owner_Of (Value)'Old
            and then Authentication_Epoch_Of (Value) =
              Authentication_Epoch_Of (Value)'Old
            and then Authentication_Session_Id_Of (Value) =
              Authentication_Session_Id_Of (Value)'Old
            and then Authentication_Challenge_Length_Of (Value) =
              Authentication_Challenge_Length_Of (Value)'Old
            and then Authentication_Buffer_Of (Value) =
              Authentication_Buffer_Of (Value)'Old
            and then SMB.Engine."=" (Authentication_Expected_Of (Value),
              Authentication_Expected_Of (Value)'Old)
            and then SMB.Engine.Current_Owner_Id (State) =
              SMB.Engine.Current_Owner_Id (State)'Old
            and then SMB.Engine.Current_Epoch (State) =
              SMB.Engine.Current_Epoch (State)'Old
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Current_Phase (State)'Old
            and then SMB.Engine.Current_Session_Id (State) =
              SMB.Engine.Current_Session_Id (State)'Old
            and then SMB.Engine.Has_Pending_Request (State) =
              SMB.Engine.Has_Pending_Request (State)'Old
            and then SMB.Engine.Has_Validated_Response (State) =
              SMB.Engine.Has_Validated_Response (State)'Old
            and then SMB.Engine.Has_Signing_Key (State) =
              SMB.Engine.Has_Signing_Key (State)'Old
            and then SMB.Engine.Current_Response_Info (State) =
              SMB.Engine.Current_Response_Info (State)'Old
         else True);

   procedure Complete_Authenticate
     (Value : in out Authentication;
      State : in out SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Nt_Status : out SMB.DWord;
      Status : out SMB.Core_Status)
   with
     Pre => Packet'Length <= SMB.Maximum_Frame_Size,
     Post =>
       (if Status = SMB.Ok and then Nt_Status = SMB.Success then
          Authentication_Stage_Of (Value)'Old = Authenticate_Sent
          and then Authentication_Owner_Of (Value)'Old =
            SMB.Engine.Current_Owner_Id (State)'Old
          and then Authentication_Epoch_Of (Value)'Old =
            SMB.Engine.Current_Epoch (State)'Old
          and then Authentication_Context_Matches (Value, State)
          and then Authentication_Owner_Of (Value) =
            Authentication_Owner_Of (Value)'Old
          and then Authentication_Epoch_Of (Value) =
            Authentication_Epoch_Of (Value)'Old
          and then Authentication_Session_Id_Of (Value) =
            Authentication_Session_Id_Of (Value)'Old
          and then Authentication_Stage_Of (Value) = Authentication_Finished
          and then SMB.Engine.Current_Phase (State) = SMB.Engine.Authenticated
          and then SMB.Engine.Has_Signing_Key (State)
        elsif Authentication_Stage_Of (Value)'Old = Authenticate_Sent
          and then Authentication_Owner_Of (Value)'Old =
            SMB.Engine.Current_Owner_Id (State)'Old
          and then Authentication_Epoch_Of (Value)'Old =
            SMB.Engine.Current_Epoch (State)'Old
          and then SMB.Engine.Pending_Request_Matches
            (State'Old, Authentication_Expected_Of (Value)'Old)
        then
          Authentication_Stage_Of (Value) = Authentication_Failed
          and then Authentication_Session_Id_Of (Value) =
            Authentication_Session_Id_Of (Value)'Old
          and then SMB.Engine.Current_Phase (State) =
            SMB.Engine.Disconnected
          and then (Nt_Status = 0 or else Status = SMB.Ok)
        else
          Authentication_Stage_Of (Value) =
            Authentication_Stage_Of (Value)'Old
          and then Authentication_Owner_Of (Value) =
            Authentication_Owner_Of (Value)'Old
          and then Authentication_Epoch_Of (Value) =
            Authentication_Epoch_Of (Value)'Old
          and then Authentication_Session_Id_Of (Value) =
            Authentication_Session_Id_Of (Value)'Old
          and then Authentication_Challenge_Length_Of (Value) =
            Authentication_Challenge_Length_Of (Value)'Old
          and then Authentication_Buffer_Of (Value) =
            Authentication_Buffer_Of (Value)'Old
          and then SMB.Engine."=" (Authentication_Expected_Of (Value),
            Authentication_Expected_Of (Value)'Old)
          and then SMB.Engine.Current_Owner_Id (State) =
            SMB.Engine.Current_Owner_Id (State)'Old
          and then SMB.Engine.Current_Epoch (State) =
            SMB.Engine.Current_Epoch (State)'Old
          and then SMB.Engine.Current_Phase (State) =
            SMB.Engine.Current_Phase (State)'Old
          and then SMB.Engine.Current_Session_Id (State) =
            SMB.Engine.Current_Session_Id (State)'Old
          and then SMB.Engine.Has_Pending_Request (State) =
            SMB.Engine.Has_Pending_Request (State)'Old
          and then SMB.Engine.Has_Validated_Response (State) =
            SMB.Engine.Has_Validated_Response (State)'Old
          and then SMB.Engine.Has_Signing_Key (State) =
            SMB.Engine.Has_Signing_Key (State)'Old
          and then SMB.Engine.Current_Response_Info (State) =
            SMB.Engine.Current_Response_Info (State)'Old);

   procedure Abort_Authentication
     (Value : in out Authentication;
      State : in out SMB.Engine.Engine_State;
      Status : out SMB.Core_Status)
   with
     Post =>
       (if Status = SMB.Ok then
          Authentication_Owner_Of (Value)'Old =
            SMB.Engine.Current_Owner_Id (State)'Old
          and then Authentication_Epoch_Of (Value)'Old =
            SMB.Engine.Current_Epoch (State)'Old
          and then Authentication_Owner_Of (Value) =
            Authentication_Owner_Of (Value)'Old
          and then Authentication_Epoch_Of (Value) =
            Authentication_Epoch_Of (Value)'Old
          and then Authentication_Session_Id_Of (Value) =
            Authentication_Session_Id_Of (Value)'Old
          and then Authentication_Stage_Of (Value) = Authentication_Failed
          and then SMB.Engine.Current_Phase (State) =
            SMB.Engine.Disconnected
          and then not SMB.Engine.Has_Pending_Request (State)
          and then not SMB.Engine.Has_Validated_Response (State)
          and then SMB.Engine.Signing_Key_Is_Zero (State)
        elsif Status = SMB.Invalid_State_Status
          and then
            (Authentication_Owner_Of (Value)'Old /=
               SMB.Engine.Current_Owner_Id (State)'Old
             or else Authentication_Epoch_Of (Value)'Old /=
               SMB.Engine.Current_Epoch (State)'Old
             or else Authentication_Stage_Of (Value)'Old in
               Authentication_Ready | Authentication_Finished |
                 Authentication_Failed)
        then
          Authentication_Stage_Of (Value) =
            Authentication_Stage_Of (Value)'Old
          and then Authentication_Owner_Of (Value) =
            Authentication_Owner_Of (Value)'Old
          and then Authentication_Epoch_Of (Value) =
            Authentication_Epoch_Of (Value)'Old
          and then Authentication_Session_Id_Of (Value) =
            Authentication_Session_Id_Of (Value)'Old
          and then Authentication_Challenge_Length_Of (Value) =
            Authentication_Challenge_Length_Of (Value)'Old
          and then Authentication_Buffer_Of (Value) =
            Authentication_Buffer_Of (Value)'Old
          and then SMB.Engine."=" (Authentication_Expected_Of (Value),
            Authentication_Expected_Of (Value)'Old)
          and then SMB.Engine.Current_Owner_Id (State) =
            SMB.Engine.Current_Owner_Id (State)'Old
          and then SMB.Engine.Current_Epoch (State) =
            SMB.Engine.Current_Epoch (State)'Old
          and then SMB.Engine.Current_Phase (State) =
            SMB.Engine.Current_Phase (State)'Old
          and then SMB.Engine.Current_Session_Id (State) =
            SMB.Engine.Current_Session_Id (State)'Old
          and then SMB.Engine.Has_Pending_Request (State) =
            SMB.Engine.Has_Pending_Request (State)'Old
          and then SMB.Engine.Has_Validated_Response (State) =
            SMB.Engine.Has_Validated_Response (State)'Old
          and then SMB.Engine.Has_Signing_Key (State) =
            SMB.Engine.Has_Signing_Key (State)'Old
          and then SMB.Engine.Current_Response_Info (State) =
            SMB.Engine.Current_Response_Info (State)'Old
        else True);

   type Transfer_Identity is private;
   function Identity_Of (Value : Transfer) return Transfer_Identity with Ghost;
   function Transfer_Request_Of (Value : Transfer)
     return SMB.Engine.Request_Expectation with Ghost;

   function Transfer_Kind_Of (Value : Transfer) return Transfer_Kind;
   function Transfer_Stage_Of (Value : Transfer) return Transfer_Stage;
   function Transfer_Total_Of (Value : Transfer) return Natural;
   function Transfer_Completed_Of (Value : Transfer) return Natural;
   function Transfer_Remaining_Of (Value : Transfer) return Natural;
   function Transfer_Position_Of (Value : Transfer) return SMB.QWord;
   function Transfer_Initial_Offset_Of (Value : Transfer) return SMB.QWord;
   function Transfer_Requested_Of (Value : Transfer) return Natural;
   function Transfer_Token_Of (Value : Transfer)
     return SMB.Engine.Handle_Token;
   function Transfer_File_Id_Of (Value : Transfer) return SMB.Bytes;
   function Transfer_Access_Of (Value : Transfer)
     return SMB.Engine.Access_Kind;
   function Transfer_Is_Directory (Value : Transfer) return Boolean;
   function Transfer_Invariant (Value : Transfer) return Boolean;
   function Transfer_Byte_Of (Value : Transfer; Index : Natural) return SMB.Byte
   with Pre => Index < Value.Capacity;
   function Transfer_Buffer_Of (Value : Transfer) return SMB.Bytes;
   function Transfer_Snapshot_Matches
     (Value : Transfer; Data : SMB.Bytes) return Boolean
   with Pre => Data'Length <= SMB.Maximum_Frame_Size;
   function Read_Buffer_Prefix_Matches
     (Value : Transfer; Data : SMB.Bytes; Length : Natural) return Boolean
   with Pre =>
     Data'Length <= SMB.Maximum_Frame_Size
     and then Length <= Value.Capacity;
   function Transfer_Packet_Matches
     (Value : Transfer;
      State : SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Used : Natural) return Boolean
   with Pre =>
     Packet'Length <= SMB.Maximum_Frame_Size
     and then Transfer_Invariant (Value)
     and then Transfer_Requested_Of (Value) <= Transfer_Remaining_Of (Value)
     and then Transfer_Completed_Of (Value) <= Value.Capacity
     and then Transfer_Requested_Of (Value) <=
       Value.Capacity - Transfer_Completed_Of (Value);

   procedure Start_Read
     (Value : in out Transfer;
      State : SMB.Engine.Engine_State;
      Token : SMB.Engine.Handle_Token;
      Offset : SMB.QWord;
      Total : Natural;
      Status : out SMB.Core_Status)
   with
     Pre => Total <= SMB.Maximum_Frame_Size
       and then Value.Capacity = Total,
     Post =>
       (if Status = SMB.Ok then
          Transfer_Invariant (Value)
          and then Transfer_Kind_Of (Value) = Read_Transfer
          and then Transfer_Stage_Of (Value) =
            (if Total = 0 then Transfer_Finished else Ready)
          and then Transfer_Total_Of (Value) = Total
          and then Transfer_Completed_Of (Value) = 0
          and then Transfer_Remaining_Of (Value) = Total
          and then Transfer_Position_Of (Value) = Offset
          and then Transfer_Initial_Offset_Of (Value) = Offset
          and then Transfer_Token_Of (Value).Owner = Token.Owner
          and then Transfer_Token_Of (Value).Epoch = Token.Epoch
          and then Transfer_Token_Of (Value).Ticket = Token.Ticket
          and then not Transfer_Is_Directory (Value)
          and then SMB.Engine.Handle_Matches
            (State, Token, Transfer_File_Id_Of (Value),
             Transfer_Access_Of (Value), False));

   procedure Start_Write
     (Value : in out Transfer;
      State : SMB.Engine.Engine_State;
      Token : SMB.Engine.Handle_Token;
      Offset : SMB.QWord;
      Data : SMB.Bytes;
      Status : out SMB.Core_Status)
   with
     Pre => Data'Length <= SMB.Maximum_Frame_Size
       and then Value.Capacity = Data'Length,
     Post =>
       (if Status = SMB.Ok then
          Transfer_Invariant (Value)
          and then Transfer_Kind_Of (Value) = Write_Transfer
          and then Transfer_Stage_Of (Value) =
            (if Data'Length = 0 then Transfer_Finished else Ready)
          and then Transfer_Total_Of (Value) = Data'Length
          and then Transfer_Completed_Of (Value) = 0
          and then Transfer_Remaining_Of (Value) = Data'Length
          and then Transfer_Position_Of (Value) = Offset
          and then Transfer_Initial_Offset_Of (Value) = Offset
          and then Transfer_Snapshot_Matches (Value, Data)
          and then Transfer_Token_Of (Value).Owner = Token.Owner
          and then Transfer_Token_Of (Value).Epoch = Token.Epoch
          and then Transfer_Token_Of (Value).Ticket = Token.Ticket
          and then not Transfer_Is_Directory (Value)
          and then SMB.Engine.Handle_Matches
            (State, Token, Transfer_File_Id_Of (Value),
             Transfer_Access_Of (Value), False));

   procedure Prepare_Next
     (Value : in out Transfer;
      State : in out SMB.Engine.Engine_State;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with
     Pre => Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Identity_Of (Value) = Identity_Of (Value)'Old
       and then
       Used <= Output'Length
       and then
         (Status /= SMB.Ok
          or else
            (Transfer_Invariant (Value)
             and then Transfer_Stage_Of (Value) = Transfer_Prepared
             and then Transfer_Packet_Matches (Value, State, Output, Used)
             and then SMB.Engine.Handle_Matches
               (State'Old, Transfer_Token_Of (Value),
                Transfer_File_Id_Of (Value), Transfer_Access_Of (Value), False)
             and then Transfer_Completed_Of (Value) =
               Transfer_Completed_Of (Value)'Old
             and then Transfer_Remaining_Of (Value) =
               Transfer_Remaining_Of (Value)'Old
             and then Transfer_Position_Of (Value) =
               Transfer_Position_Of (Value)'Old
             and then Transfer_Buffer_Of (Value) =
               Transfer_Buffer_Of (Value)'Old));

   procedure Transfer_Send_Succeeded
     (Value : in out Transfer;
      State : SMB.Engine.Engine_State;
      Status : out SMB.Core_Status)
   with
     Post =>
       Identity_Of (Value) = Identity_Of (Value)'Old
       and then SMB.Engine."="
         (Transfer_Request_Of (Value), Transfer_Request_Of (Value)'Old)
       and then Transfer_Requested_Of (Value) = Transfer_Requested_Of (Value)'Old
       and then
       (if Status = SMB.Ok then
         (Transfer_Stage_Of (Value) = Transfer_Sent
          and then Transfer_Stage_Of (Value)'Old = Transfer_Prepared
          and then Transfer_Invariant (Value)
          and then Transfer_Completed_Of (Value) =
            Transfer_Completed_Of (Value)'Old
          and then Transfer_Remaining_Of (Value) =
            Transfer_Remaining_Of (Value)'Old
          and then Transfer_Position_Of (Value) =
            Transfer_Position_Of (Value)'Old
          and then Transfer_Buffer_Of (Value) =
            Transfer_Buffer_Of (Value)'Old));

   procedure Complete_Read
     (Value : in out Transfer;
      State : in out SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Nt_Status : out SMB.DWord;
      Status : out SMB.Core_Status)
   with
     Pre => Packet'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Identity_Of (Value) = Identity_Of (Value)'Old
       and then
       (if Status = SMB.Ok then
         (Transfer_Invariant (Value)
          and then Transfer_Stage_Of (Value)'Old = Transfer_Sent
          and then Transfer_Kind_Of (Value) = Read_Transfer
          and then not SMB.Engine.Has_Pending_Request (State)
          and then not SMB.Engine.Has_Validated_Response (State)
          and then (Transfer_Completed_Of (Value)'Old = 0
               or else
                 (for all Index in 0 ..
                    Transfer_Completed_Of (Value)'Old - 1 =>
                    Transfer_Buffer_Of (Value)'Old (Index + 1) =
                      Transfer_Byte_Of (Value, Index)))
          and then
            (if Nt_Status /= SMB.Success then
              Transfer_Stage_Of (Value) = Transfer_Finished
              and then Transfer_Completed_Of (Value) =
                Transfer_Completed_Of (Value)'Old
              and then Transfer_Remaining_Of (Value) =
                Transfer_Remaining_Of (Value)'Old
             else
                Transfer_Stage_Of (Value) in Ready | Transfer_Finished
                and then Packet'Length >= 80
                and then Natural
                  (Packet (Packet'First + 66)) <= Packet'Length
                and then SMB.Core_Wire.Encoded_U32 (Packet, 68) <=
                  SMB.DWord (SMB.Core_Protocol.Maximum_IO_Chunk)
                and then Natural
                  (SMB.Core_Wire.Encoded_U32 (Packet, 68)) <=
                    Packet'Length -
                      Natural (Packet (Packet'First + 66))
                and then Transfer_Completed_Of (Value) =
                  Transfer_Completed_Of (Value)'Old
                  + Natural (SMB.Core_Wire.Encoded_U32 (Packet, 68))
                and then
                  (SMB.Core_Wire.Encoded_U32 (Packet, 68) = 0
                   or else
                     (for all Index in 0 ..
                        Natural (SMB.Core_Wire.Encoded_U32 (Packet, 68)) - 1 =>
                        Transfer_Byte_Of
                          (Value, Transfer_Completed_Of (Value)'Old + Index) =
                          Packet
                            (Packet'First
                             + (Natural
                                  (Packet (Packet'First + 66))
                                + Index))))
          )));

   procedure Complete_Write
     (Value : in out Transfer;
      State : in out SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Nt_Status : out SMB.DWord;
      Status : out SMB.Core_Status)
   with
     Pre => Packet'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Identity_Of (Value) = Identity_Of (Value)'Old
       and then
       (if Status = SMB.Ok then
         (Transfer_Invariant (Value)
          and then Transfer_Stage_Of (Value)'Old = Transfer_Sent
          and then Transfer_Kind_Of (Value) = Write_Transfer
          and then not SMB.Engine.Has_Pending_Request (State)
          and then not SMB.Engine.Has_Validated_Response (State)
          and then
            ((Nt_Status /= SMB.Success
              and then Transfer_Stage_Of (Value) = Transfer_Finished
              and then Transfer_Completed_Of (Value) =
                Transfer_Completed_Of (Value)'Old
              and then Transfer_Remaining_Of (Value) =
                Transfer_Remaining_Of (Value)'Old)
             or
               (Nt_Status = SMB.Success
                and then Transfer_Stage_Of (Value) in Ready | Transfer_Finished
                and then Packet'Length >= 72
                and then SMB.Core_Wire.Encoded_U32 (Packet, 68) > 0
                and then SMB.Core_Wire.Encoded_U32 (Packet, 68) <=
                  SMB.DWord (SMB.Core_Protocol.Maximum_IO_Chunk)
                and then Transfer_Completed_Of (Value) =
                  Transfer_Completed_Of (Value)'Old
                  + Natural (SMB.Core_Wire.Encoded_U32 (Packet, 68))))
          and then Transfer_Buffer_Of (Value) =
            Transfer_Buffer_Of (Value)'Old));

   procedure Copy_Read_Result
     (Value : Transfer;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with
     Pre => Output'Length <= SMB.Maximum_Frame_Size
       and then Output'Length >= Value.Capacity,
     Post =>
       Used <= Output'Length
       and then
         (if Status = SMB.Ok then
            Transfer_Kind_Of (Value) = Read_Transfer
            and then Transfer_Stage_Of (Value) = Transfer_Finished
            and then Used = Transfer_Completed_Of (Value)
            and then Read_Buffer_Prefix_Matches (Value, Output, Used));

   procedure Abort_Transfer
     (Value : in out Transfer;
      State : in out SMB.Engine.Engine_State;
      Status : out SMB.Core_Status)
   with
     Post =>
       (if Status = SMB.Ok then
          Transfer_Stage_Of (Value) = Transfer_Failed
          and then SMB.Engine.Current_Phase (State) = SMB.Engine.Disconnected
          and then not SMB.Engine.Has_Pending_Request (State)
          and then not SMB.Engine.Has_Open_Handles (State)
          and then not SMB.Engine.Has_Validated_Response (State));

   function Access_Mask
     (Mode : SMB.Engine.Access_Kind;
      Delete_Access : Boolean) return SMB.DWord is
     (16#80# or 16#100000#
      or (case Mode is
            when SMB.Engine.Read_Only => 1,
            when SMB.Engine.Write_Only => 2 or 4,
            when SMB.Engine.Read_Write => 1 or 2 or 4)
      or (if Delete_Access then 16#10000# else 0));

   function Stage_Of (Value : Operation) return Operation_Stage;
   function Kind_Of (Value : Operation) return Operation_Kind;
   function Create_Access_Of (Value : Operation)
     return SMB.Engine.Access_Kind;
   function Create_Directory_Of (Value : Operation) return Boolean;
   function Create_Delete_Access_Of (Value : Operation) return Boolean;
   function Create_Disposition_Of (Value : Operation) return SMB.DWord;
   function Close_Token_Of (Value : Operation)
     return SMB.Engine.Handle_Token;
   function File_Id_Of (Value : Operation) return SMB.Bytes;
   function Packet_Matches_Prepared
     (Value : Operation;
      State : SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Used : Natural) return Boolean
   with Pre => Packet'Length <= SMB.Maximum_Frame_Size;

   procedure Prepare_Create
     (Value : in out Operation;
      State : in out SMB.Engine.Engine_State;
      Name : SMB.Bytes;
      Access_Mode : SMB.Engine.Access_Kind;
      Delete_Access : Boolean;
      Disposition : SMB.DWord;
      Directory : Boolean;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with
     Pre => Name'Length <= SMB.Core_Protocol.Maximum_Name_Bytes
       and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if Status = SMB.Ok then
            Stage_Of (Value) = Prepared
            and then Kind_Of (Value) = Create_Operation
            and then Used >= SMB.Core_Wire.Header_Size
            and then Packet_Matches_Prepared (Value, State, Output, Used)
            and then Create_Access_Of (Value) = Access_Mode
            and then Create_Directory_Of (Value) = Directory
            and then Create_Delete_Access_Of (Value) = Delete_Access
            and then Create_Disposition_Of (Value) = Disposition);

   procedure Prepare_Close
     (Value : in out Operation;
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
         (if Status = SMB.Ok then
            Stage_Of (Value) = Prepared
            and then Kind_Of (Value) = Close_Operation
            and then Used >= SMB.Core_Wire.Header_Size
            and then Packet_Matches_Prepared (Value, State, Output, Used)
            and then SMB.Engine.Handle_Matches
              (State'Old, Token, File_Id_Of (Value),
               Create_Access_Of (Value), Create_Directory_Of (Value))
            and then Close_Token_Of (Value).Owner = Token.Owner
            and then Close_Token_Of (Value).Epoch = Token.Epoch
            and then Close_Token_Of (Value).Ticket = Token.Ticket);

   procedure Send_Succeeded
     (Value : in out Operation;
      State : SMB.Engine.Engine_State;
      Status : out SMB.Core_Status)
   with
     Post =>
       Status /= SMB.Ok
       or (Stage_Of (Value) = Sent
           and Stage_Of (Value)'Old = Prepared);

   procedure Complete
     (Value : in out Operation;
      State : in out SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Nt_Status : out SMB.DWord;
      Token : out SMB.Engine.Handle_Token;
      Status : out SMB.Core_Status)
   with
     Pre => Packet'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Status /= SMB.Ok
       or (Stage_Of (Value) = Finished
           and Stage_Of (Value)'Old = Sent
           and Kind_Of (Value) = Kind_Of (Value)'Old
           and (Nt_Status /= SMB.Success
                or (Kind_Of (Value)'Old = Create_Operation
                    and SMB.Engine.Handle_Matches
                      (State, Token, File_Id_Of (Value),
                       Create_Access_Of (Value)'Old,
                       Create_Directory_Of (Value)'Old))
                or (Kind_Of (Value)'Old = Close_Operation
                    and not SMB.Engine.Valid_Handle
                      (State, Close_Token_Of (Value)'Old, False, False))));

   procedure Abort_Operation
     (Value : in out Operation;
      State : in out SMB.Engine.Engine_State;
      Status : out SMB.Core_Status)
   with
     Post =>
       (if Status = SMB.Ok then
          Stage_Of (Value) = Failed
          and then SMB.Engine.Current_Phase (State) =
            SMB.Engine.Disconnected);

private
   type Authentication is limited record
      Stage : Authentication_Stage := Authentication_Ready;
      Owner, Epoch : SMB.QWord := 0;
      Session_Id : SMB.QWord := 0;
      Expected : SMB.Engine.Request_Expectation;
      Challenge_Length : Natural := 0;
      Challenge : SMB.Bytes
        (0 .. SMB.Core_Auth.Maximum_Security_Token - 1) := (others => 0);
   end record;

   type Transfer_Identity is record
      Kind : Transfer_Kind;
      Owner, Epoch : SMB.QWord;
      Token : SMB.Engine.Handle_Token;
      File_Id : SMB.Bytes (0 .. 15);
      Access_Mode : SMB.Engine.Access_Kind;
      Directory : Boolean;
      Initial_Offset : SMB.QWord;
      Total : Natural;
   end record;

   type Transfer (Capacity : Transfer_Capacity) is limited record
      Kind : Transfer_Kind := Read_Transfer;
      Stage : Transfer_Stage := Ready;
      Owner : SMB.QWord := 0;
      Epoch : SMB.QWord := 0;
      Token : SMB.Engine.Handle_Token := (others => 0);
      File_Id : SMB.Bytes (0 .. 15) := (others => 0);
      Access_Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
      Directory : Boolean := False;
      Initial_Offset : SMB.QWord := 0;
      Position : SMB.QWord := 0;
      Total : Natural := 0;
      Completed : Natural := 0;
      Remaining : Natural := 0;
      Requested : Natural := 0;
      Expected : SMB.Engine.Request_Expectation;
      case Capacity is
         when 0 =>
            null;
         when others =>
            Buffer : SMB.Bytes (1 .. Capacity) := (others => 0);
      end case;
   end record;

   type Operation is limited record
      Kind : Operation_Kind := No_Operation;
      Stage : Operation_Stage := Idle;
      Owner : SMB.QWord := 0;
      Epoch : SMB.QWord := 0;
      Expected : SMB.Engine.Request_Expectation;
      Access_Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
      Directory : Boolean := False;
      Delete_Access : Boolean := False;
      Disposition : SMB.DWord := 0;
      Wire_Access : SMB.DWord := 0;
      Close_Token : SMB.Engine.Handle_Token := (others => 0);
      File_Id : SMB.Bytes (0 .. 15) := (others => 0);
   end record;

   function Identity_Of (Value : Transfer) return Transfer_Identity is
     ((Kind => Value.Kind, Owner => Value.Owner, Epoch => Value.Epoch,
       Token => Value.Token, File_Id => Value.File_Id,
       Access_Mode => Value.Access_Mode, Directory => Value.Directory,
       Initial_Offset => Value.Initial_Offset, Total => Value.Total));

   function Transfer_Request_Of (Value : Transfer)
     return SMB.Engine.Request_Expectation is (Value.Expected);

   function Transfer_Kind_Of (Value : Transfer) return Transfer_Kind is
     (Value.Kind);
   function Transfer_Stage_Of (Value : Transfer) return Transfer_Stage is
     (Value.Stage);
   function Transfer_Total_Of (Value : Transfer) return Natural is
     (Value.Total);
   function Transfer_Completed_Of (Value : Transfer) return Natural is
     (Value.Completed);
   function Transfer_Remaining_Of (Value : Transfer) return Natural is
     (Value.Remaining);
   function Transfer_Position_Of (Value : Transfer) return SMB.QWord is
     (Value.Position);
   function Transfer_Initial_Offset_Of
     (Value : Transfer) return SMB.QWord is (Value.Initial_Offset);
   function Transfer_Requested_Of (Value : Transfer) return Natural is
     (Value.Requested);
   function Transfer_Token_Of (Value : Transfer)
     return SMB.Engine.Handle_Token is (Value.Token);
   function Transfer_File_Id_Of (Value : Transfer) return SMB.Bytes is
     (Value.File_Id);
   function Transfer_Access_Of (Value : Transfer)
     return SMB.Engine.Access_Kind is (Value.Access_Mode);
   function Transfer_Is_Directory (Value : Transfer) return Boolean is
     (Value.Directory);
   function Transfer_Invariant (Value : Transfer) return Boolean is
     (Value.Completed <= Value.Total
     and then Value.Remaining <= Value.Total
     and then Value.Total <= Value.Capacity
     and then Value.Requested <= Value.Remaining
     and then Value.Completed <= Natural'Last - Value.Remaining
      and then Value.Completed + Value.Remaining = Value.Total
      and then SMB.QWord (Value.Total) <=
        SMB.QWord'Last - Value.Initial_Offset
      and then SMB.QWord (Value.Completed) <=
        SMB.QWord'Last - Value.Initial_Offset
      and then Value.Position =
        Value.Initial_Offset + SMB.QWord (Value.Completed)
      and then Value.Requested <= SMB.Core_Protocol.Maximum_IO_Chunk
      and then
        (if Value.Stage in Transfer_Prepared | Transfer_Sent then
           Value.Expected.Command =
             (if Value.Kind = Read_Transfer then 8 else 9)
           and then Value.Expected.Request_Amount = Value.Requested));
   function Transfer_Byte_Of
     (Value : Transfer; Index : Natural) return SMB.Byte is
     (Value.Buffer (Index + 1));
   function Transfer_Buffer_Of (Value : Transfer) return SMB.Bytes is
     (if Value.Capacity = 0 then SMB.Bytes'(1 .. 0 => 0)
      else Value.Buffer);
   function Transfer_Snapshot_Matches
     (Value : Transfer; Data : SMB.Bytes) return Boolean is
     (Value.Kind = Write_Transfer
      and then Data'Length = Value.Capacity
      and then
        (if Value.Capacity = 0 then True
         else
           (for all Index in 0 .. Value.Capacity - 1 =>
              Value.Buffer (Index + 1) = Data (Data'First + Index))));
   function Read_Buffer_Prefix_Matches
     (Value : Transfer; Data : SMB.Bytes; Length : Natural) return Boolean is
     (Value.Kind = Read_Transfer
      and then Length <= Value.Completed
      and then Length <= Data'Length
      and then
        (if Length = 0 then True
         else
           (for all Index in 0 .. Length - 1 =>
              Value.Buffer (Index + 1) = Data (Data'First + Index))));
   function Transfer_Packet_Matches
     (Value : Transfer;
      State : SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Used : Natural) return Boolean is
     (Value.Stage = Transfer_Prepared
      and then Value.Owner = SMB.Engine.Current_Owner_Id (State)
      and then Value.Epoch = SMB.Engine.Current_Epoch (State)
      and then SMB.Engine.Pending_Request_Matches (State, Value.Expected)
      and then Value.Expected.Request_Amount = Value.Requested
      and then Value.Requested <= Value.Remaining
      and then Value.Completed <= Value.Capacity - Value.Requested
      and then Used <= Packet'Length
      and then Used >= SMB.Core_Wire.Header_Size + 48
      and then SMB.Core_Wire.Encoded_U16 (Packet, 12) =
        SMB.Word (Value.Expected.Command)
      and then SMB.Core_Wire.Encoded_U32 (Packet, 16) = 8
      and then SMB.Core_Wire.Encoded_U64 (Packet, 24) =
        Value.Expected.Message_Id
      and then SMB.Core_Wire.Encoded_U32 (Packet, 36) =
        Value.Expected.Tree_Id
      and then SMB.Core_Wire.Encoded_U64 (Packet, 40) =
        Value.Expected.Session_Id
      and then
        (if Value.Kind = Read_Transfer then
           Used = SMB.Core_Wire.Header_Size + 49
           and then Packet (Packet'First + SMB.Core_Wire.Header_Size + 4) =
             SMB.Core_Wire.U32_Byte
               (SMB.DWord (Value.Requested), 0)
           and then Packet (Packet'First + SMB.Core_Wire.Header_Size + 5) =
             SMB.Core_Wire.U32_Byte
               (SMB.DWord (Value.Requested), 1)
           and then Packet (Packet'First + SMB.Core_Wire.Header_Size + 6) =
             SMB.Core_Wire.U32_Byte
               (SMB.DWord (Value.Requested), 2)
           and then Packet (Packet'First + SMB.Core_Wire.Header_Size + 7) =
             SMB.Core_Wire.U32_Byte
               (SMB.DWord (Value.Requested), 3)
           and then
             (for all Byte_Index in 0 .. 7 =>
                Packet
                  (Packet'First + SMB.Core_Wire.Header_Size + 8 + Byte_Index) =
                  SMB.Core_Wire.U64_Byte (Value.Position, Byte_Index))
           and then
             (for all Index in 0 .. 15 =>
                Packet
                  (Packet'First + SMB.Core_Wire.Header_Size + 16 + Index) =
                  Value.File_Id (Index))
         else
           Value.Requested > 0
           and then Used = SMB.Core_Wire.Header_Size + 48 + Value.Requested
           and then Packet (Packet'First + SMB.Core_Wire.Header_Size + 4) =
             SMB.Core_Wire.U32_Byte
               (SMB.DWord (Value.Requested), 0)
           and then Packet (Packet'First + SMB.Core_Wire.Header_Size + 5) =
             SMB.Core_Wire.U32_Byte
               (SMB.DWord (Value.Requested), 1)
           and then Packet (Packet'First + SMB.Core_Wire.Header_Size + 6) =
             SMB.Core_Wire.U32_Byte
               (SMB.DWord (Value.Requested), 2)
           and then Packet (Packet'First + SMB.Core_Wire.Header_Size + 7) =
             SMB.Core_Wire.U32_Byte
               (SMB.DWord (Value.Requested), 3)
           and then
             (for all Byte_Index in 0 .. 7 =>
                Packet
                  (Packet'First + SMB.Core_Wire.Header_Size + 8 + Byte_Index) =
                  SMB.Core_Wire.U64_Byte (Value.Position, Byte_Index))
           and then
             (for all Index in 0 .. 15 =>
                Packet
                  (Packet'First + SMB.Core_Wire.Header_Size + 16 + Index) =
                  Value.File_Id (Index))
           and then
             (for all Index in 0 .. Value.Requested - 1 =>
                Packet
                  (Packet'First + SMB.Core_Wire.Header_Size + 48 + Index) =
                    Value.Buffer (Value.Completed + Index + 1))));

   function Packet_Matches_Prepared
     (Value : Operation;
      State : SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Used : Natural) return Boolean is
     (Value.Stage = Prepared
      and then Value.Owner = SMB.Engine.Current_Owner_Id (State)
      and then Value.Epoch = SMB.Engine.Current_Epoch (State)
      and then SMB.Engine.Pending_Request_Matches (State, Value.Expected)
      and then Used <= Packet'Length
      and then Used >= SMB.Core_Wire.Header_Size + 24
      and then SMB.Core_Wire.Encoded_U16 (Packet, 12) =
        SMB.Word (Value.Expected.Command)
      and then SMB.Core_Wire.Encoded_U32 (Packet, 16) = 8
      and then SMB.Core_Wire.Encoded_U64 (Packet, 24) =
        Value.Expected.Message_Id
      and then SMB.Core_Wire.Encoded_U32 (Packet, 36) =
        Value.Expected.Tree_Id
      and then SMB.Core_Wire.Encoded_U64 (Packet, 40) =
        Value.Expected.Session_Id
      and then
        (if Value.Kind = Create_Operation then
           Used >= SMB.Core_Wire.Header_Size + 56
           and then
             (for all Index in 0 .. 3 =>
                Packet
                  (Packet'First + SMB.Core_Wire.Header_Size + 24 + Index) =
                SMB.Core_Wire.U32_Byte (Value.Wire_Access, Index))
            and then
             (for all Index in 0 .. 3 =>
                Packet
                  (Packet'First + SMB.Core_Wire.Header_Size + 28 + Index) =
                SMB.Core_Wire.U32_Byte
                  ((if Value.Directory then 16#10# else 0), Index))
           and then
             (for all Index in 0 .. 3 =>
                Packet
                  (Packet'First + SMB.Core_Wire.Header_Size + 40 + Index) =
                SMB.Core_Wire.U32_Byte
                  ((if Value.Directory then 1 else 16#40#), Index))
           and then
             (for all Index in 0 .. 3 =>
                Packet
                  (Packet'First + SMB.Core_Wire.Header_Size + 36 + Index) =
                SMB.Core_Wire.U32_Byte (Value.Disposition, Index))
           and then Value.Wire_Access =
             Access_Mask (Value.Access_Mode, Value.Delete_Access)
         elsif Value.Kind = Close_Operation then
           (for all Index in 0 .. 15 =>
              Packet
                (Packet'First + SMB.Core_Wire.Header_Size + 8 + Index) =
                Value.File_Id (Value.File_Id'First + Index))
         else False));
end SMB.Core_Client;
