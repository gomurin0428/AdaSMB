with SMB.Crypto;
with SMB.Core_NTLM;
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
   use type SMB.Engine.Engine_State;
   use type SMB.Engine.Handle_Token;
   use type SMB.Engine.Request_Expectation;
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

   type Directory_Stage is
     (Directory_Idle,
      Query_Ready,
      Query_Prepared,
      Query_Sent,
      Page_Ready,
      Directory_Finished,
      Directory_Failed);
   type Directory_Enumeration is limited private;
   type Metadata_Kind is
     (No_Metadata, Rename_Metadata, Disposition_Metadata);
   type Metadata_Stage is
     (Metadata_Idle, Metadata_Prepared, Metadata_Sent,
      Metadata_Finished, Metadata_Failed);
   type Metadata_Operation is limited private;
   type Metadata_State_Snapshot is record
      Kind : Metadata_Kind;
      Stage : Metadata_Stage;
      Owner, Epoch : SMB.QWord;
      Token : SMB.Engine.Handle_Token;
      File_Id : SMB.Bytes (0 .. 15);
      Access_Mode : SMB.Engine.Access_Kind;
      Directory, Delete_File : Boolean;
      Name_Length : Natural;
      Expected : SMB.Engine.Request_Expectation;
   end record;
   Directory_Request_Size : constant Natural :=
     SMB.Core_Wire.Header_Size + 34;
   type Directory_State_Snapshot is record
      Stage : Directory_Stage;
      Owner, Epoch : SMB.QWord;
      Token : SMB.Engine.Handle_Token;
      File_Id : SMB.Bytes (0 .. 15);
      Access_Mode : SMB.Engine.Access_Kind;
      Expected : SMB.Engine.Request_Expectation;
      Page_Length, Cursor, Page_Count, Entry_Count : Natural;
   end record;

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
        else
          Authentication_Stage_Of (Value)'Old = Negotiate_Sent
          and then Authentication_Owner_Of (Value)'Old =
            SMB.Engine.Current_Owner_Id (State)'Old
          and then Authentication_Epoch_Of (Value)'Old =
            SMB.Engine.Current_Epoch (State)'Old
          and then Authentication_Stage_Of (Value) = Authentication_Failed
          and then Authentication_Challenge_Length_Of (Value) = 0
          and then
            (for all Index in Authentication_Buffer_Of (Value)'Range =>
               Authentication_Buffer_Of (Value) (Index) = 0)
          and then SMB.Engine.Current_Phase (State) =
            SMB.Engine.Disconnected
          and then not SMB.Engine.Has_Pending_Request (State)
          and then not SMB.Engine.Has_Validated_Response (State)
          and then SMB.Engine.Signing_Key_Is_Zero (State)
          and then SMB.Engine.Current_Session_Id (State) = 0);

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
         else
           Used = 0
           and then (for all Index in Output'Range => Output (Index) = 0)
           and then Authentication_Stage_Of (Value)'Old = Challenge_Received
           and then Authentication_Owner_Of (Value)'Old =
             SMB.Engine.Current_Owner_Id (State)'Old
           and then Authentication_Epoch_Of (Value)'Old =
             SMB.Engine.Current_Epoch (State)'Old
           and then Authentication_Stage_Of (Value) = Authentication_Failed
           and then Authentication_Challenge_Length_Of (Value) = 0
           and then
             (for all Index in Authentication_Buffer_Of (Value)'Range =>
                Authentication_Buffer_Of (Value) (Index) = 0)
           and then SMB.Engine.Current_Phase (State) =
             SMB.Engine.Disconnected
           and then not SMB.Engine.Has_Pending_Request (State)
           and then not SMB.Engine.Has_Validated_Response (State)
           and then SMB.Engine.Signing_Key_Is_Zero (State)
           and then SMB.Engine.Current_Session_Id (State) = 0);

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
          and then not SMB.Engine.Has_Pending_Request (State)
          and then not SMB.Engine.Has_Validated_Response (State)
          and then SMB.Engine.Current_Response_Info (State).Session_Id =
            SMB.Engine.Current_Session_Id (State)
          and then SMB.Engine.Current_Session_Id (State) =
            SMB.Engine.Current_Session_Id (State)'Old
          and then SMB.Engine.Final_Token_MIC_Matches
            (Packet, SMB.Engine.Current_Response_Info (State),
             SMB.Core_NTLM.Mechanism_List_MIC
               (SMB.Crypto.Digest_128
                  (SMB.Engine.Current_Signing_Key (State)), True))
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
          and then not SMB.Engine.Has_Pending_Request (State)
          and then not SMB.Engine.Has_Validated_Response (State)
          and then SMB.Engine.Signing_Key_Is_Zero (State)
          and then Authentication_Challenge_Length_Of (Value) = 0
          and then
            (for all Index in Authentication_Buffer_Of (Value)'Range =>
               Authentication_Buffer_Of (Value) (Index) = 0)
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
          and then Authentication_Challenge_Length_Of (Value) = 0
          and then
            (for all Index in Authentication_Buffer_Of (Value)'Range =>
               Authentication_Buffer_Of (Value) (Index) = 0)
          and then SMB.Engine.Current_Owner_Id (State) =
            SMB.Engine.Current_Owner_Id (State)'Old
          and then SMB.Engine.Current_Epoch (State)'Old < SMB.QWord'Last
          and then SMB.Engine.Current_Epoch (State) =
            SMB.Engine.Current_Epoch (State)'Old + 1
          and then SMB.Engine.Current_Session_Id (State) = 0
        elsif Status = SMB.Counter_Exhausted then
          Authentication_Owner_Of (Value)'Old =
            SMB.Engine.Current_Owner_Id (State)'Old
          and then Authentication_Epoch_Of (Value)'Old =
            SMB.Engine.Current_Epoch (State)'Old
          and then Authentication_Stage_Of (Value)'Old not in
            Authentication_Ready | Authentication_Finished |
              Authentication_Failed
          and then SMB.Engine.Current_Epoch (State)'Old = SMB.QWord'Last
          and then Authentication_Stage_Of (Value) = Authentication_Failed
          and then SMB.Engine.Current_Phase (State) =
            SMB.Engine.Disconnected
          and then not SMB.Engine.Has_Pending_Request (State)
          and then not SMB.Engine.Has_Validated_Response (State)
          and then SMB.Engine.Signing_Key_Is_Zero (State)
          and then SMB.Engine.Current_Owner_Id (State) = 0
          and then SMB.Engine.Current_Epoch (State) =
            SMB.Engine.Current_Epoch (State)'Old
          and then SMB.Engine.Current_Session_Id (State) = 0
          and then Authentication_Challenge_Length_Of (Value) = 0
          and then
            (for all Index in Authentication_Buffer_Of (Value)'Range =>
               Authentication_Buffer_Of (Value) (Index) = 0)
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
        else False);

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
   type Directory_Identity is private;
   function Identity_Of
     (Value : Directory_Enumeration) return Directory_Identity
   with Ghost;
   function Directory_Stage_Of
     (Value : Directory_Enumeration) return Directory_Stage;
   function Directory_Page_Length_Of
     (Value : Directory_Enumeration) return Natural;
   function Directory_Cursor_Of
     (Value : Directory_Enumeration) return Natural;
   function Directory_Page_Count_Of
     (Value : Directory_Enumeration) return Natural;
   function Directory_Entry_Count_Of
     (Value : Directory_Enumeration) return Natural;
   function Directory_Token_Of
     (Value : Directory_Enumeration) return SMB.Engine.Handle_Token;
   function Directory_File_Id_Of
     (Value : Directory_Enumeration) return SMB.Bytes;
   function Directory_Access_Of
     (Value : Directory_Enumeration) return SMB.Engine.Access_Kind;
   function Directory_Owner_Of
     (Value : Directory_Enumeration) return SMB.QWord
   with Ghost;
   function Directory_Epoch_Of
     (Value : Directory_Enumeration) return SMB.QWord
   with Ghost;
   function Directory_Expected_Of
     (Value : Directory_Enumeration)
       return SMB.Engine.Request_Expectation
   with Ghost;
   function Directory_Snapshot_Of
     (Value : Directory_Enumeration) return Directory_State_Snapshot
   with Ghost;
   function Directory_Snapshot_Context_Matches
     (Snapshot : Directory_State_Snapshot;
      State : SMB.Engine.Engine_State) return Boolean
   with Ghost;
   function Directory_Invariant
     (Value : Directory_Enumeration) return Boolean;
   function Directory_Context_Matches
     (Value : Directory_Enumeration;
      State : SMB.Engine.Engine_State) return Boolean
   with Ghost;
   function Directory_Page_Of
     (Value : Directory_Enumeration) return SMB.Bytes
   with Ghost;
   function Directory_Page_Byte_Of
     (Value : Directory_Enumeration; Index : Natural) return SMB.Byte
   with Pre => Index < SMB.Core_Protocol.Maximum_IO_Chunk;
   function Directory_Page_Matches
     (Value : Directory_Enumeration;
      Packet : SMB.Bytes;
      Offset, Length : Natural) return Boolean
   with Pre =>
     Packet'Length <= SMB.Maximum_Frame_Size
     and then Offset <= Packet'Length
     and then Length <= Packet'Length - Offset
     and then Length <= SMB.Core_Protocol.Maximum_IO_Chunk;
   function Directory_Packet_Matches
     (Value : Directory_Enumeration;
      State : SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Used : Natural) return Boolean
   with Ghost,
     Pre => Packet'Length <= SMB.Maximum_Frame_Size;
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

   function Unverified_Authentication_Status
     (Value : Authentication;
      State : SMB.Engine.Engine_State;
      Packet : SMB.Bytes) return SMB.DWord
   with Pre => Packet'Length <= SMB.Maximum_Frame_Size,
     Post =>
       (if Unverified_Authentication_Status'Result /= 0 then
          Packet'Length >= 72
          and then Unverified_Authentication_Status'Result =
            SMB.Core_Wire.Header_Nt_Status (Packet)
          and then
            (Unverified_Authentication_Status'Result and 16#C000_0000#) =
              16#C000_0000#);

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

   procedure Start_Directory
     (Value : in out Directory_Enumeration;
      State : SMB.Engine.Engine_State;
      Token : SMB.Engine.Handle_Token;
      Status : out SMB.Core_Status)
   with
     Post =>
       (if Status = SMB.Ok then
          Directory_Stage_Of (Value) = Query_Ready
          and then Directory_Invariant (Value)
          and then Directory_Owner_Of (Value) =
            SMB.Engine.Current_Owner_Id (State)
          and then Directory_Epoch_Of (Value) =
            SMB.Engine.Current_Epoch (State)
          and then Directory_Token_Of (Value).Owner = Token.Owner
          and then Directory_Token_Of (Value).Epoch = Token.Epoch
          and then Directory_Token_Of (Value).Ticket = Token.Ticket
          and then SMB.Engine.Handle_Matches
            (State, Token, Directory_File_Id_Of (Value),
             Directory_Access_Of (Value), True)
          and then Directory_Page_Count_Of (Value) = 0
          and then Directory_Entry_Count_Of (Value) = 0)
       and then
         (if Status = SMB.Invalid_State_Status then
            Directory_Snapshot_Of (Value) =
              Directory_Snapshot_Of (Value)'Old
            and then Directory_Page_Of (Value) =
              Directory_Page_Of (Value)'Old);

   procedure Prepare_Directory_Query
     (Value : in out Directory_Enumeration;
      State : in out SMB.Engine.Engine_State;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with
     Pre => Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Identity_Of (Value) = Identity_Of (Value)'Old
       and then Used <= Output'Length
       and then
         (if Status = SMB.Ok then
            Directory_Stage_Of (Value) = Query_Prepared
            and then Directory_Stage_Of (Value)'Old = Query_Ready
            and then Directory_Invariant (Value)
            and then Directory_Packet_Matches (Value, State, Output, Used)
            and then SMB.Engine.Handle_Matches
              (State'Old, Directory_Token_Of (Value),
               Directory_File_Id_Of (Value),
               Directory_Access_Of (Value), True)
            and then Directory_Page_Count_Of (Value) =
              Directory_Page_Count_Of (Value)'Old + 1
            and then Directory_Entry_Count_Of (Value) =
              Directory_Entry_Count_Of (Value)'Old
            and then Directory_Page_Length_Of (Value) =
              Directory_Page_Length_Of (Value)'Old
            and then Directory_Cursor_Of (Value) =
              Directory_Cursor_Of (Value)'Old)
       and then
         (if Status = SMB.Invalid_State_Status
            and then
              (Directory_Stage_Of (Value)'Old /= Query_Ready
               or else not Directory_Invariant (Value)'Old
               or else not Directory_Snapshot_Context_Matches
                 (Directory_Snapshot_Of (Value)'Old, State'Old)
               or else SMB.Engine.Current_Phase (State'Old) /=
                 SMB.Engine.Share_Connected
               or else SMB.Engine.Has_Pending_Request (State'Old)
               or else SMB.Engine.Has_Validated_Response (State'Old))
          then Directory_Snapshot_Of (Value) =
            Directory_Snapshot_Of (Value)'Old
            and then State = State'Old
            and then Directory_Page_Of (Value) =
              Directory_Page_Of (Value)'Old);

   procedure Directory_Send_Succeeded
     (Value : in out Directory_Enumeration;
      State : SMB.Engine.Engine_State;
      Status : out SMB.Core_Status)
   with
     Post =>
       Identity_Of (Value) = Identity_Of (Value)'Old
       and then
       Directory_Page_Count_Of (Value) =
         Directory_Page_Count_Of (Value)'Old
       and then Directory_Entry_Count_Of (Value) =
         Directory_Entry_Count_Of (Value)'Old
       and then
       (if Status = SMB.Ok then
            Directory_Stage_Of (Value) = Query_Sent
            and then Directory_Stage_Of (Value)'Old = Query_Prepared
            and then Directory_Context_Matches (Value, State)
            and then SMB.Engine.Pending_Request_Matches
              (State, Directory_Expected_Of (Value)))
       and then
         (if Status = SMB.Invalid_State_Status then
            Directory_Snapshot_Of (Value) =
              Directory_Snapshot_Of (Value)'Old
            and then Directory_Page_Of (Value) =
              Directory_Page_Of (Value)'Old);

   procedure Complete_Directory_Page
     (Value : in out Directory_Enumeration;
      State : in out SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Nt_Status : out SMB.DWord;
      Status : out SMB.Core_Status)
   with
     Pre => Packet'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Identity_Of (Value) = Identity_Of (Value)'Old
       and then
       Directory_Page_Count_Of (Value) =
         Directory_Page_Count_Of (Value)'Old
       and then Directory_Entry_Count_Of (Value) =
         Directory_Entry_Count_Of (Value)'Old
       and then
        (if Status = SMB.Ok then
            Directory_Stage_Of (Value)'Old = Query_Sent
            and then Directory_Stage_Of (Value) in
              Page_Ready | Directory_Finished
            and then not SMB.Engine.Has_Pending_Request (State)
            and then not SMB.Engine.Has_Validated_Response (State)
            and then Directory_Entry_Count_Of (Value) =
              Directory_Entry_Count_Of (Value)'Old
            and then
             (if Directory_Stage_Of (Value) = Page_Ready then
                 Nt_Status = SMB.Success
                 and then Packet'Length >= 72
                 and then SMB.Core_Wire.Encoded_U32 (Packet, 68) <=
                   SMB.DWord (SMB.Core_Protocol.Maximum_IO_Chunk)
                 and then Directory_Page_Length_Of (Value) =
                   Natural (SMB.Core_Wire.Encoded_U32 (Packet, 68))
                 and then Directory_Cursor_Of (Value) = 0
                 and then Natural
                   (SMB.Core_Wire.Encoded_U16 (Packet, 66)) <=
                     Packet'Length
                 and then Directory_Page_Length_Of (Value) <=
                   Packet'Length - Natural
                     (SMB.Core_Wire.Encoded_U16 (Packet, 66))
                 and then Directory_Page_Matches
                   (Value, Packet,
                    Natural (SMB.Core_Wire.Encoded_U16 (Packet, 66)),
                    Directory_Page_Length_Of (Value))
               else Directory_Page_Length_Of (Value) = 0))
       and then
         (if Status = SMB.Invalid_State_Status
            and then
              (Directory_Stage_Of (Value)'Old /= Query_Sent
               or else not Directory_Invariant (Value)'Old
               or else not Directory_Snapshot_Context_Matches
                 (Directory_Snapshot_Of (Value)'Old, State'Old)
               or else not SMB.Engine.Pending_Request_Matches
                 (State'Old, Directory_Expected_Of (Value)'Old)
               or else SMB.Engine.Has_Validated_Response (State'Old))
          then Directory_Snapshot_Of (Value) =
            Directory_Snapshot_Of (Value)'Old
            and then State = State'Old
            and then Directory_Page_Of (Value) =
              Directory_Page_Of (Value)'Old);

   procedure Next_Directory_Entry
     (Value : in out Directory_Enumeration;
      State : in out SMB.Engine.Engine_State;
      Name : in out SMB.Bytes;
      Used : out Natural;
      Info : out SMB.Core_Protocol.Directory_Info;
      Status : out SMB.Core_Status)
   with
     Pre => Name'Length <= SMB.Core_Protocol.Maximum_Name_Bytes,
     Post =>
       Identity_Of (Value) = Identity_Of (Value)'Old
       and then Directory_Page_Of (Value) =
         Directory_Page_Of (Value)'Old
       and then Directory_Page_Count_Of (Value) =
         Directory_Page_Count_Of (Value)'Old
       and then Used <= Name'Length
       and then
         (if Status = SMB.Ok then
            Directory_Invariant (Value)
            and then
            Directory_Stage_Of (Value)'Old = Page_Ready
            and then Directory_Stage_Of (Value) in Page_Ready | Query_Ready
            and then Directory_Cursor_Of (Value) = Info.Next_Cursor
            and then Directory_Cursor_Of (Value) >
              Directory_Cursor_Of (Value)'Old
            and then Directory_Entry_Count_Of (Value) =
              Directory_Entry_Count_Of (Value)'Old + 1
            and then Used > 0
            and then Used = Info.Name_Length
            and then Directory_Page_Length_Of (Value) =
              Directory_Page_Length_Of (Value)'Old
            and then Directory_Entry_Count_Of (Value) <=
              SMB.Core_Protocol.Maximum_Directory_Entries
            and then Info.Name_Offset =
              Directory_Cursor_Of (Value)'Old + 104
            and then Info.Name_Length = Natural
              (SMB.Core_Wire.Encoded_U32
                 (Directory_Page_Of (Value)'Old,
                  Directory_Cursor_Of (Value)'Old + 60))
            and then Info.Size = SMB.Core_Wire.Encoded_U64
              (Directory_Page_Of (Value)'Old,
               Directory_Cursor_Of (Value)'Old + 40)
            and then Info.Attributes = SMB.Core_Wire.Encoded_U32
              (Directory_Page_Of (Value)'Old,
               Directory_Cursor_Of (Value)'Old + 56)
            and then Name
              (Name'First .. Name'First + (Used - 1)) =
                Directory_Page_Of (Value)'Old
                  (Info.Name_Offset .. Info.Name_Offset + Used - 1))
       and then
         (if Status = SMB.Resource_Limit
            and then Directory_Stage_Of (Value) = Page_Ready
          then Directory_Snapshot_Of (Value) =
            Directory_Snapshot_Of (Value)'Old
            and then State = State'Old
            and then Name = Name'Old
            and then Used = 0)
       and then
         (if Status = SMB.Invalid_State_Status
            and then
              (Directory_Stage_Of (Value)'Old /= Page_Ready
               or else not Directory_Invariant (Value)'Old
               or else not Directory_Snapshot_Context_Matches
                 (Directory_Snapshot_Of (Value)'Old, State'Old)
               or else SMB.Engine.Has_Pending_Request (State'Old)
               or else SMB.Engine.Has_Validated_Response (State'Old))
          then Directory_Snapshot_Of (Value) =
            Directory_Snapshot_Of (Value)'Old
            and then State = State'Old
            and then Directory_Page_Of (Value) =
              Directory_Page_Of (Value)'Old
            and then Name = Name'Old
            and then Used = 0);

   procedure Abort_Directory
     (Value : in out Directory_Enumeration;
      State : in out SMB.Engine.Engine_State;
      Status : out SMB.Core_Status)
   with
     Post =>
       Identity_Of (Value) = Identity_Of (Value)'Old
       and then
       (if Status = SMB.Invalid_State_Status
            and then
              (Directory_Stage_Of (Value)'Old not in
                 Query_Ready | Query_Prepared | Query_Sent | Page_Ready
               or else not Directory_Snapshot_Context_Matches
                 (Directory_Snapshot_Of (Value)'Old, State'Old)
               or else
                 (if Directory_Stage_Of (Value)'Old in
                       Query_Prepared | Query_Sent
                  then
                    not SMB.Engine.Pending_Request_Matches
                      (State'Old, Directory_Expected_Of (Value)'Old)
                    or else SMB.Engine.Has_Validated_Response (State'Old)
                  else
                    SMB.Engine.Has_Pending_Request (State'Old)
                    or else SMB.Engine.Has_Validated_Response (State'Old)))
          then Directory_Snapshot_Of (Value) =
            Directory_Snapshot_Of (Value)'Old
            and then Directory_Page_Of (Value) =
              Directory_Page_Of (Value)'Old
            and then State = State'Old)
       and then
         (if Status = SMB.Ok then
            Directory_Stage_Of (Value) = Directory_Failed
            and then Directory_Stage_Of (Value)'Old in
              Query_Ready | Query_Prepared | Query_Sent | Page_Ready);

   function Metadata_Stage_Of
     (Value : Metadata_Operation) return Metadata_Stage;
   function Metadata_Kind_Of
     (Value : Metadata_Operation) return Metadata_Kind;
   function Metadata_Snapshot_Of
     (Value : Metadata_Operation) return Metadata_State_Snapshot;
   function Metadata_Expected_Of
     (Value : Metadata_Operation) return SMB.Engine.Request_Expectation
   with Ghost;
   function Metadata_Preparation_Context_Matches
     (Snapshot : Metadata_State_Snapshot;
      State : SMB.Engine.Engine_State;
      Token : SMB.Engine.Handle_Token) return Boolean
   with Ghost;
   function Metadata_Continuation_Context_Matches
     (Snapshot : Metadata_State_Snapshot;
      State : SMB.Engine.Engine_State) return Boolean
   with Ghost;
   function Metadata_Packet_Matches
     (Value : Metadata_Operation;
      State : SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Used : Natural) return Boolean
   with Ghost,
     Pre => Packet'Length <= SMB.Maximum_Frame_Size;
   procedure Prepare_Disposition
     (Value : in out Metadata_Operation;
      State : in out SMB.Engine.Engine_State;
      Token : SMB.Engine.Handle_Token;
      Delete_File : Boolean;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if not Metadata_Preparation_Context_Matches
               (Metadata_Snapshot_Of (Value)'Old, State'Old, Token)
             or else Output'Length < SMB.Core_Wire.Header_Size + 33
          then Status /= SMB.Ok
            and then Metadata_Snapshot_Of (Value) =
              Metadata_Snapshot_Of (Value)'Old
            and then State = State'Old and then Used = 0)
       and then
         (if Status = SMB.Invalid_State_Status
              and then not Metadata_Preparation_Context_Matches
                (Metadata_Snapshot_Of (Value)'Old, State'Old, Token)
          then Metadata_Snapshot_Of (Value) =
                 Metadata_Snapshot_Of (Value)'Old
            and then State = State'Old
            and then Used = 0)
       and then
         (if Status in SMB.Invalid_Length | SMB.Resource_Limit
              and then Metadata_Stage_Of (Value) =
                Metadata_Stage_Of (Value)'Old
          then Metadata_Snapshot_Of (Value) =
                 Metadata_Snapshot_Of (Value)'Old
            and then State = State'Old
            and then Used = 0)
       and then
         (if Status = SMB.Ok then
            Metadata_Stage_Of (Value) = Metadata_Prepared
            and then Metadata_Kind_Of (Value) = Disposition_Metadata
            and then Used = 97
            and then SMB.Engine.Pending_Request_Matches
              (State, Metadata_Expected_Of (Value))
            and then Metadata_Packet_Matches (Value, State, Output, Used)
            and then SMB.Engine.Handle_Matches_In_States
              (State'Old, State, Token,
               Metadata_Snapshot_Of (Value).File_Id,
               Metadata_Snapshot_Of (Value).Access_Mode,
               Metadata_Snapshot_Of (Value).Directory)
            and then SMB.Engine.Handle_Matches
              (State, Token, Metadata_Snapshot_Of (Value).File_Id,
               Metadata_Snapshot_Of (Value).Access_Mode,
               Metadata_Snapshot_Of (Value).Directory)
            and then Metadata_Snapshot_Of (Value).Token = Token
            and then Metadata_Snapshot_Of (Value).Delete_File = Delete_File
            and then Metadata_Snapshot_Of (Value).Name_Length = 0);
   procedure Prepare_Rename
     (Value : in out Metadata_Operation;
      State : in out SMB.Engine.Engine_State;
      Token : SMB.Engine.Handle_Token;
      Name : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => Name'Length <= SMB.Core_Protocol.Maximum_Name_Bytes
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if not Metadata_Preparation_Context_Matches
               (Metadata_Snapshot_Of (Value)'Old, State'Old, Token)
             or else Name'Length = 0 or else Name'Length mod 2 /= 0
             or else Output'Length <
               SMB.Core_Wire.Header_Size + 52 + Name'Length
          then Status /= SMB.Ok
            and then Metadata_Snapshot_Of (Value) =
              Metadata_Snapshot_Of (Value)'Old
            and then State = State'Old and then Used = 0)
       and then
         (if Status = SMB.Invalid_State_Status
              and then not Metadata_Preparation_Context_Matches
                (Metadata_Snapshot_Of (Value)'Old, State'Old, Token)
          then Metadata_Snapshot_Of (Value) =
                 Metadata_Snapshot_Of (Value)'Old
            and then State = State'Old
            and then Used = 0)
       and then
         (if Status in SMB.Invalid_Length | SMB.Resource_Limit
              and then Metadata_Stage_Of (Value) =
                Metadata_Stage_Of (Value)'Old
          then Metadata_Snapshot_Of (Value) =
                 Metadata_Snapshot_Of (Value)'Old
            and then State = State'Old
            and then Used = 0)
       and then
         (if Status = SMB.Ok then
            Metadata_Stage_Of (Value) = Metadata_Prepared
            and then Metadata_Kind_Of (Value) = Rename_Metadata
            and then Used = SMB.Core_Wire.Header_Size + 52 + Name'Length
            and then SMB.Engine.Pending_Request_Matches
              (State, Metadata_Expected_Of (Value))
            and then Metadata_Packet_Matches (Value, State, Output, Used)
            and then SMB.Engine.Handle_Matches_In_States
              (State'Old, State, Token,
               Metadata_Snapshot_Of (Value).File_Id,
               Metadata_Snapshot_Of (Value).Access_Mode,
               Metadata_Snapshot_Of (Value).Directory)
            and then SMB.Engine.Handle_Matches
              (State, Token, Metadata_Snapshot_Of (Value).File_Id,
               Metadata_Snapshot_Of (Value).Access_Mode,
               Metadata_Snapshot_Of (Value).Directory)
            and then Metadata_Snapshot_Of (Value).Token = Token
            and then Metadata_Snapshot_Of (Value).Delete_File = False
            and then Metadata_Snapshot_Of (Value).Name_Length =
              Name'Length
            and then Name'Length > 0
            and then Name'Length mod 2 = 0
            and then
              (for all Index in 0 .. Name'Length - 1 =>
                 Output
                   (Output'First + SMB.Core_Wire.Header_Size + 52 + Index) =
                     Name (Name'First + Index)));
   procedure Metadata_Send_Succeeded
     (Value : in out Metadata_Operation;
      State : SMB.Engine.Engine_State;
      Status : out SMB.Core_Status)
   with Post =>
     (if Status = SMB.Ok then
        Metadata_Continuation_Context_Matches
          (Metadata_Snapshot_Of (Value), State))
     and then
     (if Status = SMB.Invalid_State_Status then
        Metadata_Snapshot_Of (Value).Stage =
          Metadata_Snapshot_Of (Value)'Old.Stage
        and then Metadata_Snapshot_Of (Value).Kind =
          Metadata_Snapshot_Of (Value)'Old.Kind
        and then Metadata_Snapshot_Of (Value).Owner =
          Metadata_Snapshot_Of (Value)'Old.Owner
        and then Metadata_Snapshot_Of (Value).Epoch =
          Metadata_Snapshot_Of (Value)'Old.Epoch
        and then Metadata_Snapshot_Of (Value).Token =
          Metadata_Snapshot_Of (Value)'Old.Token
        and then Metadata_Snapshot_Of (Value).File_Id =
          Metadata_Snapshot_Of (Value)'Old.File_Id
        and then Metadata_Snapshot_Of (Value).Access_Mode =
          Metadata_Snapshot_Of (Value)'Old.Access_Mode
        and then Metadata_Snapshot_Of (Value).Directory =
          Metadata_Snapshot_Of (Value)'Old.Directory
            and then Metadata_Snapshot_Of (Value).Expected =
              Metadata_Snapshot_Of (Value)'Old.Expected
            and then Metadata_Snapshot_Of (Value).Delete_File =
              Metadata_Snapshot_Of (Value)'Old.Delete_File
            and then Metadata_Snapshot_Of (Value).Name_Length =
              Metadata_Snapshot_Of (Value)'Old.Name_Length
     elsif Status = SMB.Ok then
        Metadata_Stage_Of (Value) = Metadata_Sent
        and then Metadata_Stage_Of (Value)'Old = Metadata_Prepared
        and then Metadata_Snapshot_Of (Value).Kind =
          Metadata_Snapshot_Of (Value)'Old.Kind
        and then Metadata_Snapshot_Of (Value).Owner =
          Metadata_Snapshot_Of (Value)'Old.Owner
        and then Metadata_Snapshot_Of (Value).Epoch =
          Metadata_Snapshot_Of (Value)'Old.Epoch
        and then Metadata_Snapshot_Of (Value).Token =
          Metadata_Snapshot_Of (Value)'Old.Token
        and then Metadata_Snapshot_Of (Value).File_Id =
          Metadata_Snapshot_Of (Value)'Old.File_Id
        and then Metadata_Snapshot_Of (Value).Access_Mode =
          Metadata_Snapshot_Of (Value)'Old.Access_Mode
        and then Metadata_Snapshot_Of (Value).Directory =
          Metadata_Snapshot_Of (Value)'Old.Directory
        and then Metadata_Snapshot_Of (Value).Expected =
          Metadata_Snapshot_Of (Value)'Old.Expected
        and then Metadata_Snapshot_Of (Value).Delete_File =
          Metadata_Snapshot_Of (Value)'Old.Delete_File
        and then Metadata_Snapshot_Of (Value).Name_Length =
          Metadata_Snapshot_Of (Value)'Old.Name_Length);
   procedure Complete_Metadata
     (Value : in out Metadata_Operation;
      State : in out SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Nt_Status : out SMB.DWord;
      Status : out SMB.Core_Status)
   with Pre => Packet'Length <= SMB.Maximum_Frame_Size,
     Post =>
       (if Metadata_Stage_Of (Value)'Old /= Metadata_Sent
                or else not Metadata_Continuation_Context_Matches
                  (Metadata_Snapshot_Of (Value)'Old, State'Old)
        then Status = SMB.Invalid_State_Status
          and then Metadata_Snapshot_Of (Value) = Metadata_Snapshot_Of (Value)'Old
          and then State = State'Old)
       and then
       (if Status = SMB.Invalid_State_Status
             and then Metadata_Stage_Of (Value) =
               Metadata_Stage_Of (Value)'Old
        then
          Metadata_Snapshot_Of (Value) = Metadata_Snapshot_Of (Value)'Old
          and then State = State'Old
          and then Nt_Status = 0
        elsif Status = SMB.Ok then
          Metadata_Stage_Of (Value) = Metadata_Finished
          and then Metadata_Stage_Of (Value)'Old = Metadata_Sent
          and then Metadata_Snapshot_Of (Value).Kind =
            Metadata_Snapshot_Of (Value)'Old.Kind
          and then Metadata_Snapshot_Of (Value).Owner =
            Metadata_Snapshot_Of (Value)'Old.Owner
          and then Metadata_Snapshot_Of (Value).Epoch =
            Metadata_Snapshot_Of (Value)'Old.Epoch
          and then Metadata_Snapshot_Of (Value).Token =
            Metadata_Snapshot_Of (Value)'Old.Token
          and then Metadata_Snapshot_Of (Value).File_Id =
            Metadata_Snapshot_Of (Value)'Old.File_Id
          and then Metadata_Snapshot_Of (Value).Access_Mode =
            Metadata_Snapshot_Of (Value)'Old.Access_Mode
          and then Metadata_Snapshot_Of (Value).Directory =
            Metadata_Snapshot_Of (Value)'Old.Directory
          and then Metadata_Snapshot_Of (Value).Delete_File =
            Metadata_Snapshot_Of (Value)'Old.Delete_File
          and then Metadata_Snapshot_Of (Value).Name_Length =
            Metadata_Snapshot_Of (Value)'Old.Name_Length
          and then Metadata_Snapshot_Of (Value).Expected =
            Metadata_Snapshot_Of (Value)'Old.Expected
          and then SMB.Engine.Current_Owner_Id (State) =
            Metadata_Snapshot_Of (Value).Owner
          and then SMB.Engine.Current_Epoch (State) =
            Metadata_Snapshot_Of (Value).Epoch
          and then SMB.Engine.Current_Phase (State) =
            SMB.Engine.Share_Connected
          and then SMB.Engine.Handle_Matches
            (State, Metadata_Snapshot_Of (Value).Token,
             Metadata_Snapshot_Of (Value).File_Id,
             Metadata_Snapshot_Of (Value).Access_Mode,
             Metadata_Snapshot_Of (Value).Directory)
          and then not SMB.Engine.Has_Pending_Request (State)
          and then not SMB.Engine.Has_Validated_Response (State)
        else Metadata_Stage_Of (Value) = Metadata_Failed
          and then SMB.Engine.Current_Phase (State) =
            SMB.Engine.Disconnected);
   procedure Abort_Metadata
     (Value : in out Metadata_Operation;
      State : in out SMB.Engine.Engine_State;
      Status : out SMB.Core_Status)
   with Post =>
     (if Metadata_Snapshot_Of (Value)'Old.Stage not in
           Metadata_Prepared | Metadata_Sent
          or else Metadata_Snapshot_Of (Value)'Old.Owner /=
            SMB.Engine.Current_Owner_Id (State'Old)
          or else Metadata_Snapshot_Of (Value)'Old.Epoch /=
            SMB.Engine.Current_Epoch (State'Old)
          or else not SMB.Engine.Pending_Request_Matches
            (State'Old, Metadata_Snapshot_Of (Value)'Old.Expected)
      then Status = SMB.Invalid_State_Status
        and then Metadata_Snapshot_Of (Value) =
          Metadata_Snapshot_Of (Value)'Old
        and then State = State'Old)
     and then
     (if Status = SMB.Invalid_State_Status then
        Metadata_Snapshot_Of (Value).Stage =
          Metadata_Snapshot_Of (Value)'Old.Stage
        and then Metadata_Snapshot_Of (Value).Kind =
          Metadata_Snapshot_Of (Value)'Old.Kind
        and then Metadata_Snapshot_Of (Value).Owner =
          Metadata_Snapshot_Of (Value)'Old.Owner
        and then Metadata_Snapshot_Of (Value).Epoch =
          Metadata_Snapshot_Of (Value)'Old.Epoch
        and then Metadata_Snapshot_Of (Value).Token =
          Metadata_Snapshot_Of (Value)'Old.Token
        and then Metadata_Snapshot_Of (Value).File_Id =
          Metadata_Snapshot_Of (Value)'Old.File_Id
        and then Metadata_Snapshot_Of (Value).Access_Mode =
          Metadata_Snapshot_Of (Value)'Old.Access_Mode
        and then Metadata_Snapshot_Of (Value).Directory =
          Metadata_Snapshot_Of (Value)'Old.Directory
        and then Metadata_Snapshot_Of (Value).Expected =
          Metadata_Snapshot_Of (Value)'Old.Expected
        and then Metadata_Snapshot_Of (Value).Delete_File =
          Metadata_Snapshot_Of (Value)'Old.Delete_File
        and then Metadata_Snapshot_Of (Value).Name_Length =
          Metadata_Snapshot_Of (Value)'Old.Name_Length
        and then State = State'Old
      elsif Status = SMB.Ok then
        Metadata_Stage_Of (Value) = Metadata_Failed
        and then SMB.Engine.Current_Phase (State) =
          SMB.Engine.Disconnected);

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
   type Directory_Identity is record
      Owner, Epoch : SMB.QWord;
      Token : SMB.Engine.Handle_Token;
      File_Id : SMB.Bytes (0 .. 15);
      Access_Mode : SMB.Engine.Access_Kind;
   end record;

   type Directory_Enumeration is limited record
      Stage : Directory_Stage := Directory_Idle;
      Owner, Epoch : SMB.QWord := 0;
      Token : SMB.Engine.Handle_Token := (others => 0);
      File_Id : SMB.Bytes (0 .. 15) := (others => 0);
      Access_Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
      Expected : SMB.Engine.Request_Expectation;
      Page_Length : Natural := 0;
      Cursor : Natural := 0;
      Page_Count : Natural := 0;
      Entry_Count : Natural := 0;
      Page : SMB.Bytes
        (0 .. SMB.Core_Protocol.Maximum_IO_Chunk - 1) := (others => 0);
   end record;

   type Authentication is limited record
      Stage : Authentication_Stage := Authentication_Ready;
      Owner, Epoch : SMB.QWord := 0;
      Session_Id : SMB.QWord := 0;
      Expected : SMB.Engine.Request_Expectation;
      Challenge_Length : Natural := 0;
      Challenge : SMB.Bytes
        (0 .. SMB.Core_Auth.Maximum_Security_Token - 1) := (others => 0);
   end record;

   function Identity_Of
     (Value : Directory_Enumeration) return Directory_Identity is
     ((Owner => Value.Owner, Epoch => Value.Epoch, Token => Value.Token,
       File_Id => Value.File_Id, Access_Mode => Value.Access_Mode));

   function Directory_Snapshot_Of
     (Value : Directory_Enumeration) return Directory_State_Snapshot is
     ((Stage => Value.Stage,
       Owner => Value.Owner,
       Epoch => Value.Epoch,
       Token => Value.Token,
       File_Id => Value.File_Id,
       Access_Mode => Value.Access_Mode,
       Expected => Value.Expected,
       Page_Length => Value.Page_Length,
       Cursor => Value.Cursor,
       Page_Count => Value.Page_Count,
       Entry_Count => Value.Entry_Count));
   function Directory_Snapshot_Context_Matches
     (Snapshot : Directory_State_Snapshot;
      State : SMB.Engine.Engine_State) return Boolean is
     (Snapshot.Owner = SMB.Engine.Current_Owner_Id (State)
      and then Snapshot.Epoch = SMB.Engine.Current_Epoch (State)
      and then SMB.Engine.Handle_Matches
        (State, Snapshot.Token, Snapshot.File_Id, Snapshot.Access_Mode, True));

   function Directory_Stage_Of
     (Value : Directory_Enumeration) return Directory_Stage is
     (Value.Stage);
   function Directory_Page_Length_Of
     (Value : Directory_Enumeration) return Natural is
     (Value.Page_Length);
   function Directory_Cursor_Of
     (Value : Directory_Enumeration) return Natural is
     (Value.Cursor);
   function Directory_Page_Count_Of
     (Value : Directory_Enumeration) return Natural is
     (Value.Page_Count);
   function Directory_Entry_Count_Of
     (Value : Directory_Enumeration) return Natural is
     (Value.Entry_Count);
   function Directory_Token_Of
     (Value : Directory_Enumeration) return SMB.Engine.Handle_Token is
     (Value.Token);
   function Directory_File_Id_Of
     (Value : Directory_Enumeration) return SMB.Bytes is
     (Value.File_Id);
   function Directory_Access_Of
     (Value : Directory_Enumeration) return SMB.Engine.Access_Kind is
     (Value.Access_Mode);
   function Directory_Owner_Of
     (Value : Directory_Enumeration) return SMB.QWord is
     (Value.Owner);
   function Directory_Epoch_Of
     (Value : Directory_Enumeration) return SMB.QWord is
     (Value.Epoch);
   function Directory_Expected_Of
     (Value : Directory_Enumeration)
       return SMB.Engine.Request_Expectation is
     (Value.Expected);
   function Directory_Invariant
     (Value : Directory_Enumeration) return Boolean is
     (Value.Page_Length <= SMB.Core_Protocol.Maximum_IO_Chunk
      and then Value.Cursor <= Value.Page_Length
      and then Value.Page_Count <=
        SMB.Core_Protocol.Maximum_Directory_Pages
      and then Value.Entry_Count <=
        SMB.Core_Protocol.Maximum_Directory_Entries
      and then
        (if Value.Stage = Page_Ready then
           Value.Cursor < Value.Page_Length
           and then Value.Page_Length > 0)
      and then
        (if Value.Stage in Query_Prepared | Query_Sent then
           Value.Page_Count > 0));
   function Directory_Context_Matches
     (Value : Directory_Enumeration;
      State : SMB.Engine.Engine_State) return Boolean is
     (Value.Owner = SMB.Engine.Current_Owner_Id (State)
      and then Value.Epoch = SMB.Engine.Current_Epoch (State)
      and then SMB.Engine.Valid_Handle
        (State, Value.Token, True, False));
   function Directory_Page_Of
     (Value : Directory_Enumeration) return SMB.Bytes is
     (Value.Page);
   function Directory_Page_Byte_Of
     (Value : Directory_Enumeration; Index : Natural) return SMB.Byte is
     (Value.Page (Index));
   function Directory_Page_Matches
     (Value : Directory_Enumeration;
      Packet : SMB.Bytes;
      Offset, Length : Natural) return Boolean is
     (Value.Page_Length = Length
      and then
        (if Length = 0 then True
         else
           (for all Index in 0 .. Length - 1 =>
              Value.Page (Index) =
                Packet (Packet'First + (Offset + Index)))));
   function Directory_Packet_Matches
     (Value : Directory_Enumeration;
      State : SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Used : Natural) return Boolean is
     (Value.Stage = Query_Prepared
      and then Directory_Invariant (Value)
      and then Value.Owner = SMB.Engine.Current_Owner_Id (State)
      and then Value.Epoch = SMB.Engine.Current_Epoch (State)
      and then SMB.Engine.Pending_Request_Matches (State, Value.Expected)
      and then Value.Expected.Command = 14
      and then Value.Expected.Request_Signed
      and then Value.Expected.Signed
      and then Value.Expected.Request_Amount =
        SMB.Core_Protocol.Maximum_IO_Chunk
      and then Used = Directory_Request_Size
      and then Used <= Packet'Length
      and then SMB.Core_Wire.Encoded_U16 (Packet, 12) = 14
      and then SMB.Core_Wire.Encoded_U32 (Packet, 16) = 8
      and then SMB.Core_Wire.Encoded_U64 (Packet, 24) =
        Value.Expected.Message_Id
      and then SMB.Core_Wire.Encoded_U32 (Packet, 36) =
        Value.Expected.Tree_Id
      and then SMB.Core_Wire.Encoded_U64 (Packet, 40) =
        Value.Expected.Session_Id
      and then SMB.Core_Wire.Encoded_U16
        (Packet, SMB.Core_Wire.Header_Size) = 33
      and then Packet (Packet'First + SMB.Core_Wire.Header_Size + 2) = 37
      and then Packet (Packet'First + SMB.Core_Wire.Header_Size + 3) =
        (if Value.Page_Count = 1 then 1 else 0)
      and then SMB.Core_Wire.Encoded_U32
        (Packet, SMB.Core_Wire.Header_Size + 4) = 0
      and then
        (for all Index in 0 .. 15 =>
           Packet (Packet'First + SMB.Core_Wire.Header_Size + 8 + Index) =
             Value.File_Id (Value.File_Id'First + Index))
      and then SMB.Core_Wire.Encoded_U16
        (Packet, SMB.Core_Wire.Header_Size + 24) = 96
      and then SMB.Core_Wire.Encoded_U16
        (Packet, SMB.Core_Wire.Header_Size + 26) = 2
      and then SMB.Core_Wire.Encoded_U32
        (Packet, SMB.Core_Wire.Header_Size + 28) =
          SMB.DWord (SMB.Core_Protocol.Maximum_IO_Chunk)
      and then Packet (Packet'First + SMB.Core_Wire.Header_Size + 32) =
        16#2A#
      and then Packet (Packet'First + SMB.Core_Wire.Header_Size + 33) = 0);

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

   type Metadata_Operation is limited record
      Kind : Metadata_Kind := No_Metadata;
      Stage : Metadata_Stage := Metadata_Idle;
      Owner, Epoch : SMB.QWord := 0;
      Token : SMB.Engine.Handle_Token := (others => 0);
      File_Id : SMB.Bytes (0 .. 15) := (others => 0);
      Access_Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
      Directory : Boolean := False;
      Delete_File : Boolean := False;
      Name_Length : Natural := 0;
      Expected : SMB.Engine.Request_Expectation;
   end record;

   function Metadata_Preparation_Context_Matches
     (Snapshot : Metadata_State_Snapshot;
      State : SMB.Engine.Engine_State;
      Token : SMB.Engine.Handle_Token) return Boolean is
     (Snapshot.Stage = Metadata_Idle
      and then SMB.Engine.Current_Phase (State) =
        SMB.Engine.Share_Connected
      and then not SMB.Engine.Has_Pending_Request (State)
      and then not SMB.Engine.Has_Validated_Response (State)
      and then Token.Owner = SMB.Engine.Current_Owner_Id (State)
      and then Token.Epoch = SMB.Engine.Current_Epoch (State)
      and then Token.Ticket /= 0
      and then SMB.Engine.Valid_Handle (State, Token, False, False));

   function Metadata_Continuation_Context_Matches
     (Snapshot : Metadata_State_Snapshot;
      State : SMB.Engine.Engine_State) return Boolean is
     (Snapshot.Stage = Metadata_Sent
      and then Snapshot.Expected.Command = 17
      and then Snapshot.Expected.Signed
      and then Snapshot.Expected.Request_Signed
      and then Snapshot.Owner = SMB.Engine.Current_Owner_Id (State)
      and then Snapshot.Epoch = SMB.Engine.Current_Epoch (State)
      and then SMB.Engine.Current_Phase (State) =
        SMB.Engine.Share_Connected
      and then SMB.Engine.Handle_Matches
        (State, Snapshot.Token, Snapshot.File_Id, Snapshot.Access_Mode,
         Snapshot.Directory)
      and then SMB.Engine.Pending_Request_Matches
        (State, Snapshot.Expected));

   function Metadata_Packet_Matches
     (Value : Metadata_Operation;
      State : SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Used : Natural) return Boolean is
     (Value.Stage = Metadata_Prepared
      and then Value.Kind in Rename_Metadata | Disposition_Metadata
      and then Value.Owner = SMB.Engine.Current_Owner_Id (State)
      and then Value.Epoch = SMB.Engine.Current_Epoch (State)
      and then Value.Token.Owner = Value.Owner
      and then Value.Token.Epoch = Value.Epoch
      and then Value.Token.Ticket /= 0
      and then SMB.Engine.Pending_Request_Matches (State, Value.Expected)
      and then Value.Expected.Command = 17
      and then Value.Expected.Request_Signed
      and then Value.Expected.Signed
      and then Value.Expected.Request_Amount = 0
      and then Value.Name_Length <= SMB.Core_Protocol.Maximum_Name_Bytes
      and then Used <= Packet'Length
      and then Used =
        (if Value.Kind = Disposition_Metadata
         then SMB.Core_Wire.Header_Size + 33
         else SMB.Core_Wire.Header_Size + 52 + Value.Name_Length)
      and then SMB.Core_Wire.Encoded_U16 (Packet, 4) =
        SMB.Word (SMB.Core_Wire.Header_Size)
      and then SMB.Core_Wire.Encoded_U16 (Packet, 12) = 17
      and then SMB.Core_Wire.Encoded_U32 (Packet, 16) = 8
      and then SMB.Core_Wire.Encoded_U64 (Packet, 24) =
        Value.Expected.Message_Id
      and then SMB.Core_Wire.Encoded_U32 (Packet, 36) =
        Value.Expected.Tree_Id
      and then SMB.Core_Wire.Encoded_U64 (Packet, 40) =
        Value.Expected.Session_Id
      and then SMB.Core_Wire.Encoded_U16
        (Packet, SMB.Core_Wire.Header_Size) = 33
      and then Packet
        (Packet'First + SMB.Core_Wire.Header_Size + 2) = 1
      and then SMB.Core_Wire.Encoded_U16
        (Packet, SMB.Core_Wire.Header_Size + 8) = 96
      and then
        (for all Index in 10 .. 15 =>
           Packet
             (Packet'First + SMB.Core_Wire.Header_Size + Index) = 0)
      and then
        (for all Index in 0 .. 15 =>
           Packet
             (Packet'First + SMB.Core_Wire.Header_Size + 16 + Index) =
               Value.File_Id (Value.File_Id'First + Index))
      and then
        (if Value.Kind = Disposition_Metadata then
           Packet
             (Packet'First + SMB.Core_Wire.Header_Size + 3) = 13
           and then SMB.Core_Wire.Encoded_U32
             (Packet, SMB.Core_Wire.Header_Size + 4) = 1
           and then Packet
             (Packet'First + SMB.Core_Wire.Header_Size + 32) =
               (if Value.Delete_File then 1 else 0)
         else
           Value.Name_Length <= SMB.Core_Protocol.Maximum_Name_Bytes
           and then Packet
             (Packet'First + SMB.Core_Wire.Header_Size + 3) = 10
           and then SMB.Core_Wire.Encoded_U32
             (Packet, SMB.Core_Wire.Header_Size + 4) =
               SMB.DWord (20 + Value.Name_Length)
           and then
             (for all Index in 32 .. 47 =>
                Packet
                  (Packet'First + SMB.Core_Wire.Header_Size + Index) = 0)
           and then SMB.Core_Wire.Encoded_U32
             (Packet, SMB.Core_Wire.Header_Size + 48) =
               SMB.DWord (Value.Name_Length)));

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
