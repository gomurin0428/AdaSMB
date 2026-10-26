with SMB.Crypto;

package body SMB.Core_Client
  with SPARK_Mode
is
   pragma Unevaluated_Use_Of_Old (Allow);

   Header_Length : constant Natural := SMB.Core_Wire.Header_Size;
   procedure Sign_Packet
     (Packet : in out SMB.Bytes;
      Used : Natural;
      Key : SMB.Bytes;
      Status : out SMB.Core_Status)
   with
     Pre =>
       Packet'Length <= SMB.Maximum_Frame_Size
       and then Used >= Header_Length
       and then Used <= Packet'Length
       and then Key'Length <= SMB.Maximum_Frame_Size,
     Post =>
       (if Status = SMB.Ok then
          (for all Index in Packet'Range =>
             (if Index < Packet'First + 48
                or else Index > Packet'First + 63
              then Packet (Index) = Packet'Old (Index)))
        else Packet = Packet'Old)
   is
   begin
      SMB.Core_Wire.Sign
        (Packet
           (Packet'First .. Packet'Last - (Packet'Length - Used)),
         Key, Status);
   end Sign_Packet;

   procedure Fail_Transfer
     (Value : in out Transfer;
      State : in out SMB.Engine.Engine_State;
      Failure : SMB.Core_Status;
      Status : out SMB.Core_Status)
   with Pre => Failure /= SMB.Ok,
        Post => Status /= SMB.Ok
          and then Identity_Of (Value) = Identity_Of (Value)'Old
          and then Transfer_Buffer_Of (Value) = Transfer_Buffer_Of (Value)'Old
   is
      Invalidate_Status : SMB.Core_Status;
   begin
      SMB.Engine.Invalidate (State, Invalidate_Status);
      Value.Stage := Transfer_Failed;
      Status :=
        (if Invalidate_Status = SMB.Ok then Failure else Invalidate_Status);
   end Fail_Transfer;

   procedure Clear_Transfer_Buffer (Buffer : in out SMB.Bytes)
   with Post =>
     (for all Index in Buffer'Range => Buffer (Index) = 0)
   is
   begin
      for Index in Buffer'Range loop
         Buffer (Index) := 0;
         pragma Loop_Invariant
           (for all Cleared in Buffer'First .. Index =>
              Buffer (Cleared) = 0);
      end loop;
   end Clear_Transfer_Buffer;

   procedure Clear_Output (Output : out SMB.Bytes) is
   begin
      for Index in Output'Range loop
         Output (Index) := 0;
      end loop;
   end Clear_Output;

   procedure Clear_Authentication_Buffer (Value : in out Authentication)
   with Post =>
     Value.Stage = Value.Stage'Old
     and then Value.Owner = Value.Owner'Old
     and then Value.Epoch = Value.Epoch'Old
     and then Value.Session_Id = Value.Session_Id'Old
     and then SMB.Engine."=" (Value.Expected, Value.Expected'Old)
     and then Value.Challenge_Length = 0
     and then
       (for all Index in Value.Challenge'Range =>
          Value.Challenge (Index) = 0)
   is
   begin
      for Index in Value.Challenge'Range loop
         Value.Challenge (Index) := 0;
         pragma Loop_Invariant
           (for all Cleared in Value.Challenge'First .. Index =>
              Value.Challenge (Cleared) = 0);
      end loop;
      Value.Challenge_Length := 0;
   end Clear_Authentication_Buffer;

   procedure Prepare_Unsigned_Header
     (Packet : in out SMB.Bytes;
      Expected : SMB.Engine.Request_Expectation;
      Status : out SMB.Core_Status)
   with
     Pre => Packet'Length <= SMB.Maximum_Frame_Size,
     Post =>
       (if Status = SMB.Ok then
          SMB.Core_Wire.Encoded_U16 (Packet, 12) =
            SMB.Word (Expected.Command)
          and then SMB.Core_Wire.Encoded_U64 (Packet, 24) =
            Expected.Message_Id
          and then SMB.Core_Wire.Encoded_U32 (Packet, 36) =
            Expected.Tree_Id
          and then SMB.Core_Wire.Encoded_U64 (Packet, 40) =
            Expected.Session_Id
          and then SMB.Core_Wire.Encoded_U32 (Packet, 16) = 0)
   is
   begin
      if Packet'Length < Header_Length
        or else Packet'Length > SMB.Maximum_Frame_Size
      then
         Status := SMB.Invalid_Length;
         return;
      end if;
      SMB.Core_Wire.Initialize_Header
        (Packet, Expected.Command, Expected.Message_Id,
         Expected.Tree_Id, Expected.Session_Id, 1, Status);
   end Prepare_Unsigned_Header;

   function Authentication_Stage_Of
     (Value : Authentication) return Authentication_Stage is
     (Value.Stage);

   function Authentication_Session_Id_Of
     (Value : Authentication) return SMB.QWord is
     (Value.Session_Id);

   function Authentication_Challenge_Length_Of
     (Value : Authentication) return Natural is
     (Value.Challenge_Length);

   function Authentication_Challenge_Byte_Of
     (Value : Authentication; Index : Natural) return SMB.Byte is
     (Value.Challenge (Index));

   function Authentication_Buffer_Of
     (Value : Authentication) return SMB.Bytes is
     (Value.Challenge);

   function Authentication_Expected_Of
     (Value : Authentication)
       return SMB.Engine.Request_Expectation is
     (Value.Expected);

   function Authentication_Packet_Matches
     (Value : Authentication;
      State : SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Used : Natural) return Boolean is
     (Used >= Header_Length
      and then Used <= Packet'Length
      and then Value.Owner = SMB.Engine.Current_Owner_Id (State)
      and then Value.Epoch = SMB.Engine.Current_Epoch (State)
      and then Value.Expected.Command = 1
      and then not Value.Expected.Request_Signed
      and then SMB.Engine.Pending_Request_Matches (State, Value.Expected)
      and then SMB.Core_Wire.Encoded_U16 (Packet, 12) = 1
      and then SMB.Core_Wire.Encoded_U64 (Packet, 24) =
        Value.Expected.Message_Id
      and then SMB.Core_Wire.Encoded_U32 (Packet, 36) =
        Value.Expected.Tree_Id
      and then SMB.Core_Wire.Encoded_U64 (Packet, 40) =
        Value.Expected.Session_Id
      and then SMB.Core_Wire.Encoded_U32 (Packet, 16) = 0
      and then (if Value.Stage = Negotiate_Prepared then
                  not Value.Expected.Signed
                  and then Value.Expected.Session_Id = 0
                else Value.Expected.Signed));

   procedure Fail_Authentication
     (Value : in out Authentication;
      State : in out SMB.Engine.Engine_State;
      Failure : SMB.Core_Status;
      Status : out SMB.Core_Status)
   is
      Invalidate_Status : SMB.Core_Status;
   begin
      SMB.Engine.Invalidate (State, Invalidate_Status);
      Clear_Authentication_Buffer (Value);
      Value.Stage := Authentication_Failed;
      Status := (if Invalidate_Status = SMB.Ok then Failure
                 else Invalidate_Status);
   end Fail_Authentication;

   procedure Prepare_Negotiate
     (Value : in out Authentication;
      State : in out SMB.Engine.Engine_State;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
      Token : SMB.Bytes
        (0 .. SMB.Core_Auth.Maximum_Security_Token - 1) := (others => 0);
      Token_Used : Natural := 0;
      Message_Id : SMB.QWord;
      Expected : SMB.Engine.Request_Expectation;
      Field_Status : SMB.Core_Status;
      Begin_Status : SMB.Core_Status;
      Body_Used : Natural;
   begin
      Clear_Output (Output);
      Used := 0;
      if Value.Stage /= Authentication_Ready
        or else SMB.Engine.Current_Phase (State) /= SMB.Engine.Negotiated
        or else SMB.Engine.Current_Session_Id (State) /= 0
        or else SMB.Engine.Has_Pending_Request (State)
        or else Output'Length < Header_Length
        or else Output'First > Natural'Last - Header_Length
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      SMB.Core_Auth.Build_Negotiate_Token (Token, Token_Used, Status);
      if Status /= SMB.Ok then
         Value.Stage := Authentication_Failed;
         return;
      end if;
      if Token_Used = 0 or else Output'Length < Header_Length + 24 + Token_Used
      then
         Value.Stage := Authentication_Failed;
         Status := SMB.Resource_Limit;
         return;
      end if;
      SMB.Core_Protocol.Build_Session_Setup
        (Token (Token'First .. Token'First + Token_Used - 1),
         Output (Output'First + Header_Length .. Output'Last),
         Body_Used, Status);
      if Status /= SMB.Ok then
         Value.Stage := Authentication_Failed;
         return;
      end if;
      SMB.Engine.Begin_Request
        (State, 1, False, False, Message_Id, Expected, Begin_Status);
      if Begin_Status /= SMB.Ok then
         Value.Stage := Authentication_Failed;
         Status := Begin_Status;
         return;
      end if;
      pragma Assert (Message_Id = Expected.Message_Id);
      Value.Stage := Negotiate_Prepared;
      Value.Owner := SMB.Engine.Current_Owner_Id (State);
      Value.Epoch := SMB.Engine.Current_Epoch (State);
      Value.Expected := Expected;
      Value.Session_Id := 0;
      Value.Challenge_Length := 0;
      Prepare_Unsigned_Header (Output, Expected, Field_Status);
      if Field_Status /= SMB.Ok then
         Fail_Authentication (Value, State, Field_Status, Status);
         return;
      end if;
      Used := Header_Length + Body_Used;
      Status := SMB.Ok;
      pragma Assert (Value.Stage = Negotiate_Prepared);
      pragma Assert (Value.Expected.Session_Id = 0);
      pragma Assert
        (SMB.Engine.Pending_Request_Matches (State, Value.Expected));
      pragma Assert (SMB.Core_Wire.Encoded_U16 (Output, 12) = 1);
      pragma Assert
        (SMB.Core_Wire.Encoded_U64 (Output, 24) =
           Value.Expected.Message_Id);
      pragma Assert
        (SMB.Core_Wire.Encoded_U32 (Output, 36) =
           Value.Expected.Tree_Id);
      pragma Assert
        (SMB.Core_Wire.Encoded_U64 (Output, 40) =
           Value.Expected.Session_Id);
      pragma Assert (SMB.Core_Wire.Encoded_U32 (Output, 16) = 0);
   end Prepare_Negotiate;

   procedure Authentication_Send_Succeeded
     (Value : in out Authentication;
      State : SMB.Engine.Engine_State;
      Status : out SMB.Core_Status) is
   begin
      if Value.Owner /= SMB.Engine.Current_Owner_Id (State)
        or else Value.Epoch /= SMB.Engine.Current_Epoch (State)
        or else not SMB.Engine.Pending_Request_Matches (State, Value.Expected)
      then
         Status := SMB.Invalid_State_Status;
         return;
      elsif Value.Stage = Negotiate_Prepared then
         Value.Stage := Negotiate_Sent;
      elsif Value.Stage = Authenticate_Prepared then
         Value.Stage := Authenticate_Sent;
      else
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      Status := SMB.Ok;
   end Authentication_Send_Succeeded;

   procedure Complete_Challenge
     (Value : in out Authentication;
      State : in out SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Nt_Status : out SMB.DWord;
      Status : out SMB.Core_Status) is
      Accept_Status : SMB.Core_Status;
      Receipt_Status : SMB.Core_Status;
      Info : SMB.Core_Protocol.Response_Info;
   begin
      Nt_Status := 0;
      if Value.Stage /= Negotiate_Sent
        or else Value.Expected.Command /= 1
        or else Value.Expected.Request_Signed
        or else Value.Expected.Signed
        or else Value.Expected.Session_Id /= 0
        or else not SMB.Engine.Pending_Request_Matches (State, Value.Expected)
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      pragma Assert (Value.Expected.Command = 1);
      pragma Assert (not Value.Expected.Signed);
      pragma Assert (SMB.Engine.Pending_Command (State) = 1);
      pragma Assert (not SMB.Engine.Pending_Response_Is_Signed (State));
      SMB.Engine.Accept_Response (State, Packet, Nt_Status, Accept_Status);
      if Accept_Status /= SMB.Ok then
         Value.Stage := Authentication_Failed;
         Clear_Authentication_Buffer (Value);
         Status := Accept_Status;
         return;
      end if;
      Info := SMB.Engine.Current_Response_Info (State);
      if Nt_Status /= SMB.Status_More_Processing_Required then
         SMB.Engine.Discard_Response_Receipt (State, Receipt_Status);
         if Receipt_Status /= SMB.Ok then
            Fail_Authentication (Value, State, Receipt_Status, Status);
         else
            SMB.Engine.Invalidate (State, Receipt_Status);
            Clear_Authentication_Buffer (Value);
            Value.Stage := Authentication_Failed;
            Status := (if Nt_Status = SMB.Success
                       then SMB.Unsupported_Feature else SMB.Ok);
         end if;
         return;
      end if;
      if Info.Session_Id = 0
        or else Info.Data_Length > SMB.Core_Auth.Maximum_Security_Token
        or else Info.Data_Offset > Packet'Length
        or else Info.Data_Length > Packet'Length - Info.Data_Offset
      then
         Fail_Authentication (Value, State, SMB.Invalid_Protocol, Status);
         return;
      end if;
      if Info.Data_Length > 0 then
         Value.Challenge (0 .. Info.Data_Length - 1) :=
           Packet
             (Packet'First + Info.Data_Offset ..
              Packet'First + (Info.Data_Offset + Info.Data_Length - 1));
      end if;
      Value.Challenge_Length := Info.Data_Length;
      Value.Session_Id := Info.Session_Id;
      Value.Stage := Challenge_Received;
      Status := SMB.Ok;
   end Complete_Challenge;

   procedure Prepare_Authenticate
     (Value : in out Authentication;
      State : in out SMB.Engine.Engine_State;
      User, Password, Domain : String;
      Nonce : SMB.Bytes;
      Current_Filetime : SMB.QWord;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
      Token : SMB.Bytes
        (0 .. SMB.Core_Auth.Maximum_Security_Token - 1) := (others => 0);
      Key : SMB.Crypto.Digest_128 := (others => 0);
      Token_Used : Natural := 0;
      Body_Used : Natural;
      Message_Id : SMB.QWord;
      Expected : SMB.Engine.Request_Expectation;
      Engine_Status : SMB.Core_Status;
      Field_Status : SMB.Core_Status;
      Empty : constant SMB.Bytes := (1 .. 0 => 0);
   begin
      Clear_Output (Output);
      Used := 0;
      if Value.Stage /= Challenge_Received
        or else Value.Challenge_Length >
          SMB.Core_Auth.Maximum_Security_Token
        or else User'Length > SMB.Core_Auth.Maximum_Credential_Bytes
        or else Password'Length > SMB.Core_Auth.Maximum_Credential_Bytes
        or else Domain'Length > SMB.Core_Auth.Maximum_Credential_Bytes
        or else Nonce'Length /= 8
        or else Output'Length < Header_Length
        or else Output'First > Natural'Last - Header_Length
      then
         if Value.Stage = Challenge_Received then
            Fail_Authentication (Value, State, SMB.Resource_Limit, Status);
         else
            Status := SMB.Invalid_State_Status;
         end if;
         return;
      end if;
      if Value.Challenge_Length = 0 then
         SMB.Core_Auth.Authenticate
           (User, Password, Domain, Nonce, Empty, Current_Filetime,
            Token, Token_Used, Key, Status);
      else
         SMB.Core_Auth.Authenticate
           (User, Password, Domain, Nonce,
            Value.Challenge (0 .. Value.Challenge_Length - 1),
            Current_Filetime, Token, Token_Used, Key, Status);
      end if;
      if Status /= SMB.Ok or else Token_Used = 0 then
         if Status = SMB.Ok then
            Status := SMB.Resource_Limit;
         end if;
         declare
            Failure : constant SMB.Core_Status := Status;
         begin
            Key := (others => 0);
            Clear_Output (Token);
            Fail_Authentication (Value, State, Failure, Status);
         end;
         return;
      end if;
      if Output'Length < Header_Length + 24 + Token_Used then
         Fail_Authentication (Value, State, SMB.Resource_Limit, Status);
         return;
      end if;
      SMB.Core_Protocol.Build_Session_Setup
        (Token (Token'First .. Token'First + Token_Used - 1),
         Output (Output'First + Header_Length .. Output'Last),
         Body_Used, Engine_Status);
      if Engine_Status /= SMB.Ok then
         Key := (others => 0);
         Clear_Output (Token);
         Fail_Authentication (Value, State, Engine_Status, Status);
         return;
      end if;
      SMB.Engine.Install_Session_Key
        (State, Value.Session_Id, Key, Engine_Status);
      if Engine_Status /= SMB.Ok then
         Key := (others => 0);
         Clear_Output (Token);
         Fail_Authentication (Value, State, Engine_Status, Status);
         return;
      end if;
      SMB.Engine.Begin_Request
        (State, 1, False, True, Message_Id, Expected, Engine_Status);
      if Engine_Status /= SMB.Ok then
         Key := (others => 0);
         Clear_Output (Token);
         Fail_Authentication (Value, State, Engine_Status, Status);
         return;
      end if;
      Value.Expected := Expected;
      Value.Owner := SMB.Engine.Current_Owner_Id (State);
      Value.Epoch := SMB.Engine.Current_Epoch (State);
      Value.Stage := Authenticate_Prepared;
      Prepare_Unsigned_Header (Output, Expected, Field_Status);
      if Field_Status /= SMB.Ok then
         Key := (others => 0);
         Clear_Output (Token);
         Fail_Authentication (Value, State, Field_Status, Status);
         return;
      end if;
      Used := Header_Length + Body_Used;
      Key := (others => 0);
      Clear_Output (Token);
      Status := SMB.Ok;
   end Prepare_Authenticate;

   procedure Complete_Authenticate
     (Value : in out Authentication;
      State : in out SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Nt_Status : out SMB.DWord;
      Status : out SMB.Core_Status) is
      Accept_Status : SMB.Core_Status;
      Receipt_Status : SMB.Core_Status;
      Invalidate_Status : SMB.Core_Status;
      Failure_Status : SMB.Core_Status;
   begin
      Nt_Status := 0;
      if Value.Stage /= Authenticate_Sent
        or else not SMB.Engine.Pending_Request_Matches (State, Value.Expected)
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      SMB.Engine.Accept_Response (State, Packet, Nt_Status, Accept_Status);
      if Accept_Status /= SMB.Ok then
         Value.Stage := Authentication_Failed;
         Clear_Authentication_Buffer (Value);
         Status := Accept_Status;
         return;
      end if;
      if Nt_Status /= SMB.Success then
         SMB.Engine.Discard_Response_Receipt (State, Receipt_Status);
         SMB.Engine.Invalidate (State, Invalidate_Status);
         Clear_Authentication_Buffer (Value);
         Value.Stage := Authentication_Failed;
         Status := (if Invalidate_Status = SMB.Ok then SMB.Ok
                    else Invalidate_Status);
         return;
      end if;
      SMB.Engine.Mark_Authenticated (State, Status);
      if Status = SMB.Ok then
         Clear_Authentication_Buffer (Value);
         Value.Stage := Authentication_Finished;
         pragma Assert (Value.Stage = Authentication_Finished);
      else
         Failure_Status := Status;
         SMB.Engine.Invalidate (State, Invalidate_Status);
         Clear_Authentication_Buffer (Value);
         Value.Stage := Authentication_Failed;
         Status := (if Invalidate_Status = SMB.Ok then Failure_Status
                    else Invalidate_Status);
      end if;
   end Complete_Authenticate;

   procedure Abort_Authentication
     (Value : in out Authentication;
      State : in out SMB.Engine.Engine_State;
      Status : out SMB.Core_Status) is
      Invalidate_Status : SMB.Core_Status;
   begin
      if Value.Stage in Authentication_Ready |
        Authentication_Finished | Authentication_Failed
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      SMB.Engine.Invalidate (State, Invalidate_Status);
      Clear_Authentication_Buffer (Value);
      Value.Stage := Authentication_Failed;
      Status := Invalidate_Status;
   end Abort_Authentication;

   procedure Copy_Read_Chunk
     (Value : in out Transfer;
      Completed : Natural;
      Packet : SMB.Bytes;
      Offset, Count : Natural)
   with Pre =>
     Value.Capacity > 0
     and then Packet'Length <= SMB.Maximum_Frame_Size
     and then Completed <= Value.Capacity
     and then Count <= Value.Capacity - Completed
     and then Offset <= Packet'Length
     and then Count <= Packet'Length - Offset,
     Post =>
       Identity_Of (Value) = Identity_Of (Value)'Old
       and then Value.Stage = Value.Stage'Old
       and then Value.Requested = Value.Requested'Old
       and then SMB.Engine."=" (Value.Expected, Value.Expected'Old)
       and then Value.Completed = Value.Completed'Old
       and then Value.Remaining = Value.Remaining'Old
       and then Value.Position = Value.Position'Old
       and then
         (for all Index in 0 .. Value.Capacity - 1 =>
            (if Index < Completed or else Index >= Completed + Count then
               Transfer_Byte_Of (Value, Index) =
                 Transfer_Buffer_Of (Value)'Old (Index + 1)))
       and then
         (if Count > 0 then
            (for all Index in 0 .. Count - 1 =>
               Transfer_Byte_Of (Value, Completed + Index) =
                 Packet (Packet'First + Offset + Index)))
   is
   begin
      if Count > 0 then
         Value.Buffer (Completed + 1 .. Completed + Count) :=
           Packet (Packet'First + Offset .. Packet'First + Offset + (Count - 1));
      end if;
   end Copy_Read_Chunk;

   procedure Fail_After_Reservation
     (Value : in out Operation;
      State : in out SMB.Engine.Engine_State;
      Failure : SMB.Core_Status;
      Status : out SMB.Core_Status) is
      Invalidate_Status : SMB.Core_Status;
   begin
      SMB.Engine.Invalidate (State, Invalidate_Status);
      Value.Stage := Failed;
      Status :=
        (if Invalidate_Status = SMB.Ok then Failure else Invalidate_Status);
   end Fail_After_Reservation;

   procedure Prepare_Header
     (Packet : in out SMB.Bytes;
      Expected : SMB.Engine.Request_Expectation;
      Status : out SMB.Core_Status)
   with Pre =>
     Packet'Length <= SMB.Maximum_Frame_Size,
     Post =>
       (if Status = SMB.Ok then
          SMB.Core_Wire.Encoded_U16 (Packet, 12) =
            SMB.Word (Expected.Command)
          and then SMB.Core_Wire.Encoded_U64 (Packet, 24) =
            Expected.Message_Id
          and then SMB.Core_Wire.Encoded_U32 (Packet, 36) =
            Expected.Tree_Id
          and then SMB.Core_Wire.Encoded_U64 (Packet, 40) =
            Expected.Session_Id
          and then SMB.Core_Wire.Encoded_U32 (Packet, 16) = 8
          and then
            (for all Index in Packet'Range =>
               (if Index - Packet'First >= Header_Length
                then Packet (Index) = Packet'Old (Index))))
   is
      Field_Status : SMB.Core_Status;
   begin
      if Packet'Length < Header_Length then
         Status := SMB.Invalid_Length;
         return;
      end if;
      SMB.Core_Wire.Initialize_Header
        (Packet, Expected.Command, Expected.Message_Id, Expected.Tree_Id,
         Expected.Session_Id, 1, Field_Status);
      if Field_Status /= SMB.Ok then
         Status := Field_Status;
         return;
      end if;
      SMB.Core_Wire.Write_U32 (Packet, 16, 8, Field_Status);
      if Field_Status /= SMB.Ok then
         Status := Field_Status;
         return;
      end if;
      Status := SMB.Ok;
   end Prepare_Header;

   function Stage_Of (Value : Operation) return Operation_Stage is
     (Value.Stage);

   function Kind_Of (Value : Operation) return Operation_Kind is
     (Value.Kind);

   function Create_Access_Of (Value : Operation)
     return SMB.Engine.Access_Kind is
     (Value.Access_Mode);

   function Create_Directory_Of (Value : Operation) return Boolean is
     (Value.Directory);

   function Create_Delete_Access_Of (Value : Operation) return Boolean is
     (Value.Delete_Access);

   function Create_Disposition_Of (Value : Operation) return SMB.DWord is
     (Value.Disposition);

   function Close_Token_Of (Value : Operation)
     return SMB.Engine.Handle_Token is
     (Value.Close_Token);

   function File_Id_Of (Value : Operation) return SMB.Bytes is
     (Value.File_Id);

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
      Status : out SMB.Core_Status) is
      Name_Bytes : constant Natural := Natural'Max (1, Name'Length);
      Required_Body : constant Natural := 56 + Name_Bytes;
      Required : constant Natural := Header_Length + Required_Body;
      Message_Id : SMB.QWord;
      Expected : SMB.Engine.Request_Expectation;
      Begin_Status : SMB.Core_Status;
      Field_Status : SMB.Core_Status;
      Key : SMB.Bytes (0 .. 15);
      Wire_Access : constant SMB.DWord :=
        Access_Mask (Access_Mode, Delete_Access);
   begin
      Clear_Output (Output);
      Used := 0;
      if Value.Stage = Prepared or else Value.Stage = Sent then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      if Name'Length > SMB.Core_Protocol.Maximum_Name_Bytes
        or else Name'Length mod 2 /= 0
        or else Disposition < 1
        or else Disposition > 5
      then
         Value.Stage := Failed;
         Status := SMB.Invalid_Value;
         return;
      end if;
      if Required > Output'Length then
         Value.Stage := Failed;
         Status := SMB.Resource_Limit;
         return;
      end if;
      SMB.Engine.Begin_Request
        (State, 5, True, True, Message_Id, Expected, Begin_Status);
      if Begin_Status /= SMB.Ok then
         Value.Stage := Failed;
         Status := Begin_Status;
         return;
      end if;
      if Message_Id /= Expected.Message_Id then
         Fail_After_Reservation
           (Value, State, SMB.Invalid_State_Status, Status);
         return;
      end if;
      Value.Kind := Create_Operation;
      Value.Stage := Prepared;
      Value.Owner := SMB.Engine.Current_Owner_Id (State);
      Value.Epoch := SMB.Engine.Current_Epoch (State);
      Value.Wire_Access := Wire_Access;
      Value.Expected := Expected;
      Value.Access_Mode := Access_Mode;
      Value.Directory := Directory;
      Value.Delete_Access := Delete_Access;
      Value.Disposition := Disposition;
      Key := SMB.Engine.Current_Signing_Key (State);
      Prepare_Header
        (Output (Output'First .. Output'First + (Required - 1)),
         Expected, Field_Status);
      if Field_Status /= SMB.Ok then
         Fail_After_Reservation (Value, State, Field_Status, Status);
         return;
      end if;
      SMB.Core_Protocol.Build_Create
        (Name, Wire_Access, Disposition,
         Directory,
         Output
         (Output'First + Header_Length
            .. Output'First + (Required - 1)),
         Used, Field_Status);
      if Field_Status /= SMB.Ok then
         Fail_After_Reservation (Value, State, Field_Status, Status);
         return;
      end if;
      pragma Assert
        (for all Index in 0 .. 3 =>
           Output (Output'First + Header_Length + 24 + Index) =
             SMB.Core_Wire.U32_Byte (Wire_Access, Index));
      pragma Assert
        (for all Index in 0 .. 3 =>
           Output (Output'First + Header_Length + 28 + Index) =
             SMB.Core_Wire.U32_Byte
               ((if Value.Directory then 16#10# else 0), Index));
      pragma Assert
        (for all Index in 0 .. 3 =>
           Output (Output'First + Header_Length + 40 + Index) =
             SMB.Core_Wire.U32_Byte
               ((if Value.Directory then 1 else 16#40#), Index));
      SMB.Core_Wire.Sign
        (Output (Output'First .. Output'First + (Required - 1)),
         Key, Field_Status);
      if Field_Status /= SMB.Ok then
         Fail_After_Reservation (Value, State, Field_Status, Status);
         return;
      end if;
      pragma Assert
        (SMB.Core_Wire.Encoded_U32 (Output, 16) = 8);
      pragma Assert
        (SMB.Core_Wire.Encoded_U32 (Output, 36) = Expected.Tree_Id);
      pragma Assert
        (SMB.Core_Wire.Encoded_U64 (Output, 24) = Expected.Message_Id);
      pragma Assert
        (SMB.Core_Wire.Encoded_U64 (Output, 40) = Expected.Session_Id);
      pragma Assert
        (for all Index in 0 .. 3 =>
           Output (Output'First + Header_Length + 24 + Index) =
             SMB.Core_Wire.U32_Byte (Wire_Access, Index));
      pragma Assert
        (for all Index in 0 .. 3 =>
           Output (Output'First + Header_Length + 28 + Index) =
             SMB.Core_Wire.U32_Byte
               ((if Value.Directory then 16#10# else 0), Index));
      pragma Assert
        (for all Index in 0 .. 3 =>
           Output (Output'First + Header_Length + 40 + Index) =
             SMB.Core_Wire.U32_Byte
               ((if Value.Directory then 1 else 16#40#), Index));
      Used := Required_Body + Header_Length;
      Value.Close_Token := (others => 0);
      Value.File_Id := (others => 0);
      Status := SMB.Ok;
   end Prepare_Create;

   procedure Prepare_Close
     (Value : in out Operation;
      State : in out SMB.Engine.Engine_State;
      Token : SMB.Engine.Handle_Token;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
      File_Id : SMB.Bytes (0 .. 15);
      Access_Mode : SMB.Engine.Access_Kind;
      Is_Directory : Boolean;
      Message_Id : SMB.QWord;
      Expected : SMB.Engine.Request_Expectation;
      Begin_Status : SMB.Core_Status;
      Field_Status : SMB.Core_Status;
      Key : SMB.Bytes (0 .. 15);
      Required : constant Natural := Header_Length + 24;
   begin
      Clear_Output (Output);
      Used := 0;
      if Value.Stage = Prepared or else Value.Stage = Sent then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      if Output'Length < Required then
         Value.Stage := Failed;
         Status := SMB.Resource_Limit;
         return;
      end if;
      SMB.Engine.Validate_Handle
        (State, Token, False, False, File_Id, Access_Mode, Is_Directory,
         Begin_Status);
      if Begin_Status /= SMB.Ok then
         Value.Stage := Failed;
         Status := Begin_Status;
         return;
      end if;
      SMB.Engine.Begin_Request
        (State, 6, True, True, Message_Id, Expected, Begin_Status,
         Close_Token => Token);
      if Begin_Status /= SMB.Ok then
         Value.Stage := Failed;
         Status := Begin_Status;
         return;
      end if;
      if Message_Id /= Expected.Message_Id then
         Fail_After_Reservation
           (Value, State, SMB.Invalid_State_Status, Status);
         return;
      end if;
      Value.Kind := Close_Operation;
      Value.Stage := Prepared;
      Value.Owner := SMB.Engine.Current_Owner_Id (State);
      Value.Epoch := SMB.Engine.Current_Epoch (State);
      Value.Expected := Expected;
      Value.Close_Token := Token;
      Value.Access_Mode := Access_Mode;
      Value.Directory := Is_Directory;
      Key := SMB.Engine.Current_Signing_Key (State);
      SMB.Core_Protocol.Build_Close
        (File_Id,
         Output
           (Output'First + Header_Length
            .. Output'First + (Required - 1)),
         Used, Field_Status);
      if Field_Status /= SMB.Ok then
         Fail_After_Reservation (Value, State, Field_Status, Status);
         return;
      end if;
      Prepare_Header
        (Output (Output'First .. Output'First + (Required - 1)),
         Expected, Field_Status);
      if Field_Status /= SMB.Ok then
         Fail_After_Reservation (Value, State, Field_Status, Status);
         return;
      end if;
      SMB.Core_Wire.Sign
        (Output (Output'First .. Output'First + (Required - 1)),
         Key, Field_Status);
      if Field_Status /= SMB.Ok then
         Fail_After_Reservation (Value, State, Field_Status, Status);
         return;
      end if;
      pragma Assert
        (SMB.Core_Wire.Encoded_U64 (Output, 24) = Expected.Message_Id);
      pragma Assert
        (SMB.Core_Wire.Encoded_U32 (Output, 36) = Expected.Tree_Id);
      pragma Assert
        (SMB.Core_Wire.Encoded_U64 (Output, 40) = Expected.Session_Id);
      pragma Assert
        (SMB.Core_Wire.Encoded_U64 (Output, 24) = Expected.Message_Id);
      Value.File_Id := File_Id;
      pragma Assert
        (SMB.Core_Wire.Encoded_U16 (Output, 12) =
           SMB.Word (Value.Expected.Command));
      pragma Assert
        (SMB.Core_Wire.Encoded_U32 (Output, 36) =
           Value.Expected.Tree_Id);
      Used := Required;
      Value.Delete_Access := False;
      Value.Disposition := 0;
      Value.Wire_Access := 0;
      Status := SMB.Ok;
   end Prepare_Close;

   procedure Send_Succeeded
     (Value : in out Operation;
      State : SMB.Engine.Engine_State;
      Status : out SMB.Core_Status) is
   begin
      if Value.Stage /= Prepared
        or else Value.Owner /= SMB.Engine.Current_Owner_Id (State)
        or else Value.Epoch /= SMB.Engine.Current_Epoch (State)
        or else not SMB.Engine.Pending_Request_Matches (State, Value.Expected)
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      Value.Stage := Sent;
      Status := SMB.Ok;
   end Send_Succeeded;

   procedure Complete
     (Value : in out Operation;
      State : in out SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Nt_Status : out SMB.DWord;
      Token : out SMB.Engine.Handle_Token;
      Status : out SMB.Core_Status) is
      Accept_Status : SMB.Core_Status;
      Receipt_Status : SMB.Core_Status;
      Info : SMB.Core_Protocol.Response_Info;
   begin
      Nt_Status := 0;
      Token := (others => 0);
      if Value.Stage /= Sent
        or else Value.Kind not in Create_Operation | Close_Operation
        or else Value.Owner /= SMB.Engine.Current_Owner_Id (State)
        or else Value.Epoch /= SMB.Engine.Current_Epoch (State)
        or else not SMB.Engine.Pending_Request_Matches (State, Value.Expected)
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      SMB.Engine.Accept_Response (State, Packet, Nt_Status, Accept_Status);
      if Accept_Status /= SMB.Ok then
         Value.Stage := Failed;
         Status := Accept_Status;
         return;
      end if;
      if Nt_Status = SMB.Success then
         Info := SMB.Engine.Current_Response_Info (State);
         if Value.Kind = Create_Operation then
            Value.File_Id := Info.File_Id;
            SMB.Engine.Register_Handle
              (State, Info.File_Id, Value.Access_Mode, Value.Directory,
               Token, Receipt_Status);
         else
            SMB.Engine.Close_Handle
              (State, Value.Close_Token, Receipt_Status,
               Close_Token => Value.Close_Token);
         end if;
         if Receipt_Status /= SMB.Ok then
            declare
               Invalidate_Status : SMB.Core_Status;
            begin
               SMB.Engine.Invalidate (State, Invalidate_Status);
               Status :=
                 (if Invalidate_Status = SMB.Ok
                  then Receipt_Status else Invalidate_Status);
            end;
            Value.Stage := Failed;
            return;
         end if;
      else
         SMB.Engine.Discard_Response_Receipt (State, Receipt_Status);
         if Receipt_Status /= SMB.Ok then
            declare
               Invalidate_Status : SMB.Core_Status;
            begin
               SMB.Engine.Invalidate (State, Invalidate_Status);
               Status :=
                 (if Invalidate_Status = SMB.Ok
                  then Receipt_Status else Invalidate_Status);
            end;
            Value.Stage := Failed;
            return;
         end if;
      end if;
      Value.Stage := Finished;
      Status := SMB.Ok;
   end Complete;

   procedure Abort_Operation
     (Value : in out Operation;
      State : in out SMB.Engine.Engine_State;
      Status : out SMB.Core_Status) is
      Invalidate_Status : SMB.Core_Status;
   begin
      if (Value.Stage /= Prepared and then Value.Stage /= Sent)
        or else Value.Owner /= SMB.Engine.Current_Owner_Id (State)
        or else Value.Epoch /= SMB.Engine.Current_Epoch (State)
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      SMB.Engine.Invalidate (State, Invalidate_Status);
      Value.Stage := Failed;
      Status := Invalidate_Status;
   end Abort_Operation;

   procedure Start_Read
     (Value : in out Transfer;
      State : SMB.Engine.Engine_State;
      Token : SMB.Engine.Handle_Token;
      Offset : SMB.QWord;
      Total : Natural;
      Status : out SMB.Core_Status) is
      File_Id : SMB.Bytes (0 .. 15);
      Access_Mode : SMB.Engine.Access_Kind;
      Directory : Boolean;
   begin
      if Value.Stage = Transfer_Prepared or else Value.Stage = Transfer_Sent
        or else SMB.Engine.Has_Pending_Request (State)
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      SMB.Engine.Validate_Handle
        (State, Token, True, False, File_Id, Access_Mode, Directory, Status);
      if Status /= SMB.Ok then
         Value.Stage := Transfer_Failed;
         return;
      end if;
      if Directory then
         Value.Stage := Transfer_Failed;
         Status := SMB.Invalid_Value;
         return;
      end if;
      SMB.Core_Protocol.Check_Transfer_Range (Offset, Total, Status);
      if Status /= SMB.Ok then
         Value.Stage := Transfer_Failed;
         return;
      end if;
      if Value.Capacity > 0 then
         Clear_Transfer_Buffer (Value.Buffer);
      end if;
      Value.Kind := Read_Transfer;
      Value.Stage := (if Total = 0 then Transfer_Finished else Ready);
      Value.Owner := SMB.Engine.Current_Owner_Id (State);
      Value.Epoch := SMB.Engine.Current_Epoch (State);
      Value.Token := Token;
      Value.File_Id := File_Id;
      Value.Access_Mode := Access_Mode;
      Value.Directory := False;
      Value.Initial_Offset := Offset;
      Value.Position := Offset;
      Value.Total := Total;
      Value.Completed := 0;
      Value.Remaining := Total;
      Value.Requested := 0;
      Value.Expected := (others => <>);
      Status := SMB.Ok;
   end Start_Read;

   procedure Start_Write
     (Value : in out Transfer;
      State : SMB.Engine.Engine_State;
      Token : SMB.Engine.Handle_Token;
      Offset : SMB.QWord;
      Data : SMB.Bytes;
      Status : out SMB.Core_Status) is
      File_Id : SMB.Bytes (0 .. 15);
      Access_Mode : SMB.Engine.Access_Kind;
      Directory : Boolean;
   begin
      if Value.Stage = Transfer_Prepared or else Value.Stage = Transfer_Sent
        or else SMB.Engine.Has_Pending_Request (State)
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      SMB.Engine.Validate_Handle
        (State, Token, False, True, File_Id, Access_Mode, Directory, Status);
      if Status /= SMB.Ok then
         Value.Stage := Transfer_Failed;
         return;
      end if;
      if Directory then
         Value.Stage := Transfer_Failed;
         Status := SMB.Invalid_Value;
         return;
      end if;
      SMB.Core_Protocol.Check_Transfer_Range
        (Offset, Data'Length, Status);
      if Status /= SMB.Ok then
         Value.Stage := Transfer_Failed;
         return;
      end if;
      Value.Kind := Write_Transfer;
      Value.Stage :=
        (if Data'Length = 0 then Transfer_Finished else Ready);
      Value.Owner := SMB.Engine.Current_Owner_Id (State);
      Value.Epoch := SMB.Engine.Current_Epoch (State);
      Value.Token := Token;
      Value.File_Id := File_Id;
      Value.Access_Mode := Access_Mode;
      Value.Directory := False;
      Value.Initial_Offset := Offset;
      Value.Position := Offset;
      Value.Total := Data'Length;
      Value.Completed := 0;
      Value.Remaining := Data'Length;
      Value.Requested := 0;
      Value.Expected := (others => <>);
      if Data'Length > 0 then
         for Index in 0 .. Data'Length - 1 loop
            Value.Buffer (Index + 1) := Data (Data'First + Index);
            pragma Loop_Invariant
              (for all Copied in 0 .. Index =>
                 Value.Buffer (Copied + 1) =
                   Data (Data'First + Copied));
         end loop;
      end if;
      Status := SMB.Ok;
   end Start_Write;

   procedure Prepare_Next
     (Value : in out Transfer;
      State : in out SMB.Engine.Engine_State;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
      File_Id : SMB.Bytes (0 .. 15);
      Access_Mode : SMB.Engine.Access_Kind;
      Directory : Boolean;
      Amount : Natural;
      Limit : constant Natural :=
        (if Value.Kind = Read_Transfer
         then SMB.Engine.Current_Max_Read (State)
         else SMB.Engine.Current_Max_Write (State));
      Message_Id : SMB.QWord;
      Expected : SMB.Engine.Request_Expectation;
      Begin_Status : SMB.Core_Status;
      Field_Status : SMB.Core_Status;
      Key : SMB.Bytes (0 .. 15);
      Body_Used : Natural;
      Body_Length : Natural;
      Command : SMB.Core_Wire.Command_Code;
      Old_Completed : Natural;
      Old_Remaining : Natural;
      Old_Position : SMB.QWord;
   begin
      Old_Completed := Value.Completed;
      Old_Remaining := Value.Remaining;
      Old_Position := Value.Position;
      Clear_Output (Output);
      Used := 0;
      if Value.Stage /= Ready
        or else Value.Owner /= SMB.Engine.Current_Owner_Id (State)
        or else Value.Epoch /= SMB.Engine.Current_Epoch (State)
        or else Value.Capacity = 0
        or else Value.Remaining = 0
        or else not Transfer_Invariant (Value)
        or else SMB.Engine.Has_Pending_Request (State)
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      SMB.Engine.Validate_Handle
        (State, Value.Token,
         Value.Kind = Read_Transfer, Value.Kind = Write_Transfer,
         File_Id, Access_Mode, Directory, Status);
      if Status /= SMB.Ok then
         Value.Stage := Transfer_Failed;
         return;
      end if;
      if Directory or else File_Id /= Value.File_Id
        or else Access_Mode /= Value.Access_Mode
      then
         Value.Stage := Transfer_Failed;
         Status := SMB.Invalid_Handle_Status;
         return;
      end if;
      SMB.Core_Protocol.Select_Transfer_Amount
        (Value.Remaining,
         Natural'Min (Limit, SMB.Core_Protocol.Maximum_IO_Chunk),
         Amount, Status);
      if Status /= SMB.Ok or else Amount = 0 then
         Value.Stage := Transfer_Failed;
         if Status = SMB.Ok then
            Status := SMB.Invalid_Value;
         end if;
         return;
      end if;
      Body_Length :=
        (if Value.Kind = Read_Transfer then 49 else 48 + Amount);
      if Output'Length < Header_Length
        or else Body_Length > Output'Length - Header_Length
        or else Output'Length > SMB.Maximum_Frame_Size
      then
         Value.Stage := Transfer_Failed;
         Status := SMB.Resource_Limit;
         return;
      end if;
      declare
         Body_Size : constant Natural := Body_Length;
         Body_Buffer : SMB.Bytes (0 .. Body_Size - 1);
      begin
         if Value.Kind = Read_Transfer then
            SMB.Core_Protocol.Build_Read
              (File_Id, Value.Position, Amount,
               Body_Buffer, Body_Used, Field_Status);
            Command := 8;
            if Field_Status = SMB.Ok then
               pragma Assert
                 (for all Byte_Index in 0 .. 7 =>
                    Body_Buffer (8 + Byte_Index) =
                      SMB.Core_Wire.U64_Byte
                        (Value.Position, Byte_Index));
            end if;
         else
            Command := 9;
            declare
               Payload : constant SMB.Bytes :=
                 Value.Buffer
                   (Value.Completed + 1 .. Value.Completed + Amount);
            begin
               pragma Assert
                 (for all Index in 0 .. Amount - 1 =>
                    Payload (Payload'First + Index) =
                      Value.Buffer (Value.Completed + Index + 1));
               SMB.Core_Protocol.Build_Write
                 (File_Id, Value.Position, Payload,
                  Body_Buffer, Body_Used, Field_Status);
               if Field_Status = SMB.Ok then
                  pragma Assert
                    (for all Index in 0 .. Amount - 1 =>
                       Body_Buffer (48 + Index) =
                         Value.Buffer (Value.Completed + Index + 1));
               end if;
            end;
         end if;
         if Field_Status = SMB.Ok then
            Output
              (Output'First + Header_Length ..
               Output'First + Header_Length + (Body_Used - 1)) :=
              Body_Buffer (0 .. Body_Used - 1);
            pragma Assert
              (for all Byte_Index in 0 .. 7 =>
                 Output
                   (Output'First + Header_Length + 8 + Byte_Index) =
                 SMB.Core_Wire.U64_Byte (Value.Position, Byte_Index));
            if Value.Kind = Write_Transfer then
               pragma Assert
                 (for all Index in 0 .. Amount - 1 =>
                    Output
                      (Output'First + Header_Length + 48 + Index) =
                    Value.Buffer (Value.Completed + Index + 1));
            end if;
         end if;
      end;
      if Field_Status /= SMB.Ok or else Body_Used /= Body_Length then
         Value.Stage := Transfer_Failed;
         if Field_Status = SMB.Ok then
            Status := SMB.Invalid_Length;
         else
            Status := Field_Status;
         end if;
         return;
      end if;
      SMB.Engine.Begin_Request
        (State, Command, True, True, Message_Id, Expected, Begin_Status,
         Request_Amount => Amount);
      if Begin_Status /= SMB.Ok then
         Value.Stage := Transfer_Failed;
         Status := Begin_Status;
         return;
      end if;
      Value.Expected := Expected;
      pragma Assert (Value.Expected.Tree_Id = Expected.Tree_Id);
      Value.Requested := Amount;
      if Message_Id /= Expected.Message_Id
        or else Expected.Request_Amount /= Amount
      then
         Fail_Transfer
           (Value, State, SMB.Invalid_State_Status, Status);
         return;
      end if;
      Value.File_Id := File_Id;
      Value.Access_Mode := Access_Mode;
      Value.Stage := Transfer_Prepared;
      Key := SMB.Engine.Current_Signing_Key (State);
      Used := Header_Length + Body_Used;
      Prepare_Header
        (Output, Expected, Field_Status);
      if Field_Status /= SMB.Ok then
         Fail_Transfer (Value, State, Field_Status, Status);
         Used := 0;
         return;
      end if;
      pragma Assert
        (SMB.Core_Wire.Encoded_U32 (Output, 36) =
           Expected.Tree_Id);
      Sign_Packet (Output, Used, Key, Field_Status);
      if Field_Status /= SMB.Ok then
         Fail_Transfer (Value, State, Field_Status, Status);
         Used := 0;
         return;
      end if;
      pragma Assert
        (SMB.Core_Wire.Encoded_U64 (Output, 24) = Expected.Message_Id);
      pragma Assert
        (SMB.Core_Wire.Encoded_U16 (Output, 12) =
           SMB.Word (Expected.Command));
      pragma Assert
        (SMB.Core_Wire.Encoded_U32 (Output, 36) =
           Value.Expected.Tree_Id);
      Value.Stage := Transfer_Prepared;
      pragma Assert (Transfer_Invariant (Value));
      pragma Assert (Value.Requested = Amount);
      pragma Assert
        (for all Byte_Index in 0 .. 3 =>
           Output
             (Output'First + Header_Length + 4 + Byte_Index) =
           SMB.Core_Wire.U32_Byte (SMB.DWord (Amount), Byte_Index));
      pragma Assert
        (Transfer_Packet_Matches (Value, State, Output, Used));
      pragma Assert
        (Transfer_Completed_Of (Value) =
           Old_Completed);
      pragma Assert
        (Transfer_Remaining_Of (Value) =
           Old_Remaining);
      pragma Assert
        (Transfer_Position_Of (Value) =
           Old_Position);
      Status := SMB.Ok;
   end Prepare_Next;

   procedure Transfer_Send_Succeeded
     (Value : in out Transfer;
      State : SMB.Engine.Engine_State;
      Status : out SMB.Core_Status) is
   begin
      if Value.Stage /= Transfer_Prepared
        or else not Transfer_Invariant (Value)
        or else Value.Owner /= SMB.Engine.Current_Owner_Id (State)
        or else Value.Epoch /= SMB.Engine.Current_Epoch (State)
        or else not SMB.Engine.Pending_Request_Matches (State, Value.Expected)
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      pragma Assert (Transfer_Invariant (Value));
      Value.Stage := Transfer_Sent;
      Status := SMB.Ok;
   end Transfer_Send_Succeeded;

   procedure Complete_Read
     (Value : in out Transfer;
      State : in out SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Nt_Status : out SMB.DWord;
      Status : out SMB.Core_Status) is
      Accept_Status : SMB.Core_Status;
      Receipt_Status : SMB.Core_Status;
      Info : SMB.Core_Protocol.Response_Info;
      Progress_Status : SMB.Core_Status;
      Old_Requested : Natural;
      Old_Completed : Natural;
   begin
      Nt_Status := 0;
      if Value.Kind /= Read_Transfer
        or else Value.Stage /= Transfer_Sent
        or else not Transfer_Invariant (Value)
        or else Value.Owner /= SMB.Engine.Current_Owner_Id (State)
        or else Value.Epoch /= SMB.Engine.Current_Epoch (State)
        or else not SMB.Engine.Pending_Request_Matches (State, Value.Expected)
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      pragma Assert (Transfer_Invariant (Value));
      Old_Requested := Value.Requested;
      Old_Completed := Transfer_Completed_Of (Value);
      SMB.Engine.Accept_Response (State, Packet, Nt_Status, Accept_Status);
      if Accept_Status /= SMB.Ok then
         Value.Stage := Transfer_Failed;
         Status := Accept_Status;
         return;
      end if;
      Value.Requested := 0;
      if Nt_Status /= SMB.Success then
         Value.Stage := Transfer_Finished;
         SMB.Engine.Discard_Response_Receipt (State, Receipt_Status);
         if Receipt_Status /= SMB.Ok then
            Fail_Transfer (Value, State, Receipt_Status, Status);
            return;
         end if;
         Status := SMB.Ok;
         return;
      end if;
      Info := SMB.Engine.Current_Response_Info (State);
      pragma Assert (Packet'Length >= 80);
      pragma Assert
        (Info.Data_Offset =
           Natural (Packet (Packet'First + 66)));
      pragma Assert (Packet (Packet'First + 67) = 0);
      pragma Assert
        (Info.Data_Length =
           Natural (SMB.Core_Wire.Encoded_U32 (Packet, 68)));
      pragma Assert
        (SMB.Core_Wire.Encoded_U32 (Packet, 68) <=
           SMB.DWord (SMB.Core_Protocol.Maximum_IO_Chunk));
      if Value.Capacity = 0
        or else Info.Data_Length > Old_Requested
        or else Info.Data_Length > Value.Remaining
        or else Info.Data_Length > Value.Capacity
        or else Info.Data_Length > Value.Capacity - Value.Completed
        or else Info.Data_Offset > Packet'Length
        or else Info.Data_Length > Packet'Length - Info.Data_Offset
      then
         Fail_Transfer
           (Value, State, SMB.Invalid_Protocol, Status);
         return;
      end if;
      SMB.Core_Protocol.Advance_Transfer
        (Value.Position, Value.Remaining, Old_Requested, Info.Data_Length,
         Progress_Status, Require_Progress => False);
      if Progress_Status /= SMB.Ok then
         Fail_Transfer (Value, State, Progress_Status, Status);
         return;
      end if;
      pragma Assert
        (Value.Completed + Info.Data_Length <= Value.Total);
      pragma Assert
        (SMB.QWord (Value.Total) <=
           SMB.QWord'Last - Value.Initial_Offset);
      Value.Completed := Value.Completed + Info.Data_Length;
      pragma Assert (Value.Completed <= Value.Total);
      pragma Assert
        (SMB.QWord (Value.Completed) <= SMB.QWord (Value.Total));
      pragma Assert
        (SMB.QWord (Value.Completed) <=
           SMB.QWord'Last - Value.Initial_Offset);
      Value.Position :=
        Value.Initial_Offset + SMB.QWord (Value.Completed);
      if Info.Data_Length = 0 or else Info.Data_Length < Old_Requested
        or else Value.Remaining = 0
      then
         Value.Stage := Transfer_Finished;
      else
         Value.Stage := Ready;
      end if;
      Copy_Read_Chunk
        (Value, Old_Completed, Packet,
         Natural (Packet (Packet'First + 66)),
         Natural (SMB.Core_Wire.Encoded_U32 (Packet, 68)));
      pragma Assert
        (Value.Completed + Value.Remaining = Value.Total);
      pragma Assert
        (Value.Completed <= Natural'Last - Value.Remaining);
      pragma Assert
        (Value.Position =
           Value.Initial_Offset + SMB.QWord (Value.Completed));
      pragma Assert (Transfer_Invariant (Value));
      SMB.Engine.Discard_Response_Receipt (State, Receipt_Status);
      if Receipt_Status /= SMB.Ok then
         Fail_Transfer (Value, State, Receipt_Status, Status);
         return;
      end if;
      pragma Assert (not SMB.Engine.Has_Pending_Request (State));
      pragma Assert (not SMB.Engine.Has_Validated_Response (State));
      pragma Assert (Value.Completed >= Old_Completed);
      pragma Assert (Value.Completed - Old_Completed = Info.Data_Length);
      pragma Assert
        (if SMB.Core_Wire.Encoded_U32 (Packet, 68) > 0 then
           (for all Index in 0 ..
              Natural (SMB.Core_Wire.Encoded_U32 (Packet, 68)) - 1 =>
              Transfer_Byte_Of (Value, Old_Completed + Index) =
                Packet
                  (Packet'First + Natural (Packet (Packet'First + 66))
                   + Index)));
      Status := SMB.Ok;
   end Complete_Read;

   procedure Complete_Write
     (Value : in out Transfer;
      State : in out SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Nt_Status : out SMB.DWord;
      Status : out SMB.Core_Status) is
      Accept_Status : SMB.Core_Status;
      Receipt_Status : SMB.Core_Status;
      Progress_Status : SMB.Core_Status;
      Old_Requested : Natural;
      Old_Completed : Natural;
      Old_Remaining : Natural;
      Count : Natural := 0;
   begin
      Nt_Status := 0;
      if Value.Kind /= Write_Transfer
        or else Value.Stage /= Transfer_Sent
        or else not Transfer_Invariant (Value)
        or else Value.Owner /= SMB.Engine.Current_Owner_Id (State)
        or else Value.Epoch /= SMB.Engine.Current_Epoch (State)
        or else not SMB.Engine.Pending_Request_Matches (State, Value.Expected)
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      pragma Assert (Transfer_Invariant (Value));
      Old_Requested := Value.Requested;
      Old_Completed := Value.Completed;
      Old_Remaining := Value.Remaining;
      SMB.Engine.Accept_Response (State, Packet, Nt_Status, Accept_Status);
      if Accept_Status /= SMB.Ok then
         Value.Stage := Transfer_Failed;
         Status := Accept_Status;
         return;
      end if;
      if Nt_Status /= SMB.Success then
         Value.Stage := Transfer_Finished;
      else
         Count := SMB.Engine.Current_Response_Info (State).Count;
         pragma Assert
           (Count = Natural (SMB.Core_Wire.Encoded_U32 (Packet, 68)));
         pragma Assert
           (SMB.Core_Wire.Encoded_U32 (Packet, 68) <=
              SMB.DWord (SMB.Core_Protocol.Maximum_IO_Chunk));
         if Count = 0 then
            Fail_Transfer (Value, State, SMB.Invalid_Protocol, Status);
            return;
         end if;
         if Count > Old_Requested or else Count > Value.Remaining then
            Fail_Transfer (Value, State, SMB.Invalid_Value, Status);
            return;
         end if;
         if Count > Value.Capacity - Value.Completed then
            Fail_Transfer (Value, State, SMB.Invalid_Value, Status);
            return;
         end if;
         SMB.Core_Protocol.Advance_Transfer
           (Value.Position, Value.Remaining, Old_Requested, Count,
            Progress_Status);
         if Progress_Status /= SMB.Ok then
            Fail_Transfer (Value, State, Progress_Status, Status);
            return;
         end if;
         pragma Assert (Value.Completed + Count <= Value.Total);
         pragma Assert
           (SMB.QWord (Value.Total) <=
              SMB.QWord'Last - Value.Initial_Offset);
         Value.Completed := Value.Completed + Count;
         pragma Assert (Value.Completed <= Value.Total);
         pragma Assert
           (SMB.QWord (Value.Completed) <= SMB.QWord (Value.Total));
         pragma Assert
           (SMB.QWord (Value.Completed) <=
              SMB.QWord'Last - Value.Initial_Offset);
         Value.Position :=
           Value.Initial_Offset + SMB.QWord (Value.Completed);
         Value.Stage :=
           (if Value.Remaining = 0 then Transfer_Finished else Ready);
      end if;
      Value.Requested := 0;
      pragma Assert
        (Value.Completed + Value.Remaining = Value.Total);
      pragma Assert
        (Value.Completed <= Natural'Last - Value.Remaining);
      pragma Assert
        (Value.Position =
           Value.Initial_Offset + SMB.QWord (Value.Completed));
      pragma Assert (Transfer_Invariant (Value));
      SMB.Engine.Discard_Response_Receipt (State, Receipt_Status);
      if Receipt_Status /= SMB.Ok then
         Fail_Transfer (Value, State, Receipt_Status, Status);
         return;
      end if;
      pragma Assert (not SMB.Engine.Has_Pending_Request (State));
      pragma Assert (not SMB.Engine.Has_Validated_Response (State));
      if Nt_Status /= SMB.Success then
         pragma Assert (Value.Completed = Old_Completed);
         pragma Assert (Value.Remaining = Old_Remaining);
      else
         pragma Assert
           (Value.Completed >= Old_Completed);
         pragma Assert (Value.Completed - Old_Completed = Count);
      end if;
      Status := SMB.Ok;
   end Complete_Write;

   procedure Copy_Read_Result
     (Value : Transfer;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
   begin
      Clear_Output (Output);
      Used := 0;
      if Value.Kind /= Read_Transfer
        or else Value.Stage /= Transfer_Finished
        or else not Transfer_Invariant (Value)
        or else Value.Completed > Output'Length
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      if Value.Completed > 0 then
         for Index in 0 .. Value.Completed - 1 loop
            Output (Output'First + Index) := Value.Buffer (Index + 1);
            pragma Loop_Invariant
              (for all Copied in 0 .. Index =>
                 Output (Output'First + Copied) =
                   Value.Buffer (Copied + 1));
         end loop;
      end if;
      Used := Value.Completed;
      Status := SMB.Ok;
   end Copy_Read_Result;

   procedure Abort_Transfer
     (Value : in out Transfer;
      State : in out SMB.Engine.Engine_State;
      Status : out SMB.Core_Status) is
      Invalidate_Status : SMB.Core_Status;
   begin
      if Value.Stage not in Transfer_Prepared | Transfer_Sent
        or else Value.Owner /= SMB.Engine.Current_Owner_Id (State)
        or else Value.Epoch /= SMB.Engine.Current_Epoch (State)
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      SMB.Engine.Invalidate (State, Invalidate_Status);
      Value.Stage := Transfer_Failed;
      Status := Invalidate_Status;
   end Abort_Transfer;
end SMB.Core_Client;
