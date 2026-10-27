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
          (if Packet'Length > Header_Length then
             Packet (Packet'First + Header_Length .. Packet'Last) =
               Packet'Old (Packet'First + Header_Length .. Packet'Last))
          and then
          (for all Index in Packet'Range =>
             (if Index < Packet'First + 48
                or else Index > Packet'First + 63
              then Packet (Index) = Packet'Old (Index)))
          and then
            SMB.Core_Wire.Encoded_U16 (Packet, 4) =
              SMB.Core_Wire.Encoded_U16 (Packet'Old, 4)
          and then
            SMB.Core_Wire.Encoded_U16 (Packet, 12) =
              SMB.Core_Wire.Encoded_U16 (Packet'Old, 12)
          and then
            SMB.Core_Wire.Encoded_U32 (Packet, 16) =
              SMB.Core_Wire.Encoded_U32 (Packet'Old, 16)
          and then
            SMB.Core_Wire.Encoded_U64 (Packet, 24) =
              SMB.Core_Wire.Encoded_U64 (Packet'Old, 24)
          and then
            SMB.Core_Wire.Encoded_U32 (Packet, 36) =
              SMB.Core_Wire.Encoded_U32 (Packet'Old, 36)
          and then
            SMB.Core_Wire.Encoded_U64 (Packet, 40) =
              SMB.Core_Wire.Encoded_U64 (Packet'Old, 40)
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
      Buffer := (others => 0);
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
      Value.Challenge := (others => 0);
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
          and then SMB.Core_Wire.Encoded_U32 (Packet, 16) = 0
          and then
            (for all Index in Packet'Range =>
               (if Index - Packet'First >= Header_Length
                then Packet (Index) = Packet'Old (Index)
                else True)))
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

   function Authentication_Owner_Of
     (Value : Authentication) return SMB.QWord is
     (Value.Owner);

   function Authentication_Epoch_Of
     (Value : Authentication) return SMB.QWord is
     (Value.Epoch);

   function Authentication_Context_Matches
     (Value : Authentication;
      State : SMB.Engine.Engine_State) return Boolean is
     (Value.Owner = SMB.Engine.Current_Owner_Id (State)
      and then Value.Epoch = SMB.Engine.Current_Epoch (State));

   function Authentication_Packet_Matches
     (Value : Authentication;
      State : SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Used : Natural) return Boolean is
     (Used >= Header_Length
      and then Used <= Packet'Length
      and then Used <=
        Header_Length + 24 + SMB.Core_Auth.Maximum_Security_Token
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
      and then Used >= Header_Length + 24
      and then SMB.Core_Wire.Encoded_U16 (Packet, Header_Length) = 25
      and then Packet (Packet'First + Header_Length + 2) = 0
      and then Packet (Packet'First + Header_Length + 3) = 3
      and then SMB.Core_Wire.Encoded_U16
        (Packet, Header_Length + 12) = 88
      and then SMB.Core_Wire.Encoded_U16
        (Packet, Header_Length + 14) =
          SMB.Word (Used - Header_Length - 24)
      and then SMB.Core_Wire.Encoded_U64
        (Packet, Header_Length + 16) = 0
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
        or else SMB.Engine.Has_Validated_Response (State)
        or else SMB.Engine.Has_Signing_Key (State)
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
      pragma Assert (Body_Used = 24 + Token_Used);
      pragma Assert
        (for all Index in 0 .. Token_Used - 1 =>
           Output
             (Output'First + Header_Length + 24 + Index) =
               Token (Token'First + Index));
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
        or else not Authentication_Context_Matches (Value, State)
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
        or else not Authentication_Context_Matches (Value, State)
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      if Value.Challenge_Length >
          SMB.Core_Auth.Maximum_Security_Token
        or else User'Length > SMB.Core_Auth.Maximum_Credential_Bytes
        or else Password'Length > SMB.Core_Auth.Maximum_Credential_Bytes
        or else Domain'Length > SMB.Core_Auth.Maximum_Credential_Bytes
        or else Nonce'Length /= 8
        or else Output'Length < Header_Length
        or else Output'First > Natural'Last - Header_Length
      then
         Fail_Authentication (Value, State, SMB.Resource_Limit, Status);
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
            Clear_Output (Key);
            Clear_Output (Token);
            Fail_Authentication (Value, State, Failure, Status);
         end;
         return;
      end if;
      if Output'Length < Header_Length + 24 + Token_Used then
         Clear_Output (Key);
         Clear_Output (Token);
         Fail_Authentication (Value, State, SMB.Resource_Limit, Status);
         return;
      end if;
      SMB.Core_Protocol.Build_Session_Setup
        (Token (Token'First .. Token'First + Token_Used - 1),
         Output (Output'First + Header_Length .. Output'Last),
         Body_Used, Engine_Status);
      if Engine_Status /= SMB.Ok then
         Clear_Output (Key);
         Clear_Output (Token);
         Fail_Authentication (Value, State, Engine_Status, Status);
         return;
      end if;
      SMB.Engine.Install_Session_Key
        (State, Value.Session_Id, Key, Engine_Status);
      if Engine_Status /= SMB.Ok then
         Clear_Output (Key);
         Clear_Output (Token);
         Fail_Authentication (Value, State, Engine_Status, Status);
         return;
      end if;
      SMB.Engine.Begin_Request
        (State, 1, False, True, Message_Id, Expected, Engine_Status);
      if Engine_Status /= SMB.Ok then
         Clear_Output (Key);
         Clear_Output (Token);
         Fail_Authentication (Value, State, Engine_Status, Status);
         return;
      end if;
      Value.Expected := Expected;
      Value.Stage := Authenticate_Prepared;
      Prepare_Unsigned_Header (Output, Expected, Field_Status);
      if Field_Status /= SMB.Ok then
         Clear_Output (Key);
         Clear_Output (Token);
         Fail_Authentication (Value, State, Field_Status, Status);
         return;
      end if;
      pragma Assert (Body_Used = 24 + Token_Used);
      pragma Assert
        (for all Index in 0 .. Token_Used - 1 =>
           Output
             (Output'First + Header_Length + 24 + Index) =
               Token (Token'First + Index));
      Used := Header_Length + Body_Used;
      Clear_Output (Key);
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
        or else not Authentication_Context_Matches (Value, State)
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
         Status := SMB.Ok;
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
      if not Authentication_Context_Matches (Value, State)
        or else Value.Stage in Authentication_Ready |
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
          SMB.Core_Wire.Encoded_U16 (Packet, 4) = 64
          and then SMB.Core_Wire.Encoded_U16 (Packet, 6) = 1
          and then SMB.Core_Wire.Encoded_U16 (Packet, 12) =
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

   function Directory_Context_Valid
     (Value : Directory_Enumeration;
      State : SMB.Engine.Engine_State) return Boolean
   with Post =>
     (if Directory_Context_Valid'Result then
        Directory_Context_Matches (Value, State)
        and then SMB.Engine.Handle_Matches
          (State, Value.Token, Value.File_Id, Value.Access_Mode, True))
   is
      File_Id : SMB.Bytes (0 .. 15) := (others => 0);
      Access_Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
      Is_Directory : Boolean := False;
      Handle_Status : SMB.Core_Status;
   begin
      if Value.Owner /= SMB.Engine.Current_Owner_Id (State)
        or else Value.Epoch /= SMB.Engine.Current_Epoch (State)
        or else SMB.Engine.Current_Phase (State) /=
          SMB.Engine.Share_Connected
      then
         return False;
      end if;
      SMB.Engine.Validate_Handle
        (State, Value.Token, True, False, File_Id, Access_Mode,
         Is_Directory, Handle_Status);
      if Handle_Status /= SMB.Ok
        or else not Is_Directory
        or else File_Id /= Value.File_Id
        or else Access_Mode /= Value.Access_Mode
      then
         return False;
      end if;
      pragma Assert (Is_Directory);
      pragma Assert (File_Id = Value.File_Id);
      pragma Assert (Access_Mode = Value.Access_Mode);
      pragma Assert
        (SMB.Engine.Handle_Matches
           (State, Value.Token, File_Id, Access_Mode, Is_Directory));
      pragma Assert
        (for all Index in Value.File_Id'Range =>
           File_Id (Index) = Value.File_Id (Index));
      pragma Assert
        (SMB.Engine.Handle_Matches_Equivalent
           (State, Value.Token, File_Id, Value.File_Id,
            Access_Mode, Is_Directory));
      pragma Assert
        (SMB.Engine.Handle_Matches
           (State, Value.Token, Value.File_Id, Value.Access_Mode, True));
      return True;
   end Directory_Context_Valid;

   procedure Fail_Directory
     (Value : in out Directory_Enumeration;
      State : in out SMB.Engine.Engine_State;
      Failure : SMB.Core_Status;
      Status : out SMB.Core_Status)
   is
      Invalidate_Status : SMB.Core_Status;
   begin
      SMB.Engine.Invalidate (State, Invalidate_Status);
      Value.Stage := Directory_Failed;
      Status :=
        (if Invalidate_Status = SMB.Ok then Failure else Invalidate_Status);
   end Fail_Directory;

   function Metadata_Context_Valid
     (Value : Metadata_Operation;
      State : SMB.Engine.Engine_State) return Boolean
   with Post =>
     (if Metadata_Context_Valid'Result then
        Value.Owner = SMB.Engine.Current_Owner_Id (State)
        and then Value.Epoch = SMB.Engine.Current_Epoch (State)
        and then Value.Expected.Command = 17
        and then Value.Expected.Signed
        and then Value.Expected.Request_Signed
        and then SMB.Engine.Current_Phase (State) = SMB.Engine.Share_Connected
        and then SMB.Engine.Handle_Matches
          (State, Value.Token, Value.File_Id, Value.Access_Mode,
           Value.Directory))
   is
      Id : SMB.Bytes (0 .. 15) := (others => 0);
      Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
      Is_Directory : Boolean := False;
      S : SMB.Core_Status;
   begin
      if Value.Expected.Command /= 17
        or else not Value.Expected.Signed
        or else not Value.Expected.Request_Signed
        or else Value.Owner /= SMB.Engine.Current_Owner_Id (State)
        or else Value.Epoch /= SMB.Engine.Current_Epoch (State)
        or else SMB.Engine.Current_Phase (State) /=
          SMB.Engine.Share_Connected
      then
         return False;
      end if;
      SMB.Engine.Validate_Handle
        (State, Value.Token, False, False, Id, Mode, Is_Directory, S);
      if S /= SMB.Ok
        or else Id /= Value.File_Id
        or else Mode /= Value.Access_Mode
        or else Is_Directory /= Value.Directory
      then
         return False;
      end if;
      pragma Assert
        (SMB.Engine.Handle_Matches
           (State, Value.Token, Id, Mode, Is_Directory));
      pragma Assert
        (for all Index in Value.File_Id'Range =>
           Id (Index) = Value.File_Id (Index));
      pragma Assert
        (SMB.Engine.Handle_Matches_Equivalent
           (State, Value.Token, Id, Value.File_Id, Mode, Is_Directory));
      pragma Assert
        (SMB.Engine.Handle_Matches
           (State, Value.Token, Value.File_Id, Value.Access_Mode,
            Value.Directory));
      return True;
   end Metadata_Context_Valid;

   procedure Fail_Metadata
     (Value : in out Metadata_Operation;
      State : in out SMB.Engine.Engine_State;
      Failure : SMB.Core_Status;
      Status : out SMB.Core_Status)
   with Pre => Failure /= SMB.Ok,
     Post => Status /= SMB.Ok
       and then Metadata_Stage_Of (Value) = Metadata_Failed
       and then SMB.Engine.Current_Phase (State) = SMB.Engine.Disconnected
   is
      S : SMB.Core_Status;
   begin
      SMB.Engine.Invalidate (State, S);
      Value.Stage := Metadata_Failed;
      Status := (if S = SMB.Ok then Failure else S);
   end Fail_Metadata;

   procedure Prepare_Metadata
     (Value : in out Metadata_Operation;
      State : in out SMB.Engine.Engine_State;
      Token : SMB.Engine.Handle_Token;
      Kind : Metadata_Kind;
      Delete_File : Boolean;
      Name : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with
     Pre => Kind in Rename_Metadata | Disposition_Metadata
       and then Name'Length <= SMB.Core_Protocol.Maximum_Name_Bytes
       and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if not Metadata_Preparation_Context_Matches
               (Metadata_Snapshot_Of (Value)'Old, State'Old, Token)
             or else Output'Length <
               Header_Length +
                 (if Kind = Disposition_Metadata then 33 else 52 + Name'Length)
             or else (Kind = Rename_Metadata
                      and then (Name'Length = 0 or else Name'Length mod 2 /= 0))
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
            Metadata_Packet_Matches (Value, State, Output, Used)
            and then Metadata_Stage_Of (Value)'Old = Metadata_Idle
            and then Metadata_Kind_Of (Value) = Kind
            and then Metadata_Snapshot_Of (Value).Token = Token
            and then Metadata_Snapshot_Of (Value).Delete_File = Delete_File
            and then Metadata_Snapshot_Of (Value).Name_Length = Name'Length
            and then SMB.Engine.Handle_Matches_In_States
              (State'Old, State, Token,
               Metadata_Snapshot_Of (Value).File_Id,
               Metadata_Snapshot_Of (Value).Access_Mode,
               Metadata_Snapshot_Of (Value).Directory)
            and then
              (if Kind = Rename_Metadata then
                 Name'Length > 0 and then Name'Length mod 2 = 0
                 and then
                   (for all Index in 0 .. Name'Length - 1 =>
                      Output (Output'First + Header_Length + 52 + Index) =
                        Name (Name'First + Index)))
            and then SMB.Engine.Handle_Matches
              (State'Old, Token,
               Metadata_Snapshot_Of (Value).File_Id,
               Metadata_Snapshot_Of (Value).Access_Mode,
               Metadata_Snapshot_Of (Value).Directory)
            and then SMB.Engine.Handle_Matches
              (State, Token, Metadata_Snapshot_Of (Value).File_Id,
               Metadata_Snapshot_Of (Value).Access_Mode,
               Metadata_Snapshot_Of (Value).Directory))
   is
      Id : SMB.Bytes (0 .. 15) := (others => 0);
      Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
      Dir : Boolean := False;
      S, B : SMB.Core_Status;
      Body_Used : Natural;
      Need : constant Natural :=
        (if Kind = Disposition_Metadata then Header_Length + 33
         else Header_Length + 52 + Name'Length);
      Message : SMB.QWord := 0;
      Expected : SMB.Engine.Request_Expectation;
      E : SMB.Core_Status;
      Before_Begin : constant SMB.Engine.Engine_State := State with Ghost;
      Old_Metadata : constant Metadata_State_Snapshot :=
        Metadata_Snapshot_Of (Value);
   begin
      Clear_Output (Output);
      Used := 0;
      if Value.Stage /= Metadata_Idle
        or else SMB.Engine.Current_Phase (State) /=
          SMB.Engine.Share_Connected
        or else SMB.Engine.Has_Pending_Request (State)
        or else SMB.Engine.Has_Validated_Response (State)
        or else Token.Owner /= SMB.Engine.Current_Owner_Id (State)
        or else Token.Epoch /= SMB.Engine.Current_Epoch (State)
        or else Token.Ticket = 0
      then
         Status := SMB.Invalid_State_Status;
         pragma Assert (Metadata_Snapshot_Of (Value) = Old_Metadata);
         return;
      end if;
      if Kind = Rename_Metadata
        and then (Name'Length = 0 or else Name'Length mod 2 /= 0)
      then
         Status := SMB.Invalid_Length;
         pragma Assert (Metadata_Snapshot_Of (Value) = Old_Metadata);
         return;
      end if;
      if Output'Length < Need then
         Status := SMB.Resource_Limit;
         pragma Assert (Metadata_Snapshot_Of (Value) = Old_Metadata);
         return;
      end if;
      SMB.Engine.Validate_Handle
        (State, Token, False, False, Id, Mode, Dir, S);
      if S /= SMB.Ok then
         Status := SMB.Invalid_State_Status;
         pragma Assert (Metadata_Snapshot_Of (Value) = Old_Metadata);
         return;
      end if;
      pragma Assert
        (SMB.Engine.Handle_Matches (State, Token, Id, Mode, Dir));
      pragma Assert
        (Metadata_Preparation_Context_Matches (Old_Metadata, State, Token));
      declare
         Body_Buffer : SMB.Bytes (0 .. Need - Header_Length - 1);
      begin
         if Kind = Disposition_Metadata then
            SMB.Core_Protocol.Build_Disposition
              (Id, Delete_File, Body_Buffer, Body_Used, B);
            if B = SMB.Ok then
               pragma Assert
                 (for all Index in 10 .. 15 => Body_Buffer (Index) = 0);
            end if;
         else
            SMB.Core_Protocol.Build_Rename
              (Id, Name, Body_Buffer, Body_Used, B);
            if B = SMB.Ok then
               pragma Assert
                 (for all Index in 10 .. 15 => Body_Buffer (Index) = 0);
               pragma Assert
                 (Body_Buffer (32 .. 47) = SMB.Bytes'(32 .. 47 => 0));
               pragma Assert (Body_Buffer'Length = 52 + Name'Length);
               pragma Assert
                 (for all Index in 0 .. Name'Length - 1 =>
                    Body_Buffer (52 + Index) = Name (Name'First + Index));
               pragma Assert (Body_Buffer (52 .. Body_Buffer'Last) = Name);
            end if;
         end if;
         if B /= SMB.Ok then
            Status := B;
            pragma Assert (Metadata_Snapshot_Of (Value) = Old_Metadata);
            return;
         end if;
         pragma Assert (Body_Used = Need - Header_Length);
         pragma Assert
           (for all Index in 10 .. 15 => Body_Buffer (Index) = 0);
         Output (Output'First + Header_Length ..
                 Output'First + (Need - 1)) := Body_Buffer;
      end;
      pragma Assert (Before_Begin = State);
      pragma Assert
        (for all Index in 10 .. 15 =>
           Output (Output'First + Header_Length + Index) = 0);
      SMB.Engine.Begin_Request
        (State, 17, True, True, Message, Expected, S);
      if S /= SMB.Ok then
         Status := S;
         pragma Assert (Metadata_Snapshot_Of (Value) = Old_Metadata);
         return;
      end if;
      pragma Assert
        (SMB.Engine.Handle_Matches
           (Before_Begin, Token, Id, Mode, Dir));
      pragma Assert
        (SMB.Engine.Handle_Matches_In_States
           (Before_Begin, State, Token, Id, Mode, Dir));
      pragma Assert (SMB.Engine.Handle_Matches (State, Token, Id, Mode, Dir));
      Value.Kind := Kind;
      Value.Owner := SMB.Engine.Current_Owner_Id (State);
      Value.Epoch := SMB.Engine.Current_Epoch (State);
      Value.Token := Token;
      Value.File_Id := Id;
      Value.Access_Mode := Mode;
      Value.Directory := Dir;
      Value.Delete_File := Delete_File;
      Value.Name_Length := Name'Length;
      Value.Expected := Expected;
      Value.Stage := Metadata_Prepared;
      pragma Assert (Value.File_Id = Id);
      pragma Assert
        (SMB.Engine.Handle_Matches
           (Before_Begin, Token, Value.File_Id, Value.Access_Mode,
            Value.Directory));
      pragma Assert
        (SMB.Engine.Handle_Matches_In_States
           (Before_Begin, State, Token, Value.File_Id, Value.Access_Mode,
            Value.Directory));
      Prepare_Header (Output, Expected, S);
      if S = SMB.Ok then
         Sign_Packet
           (Output, Need, SMB.Engine.Current_Signing_Key (State), E);
         S := E;
      end if;
      if S /= SMB.Ok then
         Fail_Metadata (Value, State, S, Status);
         Used := 0;
         return;
      end if;
      Used := Need;
      pragma Assert (Metadata_Packet_Matches (Value, State, Output, Used));
      pragma Assert
        (SMB.Engine.Handle_Matches
           (Before_Begin, Token, Metadata_Snapshot_Of (Value).File_Id,
            Metadata_Snapshot_Of (Value).Access_Mode,
            Metadata_Snapshot_Of (Value).Directory));
      pragma Assert
        (SMB.Engine.Handle_Matches_In_States
           (Before_Begin, State, Token, Metadata_Snapshot_Of (Value).File_Id,
            Metadata_Snapshot_Of (Value).Access_Mode,
            Metadata_Snapshot_Of (Value).Directory));
      pragma Assert
        (if Kind = Rename_Metadata then
           Output (Output'First + Header_Length + 52 ..
                   Output'First + (Need - 1)) = Name);
      pragma Assert
        (if Kind = Rename_Metadata then
           (for all Index in 0 .. Name'Length - 1 =>
              Output (Output'First + Header_Length + 52 + Index) =
                Name (Name'First + Index)));
      Status := SMB.Ok;
   end Prepare_Metadata;

   procedure Prepare_Disposition
     (Value : in out Metadata_Operation;
      State : in out SMB.Engine.Engine_State;
      Token : SMB.Engine.Handle_Token;
      Delete_File : Boolean;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
   begin
      Prepare_Metadata (Value, State, Token, Disposition_Metadata,
                        Delete_File, SMB.Bytes'(1 .. 0 => 0),
                        Output, Used, Status);
   end Prepare_Disposition;

   procedure Prepare_Rename
     (Value : in out Metadata_Operation;
      State : in out SMB.Engine.Engine_State;
      Token : SMB.Engine.Handle_Token;
      Name : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
   begin
      Prepare_Metadata (Value, State, Token, Rename_Metadata, False,
                        Name, Output, Used, Status);
   end Prepare_Rename;

   procedure Metadata_Send_Succeeded
     (Value : in out Metadata_Operation;
      State : SMB.Engine.Engine_State;
      Status : out SMB.Core_Status) is
      Old_Metadata : constant Metadata_State_Snapshot :=
        Metadata_Snapshot_Of (Value);
   begin
      if Value.Stage /= Metadata_Prepared
        or else not Metadata_Context_Valid (Value, State)
        or else not SMB.Engine.Pending_Request_Matches
          (State, Value.Expected)
      then
         Status := SMB.Invalid_State_Status;
         pragma Assert (Metadata_Snapshot_Of (Value) = Old_Metadata);
      else
         Value.Stage := Metadata_Sent;
         Status := SMB.Ok;
      end if;
   end Metadata_Send_Succeeded;

   procedure Complete_Metadata
     (Value : in out Metadata_Operation;
      State : in out SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Nt_Status : out SMB.DWord;
      Status : out SMB.Core_Status) is
      Receipt_Status : SMB.Core_Status;
      Before_Accept : constant SMB.Engine.Engine_State := State with Ghost;
      Old_Metadata : constant Metadata_State_Snapshot :=
        Metadata_Snapshot_Of (Value);
   begin
      Nt_Status := 0;
      if Value.Stage /= Metadata_Sent
        or else not Metadata_Context_Valid (Value, State)
        or else not SMB.Engine.Pending_Request_Matches
          (State, Value.Expected)
      then
         Status := SMB.Invalid_State_Status;
         pragma Assert (Metadata_Snapshot_Of (Value) = Old_Metadata);
         return;
      end if;
      SMB.Engine.Accept_Response (State, Packet, Nt_Status, Status);
      if Status /= SMB.Ok then
         Value.Stage := Metadata_Failed;
         return;
      end if;
      pragma Assert
        (SMB.Engine.Handle_Matches_In_States
           (Before_Accept, State, Value.Token, Value.File_Id,
            Value.Access_Mode, Value.Directory));
      declare
         Before_Discard : constant SMB.Engine.Engine_State := State with Ghost;
      begin
         SMB.Engine.Discard_Response_Receipt (State, Receipt_Status);
         if Receipt_Status /= SMB.Ok then
            Fail_Metadata (Value, State, Receipt_Status, Status);
            return;
         end if;
         pragma Assert
           (SMB.Engine.Handle_Matches_In_States
              (Before_Discard, State, Value.Token, Value.File_Id,
               Value.Access_Mode, Value.Directory));
      end;
      Value.Stage := Metadata_Finished;
      Status := SMB.Ok;
   end Complete_Metadata;

   procedure Abort_Metadata
     (Value : in out Metadata_Operation;
      State : in out SMB.Engine.Engine_State;
      Status : out SMB.Core_Status) is
      S : SMB.Core_Status;
      Old_Metadata : constant Metadata_State_Snapshot :=
        Metadata_Snapshot_Of (Value);
   begin
      if Value.Stage not in Metadata_Prepared | Metadata_Sent
        or else not Metadata_Context_Valid (Value, State)
        or else not SMB.Engine.Pending_Request_Matches
          (State, Value.Expected)
      then
         Status := SMB.Invalid_State_Status;
         pragma Assert (Metadata_Snapshot_Of (Value) = Old_Metadata);
         return;
      end if;
      SMB.Engine.Invalidate (State, S);
      Value.Stage := Metadata_Failed;
      Status := S;
   end Abort_Metadata;

   procedure Start_Directory
     (Value : in out Directory_Enumeration;
      State : SMB.Engine.Engine_State;
      Token : SMB.Engine.Handle_Token;
      Status : out SMB.Core_Status)
   is
      File_Id : SMB.Bytes (0 .. 15) := (others => 0);
      Access_Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
      Is_Directory : Boolean := False;
      Handle_Status : SMB.Core_Status;
   begin
      if Value.Stage /= Directory_Idle
        or else SMB.Engine.Current_Phase (State) /= SMB.Engine.Share_Connected
        or else SMB.Engine.Has_Pending_Request (State)
        or else SMB.Engine.Has_Validated_Response (State)
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      SMB.Engine.Validate_Handle
        (State, Token, True, False, File_Id, Access_Mode,
         Is_Directory, Handle_Status);
      if Handle_Status /= SMB.Ok or else not Is_Directory then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      Value.Owner := SMB.Engine.Current_Owner_Id (State);
      Value.Epoch := SMB.Engine.Current_Epoch (State);
      Value.Token := Token;
      Value.File_Id := File_Id;
      Value.Access_Mode := Access_Mode;
      Value.Expected := (others => <>);
      Value.Page_Length := 0;
      Value.Cursor := 0;
      Value.Page_Count := 0;
      Value.Entry_Count := 0;
      Value.Stage := Query_Ready;
      Status := SMB.Ok;
      pragma Assert (Directory_Invariant (Value));
      pragma Assert (Directory_Context_Matches (Value, State));
   end Start_Directory;

   procedure Prepare_Directory_Query
     (Value : in out Directory_Enumeration;
      State : in out SMB.Engine.Engine_State;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   is
      Access_Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
      File_Id : SMB.Bytes (0 .. 15) := (others => 0);
      Is_Directory : Boolean := False;
      Validate_Status : SMB.Core_Status;
      Field_Status : SMB.Core_Status;
      Begin_Status : SMB.Core_Status;
      Count_Status : SMB.Core_Status;
      Sign_Status : SMB.Core_Status;
      Body_Used : Natural := 0;
      Message_Id : SMB.QWord := 0;
      Expected : SMB.Engine.Request_Expectation;
   begin
      Clear_Output (Output);
      Used := 0;
      if Value.Stage /= Query_Ready
        or else not Directory_Invariant (Value)
        or else not Directory_Context_Valid (Value, State)
        or else SMB.Engine.Current_Phase (State) /=
          SMB.Engine.Share_Connected
        or else SMB.Engine.Has_Pending_Request (State)
        or else SMB.Engine.Has_Validated_Response (State)
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      SMB.Engine.Validate_Handle
        (State, Value.Token, True, False, File_Id, Access_Mode,
         Is_Directory, Validate_Status);
      if Validate_Status /= SMB.Ok
        or else not Is_Directory
        or else File_Id /= Value.File_Id
        or else Access_Mode /= Value.Access_Mode
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      pragma Assert
        (for all Index in Value.File_Id'Range =>
           File_Id (Index) = Value.File_Id (Index));
      pragma Assert
        (SMB.Engine.Handle_Matches
           (State, Value.Token, File_Id, Access_Mode, True));
      pragma Assert
        (SMB.Engine.Handle_Matches_Equivalent
           (State, Value.Token, File_Id, Value.File_Id,
            Access_Mode, True));
      pragma Assert
        (SMB.Engine.Handle_Matches
           (State, Value.Token, Value.File_Id, Value.Access_Mode, True));
      if Value.Page_Count >= SMB.Core_Protocol.Maximum_Directory_Pages
        or else Output'Length < Directory_Request_Size
      then
         Fail_Directory
           (Value, State, SMB.Resource_Limit, Status);
         return;
      end if;
      SMB.Core_Protocol.Build_Query_Directory
        (File_Id, Value.Page_Count = 0,
         Output (Output'First + Header_Length .. Output'Last),
         Body_Used, Field_Status);
      if Field_Status /= SMB.Ok or else Body_Used /= 34 then
         Fail_Directory
           (Value,
            State,
            (if Field_Status = SMB.Ok then SMB.Invalid_Protocol
             else Field_Status),
            Status);
         return;
      end if;
      pragma Assert
        (SMB.Core_Wire.Encoded_U16
           (Output, Header_Length) = 33);
      pragma Assert
        (Output (Output'First + Header_Length + 2) = 37);
      pragma Assert
        (Output (Output'First + Header_Length + 3) =
           (if Value.Page_Count = 0 then 1 else 0));
      pragma Assert
        (for all Index in 0 .. 15 =>
           Output
             (Output'First + Header_Length + 8 + Index) =
               File_Id (File_Id'First + Index));
      pragma Assert
        (SMB.Core_Wire.Encoded_U32
           (Output, Header_Length + 28) =
             SMB.DWord (SMB.Core_Protocol.Maximum_IO_Chunk));
      SMB.Engine.Begin_Request
        (State, 14, True, True, Message_Id, Expected, Begin_Status,
         Request_Amount => SMB.Core_Protocol.Maximum_IO_Chunk);
      if Begin_Status /= SMB.Ok then
         Fail_Directory (Value, State, Begin_Status, Status);
         return;
      end if;
      Value.Expected := Expected;
      pragma Assert (Value.Expected.Tree_Id = Expected.Tree_Id);
      Value.Stage := Query_Prepared;
      Used := Header_Length + Body_Used;
      Prepare_Header (Output, Expected, Field_Status);
      if Field_Status /= SMB.Ok then
         Fail_Directory (Value, State, Field_Status, Status);
         Used := 0;
         return;
      end if;
      pragma Assert
        (SMB.Core_Wire.Encoded_U32 (Output, 36) = Expected.Tree_Id);
      pragma Assert
        (SMB.Core_Wire.Encoded_U64 (Output, 40) = Expected.Session_Id);
      pragma Assert (Message_Id = Expected.Message_Id);
      pragma Assert (Expected.Command = 14);
      pragma Assert (Expected.Request_Signed and Expected.Signed);
      pragma Assert
        (Expected.Request_Amount = SMB.Core_Protocol.Maximum_IO_Chunk);
      pragma Assert (Body_Used = 34);
      pragma Assert
        (SMB.Core_Wire.Encoded_U16 (Output, Header_Length) = 33);
      pragma Assert
        (for all Index in 0 .. 15 =>
           Output
             (Output'First + Header_Length + 8 + Index) =
               Value.File_Id (Value.File_Id'First + Index));
      declare
         Key : constant SMB.Bytes :=
           SMB.Engine.Current_Signing_Key (State);
      begin
         Sign_Packet (Output, Used, Key, Sign_Status);
      end;
      if Sign_Status /= SMB.Ok then
         Fail_Directory (Value, State, Sign_Status, Status);
         Used := 0;
         return;
      end if;
      pragma Assert
        (SMB.Core_Wire.Encoded_U32 (Output, 36) = Expected.Tree_Id);
      SMB.Core_Protocol.Count_Directory_Page
        (Value.Page_Count, Count_Status);
      if Count_Status /= SMB.Ok then
         Fail_Directory (Value, State, Count_Status, Status);
         Used := 0;
         return;
      end if;
      pragma Assert (Value.Expected.Tree_Id = Expected.Tree_Id);
      pragma Assert
        (SMB.Core_Wire.Encoded_U32 (Output, 36) =
           Value.Expected.Tree_Id);
      pragma Assert (Directory_Invariant (Value));
      pragma Assert
        (Directory_Packet_Matches (Value, State, Output, Used));
      Status := SMB.Ok;
   end Prepare_Directory_Query;

   procedure Directory_Send_Succeeded
     (Value : in out Directory_Enumeration;
      State : SMB.Engine.Engine_State;
      Status : out SMB.Core_Status)
   is
   begin
      if Value.Stage /= Query_Prepared
        or else not Directory_Invariant (Value)
        or else not Directory_Context_Valid (Value, State)
        or else not SMB.Engine.Pending_Request_Matches
          (State, Value.Expected)
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      Value.Stage := Query_Sent;
      Status := SMB.Ok;
   end Directory_Send_Succeeded;

   procedure Complete_Directory_Page
     (Value : in out Directory_Enumeration;
      State : in out SMB.Engine.Engine_State;
      Packet : SMB.Bytes;
      Nt_Status : out SMB.DWord;
      Status : out SMB.Core_Status)
   is
      Accept_Status : SMB.Core_Status;
      Receipt_Status : SMB.Core_Status;
      Info : SMB.Core_Protocol.Response_Info;
   begin
      Nt_Status := 0;
      if Value.Stage /= Query_Sent
        or else not Directory_Invariant (Value)
        or else not Directory_Context_Valid (Value, State)
        or else not SMB.Engine.Pending_Request_Matches
          (State, Value.Expected)
        or else SMB.Engine.Has_Validated_Response (State)
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      if Packet'Length < 72 then
         Fail_Directory (Value, State, SMB.Invalid_Length, Status);
         return;
      end if;
      SMB.Engine.Accept_Response (State, Packet, Nt_Status, Accept_Status);
      if Accept_Status /= SMB.Ok then
         Value.Stage := Directory_Failed;
         Status := Accept_Status;
         return;
      end if;
      Info := SMB.Engine.Current_Response_Info (State);
      if Nt_Status /= SMB.Success
        or else Nt_Status = SMB.Status_No_More_Files
        or else Info.Data_Length = 0
      then
         Value.Page_Length := 0;
         Value.Cursor := 0;
         Value.Stage := Directory_Finished;
         SMB.Engine.Discard_Response_Receipt (State, Receipt_Status);
         if Receipt_Status /= SMB.Ok then
            Fail_Directory (Value, State, Receipt_Status, Status);
            return;
         end if;
         Status := SMB.Ok;
         return;
      end if;
      pragma Assert (Packet'Length >= 72);
      declare
         Response_Offset : constant Natural :=
           Natural (SMB.Core_Wire.Encoded_U16 (Packet, 66));
         Response_Length_Value : constant SMB.DWord :=
           SMB.Core_Wire.Encoded_U32 (Packet, 68);
      begin
         if Response_Length_Value = 0
           or else Response_Length_Value >
             SMB.DWord (SMB.Core_Protocol.Maximum_IO_Chunk)
           or else Response_Offset > Packet'Length
           or else Natural (Response_Length_Value) >
             Packet'Length - Response_Offset
           or else Response_Offset < 72
           or else Info.Data_Offset /= Response_Offset
           or else Info.Data_Length /= Natural (Response_Length_Value)
         then
            Fail_Directory (Value, State, SMB.Invalid_Protocol, Status);
            return;
         end if;
         Value.Page
           (0 .. Natural (Response_Length_Value) - 1) :=
             Packet
               (Packet'First + Response_Offset ..
                Packet'First +
                  (Response_Offset + (Natural (Response_Length_Value) - 1)));
         Value.Page_Length := Natural (Response_Length_Value);
         pragma Assert
           (Directory_Page_Length_Of (Value) =
              Natural (SMB.Core_Wire.Encoded_U32 (Packet, 68)));
         pragma Assert
           (Directory_Page_Matches
              (Value, Packet,
               Natural (SMB.Core_Wire.Encoded_U16 (Packet, 66)),
               Directory_Page_Length_Of (Value)));
      end;
      Value.Cursor := 0;
      Value.Stage := Page_Ready;
      SMB.Engine.Discard_Response_Receipt (State, Receipt_Status);
      if Receipt_Status /= SMB.Ok then
         Fail_Directory (Value, State, Receipt_Status, Status);
         return;
      end if;
      pragma Assert (Directory_Invariant (Value));
      pragma Assert
        (Directory_Page_Matches
           (Value, Packet, Info.Data_Offset, Info.Data_Length));
      Status := SMB.Ok;
   end Complete_Directory_Page;

   procedure Next_Directory_Entry
     (Value : in out Directory_Enumeration;
      State : in out SMB.Engine.Engine_State;
      Name : in out SMB.Bytes;
      Used : out Natural;
      Info : out SMB.Core_Protocol.Directory_Info;
      Status : out SMB.Core_Status)
   is
      Cursor : Natural;
      New_Entry_Count : Natural;
      Parse_Status : SMB.Core_Status;
      Count_Status : SMB.Core_Status;
      Parsed : SMB.Core_Protocol.Directory_Info;
   begin
      Used := 0;
      Info :=
        (Name_Offset => 0, Name_Length => 0, Size => 0,
         Attributes => 0, Next_Cursor => 0);
      if Value.Stage /= Page_Ready
        or else not Directory_Invariant (Value)
        or else not Directory_Context_Valid (Value, State)
        or else SMB.Engine.Has_Pending_Request (State)
        or else SMB.Engine.Has_Validated_Response (State)
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      Cursor := Value.Cursor;
      SMB.Core_Protocol.Parse_Directory_Entry
        (Value.Page (0 .. Value.Page_Length - 1), Cursor, Parsed,
         Parse_Status);
      if Parse_Status /= SMB.Ok then
         Fail_Directory (Value, State, Parse_Status, Status);
         return;
      end if;
      pragma Assert
        (Parsed.Name_Length =
           Natural
             (SMB.Core_Wire.Encoded_U32 (Value.Page, Value.Cursor + 60)));
      New_Entry_Count := Value.Entry_Count;
      SMB.Core_Protocol.Count_Directory_Entry
        (New_Entry_Count, Count_Status);
      if Count_Status /= SMB.Ok then
         Fail_Directory (Value, State, Count_Status, Status);
         return;
      end if;
      Info := Parsed;
      if Parsed.Name_Length > Name'Length then
         Status := SMB.Resource_Limit;
         return;
      end if;
      pragma Assert (Parsed.Name_Length > 0);
      pragma Assert (Parsed.Name_Offset + Parsed.Name_Length <=
        Value.Page_Length);
      Name
        (Name'First .. Name'First + (Parsed.Name_Length - 1)) :=
          Value.Page
            (Parsed.Name_Offset ..
             Parsed.Name_Offset + Parsed.Name_Length - 1);
      Used := Parsed.Name_Length;
      Value.Cursor := Cursor;
      Value.Entry_Count := New_Entry_Count;
      if Cursor = Value.Page_Length then
         Value.Stage := Query_Ready;
      else
         Value.Stage := Page_Ready;
      end if;
      pragma Assert (Directory_Invariant (Value));
      Status := SMB.Ok;
   end Next_Directory_Entry;

   procedure Abort_Directory
     (Value : in out Directory_Enumeration;
      State : in out SMB.Engine.Engine_State;
      Status : out SMB.Core_Status)
   is
      Invalidate_Status : SMB.Core_Status;
      Reserved : constant Boolean :=
        Value.Stage in Query_Prepared | Query_Sent;
   begin
      if Value.Stage not in Query_Ready | Query_Prepared |
          Query_Sent | Page_Ready
        or else not Directory_Context_Valid (Value, State)
        or else
          (if Reserved then
             not SMB.Engine.Pending_Request_Matches
               (State, Value.Expected)
             or else SMB.Engine.Has_Validated_Response (State)
           else
             SMB.Engine.Has_Pending_Request (State)
             or else SMB.Engine.Has_Validated_Response (State))
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      if Reserved then
         SMB.Engine.Invalidate (State, Invalidate_Status);
         Value.Stage := Directory_Failed;
         Status := Invalidate_Status;
      else
         Value.Stage := Directory_Failed;
         Status := SMB.Ok;
      end if;
   end Abort_Directory;

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
      Sign_Packet
        (Output, Required, Key, Field_Status);
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
         Value.Buffer := Data;
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
               pragma Assert_And_Cut
                 (Payload'Length = Amount and then
                  (for all Index in 0 .. Amount - 1 =>
                    Payload (Payload'First + Index) =
                      Value.Buffer (Value.Completed + Index + 1)));
               SMB.Core_Protocol.Build_Write
                 (File_Id, Value.Position, Payload,
                  Body_Buffer, Body_Used, Field_Status);
               if Field_Status = SMB.Ok then
                  pragma Assert_And_Cut
                    (for all Index in 0 .. Payload'Length - 1 =>
                       Body_Buffer (Body_Buffer'First + 48 + Index) =
                         Payload (Payload'First + Index));
                  pragma Assert
                    (for all Index in 0 .. Amount - 1 =>
                       Body_Buffer (Body_Buffer'First + 48 + Index) =
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

   function Unverified_Authentication_Status
     (Value : Authentication;
      State : SMB.Engine.Engine_State;
      Packet : SMB.Bytes) return SMB.DWord
   is
      Nt_Status : SMB.DWord;
      Status : SMB.Core_Status;
      Info : SMB.Core_Protocol.Response_Info;
   begin
      if Packet'Length < 72
        or else Value.Stage /= Authenticate_Sent
        or else not Authentication_Context_Matches (Value, State)
        or else not SMB.Engine.Pending_Request_Matches (State, Value.Expected)
        or else Value.Expected.Command /= 1
      then
         return 0;
      end if;
      SMB.Core_Wire.Validate_Header
        (Packet,
         (Command => 1,
          Message_Id => Value.Expected.Message_Id,
          Tree_Id => Value.Expected.Tree_Id,
          Session_Id => Value.Expected.Session_Id,
          Match_Tree => True,
          Match_Session => True,
          Signed => False),
         Nt_Status, Status);
      if Status /= SMB.Ok
        or else Nt_Status = SMB.Status_More_Processing_Required
        or else (Nt_Status and 16#C000_0000#) /= 16#C000_0000#
      then
         return 0;
      end if;
      SMB.Core_Protocol.Parse_Response (Packet, 1, Nt_Status, Info, Status);
      return (if Status = SMB.Ok then Nt_Status else 0);
   end Unverified_Authentication_Status;

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
         Output (Output'First .. Output'First + (Value.Completed - 1)) :=
           Value.Buffer (1 .. Value.Completed);
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

   function Metadata_Stage_Of
     (Value : Metadata_Operation) return Metadata_Stage is
     (Value.Stage);

   function Metadata_Kind_Of
     (Value : Metadata_Operation) return Metadata_Kind is
     (Value.Kind);

   function Metadata_Snapshot_Of
     (Value : Metadata_Operation) return Metadata_State_Snapshot is
     ((Kind => Value.Kind, Stage => Value.Stage,
       Owner => Value.Owner, Epoch => Value.Epoch,
       Token => Value.Token, File_Id => Value.File_Id,
       Access_Mode => Value.Access_Mode, Directory => Value.Directory,
       Delete_File => Value.Delete_File, Name_Length => Value.Name_Length,
       Expected => Value.Expected));

   function Metadata_Expected_Of
     (Value : Metadata_Operation) return SMB.Engine.Request_Expectation is
     (Value.Expected);
end SMB.Core_Client;
