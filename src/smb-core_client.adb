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
      --  adamutant:disable-next-line StatementDeletion: every call is on a failure branch that cannot be reached
      SMB.Engine.Invalidate (State, Invalidate_Status);
      --  adamutant:disable-next-line StatementDeletion: as above
      Value.Stage := Transfer_Failed;
      --  adamutant:disable-next-line StatementDeletion: as above
      Status :=
        --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: as above, and Invalidate only fails after 2**64 epochs
        (if Invalidate_Status = SMB.Ok then Failure else Invalidate_Status);
   end Fail_Transfer;

   procedure Clear_Transfer_Buffer (Buffer : in out SMB.Bytes)
   with Post =>
     (for all Index in Buffer'Range => Buffer (Index) = 0)
   is
   begin
      Buffer := (others => 0);
   end Clear_Transfer_Buffer;

   procedure Clear_Output (Output : out SMB.Bytes)
   with Post => (for all Index in Output'Range => Output (Index) = 0)
   is
   begin
      Output := (others => 0);
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
       Status =
         (if Packet'Length >= Header_Length then SMB.Ok
          else SMB.Invalid_Length)
       and then
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
      --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: every caller checks the output length first
      if Packet'Length < Header_Length
        --  adamutant:disable-next-line LogicalOperator, EqualityOperator: as above
        or else Packet'Length > SMB.Maximum_Frame_Size
      then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
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
      --  adamutant:disable-next-line ConditionalExpression: Invalidate only fails after 2**64 epochs
      Status := (if Invalidate_Status = SMB.Ok then Failure
                 else Invalidate_Status);
   end Fail_Authentication;

   procedure Fail_Negotiate_Preparation
     (Value : in out Authentication;
      Output : out SMB.Bytes)
   with Post =>
     Value.Stage = Authentication_Failed
     and then Value.Owner = Value.Owner'Old
     and then Value.Epoch = Value.Epoch'Old
     and then Value.Session_Id = Value.Session_Id'Old
     and then SMB.Engine."=" (Value.Expected, Value.Expected'Old)
     and then Value.Challenge_Length = 0
     and then
       (for all Index in Value.Challenge'Range =>
          Value.Challenge (Index) = 0)
     and then (for all Index in Output'Range => Output (Index) = 0)
   is
   begin
      --  adamutant:disable-next-line StatementDeletion: Prepare_Negotiate cleared Output, and its builders write nothing before failing
      Clear_Output (Output);
      --  adamutant:disable-next-line StatementDeletion: nothing has been stored before the challenge
      Clear_Authentication_Buffer (Value);
      Value.Stage := Authentication_Failed;
   end Fail_Negotiate_Preparation;

   procedure Prepare_Negotiate
     (Value : in out Authentication;
      State : in out SMB.Engine.Engine_State;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
      Token : SMB.Bytes
        --  adamutant:disable-next-line NumericLiteral: only the bytes Build_Negotiate_Token writes are used
        (0 .. SMB.Core_Auth.Maximum_Security_Token - 1) := (others => 0);
      --  adamutant:disable-next-line NumericLiteral: Build_Negotiate_Token sets it
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
      --  adamutant:disable-next-line ConditionalExpression: the NEGOTIATE token is a constant that fits Token
      if Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Fail_Negotiate_Preparation (Value, Output);
         return;
      end if;
      SMB.Core_Protocol.Build_Session_Setup
        (Token (Token'First .. Token'First + Token_Used - 1),
         Output (Output'First + Header_Length .. Output'Last),
         Body_Used, Status);
      if Status /= SMB.Ok then
         Fail_Negotiate_Preparation (Value, Output);
         return;
      end if;
      SMB.Engine.Begin_Request
        (State, 1, False, False, Message_Id, Expected, Begin_Status);
      --  adamutant:disable-next-line ConditionalExpression: the checks above leave Begin_Request nothing to reject
      if Begin_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Fail_Negotiate_Preparation (Value, Output);
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Status := Begin_Status;
         return;
      end if;
      pragma Assert (Message_Id = Expected.Message_Id);
      Value.Stage := Negotiate_Prepared;
      Value.Owner := SMB.Engine.Current_Owner_Id (State);
      Value.Epoch := SMB.Engine.Current_Epoch (State);
      Value.Expected := Expected;
      --  adamutant:disable-next-line StatementDeletion: an Authentication is ready only before its first use, with its defaults
      Value.Session_Id := 0;
      --  adamutant:disable-next-line StatementDeletion: as above
      Value.Challenge_Length := 0;
      Prepare_Unsigned_Header (Output, Expected, Field_Status);
      --  adamutant:disable-next-line ConditionalExpression: Output holds at least a header, as checked above
      if Field_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Clear_Output (Output);
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
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
         --  adamutant:disable-next-line StatementDeletion: nothing has been stored before the challenge
         Clear_Authentication_Buffer (Value);
         Status := Accept_Status;
         return;
      end if;
      Info := SMB.Engine.Current_Response_Info (State);
      if Nt_Status /= SMB.Status_More_Processing_Required then
         SMB.Engine.Discard_Response_Receipt (State, Receipt_Status);
         --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: the receipt Accept_Response just validated can be discarded
         if Receipt_Status /= SMB.Ok then
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
            Fail_Authentication (Value, State, Receipt_Status, Status);
         else
            SMB.Engine.Invalidate (State, Receipt_Status);
            --  adamutant:disable-next-line StatementDeletion: nothing has been stored before the challenge
            Clear_Authentication_Buffer (Value);
            Value.Stage := Authentication_Failed;
            --  adamutant:disable-next-line ConditionalExpression: the engine rejects an unsigned SUCCESS for SESSION_SETUP
            Status := (if Nt_Status = SMB.Success
                       then SMB.Unsupported_Feature else SMB.Ok);
         end if;
         return;
      end if;
      --  Each of these alone is rejected by the engine first, so no pairing of them can be told apart.
      --  adamutant:disable LogicalOperator
      --  adamutant:disable-next-line ConditionalExpression, NumericLiteral: the engine's response checks reject these first
      if Info.Session_Id = 0
        or else Info.Data_Length > SMB.Core_Auth.Maximum_Security_Token
        or else Info.Data_Offset > Packet'Length
        --  adamutant:disable-next-line ArithmeticOperator: as above
        or else Info.Data_Length > Packet'Length - Info.Data_Offset
      --  adamutant:enable LogicalOperator
      then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Fail_Authentication (Value, State, SMB.Invalid_Protocol, Status);
         return;
      end if;
      --  adamutant:disable-next-line ConditionalExpression, EqualityOperator, NumericLiteral: an empty copy does nothing, and a one-byte token fails Extract_Challenge whatever its byte
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
        --  adamutant:disable-next-line NumericLiteral: only the bytes Authenticate writes are used
        (0 .. SMB.Core_Auth.Maximum_Security_Token - 1) := (others => 0);
      --  adamutant:disable-next-line NumericLiteral: Authenticate sets every byte
      Key : SMB.Crypto.Digest_128 := (others => 0);
      --  adamutant:disable-next-line NumericLiteral: Authenticate sets it
      Token_Used : Natural := 0;
      Body_Used : Natural;
      Message_Id : SMB.QWord;
      Expected : SMB.Engine.Request_Expectation;
      Engine_Status : SMB.Core_Status;
      Field_Status : SMB.Core_Status;
   begin
      Clear_Output (Output);
      Used := 0;
      if Value.Stage /= Challenge_Received
        or else not Authentication_Context_Matches (Value, State)
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      --  adamutant:disable-next-line EqualityOperator: Complete_Challenge stores at most Maximum_Security_Token bytes
      if Value.Challenge_Length >
          SMB.Core_Auth.Maximum_Security_Token
        or else User'Length > SMB.Core_Auth.Maximum_Credential_Bytes
        or else Password'Length > SMB.Core_Auth.Maximum_Credential_Bytes
        or else Domain'Length > SMB.Core_Auth.Maximum_Credential_Bytes
        or else Nonce'Length /= 8
        --  adamutant:disable-next-line EqualityOperator: a header-sized output fails Build_Session_Setup with the same status
        or else Output'Length < Header_Length
        --  adamutant:disable-next-line EqualityOperator: as above
        or else Output'First > Natural'Last - Header_Length
      then
         Fail_Authentication (Value, State, SMB.Resource_Limit, Status);
         return;
      end if;
      SMB.Core_Auth.Authenticate
        (User, Password, Domain, Nonce,
         Value.Challenge (0 .. Value.Challenge_Length - 1),
         Current_Filetime, Token, Token_Used, Key, Status);
      --  adamutant:disable-next-line LogicalOperator, NumericLiteral: a successful Authenticate always writes a token
      if Status /= SMB.Ok or else Token_Used = 0 then
         --  adamutant:disable-next-line ConditionalExpression: as above
         if Status = SMB.Ok then
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
            Status := SMB.Resource_Limit;
         end if;
         declare
            Failure : constant SMB.Core_Status := Status;
         begin
            --  adamutant:disable-next-line StatementDeletion: wipes a local secret that nothing reads afterwards
            Clear_Output (Key);
            --  adamutant:disable-next-line StatementDeletion: wipes a local secret that nothing reads afterwards
            Clear_Output (Token);
            Fail_Authentication (Value, State, Failure, Status);
         end;
         return;
      end if;
      SMB.Core_Protocol.Build_Session_Setup
        (Token (Token'First .. Token'First + Token_Used - 1),
         Output (Output'First + Header_Length .. Output'Last),
         Body_Used, Engine_Status);
      if Engine_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: Output was cleared on entry, and Build_Session_Setup clears its part even when it fails
         Clear_Output (Output);
         --  adamutant:disable-next-line StatementDeletion: wipes a local secret that nothing reads afterwards
         Clear_Output (Key);
         --  adamutant:disable-next-line StatementDeletion: wipes a local secret that nothing reads afterwards
         Clear_Output (Token);
         Fail_Authentication (Value, State, Engine_Status, Status);
         return;
      end if;
      SMB.Engine.Install_Session_Key
        (State, Value.Session_Id, Key, Engine_Status);
      if Engine_Status /= SMB.Ok then
         Clear_Output (Output);
         --  adamutant:disable-next-line StatementDeletion: wipes a local secret that nothing reads afterwards
         Clear_Output (Key);
         --  adamutant:disable-next-line StatementDeletion: wipes a local secret that nothing reads afterwards
         Clear_Output (Token);
         Fail_Authentication (Value, State, Engine_Status, Status);
         return;
      end if;
      SMB.Engine.Begin_Request
        (State, 1, False, True, Message_Id, Expected, Engine_Status);
      --  adamutant:disable-next-line ConditionalExpression: after Install_Session_Key succeeds, the state meets every condition of Begin_Request
      if Engine_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Clear_Output (Output);
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Clear_Output (Key);
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Clear_Output (Token);
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Fail_Authentication (Value, State, Engine_Status, Status);
         return;
      end if;
      Value.Expected := Expected;
      Value.Stage := Authenticate_Prepared;
      Prepare_Unsigned_Header (Output, Expected, Field_Status);
      --  adamutant:disable-next-line ConditionalExpression: Output holds at least a header, as checked above
      if Field_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Clear_Output (Output);
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Clear_Output (Key);
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Clear_Output (Token);
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
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
      --  adamutant:disable-next-line StatementDeletion: wipes a local secret that nothing reads afterwards
      Clear_Output (Key);
      --  adamutant:disable-next-line StatementDeletion: wipes a local secret that nothing reads afterwards
      Clear_Output (Token);
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
      Initial_Command : constant SMB.Core_Wire.Command_Code :=
        SMB.Engine.Pending_Command (State)
      with Ghost;
      Initial_Session : constant SMB.QWord :=
        SMB.Engine.Current_Session_Id (State)
      with Ghost;
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
         --  adamutant:disable-next-line StatementDeletion: Invalidate below drops the receipt as well
         SMB.Engine.Discard_Response_Receipt (State, Receipt_Status);
         SMB.Engine.Invalidate (State, Invalidate_Status);
         Clear_Authentication_Buffer (Value);
         Value.Stage := Authentication_Failed;
         Status := SMB.Ok;
         return;
      end if;
      pragma Assert
        (if Initial_Command = 1 then
           SMB.Engine.Final_Token_MIC_Matches
             (Packet, SMB.Engine.Current_Response_Info (State),
              SMB.Core_NTLM.Mechanism_List_MIC
                (SMB.Crypto.Digest_128
                   (SMB.Engine.Current_Signing_Key (State)), True)));
      declare
         Info_Before : constant SMB.Core_Protocol.Response_Info :=
           SMB.Engine.Current_Response_Info (State)
         with Ghost;
         Key_Before : constant SMB.Crypto.Digest_128 :=
           SMB.Crypto.Digest_128 (SMB.Engine.Current_Signing_Key (State))
         with Ghost;
         Expected_MIC : constant SMB.Crypto.Digest_128 :=
           SMB.Core_NTLM.Mechanism_List_MIC (Key_Before, True)
         with Ghost;
         MIC_Before : constant Boolean :=
           SMB.Engine.Final_Token_MIC_Matches
             (Packet, Info_Before, Expected_MIC)
         with Ghost;
      begin
         pragma Assert (if Initial_Command = 1 then MIC_Before);
         SMB.Engine.Mark_Authenticated (State, Status);
         --  adamutant:disable-next-line ConditionalExpression: Accept_Response already checked the final token's MIC, which is all Mark_Authenticated checks here
         if Status = SMB.Ok then
            pragma Assert (Initial_Command = 1);
            pragma Assert
              (SMB.Core_Protocol."="
                 (SMB.Engine.Current_Response_Info (State), Info_Before)
               and then SMB.Crypto.Digest_128
                 (SMB.Engine.Current_Signing_Key (State)) = Key_Before);
            pragma Assert
              (SMB.Core_NTLM.Mechanism_List_MIC
                 (SMB.Crypto.Digest_128
                    (SMB.Engine.Current_Signing_Key (State)), True) =
               Expected_MIC);
            pragma Assert (MIC_Before);
            --  adamutant:disable-next-line StatementDeletion: a lemma: it only guides the proof
            SMB.Engine.Lemma_Final_Token_MIC_Transfer
              (Packet, Info_Before, SMB.Engine.Current_Response_Info (State),
               Expected_MIC,
               SMB.Core_NTLM.Mechanism_List_MIC
                 (SMB.Crypto.Digest_128
                    (SMB.Engine.Current_Signing_Key (State)), True));
            Clear_Authentication_Buffer (Value);
            Value.Stage := Authentication_Finished;
            pragma Assert (Value.Stage = Authentication_Finished);
            pragma Assert (not SMB.Engine.Has_Pending_Request (State));
            pragma Assert (not SMB.Engine.Has_Validated_Response (State));
            pragma Assert
              (SMB.Engine.Current_Response_Info (State).Session_Id =
               SMB.Engine.Current_Session_Id (State));
            pragma Assert
              (SMB.Engine.Current_Session_Id (State) = Initial_Session);
            pragma Assert
              (SMB.Engine.Final_Token_MIC_Matches
                 (Packet, SMB.Engine.Current_Response_Info (State),
                  SMB.Core_NTLM.Mechanism_List_MIC
                    (SMB.Crypto.Digest_128
                       (SMB.Engine.Current_Signing_Key (State)), True)));
            pragma Assert (Authentication_Context_Matches (Value, State));
         else
            --  adamutant:disable-next-line StatementDeletion: unreachable: Accept_Response already checked the MIC
            Failure_Status := Status;
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
            SMB.Engine.Invalidate (State, Invalidate_Status);
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
            Clear_Authentication_Buffer (Value);
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
            Value.Stage := Authentication_Failed;
            --  adamutant:disable-next-line StatementDeletion, ConditionalExpression, EqualityOperator: unreachable, as above
            Status := (if Invalidate_Status = SMB.Ok then Failure_Status
                       else Invalidate_Status);
         end if;
      end;
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
      --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: an empty copy does nothing
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
      --  adamutant:disable-next-line StatementDeletion: every call is on a failure branch that cannot be reached
      SMB.Engine.Invalidate (State, Invalidate_Status);
      --  adamutant:disable-next-line StatementDeletion: as above
      Value.Stage := Failed;
      --  adamutant:disable-next-line StatementDeletion: as above
      Status :=
        --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: as above, and Invalidate only fails after 2**64 epochs
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
      --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: every caller checks the output length first
      if Packet'Length < Header_Length then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Status := SMB.Invalid_Length;
         return;
      end if;
      SMB.Core_Wire.Initialize_Header
        (Packet, Expected.Command, Expected.Message_Id, Expected.Tree_Id,
         Expected.Session_Id, 1, Field_Status);
      --  adamutant:disable-next-line ConditionalExpression: as above
      if Field_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Status := Field_Status;
         return;
      end if;
      SMB.Core_Wire.Write_U32 (Packet, 16, 8, Status);
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
      --  adamutant:disable-next-line NumericLiteral: Validate_Handle sets every out parameter
      File_Id : SMB.Bytes (0 .. 15) := (others => 0);
      Access_Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
      --  adamutant:disable-next-line BooleanLiteral: Validate_Handle sets every out parameter
      Is_Directory : Boolean := False;
      Handle_Status : SMB.Core_Status;
   begin
      --  Validate_Handle rejects the same states, so no pairing of these can be told apart.
      --  adamutant:disable LogicalOperator
      --  adamutant:disable-next-line ConditionalExpression: Validate_Handle rejects the same states: the token carries the owner and epoch, and handles exist only on a connected share
      if Value.Owner /= SMB.Engine.Current_Owner_Id (State)
        or else Value.Epoch /= SMB.Engine.Current_Epoch (State)
        or else SMB.Engine.Current_Phase (State) /=
          SMB.Engine.Share_Connected
      --  adamutant:enable LogicalOperator
      then
         return False;
      end if;
      SMB.Engine.Validate_Handle
        --  adamutant:disable-next-line BooleanLiteral: Start_Directory checked read access, which a handle keeps
        (State, Value.Token, True, False, File_Id, Access_Mode,
         Is_Directory, Handle_Status);
      --  A failed lookup clears its outputs and a token's handle does not change, so every pairing of these fails the same way.
      --  adamutant:disable LogicalOperator
      if Handle_Status /= SMB.Ok
        or else not Is_Directory
        or else File_Id /= Value.File_Id
        or else Access_Mode /= Value.Access_Mode
      --  adamutant:enable LogicalOperator
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
        --  adamutant:disable-next-line ConditionalExpression: Invalidate only fails after 2**64 epochs
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
      --  adamutant:disable-next-line NumericLiteral: Validate_Handle sets every out parameter
      Id : SMB.Bytes (0 .. 15) := (others => 0);
      Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
      --  adamutant:disable-next-line BooleanLiteral: Validate_Handle sets every out parameter
      Is_Directory : Boolean := False;
      S : SMB.Core_Status;
   begin
      --  The expectation comes from Begin_Request, and Validate_Handle rejects the other states the same way, so no pairing of these can be told apart.
      --  adamutant:disable LogicalOperator
      --  adamutant:disable-next-line ConditionalExpression: the expectation comes from Begin_Request in Prepare_Metadata, and Validate_Handle rejects the other states the same way
      if Value.Expected.Command /= 17
        or else not Value.Expected.Signed
        or else not Value.Expected.Request_Signed
        or else Value.Owner /= SMB.Engine.Current_Owner_Id (State)
        or else Value.Epoch /= SMB.Engine.Current_Epoch (State)
        or else SMB.Engine.Current_Phase (State) /=
          SMB.Engine.Share_Connected
      --  adamutant:enable LogicalOperator
      then
         return False;
      end if;
      SMB.Engine.Validate_Handle
        (State, Value.Token, False, False, Id, Mode, Is_Directory, S);
      --  A failed lookup clears its outputs and a token's handle does not change, so every pairing of these fails the same way.
      --  adamutant:disable LogicalOperator
      --  adamutant:disable-next-line ConditionalExpression: a handle cannot close while its SET_INFO is in flight, and a token's handle does not change
      if S /= SMB.Ok
        or else Id /= Value.File_Id
        or else Mode /= Value.Access_Mode
        or else Is_Directory /= Value.Directory
      --  adamutant:enable LogicalOperator
      then
         --  adamutant:disable-next-line BooleanLiteral: unreachable, as above
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
      --  adamutant:disable-next-line StatementDeletion: every call is on a failure branch that cannot be reached
      SMB.Engine.Invalidate (State, S);
      --  adamutant:disable-next-line StatementDeletion: as above
      Value.Stage := Metadata_Failed;
      --  adamutant:disable-next-line StatementDeletion, ConditionalExpression, EqualityOperator: as above
      Status := (if S = SMB.Ok then Failure else S);
   end Fail_Metadata;

   --  Bytes equal one by one make equal slices. Proved on its own: in
   --  Prepare_Metadata's context GNATprove 16 times out on it. The offsets
   --  count from Target'First, so a caller computes no index.
   procedure Lemma_Slice_Equals
     (Target, Source : SMB.Bytes; First, Last : Natural)
   with Ghost,
     Pre => Target'Length <= SMB.Maximum_Frame_Size
       and then Source'Length <= SMB.Core_Protocol.Maximum_Name_Bytes
       and then
         (if Source'Length > 0 then
            First <= Last
            and then Last < Target'Length
            and then Last - First + 1 = Source'Length
            and then
              (for all Index in 0 .. Source'Length - 1 =>
                 Target (Target'First + First + Index) =
                   Source (Source'First + Index))),
     Post =>
       (if Source'Length > 0 then
          Target (Target'First + First .. Target'First + Last) = Source)
   is
   begin
      null;
   end Lemma_Slice_Equals;

   --  Writes the header of a request whose body is in place, then signs it.
   --  A procedure of its own, with the name in the body in its contract, so
   --  that GNATprove carries the name through both steps in a small context;
   --  inside Prepare_Metadata, GNATprove 16 times out on it.
   procedure Seal_Request
     (Output : in out SMB.Bytes;
      Need : Natural;
      Expected : SMB.Engine.Request_Expectation;
      Key : SMB.Bytes;
      Name : SMB.Bytes;
      Status : out SMB.Core_Status)
   with
     Pre =>
       Output'Length <= SMB.Maximum_Frame_Size
       and then Need >= Header_Length
       and then Need <= Output'Length
       and then Key'Length <= SMB.Maximum_Frame_Size
       and then Name'Length <= SMB.Core_Protocol.Maximum_Name_Bytes
       and then
         (if Name'Length > 0 then
            Header_Length + 52 + Name'Length <= Output'Length
            and then
              (for all Index in 0 .. Name'Length - 1 =>
                 Output (Output'First + Header_Length + 52 + Index) =
                   Name (Name'First + Index))),
     Post =>
       (if Status = SMB.Ok then
          SMB.Core_Wire.Encoded_U16 (Output, 4) = 64
          and then SMB.Core_Wire.Encoded_U16 (Output, 12) =
            SMB.Word (Expected.Command)
          and then SMB.Core_Wire.Encoded_U64 (Output, 24) =
            Expected.Message_Id
          and then SMB.Core_Wire.Encoded_U32 (Output, 36) =
            Expected.Tree_Id
          and then SMB.Core_Wire.Encoded_U64 (Output, 40) =
            Expected.Session_Id
          and then SMB.Core_Wire.Encoded_U32 (Output, 16) = 8
          and then
            (for all Index in Output'Range =>
               (if Index - Output'First >= Header_Length
                then Output (Index) = Output'Old (Index)))
          and then
            (if Name'Length > 0 then
               (for all Index in 0 .. Name'Length - 1 =>
                  Output (Output'First + Header_Length + 52 + Index) =
                    Name (Name'First + Index))))
   is
      pragma Unreferenced (Name);
      E : SMB.Core_Status;
   begin
      Prepare_Header (Output, Expected, Status);
      --  adamutant:disable-next-line ConditionalExpression: the precondition leaves room for the header
      if Status = SMB.Ok then
         Sign_Packet (Output, Need, Key, E);
         --  adamutant:disable-next-line StatementDeletion: Sign_Packet cannot fail on a whole request
         Status := E;
      end if;
   end Seal_Request;

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
       and then (if Kind = Disposition_Metadata then Name'Length = 0)
       and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if not Metadata_Preparation_Context_Matches
               (Metadata_Snapshot_Of (Value), State, Token)'Old
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
                (Metadata_Snapshot_Of (Value), State, Token)'Old
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
      --  adamutant:disable-next-line NumericLiteral: Validate_Handle sets every out parameter
      Id : SMB.Bytes (0 .. 15) := (others => 0);
      Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
      --  adamutant:disable-next-line BooleanLiteral: Validate_Handle sets every out parameter
      Dir : Boolean := False;
      S, B : SMB.Core_Status;
      Body_Used : Natural;
      Need : constant Natural :=
        (if Kind = Disposition_Metadata then Header_Length + 33
         else Header_Length + 52 + Name'Length);
      --  adamutant:disable-next-line NumericLiteral: Begin_Request sets it
      Message : SMB.QWord := 0;
      Expected : SMB.Engine.Request_Expectation;
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
            --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: the branch holds only an assertion
            if B = SMB.Ok then
               pragma Assert
                 (for all Index in 10 .. 15 => Body_Buffer (Index) = 0);
            end if;
         else
            SMB.Core_Protocol.Build_Rename
              (Id, Name, Body_Buffer, Body_Used, B);
            --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: the branch holds only assertions
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
         --  adamutant:disable-next-line ConditionalExpression: the builders cannot fail on a checked name and buffer
         if B /= SMB.Ok then
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
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
        ((for all Index in 10 .. 15 =>
              Output (Output'First + Header_Length + Index) = 0)
           and then
             (if Kind = Rename_Metadata then
                (for all Index in 0 .. Name'Length - 1 =>
                   Output (Output'First + Header_Length + 52 + Index) =
                     Name (Name'First + Index))));
      SMB.Engine.Begin_Request
        (State, 17, True, True, Message, Expected, S);
      --  adamutant:disable-next-line ConditionalExpression: the checks above leave Begin_Request nothing to reject
      if S /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
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
      --  Keep only what the rest of the procedure needs. With everything
      --  before this point in context, GNATprove 16 times out even on direct
      --  consequences of Seal_Request's postcondition.
      pragma Assert_And_Cut
        (Kind in Rename_Metadata | Disposition_Metadata
         and then Name'Length <= SMB.Core_Protocol.Maximum_Name_Bytes
         and then (if Kind = Disposition_Metadata then Name'Length = 0)
         and then
           (if Kind = Rename_Metadata then
              Name'Length > 0 and then Name'Length mod 2 = 0)
         and then Output'Length <= SMB.Maximum_Frame_Size
         and then Need =
           (if Kind = Disposition_Metadata then Header_Length + 33
            else Header_Length + 52 + Name'Length)
         and then Need <= Output'Length
         and then Old_Metadata.Stage = Metadata_Idle
         and then Metadata_Preparation_Context_Matches
           (Old_Metadata, Before_Begin, Token)
         and then Value.Stage = Metadata_Prepared
         and then Value.Kind = Kind
         and then Value.Owner = SMB.Engine.Current_Owner_Id (State)
         and then Value.Epoch = SMB.Engine.Current_Epoch (State)
         and then Value.Token = Token
         and then Value.Token.Owner = Value.Owner
         and then Value.Token.Epoch = Value.Epoch
         and then Value.Token.Ticket /= 0
         and then Value.Delete_File = Delete_File
         and then Value.Name_Length = Name'Length
         and then SMB.Engine."=" (Value.Expected, Expected)
         and then SMB.Engine.Pending_Request_Matches (State, Expected)
         and then Expected.Command = 17
         and then Expected.Request_Signed
         and then Expected.Signed
         and then Expected.Request_Amount = 0
         and then SMB.Engine.Handle_Matches
           (Before_Begin, Token, Value.File_Id, Value.Access_Mode,
            Value.Directory)
         and then SMB.Engine.Handle_Matches_In_States
           (Before_Begin, State, Token, Value.File_Id, Value.Access_Mode,
            Value.Directory)
         and then SMB.Engine.Handle_Matches
           (State, Token, Value.File_Id, Value.Access_Mode, Value.Directory)
         and then SMB.Core_Wire.Encoded_U16 (Output, Header_Length) = 33
         and then Output (Output'First + Header_Length + 2) = 1
         and then SMB.Core_Wire.Encoded_U16 (Output, Header_Length + 8) = 96
         and then
           (for all Index in 10 .. 15 =>
              Output (Output'First + Header_Length + Index) = 0)
         and then
           (for all Index in 0 .. 15 =>
              Output (Output'First + Header_Length + 16 + Index) =
                Value.File_Id (Value.File_Id'First + Index))
         and then
           (if Kind = Disposition_Metadata then
              Output (Output'First + Header_Length + 3) = 13
              and then SMB.Core_Wire.Encoded_U32
                (Output, Header_Length + 4) = 1
              and then Output (Output'First + Header_Length + 32) =
                (if Delete_File then 1 else 0)
            else
              Output (Output'First + Header_Length + 3) = 10
              and then SMB.Core_Wire.Encoded_U32
                (Output, Header_Length + 4) = SMB.DWord (20 + Name'Length)
              and then
                (for all Index in 32 .. 47 =>
                   Output (Output'First + Header_Length + Index) = 0)
              and then SMB.Core_Wire.Encoded_U32
                (Output, Header_Length + 48) = SMB.DWord (Name'Length)
              and then
                (for all Index in 0 .. Name'Length - 1 =>
                   Output (Output'First + Header_Length + 52 + Index) =
                     Name (Name'First + Index))));
      Seal_Request
        (Output, Need, Expected, SMB.Engine.Current_Signing_Key (State),
         Name, S);
      pragma Assert
        (if S = SMB.Ok then
           (for all Index in 10 .. 15 =>
              Output (Output'First + Header_Length + Index) = 0));
      --  adamutant:disable-next-line ConditionalExpression: as above
      if S /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Fail_Metadata (Value, State, S, Status);
         --  adamutant:disable-next-line StatementDeletion, NumericLiteral: unreachable, as above
         Used := 0;
         return;
      end if;
      Used := Need;
      pragma Assert
        ((for all Index in 10 .. 15 =>
              Output (Output'First + Header_Length + Index) = 0)
           and then
             (if Kind = Rename_Metadata then
                (for all Index in 0 .. Name'Length - 1 =>
                   Output (Output'First + Header_Length + 52 + Index) =
                     Name (Name'First + Index))));
      --  The parts of Metadata_Packet_Matches, one by one.
      pragma Assert
        (Value.Stage = Metadata_Prepared
         and then Value.Kind in Rename_Metadata | Disposition_Metadata
         and then Value.Owner = SMB.Engine.Current_Owner_Id (State)
         and then Value.Epoch = SMB.Engine.Current_Epoch (State)
         and then Value.Token.Owner = Value.Owner
         and then Value.Token.Epoch = Value.Epoch
         and then Value.Token.Ticket /= 0);
      pragma Assert
        (SMB.Engine.Pending_Request_Matches (State, Value.Expected)
         and then Value.Expected.Command = 17
         and then Value.Expected.Request_Signed
         and then Value.Expected.Signed
         and then Value.Expected.Request_Amount = 0
         and then Value.Name_Length <= SMB.Core_Protocol.Maximum_Name_Bytes);
      pragma Assert
        (Used <= Output'Length
         and then Used =
           (if Value.Kind = Disposition_Metadata
            then SMB.Core_Wire.Header_Size + 33
            else SMB.Core_Wire.Header_Size + 52 + Value.Name_Length));
      pragma Assert
        (SMB.Core_Wire.Encoded_U16 (Output, 4) =
           SMB.Word (SMB.Core_Wire.Header_Size)
         and then SMB.Core_Wire.Encoded_U16 (Output, 12) = 17
         and then SMB.Core_Wire.Encoded_U32 (Output, 16) = 8);
      pragma Assert
        (SMB.Core_Wire.Encoded_U64 (Output, 24) = Value.Expected.Message_Id
         and then SMB.Core_Wire.Encoded_U32 (Output, 36) =
           Value.Expected.Tree_Id
         and then SMB.Core_Wire.Encoded_U64 (Output, 40) =
           Value.Expected.Session_Id);
      pragma Assert
        (SMB.Core_Wire.Encoded_U16 (Output, SMB.Core_Wire.Header_Size) = 33
         and then Output (Output'First + SMB.Core_Wire.Header_Size + 2) = 1
         and then SMB.Core_Wire.Encoded_U16
           (Output, SMB.Core_Wire.Header_Size + 8) = 96);
      pragma Assert
        (for all Index in 0 .. 15 =>
           Output (Output'First + SMB.Core_Wire.Header_Size + 16 + Index) =
             Value.File_Id (Value.File_Id'First + Index));
      pragma Assert
        (if Value.Kind = Disposition_Metadata then
           Output (Output'First + SMB.Core_Wire.Header_Size + 3) = 13
           and then SMB.Core_Wire.Encoded_U32
             (Output, SMB.Core_Wire.Header_Size + 4) = 1
           and then Output (Output'First + SMB.Core_Wire.Header_Size + 32) =
             (if Value.Delete_File then 1 else 0)
         else
           Output (Output'First + SMB.Core_Wire.Header_Size + 3) = 10
           and then SMB.Core_Wire.Encoded_U32
             (Output, SMB.Core_Wire.Header_Size + 4) =
               SMB.DWord (20 + Value.Name_Length)
           and then
             (for all Index in 32 .. 47 =>
                Output (Output'First + SMB.Core_Wire.Header_Size + Index) = 0)
           and then SMB.Core_Wire.Encoded_U32
             (Output, SMB.Core_Wire.Header_Size + 48) =
               SMB.DWord (Value.Name_Length));
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
      Lemma_Slice_Equals (Output, Name, Header_Length + 52, Need - 1);
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
                        --  adamutant:disable-next-line NumericLiteral: an empty aggregate has no element to set
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
         --  adamutant:disable-next-line ConditionalExpression: the receipt Accept_Response just validated can be discarded
         if Receipt_Status /= SMB.Ok then
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
            Fail_Metadata (Value, State, Receipt_Status, Status);
            return;
         end if;
         pragma Assert
           (SMB.Engine.Handle_Matches_In_States
              (Before_Discard, State, Value.Token, Value.File_Id,
               Value.Access_Mode, Value.Directory));
      end;
      Value.Stage := Metadata_Finished;
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
      --  adamutant:disable-next-line NumericLiteral: Validate_Handle sets every out parameter
      File_Id : SMB.Bytes (0 .. 15) := (others => 0);
      Access_Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
      --  adamutant:disable-next-line BooleanLiteral: Validate_Handle sets every out parameter
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
      --  adamutant:disable-next-line StatementDeletion: a Directory_Enumeration starts only once, from its defaults
      Value.Expected := (others => <>);
      --  adamutant:disable-next-line StatementDeletion, NumericLiteral: as above
      Value.Page_Length := 0;
      --  adamutant:disable-next-line StatementDeletion: as above
      Value.Cursor := 0;
      --  adamutant:disable-next-line StatementDeletion: as above
      Value.Page_Count := 0;
      --  adamutant:disable-next-line StatementDeletion: as above
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
      --  adamutant:disable-next-line NumericLiteral: Validate_Handle sets every out parameter
      File_Id : SMB.Bytes (0 .. 15) := (others => 0);
      --  adamutant:disable-next-line BooleanLiteral: Validate_Handle sets every out parameter
      Is_Directory : Boolean := False;
      Validate_Status : SMB.Core_Status;
      Field_Status : SMB.Core_Status;
      Begin_Status : SMB.Core_Status;
      Count_Status : SMB.Core_Status;
      Sign_Status : SMB.Core_Status;
      --  adamutant:disable-next-line NumericLiteral: Build_Query_Directory sets it
      Body_Used : Natural := 0;
      --  adamutant:disable-next-line NumericLiteral: Begin_Request sets it
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
        --  adamutant:disable-next-line BooleanLiteral: Start_Directory checked read access, which a handle keeps
        (State, Value.Token, True, False, File_Id, Access_Mode,
         Is_Directory, Validate_Status);
      --  A failed lookup clears its outputs and a token's handle does not change, so every pairing of these fails the same way.
      --  adamutant:disable LogicalOperator
      --  adamutant:disable-next-line ConditionalExpression: Directory_Context_Valid made this lookup above
      if Validate_Status /= SMB.Ok
        or else not Is_Directory
        or else File_Id /= Value.File_Id
        or else Access_Mode /= Value.Access_Mode
      --  adamutant:enable LogicalOperator
      then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
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
      --  adamutant:disable-next-line ConditionalExpression, LogicalOperator: Build_Query_Directory cannot fail on a checked output and writes 34 bytes
      if Field_Status /= SMB.Ok or else Body_Used /= 34 then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Fail_Directory
           (Value,
            State,
            --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: unreachable, as above
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
      --  adamutant:disable-next-line ConditionalExpression: the checks above leave Begin_Request nothing to reject
      if Begin_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Fail_Directory (Value, State, Begin_Status, Status);
         return;
      end if;
      Value.Expected := Expected;
      pragma Assert (Value.Expected.Tree_Id = Expected.Tree_Id);
      Value.Stage := Query_Prepared;
      Used := Header_Length + Body_Used;
      Prepare_Header (Output, Expected, Field_Status);
      --  adamutant:disable-next-line ConditionalExpression: Output holds at least a header, as checked above
      if Field_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Fail_Directory (Value, State, Field_Status, Status);
         --  adamutant:disable-next-line StatementDeletion, NumericLiteral: unreachable, as above
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
      --  adamutant:disable-next-line ConditionalExpression: Sign_Packet cannot fail on a whole request
      if Sign_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Fail_Directory (Value, State, Sign_Status, Status);
         --  adamutant:disable-next-line StatementDeletion, NumericLiteral: unreachable, as above
         Used := 0;
         return;
      end if;
      pragma Assert
        (SMB.Core_Wire.Encoded_U32 (Output, 36) = Expected.Tree_Id);
      SMB.Core_Protocol.Count_Directory_Page
        (Value.Page_Count, Count_Status);
      --  adamutant:disable-next-line ConditionalExpression: the page limit was checked before anything was written
      if Count_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Fail_Directory (Value, State, Count_Status, Status);
         --  adamutant:disable-next-line StatementDeletion, NumericLiteral: unreachable, as above
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
      --  An error response carries no data, so it ends the listing whichever of these holds.
      --  adamutant:disable LogicalOperator
      if Nt_Status /= SMB.Success
        or else Nt_Status = SMB.Status_No_More_Files
        or else Info.Data_Length = 0
      --  adamutant:enable LogicalOperator
      then
         Value.Page_Length := 0;
         Value.Cursor := 0;
         Value.Stage := Directory_Finished;
         SMB.Engine.Discard_Response_Receipt (State, Receipt_Status);
         --  adamutant:disable-next-line ConditionalExpression: the receipt Accept_Response just validated can be discarded
         if Receipt_Status /= SMB.Ok then
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
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
         --  The engine's QUERY_DIRECTORY checks reject each of these first, so no pairing of them can be told apart.
         --  adamutant:disable LogicalOperator
         --  adamutant:disable-next-line ConditionalExpression, NumericLiteral: the engine's QUERY_DIRECTORY checks reject these first
         if Response_Length_Value = 0
           --  adamutant:disable-next-line EqualityOperator: as above
           or else Response_Length_Value >
             SMB.DWord (SMB.Core_Protocol.Maximum_IO_Chunk)
           --  adamutant:disable-next-line EqualityOperator: as above
           or else Response_Offset > Packet'Length
           or else Natural (Response_Length_Value) >
             --  adamutant:disable-next-line ArithmeticOperator: as above
             Packet'Length - Response_Offset
           or else Response_Offset < 72
           or else Info.Data_Offset /= Response_Offset
           or else Info.Data_Length /= Natural (Response_Length_Value)
         --  adamutant:enable LogicalOperator
         then
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
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
      --  adamutant:disable-next-line ConditionalExpression: the receipt Accept_Response just validated can be discarded
      if Receipt_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
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
         --  adamutant:disable-next-line StatementDeletion: the stage is Page_Ready already
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
      if Name'Length mod 2 /= 0
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
      --  adamutant:disable-next-line ConditionalExpression: Begin_Request returns the expectation it reserved
      if Message_Id /= Expected.Message_Id then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
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
      --  adamutant:disable-next-line ConditionalExpression: Output holds the request, as checked above
      if Field_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
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
      --  adamutant:disable-next-line ConditionalExpression: Build_Create cannot fail on a checked name and output
      if Field_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
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
      --  adamutant:disable-next-line ConditionalExpression: Sign_Packet cannot fail on a whole request
      if Field_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
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
      --  adamutant:disable-next-line ConditionalExpression: Begin_Request rejects the same close token with the same status
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
      --  adamutant:disable-next-line ConditionalExpression: Begin_Request returns the expectation it reserved
      if Message_Id /= Expected.Message_Id then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
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
      --  adamutant:disable-next-line ConditionalExpression: Build_Close cannot fail on a checked output
      if Field_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Fail_After_Reservation (Value, State, Field_Status, Status);
         return;
      end if;
      Prepare_Header
        (Output (Output'First .. Output'First + (Required - 1)),
         Expected, Field_Status);
      --  adamutant:disable-next-line ConditionalExpression: Output holds the request, as checked above
      if Field_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Fail_After_Reservation (Value, State, Field_Status, Status);
         return;
      end if;
      SMB.Core_Wire.Sign
        (Output (Output'First .. Output'First + (Required - 1)),
         Key, Field_Status);
      --  adamutant:disable-next-line ConditionalExpression: signing cannot fail on a whole request
      if Field_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
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
      --  adamutant:disable-next-line StatementDeletion, NumericLiteral: only contracts read the access mask, and a CLOSE never sends one
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
         --  adamutant:disable-next-line ConditionalExpression: Begin_Request refused a CREATE without a free slot, and the receipt holds the File_Id registered; a CLOSE receipt names its handle
         if Receipt_Status /= SMB.Ok then
            declare
               Invalidate_Status : SMB.Core_Status;
            begin
               --  adamutant:disable-next-line StatementDeletion: unreachable, as above
               SMB.Engine.Invalidate (State, Invalidate_Status);
               --  adamutant:disable-next-line StatementDeletion: unreachable, as above
               Status :=
                 --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: unreachable, as above
                 (if Invalidate_Status = SMB.Ok
                  then Receipt_Status else Invalidate_Status);
            end;
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
            Value.Stage := Failed;
            return;
         end if;
      else
         SMB.Engine.Discard_Response_Receipt (State, Receipt_Status);
         --  adamutant:disable-next-line ConditionalExpression: the receipt Accept_Response just validated can be discarded
         if Receipt_Status /= SMB.Ok then
            declare
               Invalidate_Status : SMB.Core_Status;
            begin
               --  adamutant:disable-next-line StatementDeletion: unreachable, as above
               SMB.Engine.Invalidate (State, Invalidate_Status);
               --  adamutant:disable-next-line StatementDeletion: unreachable, as above
               Status :=
                 --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: unreachable, as above
                 (if Invalidate_Status = SMB.Ok
                  then Receipt_Status else Invalidate_Status);
            end;
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
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
      --  adamutant:disable-next-line StatementDeletion: a transfer never records a directory
      Value.Directory := False;
      Value.Initial_Offset := Offset;
      Value.Position := Offset;
      Value.Total := Total;
      Value.Completed := 0;
      Value.Remaining := Total;
      Value.Requested := 0;
      --  adamutant:disable-next-line StatementDeletion: Prepare_Next sets the expectation before anything reads it
      Value.Expected := (others => <>);
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
      --  adamutant:disable-next-line StatementDeletion: a transfer never records a directory
      Value.Directory := False;
      Value.Initial_Offset := Offset;
      Value.Position := Offset;
      Value.Total := Data'Length;
      Value.Completed := 0;
      Value.Remaining := Data'Length;
      Value.Requested := 0;
      --  adamutant:disable-next-line StatementDeletion: Prepare_Next sets the expectation before anything reads it
      Value.Expected := (others => <>);
      if Data'Length > 0 then
         Value.Buffer := Data;
      end if;
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
         --  adamutant:disable-next-line EqualityOperator: Start_Read and Start_Write checked the handle's access, which does not change
         Value.Kind = Read_Transfer, Value.Kind = Write_Transfer,
         File_Id, Access_Mode, Directory, Status);
      --  adamutant:disable-next-line ConditionalExpression: a failed lookup returns a zero File_Id, which fails the check below with the same status
      if Status /= SMB.Ok then
         Value.Stage := Transfer_Failed;
         return;
      end if;
      --  A token's handle does not change, so none of these can hold.
      --  adamutant:disable LogicalOperator
      --  adamutant:disable-next-line ConditionalExpression: a token's handle does not change, and a failed lookup failed above
      if Directory or else File_Id /= Value.File_Id
        or else Access_Mode /= Value.Access_Mode
      --  adamutant:enable LogicalOperator
      then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Value.Stage := Transfer_Failed;
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Status := SMB.Invalid_Handle_Status;
         return;
      end if;
      SMB.Core_Protocol.Select_Transfer_Amount
        (Value.Remaining,
         Natural'Min (Limit, SMB.Core_Protocol.Maximum_IO_Chunk),
         Amount, Status);
      --  adamutant:disable-next-line ConditionalExpression, LogicalOperator: a ready transfer has bytes left and the negotiated sizes are nonzero
      if Status /= SMB.Ok or else Amount = 0 then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Value.Stage := Transfer_Failed;
         --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: unreachable, as above
         if Status = SMB.Ok then
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
            Status := SMB.Invalid_Value;
         end if;
         return;
      end if;
      Body_Length :=
        (if Value.Kind = Read_Transfer then 49 else 48 + Amount);
      --  adamutant:disable-next-line EqualityOperator: a header-sized output fails the body check below with the same status
      if Output'Length < Header_Length
        or else Body_Length > Output'Length - Header_Length
      then
         Value.Stage := Transfer_Failed;
         Status := SMB.Resource_Limit;
         return;
      end if;
      declare
         Body_Size : constant Natural := Body_Length;
         --  adamutant:disable-next-line ArithmeticOperator, NumericLiteral: a larger buffer holds the same body
         Body_Buffer : SMB.Bytes (0 .. Body_Size - 1);
      begin
         if Value.Kind = Read_Transfer then
            SMB.Core_Protocol.Build_Read
              (File_Id, Value.Position, Amount,
               Body_Buffer, Body_Used, Field_Status);
            Command := 8;
            --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: Build_Read cannot fail here, and the branch holds only an assertion
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
               --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: Build_Write cannot fail here, and the branch holds only assertions
               if Field_Status = SMB.Ok then
                  pragma Assert_And_Cut (Payload'Length > 0);
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
         --  adamutant:disable-next-line ConditionalExpression: the builders cannot fail here
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
            --  adamutant:disable-next-line ConditionalExpression: the branch holds only an assertion
            if Value.Kind = Write_Transfer then
               pragma Assert
                 (for all Index in 0 .. Amount - 1 =>
                    Output
                      (Output'First + Header_Length + 48 + Index) =
                    Value.Buffer (Value.Completed + Index + 1));
            end if;
         end if;
      end;
      --  adamutant:disable-next-line ConditionalExpression, LogicalOperator: the builders cannot fail here and write the body length
      if Field_Status /= SMB.Ok or else Body_Used /= Body_Length then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Value.Stage := Transfer_Failed;
         --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: unreachable, as above
         if Field_Status = SMB.Ok then
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
            Status := SMB.Invalid_Length;
         else
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
            Status := Field_Status;
         end if;
         return;
      end if;
      SMB.Engine.Begin_Request
        (State, Command, True, True, Message_Id, Expected, Begin_Status,
         Request_Amount => Amount);
      --  adamutant:disable-next-line ConditionalExpression: the checks above leave Begin_Request nothing to reject
      if Begin_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Value.Stage := Transfer_Failed;
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Status := Begin_Status;
         return;
      end if;
      Value.Expected := Expected;
      pragma Assert (Value.Expected.Tree_Id = Expected.Tree_Id);
      Value.Requested := Amount;
      --  adamutant:disable-next-line ConditionalExpression: Begin_Request returns the expectation it reserved
      if Message_Id /= Expected.Message_Id
        --  adamutant:disable-next-line LogicalOperator: as above
        or else Expected.Request_Amount /= Amount
      then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Fail_Transfer
           (Value, State, SMB.Invalid_State_Status, Status);
         return;
      end if;
      --  adamutant:disable-next-line StatementDeletion: the check above made them equal; this restates it for the proof
      Value.File_Id := File_Id;
      --  adamutant:disable-next-line StatementDeletion: as above
      Value.Access_Mode := Access_Mode;
      Key := SMB.Engine.Current_Signing_Key (State);
      Used := Header_Length + Body_Used;
      Prepare_Header
        (Output, Expected, Field_Status);
      --  adamutant:disable-next-line ConditionalExpression: Output holds the request, as checked above
      if Field_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Fail_Transfer (Value, State, Field_Status, Status);
         --  adamutant:disable-next-line StatementDeletion, NumericLiteral: unreachable, as above
         Used := 0;
         return;
      end if;
      pragma Assert
        (SMB.Core_Wire.Encoded_U32 (Output, 36) =
           Expected.Tree_Id);
      Sign_Packet (Output, Used, Key, Field_Status);
      --  adamutant:disable-next-line ConditionalExpression: Sign_Packet cannot fail on a whole request
      if Field_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Fail_Transfer (Value, State, Field_Status, Status);
         --  adamutant:disable-next-line StatementDeletion, NumericLiteral: unreachable, as above
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
        (for all Byte_Index in 0 .. 7 =>
           Output (Output'First + Header_Length + 8 + Byte_Index) =
             SMB.Core_Wire.U64_Byte (Value.Position, Byte_Index));
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
      --  adamutant:disable-next-line NumericLiteral: an error response parses the same for every command
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
         --  adamutant:disable-next-line ConditionalExpression: the receipt Accept_Response just validated can be discarded
         if Receipt_Status /= SMB.Ok then
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
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
      --  Each of these alone is rejected by the engine first, so no pairing of them can be told apart.
      --  adamutant:disable LogicalOperator
      --  adamutant:disable-next-line ConditionalExpression, NumericLiteral: the engine rejects these responses first
      if Value.Capacity = 0
        or else Info.Data_Length > Old_Requested
        or else Info.Data_Length > Value.Remaining
        or else Info.Data_Length > Value.Capacity
        --  adamutant:disable-next-line ArithmeticOperator: as above
        or else Info.Data_Length > Value.Capacity - Value.Completed
        --  adamutant:disable-next-line EqualityOperator: as above
        or else Info.Data_Offset > Packet'Length
        --  adamutant:disable-next-line ArithmeticOperator: as above
        or else Info.Data_Length > Packet'Length - Info.Data_Offset
      --  adamutant:enable LogicalOperator
      then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Fail_Transfer
           (Value, State, SMB.Invalid_Protocol, Status);
         return;
      end if;
      SMB.Core_Protocol.Advance_Transfer
        (Value.Position, Value.Remaining, Old_Requested, Info.Data_Length,
         Progress_Status, Require_Progress => False);
      --  adamutant:disable-next-line ConditionalExpression: the checks above leave Advance_Transfer nothing to reject
      if Progress_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
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
      --  adamutant:disable-next-line StatementDeletion: Advance_Transfer has moved Position there already
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
      --  adamutant:disable-next-line ConditionalExpression: the receipt Accept_Response just validated can be discarded
      if Receipt_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
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
      --  adamutant:disable-next-line NumericLiteral: it is read only after it is set
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
         --  adamutant:disable-next-line ConditionalExpression: the engine rejects a WRITE response that wrote nothing
         if Count = 0 then
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
            Fail_Transfer (Value, State, SMB.Invalid_Protocol, Status);
            return;
         end if;
         --  adamutant:disable-next-line ConditionalExpression, LogicalOperator: the engine rejects these responses first
         if Count > Old_Requested or else Count > Value.Remaining then
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
            Fail_Transfer (Value, State, SMB.Invalid_Value, Status);
            return;
         end if;
         --  adamutant:disable-next-line ConditionalExpression, ArithmeticOperator: the engine rejects these responses first
         if Count > Value.Capacity - Value.Completed then
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
            Fail_Transfer (Value, State, SMB.Invalid_Value, Status);
            return;
         end if;
         SMB.Core_Protocol.Advance_Transfer
           (Value.Position, Value.Remaining, Old_Requested, Count,
            Progress_Status);
         --  adamutant:disable-next-line ConditionalExpression: the checks above leave Advance_Transfer nothing to reject
         if Progress_Status /= SMB.Ok then
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
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
         --  adamutant:disable-next-line StatementDeletion: Advance_Transfer has moved Position there already
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
      --  adamutant:disable-next-line ConditionalExpression: the receipt Accept_Response just validated can be discarded
      if Receipt_Status /= SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Fail_Transfer (Value, State, Receipt_Status, Status);
         return;
      end if;
      pragma Assert (not SMB.Engine.Has_Pending_Request (State));
      pragma Assert (not SMB.Engine.Has_Validated_Response (State));
      --  adamutant:disable-next-line ConditionalExpression: the branch holds only an assertion
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
      --  adamutant:disable-next-line ConditionalExpression, EqualityOperator, NumericLiteral: an empty copy does nothing
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
