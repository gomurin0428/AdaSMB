with SMB.Core_NTLM;
with SMB.Crypto;

package body SMB.Engine
  with SPARK_Mode,
       Refined_State => (Identity_Registry => Next_Owner_Id)
is
   use type SMB.Core_Protocol.Response_Info;

   Next_Owner_Id : SMB.QWord := 0;

   function Bounded_Slice
     (Packet : SMB.Bytes;
      Offset, Length : Natural) return SMB.Bytes
   with Pre =>
     Packet'Length <= SMB.Maximum_Frame_Size
     and then
     Offset <= Packet'Length
     and then Length <= Packet'Length - Offset,
     Post => Bounded_Slice'Result'Length = Length;

   function Bounded_Slice
     (Packet : SMB.Bytes;
      Offset, Length : Natural) return SMB.Bytes is
   begin
      if Length = 0 then
         return SMB.Bytes'(1 .. 0 => 0);
      end if;
      return Packet
        (Packet'First + Offset
         .. Packet'Last - (Packet'Length - Offset - Length));
   end Bounded_Slice;

   procedure Initialize
      (State : in out Engine_State;
      Status : out SMB.Core_Status) is
   begin
      if State.Current /= Disconnected
        or else State.Pending
        or else State.Has_Key
        or else State.Receipt_Valid
        or else Has_Open_Handles (State)
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      if Next_Owner_Id = SMB.QWord'Last then
         Status := SMB.Counter_Exhausted;
         return;
      end if;
      Next_Owner_Id := Next_Owner_Id + 1;
      State.Current := Disconnected;
      State.Owner_Id := Next_Owner_Id;
      State.Epoch := 0;
      State.Next_Message_Id := 0;
      State.Next_Ticket := 0;
      State.Session_Id := 0;
      State.Tree_Id := 0;
      State.Max_Read := 0;
      State.Max_Write := 0;
      State.Signing_Key := (others => 0);
      State.Has_Key := False;
      State.Pending := False;
      State.Pending_Async_Id := 0;
      State.Pending_Expected := (others => <>);
      State.Receipt_Valid := False;
      State.Receipt_Command := 0;
      State.Receipt_Status := 0;
      State.Receipt_Signed := False;
      State.Receipt_MIC_Valid := False;
      State.Receipt_Close_Token := (others => 0);
      State.Receipt_Info := (others => <>);
      State.Handles := (others => <>);
      Status := SMB.Ok;
   end Initialize;

   procedure Mark_Connected
     (State : in out Engine_State;
      Status : out SMB.Core_Status) is
   begin
      if State.Owner_Id = 0 or else State.Current /= Disconnected then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      State.Current := Transport_Connected;
      Status := SMB.Ok;
   end Mark_Connected;

   procedure Mark_Negotiated
     (State : in out Engine_State;
      Maximum_Read, Maximum_Write : Natural;
      Status : out SMB.Core_Status) is
   begin
      if State.Current /= Transport_Connected
        or else not State.Receipt_Valid
        or else State.Receipt_Command /= 0
        or else State.Receipt_Status /= SMB.Success
        or else State.Receipt_Signed
        or else State.Receipt_MIC_Valid
        or else State.Pending
        or else Maximum_Read = 0
        or else Maximum_Write = 0
        or else Maximum_Read > SMB.Maximum_Frame_Size
        or else Maximum_Write > SMB.Maximum_Frame_Size
        or else State.Receipt_Info.Max_Read /= Maximum_Read
        or else State.Receipt_Info.Max_Write /= Maximum_Write
      then
         Status := SMB.Invalid_Value;
         return;
      end if;
      State.Max_Read := Maximum_Read;
      State.Max_Write := Maximum_Write;
      State.Session_Id := 0;
      State.Current := Negotiated;
      State.Receipt_Valid := False;
      Status := SMB.Ok;
   end Mark_Negotiated;

   procedure Install_Session_Key
     (State : in out Engine_State;
      Session_Id : SMB.QWord;
      Key : SMB.Bytes;
      Status : out SMB.Core_Status) is
   begin
      if State.Current /= Negotiated
        or else not State.Receipt_Valid
        or else State.Receipt_Command /= 1
        or else State.Receipt_Status /= SMB.Status_More_Processing_Required
        or else State.Receipt_Signed
        or else State.Receipt_MIC_Valid
        or else State.Receipt_Info.Session_Id /= Session_Id
        or else State.Pending
        or else State.Has_Key
        or else Session_Id = 0
        or else Key'Length /= 16
      then
         Status := SMB.Invalid_Value;
         return;
      end if;
      for Index in 0 .. 15 loop
         State.Signing_Key (Index) := Key (Key'First + Index);
      end loop;
      State.Session_Id := Session_Id;
      State.Has_Key := True;
      State.Receipt_Valid := False;
      Status := SMB.Ok;
   end Install_Session_Key;

   procedure Mark_Authenticated
     (State : in out Engine_State;
      Status : out SMB.Core_Status) is
   begin
      if State.Current /= Negotiated or else not State.Has_Key
        or else State.Session_Id = 0
        or else State.Pending
        or else not State.Receipt_Valid
        or else State.Receipt_Command /= 1
        or else State.Receipt_Status /= SMB.Success
        or else not State.Receipt_Signed
        or else not State.Receipt_MIC_Valid
        or else State.Receipt_Info.Session_Id /= State.Session_Id
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      State.Current := Authenticated;
      State.Receipt_Valid := False;
      Status := SMB.Ok;
   end Mark_Authenticated;

   procedure Mark_Share_Connected
     (State : in out Engine_State;
      Tree_Id : SMB.DWord;
      Status : out SMB.Core_Status) is
   begin
      if State.Current /= Authenticated or else Tree_Id = 0
        or else State.Pending
        or else not State.Receipt_Valid
        or else State.Receipt_Command /= 3
        or else State.Receipt_Status /= SMB.Success
        or else not State.Receipt_Signed
        or else State.Receipt_MIC_Valid
        or else State.Receipt_Info.Tree_Id /= Tree_Id
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      State.Tree_Id := Tree_Id;
      State.Current := Share_Connected;
      State.Receipt_Valid := False;
      Status := SMB.Ok;
   end Mark_Share_Connected;

   procedure Begin_Request
     (State : in out Engine_State;
      Command : SMB.Core_Wire.Command_Code;
      Request_Signed : Boolean;
      Response_Signed : Boolean;
      Message_Id : out SMB.QWord;
      Expected : out Request_Expectation;
      Status : out SMB.Core_Status;
      Request_Amount : Natural := 0;
      Close_Token : Handle_Token := (others => 0)) is
      Tree_Match : Boolean;
      Session_Match : Boolean;
      Close_Found : Boolean := False;
   begin
      Message_Id := 0;
      Expected := (others => <>);
      State.Receipt_Valid := False;
      if State.Pending then
         Status := SMB.Invalid_State_Status;
         return;
      elsif State.Next_Message_Id = SMB.QWord'Last then
         Status := SMB.Counter_Exhausted;
         return;
      end if;
      if Command = 0 then
         if State.Current /= Transport_Connected
           or else Request_Signed or else Response_Signed
         then
            Status := SMB.Invalid_State_Status;
            return;
         end if;
      elsif Command = 1 then
         if State.Current /= Negotiated
           or else Request_Signed
           or else Response_Signed /= State.Has_Key
         then
            Status := SMB.Invalid_State_Status;
            return;
         end if;
      elsif Command = 3 then
         if State.Current /= Authenticated
           or else not Request_Signed or else not Response_Signed
         then
            Status := SMB.Invalid_State_Status;
            return;
         end if;
      elsif Command = 4 or else Command = 5 or else Command = 6
        or else Command = 8 or else Command = 9
        or else Command = 14 or else Command = 17
      then
         if State.Current /= Share_Connected
           or else not Request_Signed or else not Response_Signed
         then
            Status := SMB.Invalid_State_Status;
            return;
         end if;
         if Command = 5 then
            if State.Next_Ticket = SMB.QWord'Last then
               Status := SMB.Counter_Exhausted;
               return;
            end if;
            declare
               Free : Boolean := False;
            begin
               for Item of State.Handles loop
                  if not Item.Active then
                     Free := True;
                  end if;
               end loop;
               if not Free then
                  Status := SMB.Resource_Limit;
                  return;
               end if;
            end;
         elsif Command = 6 then
            if Close_Token.Owner /= State.Owner_Id
              or else Close_Token.Epoch /= State.Epoch
              or else Close_Token.Ticket = 0
            then
               Status := SMB.Invalid_Handle_Status;
               return;
            end if;
            for Item of State.Handles loop
               if Item.Active and then Item.Ticket = Close_Token.Ticket then
                  Close_Found := True;
               end if;
            end loop;
            if not Close_Found then
               Status := SMB.Invalid_Handle_Status;
               return;
            end if;
         elsif (Command = 8 or else Command = 9)
           and then (Request_Amount = 0
                     or else Request_Amount > SMB.Core_Protocol.Maximum_IO_Chunk)
         then
            Status := SMB.Invalid_Value;
            return;
         end if;
      elsif Command = 2 then
         if State.Current /= Authenticated
           and then State.Current /= Share_Connected
         then
            Status := SMB.Invalid_State_Status;
            return;
         elsif not Request_Signed or else not Response_Signed then
            Status := SMB.Invalid_State_Status;
            return;
         end if;
      else
         Status := SMB.Unsupported_Feature;
         return;
      end if;
      Tree_Match := State.Current = Share_Connected and then Command /= 2;
      Session_Match :=
        State.Current = Authenticated or else State.Current = Share_Connected
        or else (Command = 1 and then State.Has_Key);
      Message_Id := State.Next_Message_Id;
      Expected :=
        (Command => Command,
         Message_Id => Message_Id,
         Tree_Id =>
           (if Command = 0 or else Command = 2 or else Command = 3
            then 0 else State.Tree_Id),
         Session_Id => State.Session_Id,
         Match_Tree => Tree_Match,
         Match_Session => Session_Match,
         Request_Signed => Request_Signed,
         Signed => Response_Signed,
         Request_Amount => Request_Amount,
         Close_Token => Close_Token);
      Expected.Request_Amount := Request_Amount;
      Expected.Close_Token := Close_Token;
      State.Pending_Expected := Expected;
      State.Pending_Async_Id := 0;
      State.Pending := True;
      State.Next_Message_Id := State.Next_Message_Id + 1;
      Status := SMB.Ok;
   end Begin_Request;

   procedure Invalidate
     (State : in out Engine_State;
      Status : out SMB.Core_Status) is
   begin
      State.Current := Disconnected;
      State.Pending := False;
      State.Pending_Async_Id := 0;
      State.Session_Id := 0;
      State.Tree_Id := 0;
      State.Signing_Key := (others => 0);
      State.Has_Key := False;
      State.Max_Read := 0;
      State.Max_Write := 0;
      State.Receipt_Valid := False;
      State.Receipt_Command := 0;
      State.Receipt_Status := 0;
      State.Receipt_Signed := False;
      State.Receipt_MIC_Valid := False;
      State.Receipt_Close_Token := (others => 0);
      State.Receipt_Info := (others => <>);
      State.Next_Message_Id := 0;
      State.Next_Ticket := 0;
      State.Handles := (others => <>);
      if State.Epoch = SMB.QWord'Last then
         State.Owner_Id := 0;
         Status := SMB.Counter_Exhausted;
         return;
      end if;
      State.Epoch := State.Epoch + 1;
      Status := SMB.Ok;
   end Invalidate;

   procedure Inspect_Interim_Response
     (State : in out Engine_State;
      Packet : SMB.Bytes;
      Is_Interim : out Boolean;
      Status : out SMB.Core_Status) is
      Ignore_Status : SMB.Core_Status;
      Wire_Status : SMB.Core_Status;
      Nt_Status : SMB.DWord;
      Structure_Size : SMB.Word;
      Body_Status : SMB.Core_Status;
      Supported_Command : Boolean;
   begin
      Is_Interim := False;
      Status := SMB.Ok;
      if Packet'Length < SMB.Core_Wire.Header_Size
        or else SMB.Core_Wire.Header_Nt_Status (Packet) /= SMB.Status_Pending
      then
         return;
      end if;
      if not State.Pending then
         Invalidate (State, Ignore_Status);
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      Supported_Command :=
        State.Pending_Expected.Command = 2
        or else State.Pending_Expected.Command = 4
        or else State.Pending_Expected.Command = 5
        or else State.Pending_Expected.Command = 6
        or else State.Pending_Expected.Command = 8
        or else State.Pending_Expected.Command = 9
        or else State.Pending_Expected.Command = 14
        or else State.Pending_Expected.Command = 17;
      if not Supported_Command then
         Invalidate (State, Ignore_Status);
         Status := SMB.Unsupported_Feature;
         return;
      end if;
      if not State.Has_Key
        or else not State.Pending_Expected.Request_Signed
        or else not State.Pending_Expected.Signed
        or else State.Receipt_Valid
      then
         Invalidate (State, Ignore_Status);
         Status := SMB.Signature_Error;
         return;
      end if;
      if State.Current /= Authenticated
        and then State.Current /= Share_Connected
      then
         Invalidate (State, Ignore_Status);
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      SMB.Core_Wire.Validate_Header
        (Packet,
         (Command => State.Pending_Expected.Command,
          Message_Id => State.Pending_Expected.Message_Id,
          Tree_Id => State.Pending_Expected.Tree_Id,
          Session_Id => State.Pending_Expected.Session_Id,
          Match_Tree => State.Pending_Expected.Match_Tree,
          Match_Session => State.Pending_Expected.Match_Session,
          Signed => State.Pending_Expected.Signed),
         Nt_Status, Wire_Status,
         Async_Id => State.Pending_Async_Id,
         Interim => True);
      if Wire_Status /= SMB.Ok then
         Invalidate (State, Ignore_Status);
         Status := Wire_Status;
         return;
      end if;
      if Packet'Length < 72 then
         Invalidate (State, Ignore_Status);
         Status := SMB.Invalid_Protocol;
         return;
      end if;
      SMB.Core_Wire.Read_U16
        (Packet, 64, Structure_Size, Body_Status);
      if Body_Status /= SMB.Ok
        or else Structure_Size /= 9
        or else Packet (Packet'First + 66) /= 0
        or else SMB.Core_Wire.Encoded_U32 (Packet, 68) /= 0
      then
         Invalidate (State, Ignore_Status);
         Status := SMB.Invalid_Protocol;
         return;
      end if;
      State.Pending_Async_Id := SMB.Core_Wire.Encoded_U64 (Packet, 32);
      Is_Interim := True;
   end Inspect_Interim_Response;

   procedure Accept_Response
     (State : in out Engine_State;
      Packet : SMB.Bytes;
      Nt_Status : out SMB.DWord;
      Status : out SMB.Core_Status) is
      Wire_Status : SMB.Core_Status;
      Verify_Status : SMB.Core_Status;
      Valid : Boolean;
      Ignore_Status : SMB.Core_Status;
      Parse_Status : SMB.Core_Status;
      Parsed : SMB.Core_Protocol.Response_Info;
      Mic_Status : SMB.Core_Status;
   begin
      Nt_Status := 0;
      if not State.Pending then
         Invalidate (State, Ignore_Status);
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      SMB.Core_Wire.Validate_Header
        (Packet,
         (Command => State.Pending_Expected.Command,
          Message_Id => State.Pending_Expected.Message_Id,
          Tree_Id => State.Pending_Expected.Tree_Id,
          Session_Id => State.Pending_Expected.Session_Id,
          Match_Tree => State.Pending_Expected.Match_Tree,
          Match_Session => State.Pending_Expected.Match_Session,
          Signed => State.Pending_Expected.Signed),
         Nt_Status, Wire_Status,
         Async_Id => State.Pending_Async_Id);
      if Wire_Status /= SMB.Ok then
         Invalidate (State, Ignore_Status);
         Nt_Status := 0;
         Status := Wire_Status;
         return;
      end if;
      if State.Pending_Expected.Signed then
         if not State.Has_Key then
            Invalidate (State, Ignore_Status);
            Nt_Status := 0;
            Status := SMB.Signature_Error;
            return;
         end if;
         SMB.Core_Wire.Verify_Signature
           (Packet, State.Signing_Key, Valid, Verify_Status);
         if Verify_Status /= SMB.Ok or else not Valid then
            Invalidate (State, Ignore_Status);
            Nt_Status := 0;
            Status := SMB.Signature_Error;
            return;
         end if;
      end if;
      SMB.Core_Protocol.Parse_Response
        (Packet, State.Pending_Expected.Command, Nt_Status, Parsed, Parse_Status);
      if Parse_Status /= SMB.Ok then
         Invalidate (State, Ignore_Status);
         Nt_Status := 0;
         Status := Parse_Status;
         return;
      end if;
      if State.Pending_Expected.Command = 9
        and then Nt_Status = SMB.Success
        and then (State.Pending_Expected.Request_Amount = 0
                  or else Parsed.Count > State.Pending_Expected.Request_Amount)
      then
         Invalidate (State, Ignore_Status);
         Nt_Status := 0;
         Status := SMB.Invalid_Value;
         return;
      end if;
      if State.Pending_Expected.Command = 8
        and then Nt_Status = SMB.Success
        and then (State.Pending_Expected.Request_Amount = 0
                  or else Parsed.Data_Length >
                    State.Pending_Expected.Request_Amount)
      then
         Invalidate (State, Ignore_Status);
         Nt_Status := 0;
         Status := SMB.Invalid_Value;
         return;
      end if;
      State.Receipt_MIC_Valid := False;
      if State.Pending_Expected.Command = 1
        and then Nt_Status = SMB.Success
      then
         if Parsed.Data_Length = 0 then
            declare
               Empty : constant SMB.Bytes := (1 .. 0 => 0);
            begin
               SMB.Core_NTLM.Validate_Final_Token
                 (Empty, Mic_Status,
                  SMB.Core_NTLM.Mechanism_List_MIC
                    (SMB.Crypto.Digest_128 (State.Signing_Key), True));
            end;
         else
            declare
               Token : constant SMB.Bytes :=
                 Bounded_Slice
                   (Packet, Parsed.Data_Offset, Parsed.Data_Length);
            begin
               SMB.Core_NTLM.Validate_Final_Token
                 (Token, Mic_Status,
                  SMB.Core_NTLM.Mechanism_List_MIC
                    (SMB.Crypto.Digest_128 (State.Signing_Key), True));
            end;
         end if;
         if Mic_Status /= SMB.Ok then
            Invalidate (State, Ignore_Status);
            Nt_Status := 0;
            Status := SMB.Invalid_Protocol;
            return;
         end if;
         State.Receipt_MIC_Valid := True;
      end if;
      State.Receipt_Valid := True;
      State.Receipt_Command := State.Pending_Expected.Command;
      State.Receipt_Status := Nt_Status;
      State.Receipt_Signed := State.Pending_Expected.Signed;
      State.Receipt_Info := Parsed;
      State.Receipt_Close_Token := State.Pending_Expected.Close_Token;
      State.Pending := False;
      State.Pending_Async_Id := 0;
      State.Pending_Expected := (others => <>);
      if Nt_Status = SMB.Success
        and then State.Receipt_Command = 4
      then
         State.Handles := (others => <>);
         State.Tree_Id := 0;
         State.Current := Authenticated;
         State.Receipt_Valid := False;
         State.Receipt_Command := 0;
         State.Receipt_Status := 0;
         State.Receipt_Signed := False;
         State.Receipt_MIC_Valid := False;
         State.Receipt_Close_Token := (others => 0);
         State.Receipt_Info := (others => <>);
      elsif Nt_Status = SMB.Success
        and then State.Receipt_Command = 2
      then
         Invalidate (State, Ignore_Status);
      end if;
      Status := SMB.Ok;
   end Accept_Response;

   procedure Register_Handle
     (State : in out Engine_State;
      File_Id : SMB.Bytes;
      Access_Mode : Access_Kind;
      Is_Directory : Boolean;
      Token : out Handle_Token;
      Status : out SMB.Core_Status) is
      Found : Boolean := False;
      Slot : Handle_Slot := Handle_Slot'First;
   begin
      Token := (others => 0);
      if State.Current /= Share_Connected
        or else not State.Receipt_Valid
        or else State.Receipt_Command /= 5
        or else State.Receipt_Status /= SMB.Success
        or else not State.Receipt_Signed
        or else State.Receipt_MIC_Valid
        or else State.Pending
        or else State.Receipt_Close_Token.Owner /= 0
        or else State.Receipt_Close_Token.Epoch /= 0
        or else State.Receipt_Close_Token.Ticket /= 0
      then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      if File_Id'Length /= 16 then
         Status := SMB.Invalid_Length;
         return;
      end if;
      for I in 0 .. 15 loop
         if File_Id (File_Id'First + I) /= State.Receipt_Info.File_Id (I) then
            Status := SMB.Invalid_Value;
            return;
         end if;
      end loop;
      if State.Next_Ticket = SMB.QWord'Last then
         Status := SMB.Counter_Exhausted;
         return;
      end if;
      for Index in State.Handles'Range loop
         if not Found and then not State.Handles (Index).Active then
            Found := True;
            Slot := Index;
         end if;
         pragma Loop_Invariant
           (if Found then not State.Handles (Slot).Active);
      end loop;
      if not Found then
         Status := SMB.Resource_Limit;
         return;
      end if;
      State.Next_Ticket := State.Next_Ticket + 1;
      State.Handles (Slot).Active := True;
      State.Handles (Slot).Ticket := State.Next_Ticket;
      for Index in 0 .. 15 loop
         State.Handles (Slot).File_Id (Index) := File_Id (File_Id'First + Index);
      end loop;
      State.Handles (Slot).Access_Mode := Access_Mode;
      State.Handles (Slot).Is_Directory := Is_Directory;
      Token := (Owner => State.Owner_Id,
                Epoch => State.Epoch,
                Ticket => State.Next_Ticket);
      State.Receipt_Valid := False;
      State.Receipt_Close_Token := (others => 0);
      Status := SMB.Ok;
   end Register_Handle;

   procedure Validate_Handle
     (State : Engine_State;
      Token : Handle_Token;
      Need_Read, Need_Write : Boolean;
      File_Id : out SMB.Bytes;
      Access_Mode : out Access_Kind;
      Is_Directory : out Boolean;
      Status : out SMB.Core_Status) is
   begin
      File_Id := (others => 0);
      Access_Mode := Read_Only;
      Is_Directory := False;
      if File_Id'Length /= 16 then
         Status := SMB.Invalid_Length;
         return;
      end if;
      if State.Current /= Share_Connected
        or else Token.Owner /= State.Owner_Id
        or else Token.Epoch /= State.Epoch
        or else Token.Ticket = 0
      then
         Status := SMB.Invalid_Handle_Status;
         return;
      end if;
      for Index in State.Handles'Range loop
         if State.Handles (Index).Active
           and then State.Handles (Index).Ticket = Token.Ticket
         then
            if (Need_Read
                and then State.Handles (Index).Access_Mode = Write_Only)
              or else (Need_Write
                       and then State.Handles (Index).Access_Mode = Read_Only)
            then
               null;
            else
               Access_Mode := State.Handles (Index).Access_Mode;
               Is_Directory := State.Handles (Index).Is_Directory;
               File_Id := State.Handles (Index).File_Id;
               Status := SMB.Ok;
               return;
            end if;
         end if;
         pragma Loop_Invariant
           (for all J in State.Handles'First .. Index =>
              not (State.Handles (J).Active
                   and then State.Handles (J).Ticket = Token.Ticket
                   and then (not Need_Read
                             or else State.Handles (J).Access_Mode /=
                               Write_Only)
                   and then (not Need_Write
                             or else State.Handles (J).Access_Mode /=
                               Read_Only)));
      end loop;
      Status := SMB.Invalid_Handle_Status;
   end Validate_Handle;

   procedure Close_Handle
     (State : in out Engine_State;
      Token : Handle_Token;
      Status : out SMB.Core_Status;
      Close_Token : Handle_Token := (others => 0)) is
      Found : Boolean := False;
   begin
      if State.Current /= Share_Connected
        or else not State.Receipt_Valid
        or else State.Receipt_Command /= 6
        or else State.Receipt_Status /= SMB.Success
        or else not State.Receipt_Signed
        or else State.Receipt_MIC_Valid
        or else State.Pending
        or else Close_Token.Owner /= Token.Owner
        or else Close_Token.Epoch /= Token.Epoch
        or else Close_Token.Ticket /= Token.Ticket
        or else State.Receipt_Close_Token.Owner /= Close_Token.Owner
        or else State.Receipt_Close_Token.Epoch /= Close_Token.Epoch
        or else State.Receipt_Close_Token.Ticket /= Close_Token.Ticket
        or else Token.Owner /= State.Owner_Id
        or else Token.Epoch /= State.Epoch
        or else Token.Ticket = 0
      then
         Status := SMB.Invalid_Handle_Status;
         return;
      end if;
      for Index in State.Handles'Range loop
         if State.Handles (Index).Active
           and then State.Handles (Index).Ticket = Token.Ticket
         then
            Found := True;
         end if;
         pragma Loop_Invariant
           ((not Found)
            or else Valid_Handle (State, Token, False, False));
      end loop;
      if not Found then
         Status := SMB.Invalid_Handle_Status;
         return;
      end if;
      for Index in State.Handles'Range loop
         if State.Handles (Index).Active
           and then State.Handles (Index).Ticket = Token.Ticket
         then
            State.Handles (Index).Active := False;
            State.Handles (Index).File_Id := (others => 0);
            Found := True;
         end if;
         pragma Loop_Invariant (Found);
         pragma Loop_Invariant
           (Other_Handles_Preserved (State'Loop_Entry, State, Token.Ticket));
         pragma Loop_Invariant
           (for all J in State.Handles'First .. Index =>
             not State.Handles (J).Active
             or else State.Handles (J).Ticket /= Token.Ticket);
      end loop;
      if Found then
         State.Receipt_Valid := False;
         Status := SMB.Ok;
      else
         Status := SMB.Invalid_Handle_Status;
      end if;
   end Close_Handle;

   procedure Discard_Response_Receipt
     (State : in out Engine_State;
      Status : out SMB.Core_Status) is
   begin
      if State.Pending then
         Status := SMB.Invalid_State_Status;
         return;
      end if;
      State.Receipt_Valid := False;
      State.Receipt_Command := 0;
      State.Receipt_Status := 0;
      State.Receipt_Signed := False;
      State.Receipt_MIC_Valid := False;
      State.Receipt_Close_Token := (others => 0);
      State.Receipt_Info := (others => <>);
      Status := SMB.Ok;
   end Discard_Response_Receipt;

   function Current_Phase (State : Engine_State) return Phase is
     (State.Current);
   function Current_Session_Id (State : Engine_State) return SMB.QWord is
     (State.Session_Id);
   function Current_Tree_Id (State : Engine_State) return SMB.DWord is
     (State.Tree_Id);
   function Current_Max_Read (State : Engine_State) return Natural is
     (State.Max_Read);
   function Current_Max_Write (State : Engine_State) return Natural is
     (State.Max_Write);
   function Current_Async_Id (State : Engine_State) return SMB.QWord is
     (State.Pending_Async_Id);
   function Current_Signing_Key (State : Engine_State) return SMB.Bytes is
     (State.Signing_Key);
   function Has_Open_Handles (State : Engine_State) return Boolean is
     (for some Item of State.Handles => Item.Active);

   function Has_Signing_Key (State : Engine_State) return Boolean is
     (State.Has_Key);

   function Current_Response_Info (State : Engine_State)
     return SMB.Core_Protocol.Response_Info is
     (State.Receipt_Info);

   function Response_Receipt_Matches
     (State : Engine_State;
      Command : SMB.Core_Wire.Command_Code;
      Nt_Status : SMB.DWord;
      Signed, MIC_Valid : Boolean) return Boolean is
     (State.Receipt_Valid
      and then State.Receipt_Command = Command
      and then State.Receipt_Status = Nt_Status
      and then State.Receipt_Signed = Signed
      and then State.Receipt_MIC_Valid = MIC_Valid);

   function Create_Receipt_Matches_File_Id
     (State : Engine_State;
      File_Id : SMB.Bytes) return Boolean is
     (State.Receipt_Valid
      and then State.Receipt_Command = 5
      and then State.Receipt_Status = SMB.Success
      and then State.Receipt_Signed
      and then File_Id'Length = 16
      and then (for all Index in 0 .. 15 =>
        File_Id (File_Id'First + Index) =
          State.Receipt_Info.File_Id (Index)));

   function Close_Receipt_Matches
     (State : Engine_State;
      Token : Handle_Token) return Boolean is
     (State.Receipt_Valid
      and then State.Receipt_Command = 6
      and then State.Receipt_Status = SMB.Success
      and then State.Receipt_Signed
      and then State.Receipt_Close_Token.Owner = Token.Owner
      and then State.Receipt_Close_Token.Epoch = Token.Epoch
      and then State.Receipt_Close_Token.Ticket = Token.Ticket);

   function Signing_Key_Is_Zero (State : Engine_State) return Boolean is
     (for all Key_Byte of State.Signing_Key => Key_Byte = 0);

   function Current_Owner_Id (State : Engine_State) return SMB.QWord is
     (State.Owner_Id);

   function Current_Epoch (State : Engine_State) return SMB.QWord is
     (State.Epoch);

   function Valid_Handle
     (State : Engine_State;
      Token : Handle_Token;
      Need_Read, Need_Write : Boolean) return Boolean
   is
     (State.Current = Share_Connected
      and then Token.Owner = State.Owner_Id
      and then Token.Epoch = State.Epoch
      and then Token.Ticket /= 0
      and then (for some Index in State.Handles'Range =>
        State.Handles (Index).Active
        and then State.Handles (Index).Ticket = Token.Ticket
        and then (not Need_Read
                  or else State.Handles (Index).Access_Mode /= Write_Only)
        and then (not Need_Write
                  or else State.Handles (Index).Access_Mode /= Read_Only)));

   function Handle_Matches
     (State : Engine_State;
      Token : Handle_Token;
      File_Id : SMB.Bytes;
      Access_Mode : Access_Kind;
      Is_Directory : Boolean) return Boolean is
     (State.Current = Share_Connected
      and then Token.Owner = State.Owner_Id
      and then Token.Epoch = State.Epoch
      and then Token.Ticket /= 0
      and then File_Id'Length = 16
      and then (for some Index in State.Handles'Range =>
        State.Handles (Index).Active
        and then State.Handles (Index).Ticket = Token.Ticket
        and then State.Handles (Index).Access_Mode = Access_Mode
        and then State.Handles (Index).Is_Directory = Is_Directory
        and then (for all Byte_Index in 0 .. 15 =>
          State.Handles (Index).File_Id (Byte_Index) =
            File_Id (File_Id'First + Byte_Index))));

   function Handle_Table_Equivalent
     (Left, Right : Engine_State) return Boolean is
     (Left.Handles = Right.Handles);

   function Other_Handles_Preserved
     (Left, Right : Engine_State;
      Except_Ticket : SMB.QWord := 0) return Boolean is
     (Left.Current = Right.Current
      and then Left.Owner_Id = Right.Owner_Id
      and then Left.Epoch = Right.Epoch
      and then (for all Index in Left.Handles'Range =>
        (if Left.Handles (Index).Active
           and then Left.Handles (Index).Ticket /= Except_Ticket
         then Left.Handles (Index) = Right.Handles (Index))));

   procedure Lemma_Handle_Table_Transitive
     (First, Middle, Last : Engine_State) is
   begin
      null;
   end Lemma_Handle_Table_Transitive;

   function Connection_Context_Equivalent
     (Left, Right : Engine_State) return Boolean is
     (Left.Current = Right.Current
      and then Left.Owner_Id = Right.Owner_Id
      and then Left.Epoch = Right.Epoch
      and then Left.Session_Id = Right.Session_Id
      and then Left.Tree_Id = Right.Tree_Id
      and then Left.Max_Read = Right.Max_Read
      and then Left.Max_Write = Right.Max_Write
      and then Left.Has_Key = Right.Has_Key
      and then Left.Signing_Key = Right.Signing_Key
      and then Left.Handles = Right.Handles);

   function Interim_Context_Equivalent
     (Left, Right : Engine_State) return Boolean is
     (Left.Current = Right.Current
      and then Left.Owner_Id = Right.Owner_Id
      and then Left.Epoch = Right.Epoch
      and then Left.Next_Message_Id = Right.Next_Message_Id
      and then Left.Next_Ticket = Right.Next_Ticket
      and then Left.Session_Id = Right.Session_Id
      and then Left.Tree_Id = Right.Tree_Id
      and then Left.Max_Read = Right.Max_Read
      and then Left.Max_Write = Right.Max_Write
      and then Left.Signing_Key = Right.Signing_Key
      and then Left.Has_Key = Right.Has_Key
      and then Left.Pending = Right.Pending
      and then Left.Pending_Expected = Right.Pending_Expected
      and then Left.Receipt_Valid = Right.Receipt_Valid
      and then Left.Receipt_Command = Right.Receipt_Command
      and then Left.Receipt_Status = Right.Receipt_Status
      and then Left.Receipt_Signed = Right.Receipt_Signed
      and then Left.Receipt_MIC_Valid = Right.Receipt_MIC_Valid
      and then Left.Receipt_Close_Token = Right.Receipt_Close_Token
      and then Left.Receipt_Info = Right.Receipt_Info
      and then Left.Handles = Right.Handles);

   procedure Lemma_Connection_Context_Transitive
     (First, Middle, Last : Engine_State) is
   begin
      null;
   end Lemma_Connection_Context_Transitive;

   function Handle_Matches_In_States
     (Before, After : Engine_State;
      Token : Handle_Token;
      File_Id : SMB.Bytes;
      Access_Mode : Access_Kind;
      Is_Directory : Boolean) return Boolean is
     (Handle_Table_Equivalent (Before, After)
      and then Current_Phase (Before) = Current_Phase (After)
      and then Current_Owner_Id (Before) = Current_Owner_Id (After)
      and then Current_Epoch (Before) = Current_Epoch (After));

   function Handle_Matches_Equivalent
     (State : Engine_State;
      Token : Handle_Token;
      Left_File_Id, Right_File_Id : SMB.Bytes;
      Access_Mode : Access_Kind;
      Is_Directory : Boolean) return Boolean is
     (True);
end SMB.Engine;
