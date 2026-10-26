package body SMB.Core_Client
  with SPARK_Mode
is
   Header_Length : constant Natural := SMB.Core_Wire.Header_Size;

   procedure Clear_Output (Output : out SMB.Bytes) is
   begin
      for Index in Output'Range loop
         Output (Index) := 0;
      end loop;
   end Clear_Output;

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
        (SMB.Core_Wire.Encoded_U64 (Output, 24) = Expected.Message_Id);
      pragma Assert
        (SMB.Core_Wire.Encoded_U64 (Output, 40) = Expected.Session_Id);
      pragma Assert
        (for all Index in 0 .. 3 =>
           Output (Output'First + Header_Length + 24 + Index) =
             SMB.Core_Wire.U32_Byte (Wire_Access, Index));
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
end SMB.Core_Client;
