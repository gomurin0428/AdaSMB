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
   use type SMB.Engine.Access_Kind;
   use type SMB.Engine.Phase;
   type Operation_Kind is (No_Operation, Create_Operation, Close_Operation);
   type Operation_Stage is (Idle, Prepared, Sent, Finished, Failed);

   type Operation is limited private;

   function Stage_Of (Value : Operation) return Operation_Stage;
   function Kind_Of (Value : Operation) return Operation_Kind;
   function Create_Access_Of (Value : Operation)
     return SMB.Engine.Access_Kind;
   function Create_Directory_Of (Value : Operation) return Boolean;
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
            and then Create_Directory_Of (Value) = Directory);

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
            and then Close_Token_Of (Value).Owner = Token.Owner
            and then Close_Token_Of (Value).Epoch = Token.Epoch
            and then Close_Token_Of (Value).Ticket = Token.Ticket);

   procedure Send_Succeeded
     (Value : in out Operation;
      State : SMB.Engine.Engine_State;
      Status : out SMB.Core_Status)
   with
     Post =>
       (if Status = SMB.Ok then Stage_Of (Value) = Sent);

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
       (if Status = SMB.Ok then
          Stage_Of (Value) = Finished
          and then
            (if Nt_Status = SMB.Success
             then
               (if Kind_Of (Value) = Create_Operation then
                  SMB.Engine.Handle_Matches
                    (State, Token, File_Id_Of (Value),
                     Create_Access_Of (Value),
                     Create_Directory_Of (Value))
                else
                  not SMB.Engine.Valid_Handle
                    (State, Close_Token_Of (Value), False, False))));

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
                  (Packet'First + SMB.Core_Wire.Header_Size + 36 + Index) =
                SMB.Core_Wire.U32_Byte (Value.Disposition, Index))
         elsif Value.Kind = Close_Operation then
           (for all Index in 0 .. 15 =>
              Packet
                (Packet'First + SMB.Core_Wire.Header_Size + 8 + Index) =
                Value.File_Id (Value.File_Id'First + Index))
         else False));
end SMB.Core_Client;
