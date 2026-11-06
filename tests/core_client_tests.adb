with Ada.Text_IO;
with SMB;
with SMB.Core_Client;
with SMB.Core_Protocol;
with SMB.Engine;
with SMB.Wire;
with Engine_Fixtures; use Engine_Fixtures;

package body Core_Client_Tests is
   use type SMB.Byte;
   use type SMB.Bytes;
   use type SMB.Core_Status;
   use type SMB.DWord;
   use type SMB.QWord;
   use type SMB.Word;
   use type SMB.Engine.Phase;
   use type SMB.Core_Client.Transfer_Kind;
   use type SMB.Core_Client.Transfer_Stage;
   use type SMB.Core_Client.Operation_Stage;
   use type SMB.Core_Client.Directory_Stage;
   use type SMB.Core_Client.Metadata_Stage;
   use type SMB.Core_Protocol.Directory_Info;
   use type SMB.Engine.Handle_Token;

   package Client renames SMB.Core_Client;
   subtype Engine is SMB.Engine.Engine_State;
   subtype Handle is SMB.Engine.Handle_Token;

   Checks : Natural := 0;

   procedure Check (Condition : Boolean; Message : String) is
   begin
      Checks := Checks + 1;
      Assert (Condition, Message);
   end Check;

   --  A connected share, with a handle of the given access.
   procedure Share
     (State : in out Engine;
      Token : out Handle;
      Access_Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Write;
      Reconnect : Boolean := False;
      Maximum_Read, Maximum_Write : Natural := 65_536)
   is
      Message_Id : SMB.QWord;
      Expected : SMB.Engine.Request_Expectation;
      Status : SMB.Core_Status;
   begin
      Setup_Share
        (State, Message_Id, Expected, Status, Reconnect => Reconnect,
         Maximum_Read => Maximum_Read, Maximum_Write => Maximum_Write);
      Open_Handle (State, Token, Access_Mode);
   end Share;

   --  A signed response to the pending request on the share.
   function Response
     (Command : SMB.Wire.Command_Code;
      Message_Id : SMB.QWord;
      Last : Natural;
      Structure : SMB.Word;
      Nt_Status : SMB.DWord := SMB.Success) return SMB.Bytes
   is
      Packet : SMB.Bytes (0 .. Last) := (others => 0);
   begin
      SMB.Wire.Initialize_Header
        (Packet, Command, Message_Id, Tree_Id, Session_Id);
      SMB.Wire.Put_U32 (Packet, 8, Nt_Status);
      SMB.Wire.Put_U32 (Packet, 16, 9);
      SMB.Wire.Put_U16 (Packet, 64, Structure);
      return Packet;
   end Response;

   function Read_Response
     (Message_Id : SMB.QWord; Data : SMB.Bytes) return SMB.Bytes
   is
      Packet : SMB.Bytes :=
        Response (8, Message_Id, 79 + Data'Length, 17);
   begin
      Packet (66) := 80;
      SMB.Wire.Put_U32 (Packet, 68, SMB.DWord (Data'Length));
      Packet (80 .. 79 + Data'Length) := Data;
      SMB.Wire.Sign (Packet, Key);
      return Packet;
   end Read_Response;

   function Write_Response
     (Message_Id : SMB.QWord; Count : SMB.DWord) return SMB.Bytes
   is
      Packet : SMB.Bytes := Response (9, Message_Id, 79, 17);
   begin
      SMB.Wire.Put_U32 (Packet, 68, Count);
      SMB.Wire.Sign (Packet, Key);
      return Packet;
   end Write_Response;

   function Error_Response
     (Command : SMB.Wire.Command_Code;
      Message_Id : SMB.QWord;
      Nt_Status : SMB.DWord) return SMB.Bytes
   is
      Packet : SMB.Bytes :=
        Response (Command, Message_Id, 72, 9, Nt_Status);
   begin
      SMB.Wire.Sign (Packet, Key);
      return Packet;
   end Error_Response;

   --  Prepare the next request of Value, check its header, signature, offset
   --  and length, and acknowledge the send.
   procedure Send
     (Value : in out Client.Transfer;
      State : in out Engine;
      Message_Id : out SMB.QWord;
      Offset : SMB.QWord;
      Amount : Natural;
      Label : String;
      Acknowledge : Boolean := True)
   is
      Packet : SMB.Bytes (0 .. 255) := (others => 16#EE#);
      Used : Natural;
      Status : SMB.Core_Status;
   begin
      Client.Prepare_Next (Value, State, Packet, Used, Status);
      Check
        (Status = SMB.Ok and then Used > 64
         and then SMB.Wire.Verify_Signature (Packet (0 .. Used - 1), Key)
         and then SMB.Wire.U16 (Packet, 6) = 1
         and then SMB.Wire.U16 (Packet, 14) = 1
         and then SMB.Wire.U32 (Packet, 16) = 8
         and then SMB.Wire.U64 (Packet, 72) = Offset
         and then SMB.Wire.U32 (Packet, 68) = SMB.DWord (Amount)
         and then Client.Transfer_Requested_Of (Value) = Amount,
         Label & ": signed request " & SMB.Core_Status'Image (Status));
      Message_Id := SMB.Wire.U64 (Packet, 24);
      if Acknowledge then
         Client.Transfer_Send_Succeeded (Value, State, Status);
         Check (Status = SMB.Ok, Label & ": send acknowledgement");
      end if;
   end Send;

   procedure Expect_Stage
     (Value : Client.Transfer;
      Status, Wanted : SMB.Core_Status;
      Stage : Client.Transfer_Stage;
      Label : String) is
   begin
      Check
        (Status = Wanted and then Client.Transfer_Stage_Of (Value) = Stage,
         Label & ": " & SMB.Core_Status'Image (Status) & " "
         & Client.Transfer_Stage'Image (Client.Transfer_Stage_Of (Value)));
   end Expect_Stage;

   --  Start_Read and Start_Write: the handle's access and kind, the range,
   --  and a transfer object that is reused.
   procedure Test_Starts is
      State : Engine;
      Read_Write, Read_Only, Write_Only, Folder, Folder_Write : Handle;
      Value : Client.Transfer (4);
      Empty : Client.Transfer (0);
      Data : constant SMB.Bytes (1 .. 4) := (16#11#, 16#22#, 16#33#, 16#44#);
      Status : SMB.Core_Status;

      procedure Ready (Label : String) is
      begin
         Client.Start_Read (Value, State, Read_Only, 0, 4, Status);
         Expect_Stage
           (Value, Status, SMB.Ok, Client.Ready, Label & " (read-only READ)");
      end Ready;
   begin
      Share (State, Read_Write);
      Open_Handle (State, Read_Only, SMB.Engine.Read_Only);
      Open_Handle (State, Write_Only, SMB.Engine.Write_Only);
      Open_Handle (State, Folder, SMB.Engine.Read_Only, Directory => True);
      Open_Handle
        (State, Folder_Write, SMB.Engine.Read_Write, Directory => True);

      Ready ("before a write-only READ");
      Client.Start_Read (Value, State, Write_Only, 0, 4, Status);
      Expect_Stage
        (Value, Status, SMB.Invalid_Handle_Status, Client.Transfer_Failed,
         "READ on a write-only handle");
      Ready ("before a read-only WRITE");
      Client.Start_Write (Value, State, Read_Only, 0, Data, Status);
      Expect_Stage
        (Value, Status, SMB.Invalid_Handle_Status, Client.Transfer_Failed,
         "WRITE on a read-only handle");
      Client.Start_Write (Value, State, Write_Only, 0, Data, Status);
      Expect_Stage
        (Value, Status, SMB.Ok, Client.Ready, "WRITE on a write-only handle");
      Client.Start_Read (Value, State, Folder, 0, 4, Status);
      Expect_Stage
        (Value, Status, SMB.Invalid_Value, Client.Transfer_Failed,
         "READ on a directory");
      Ready ("before a directory WRITE");
      Client.Start_Write (Value, State, Folder_Write, 0, Data, Status);
      Expect_Stage
        (Value, Status, SMB.Invalid_Value, Client.Transfer_Failed,
         "WRITE on a directory");
      Ready ("before a READ past the last offset");
      Client.Start_Read (Value, State, Read_Only, SMB.QWord'Last, 4, Status);
      Expect_Stage
        (Value, Status, SMB.Invalid_Offset, Client.Transfer_Failed,
         "READ past the last offset");
      Ready ("before a WRITE past the last offset");
      Client.Start_Write
        (Value, State, Write_Only, SMB.QWord'Last, Data, Status);
      Expect_Stage
        (Value, Status, SMB.Invalid_Offset, Client.Transfer_Failed,
         "WRITE past the last offset");

      Client.Start_Read (Empty, State, Read_Only, 7, 0, Status);
      Check
        (Status = SMB.Ok
         and then Client.Transfer_Stage_Of (Empty) = Client.Transfer_Finished
         and then not SMB.Engine.Has_Pending_Request (State),
         "empty READ finishes at once");

      --  A transfer object that is reused starts from nothing: kind,
      --  buffer and request.
      declare
         One : Client.Transfer (1);
         Message_Id : SMB.QWord;
      begin
         Client.Start_Write
           (One, State, Write_Only, 5, SMB.Bytes'(1 => 16#AB#), Status);
         Send (One, State, Message_Id, 5, 1, "WRITE before reuse",
               Acknowledge => False);
         Client.Abort_Transfer (One, State, Status);
         Check (Status = SMB.Ok, "abort the WRITE before reuse");
         Share (State, Read_Write);
         Client.Start_Read (One, State, Read_Write, 9, 1, Status);
         Check
           (Status = SMB.Ok
            and then Client.Transfer_Kind_Of (One) = Client.Read_Transfer
            and then Client.Transfer_Byte_Of (One, 0) = 0
            and then Client.Transfer_Requested_Of (One) = 0,
            "READ reusing a WRITE transfer");
         Send (One, State, Message_Id, 9, 1, "READ before reuse",
               Acknowledge => False);
         Client.Abort_Transfer (One, State, Status);
         Check (Status = SMB.Ok, "abort the READ before reuse");
         Share (State, Read_Write);
         Client.Start_Write
           (One, State, Read_Write, 3, SMB.Bytes'(1 => 16#CD#), Status);
         Check
           (Status = SMB.Ok
            and then Client.Transfer_Kind_Of (One) = Client.Write_Transfer
            and then Client.Transfer_Requested_Of (One) = 0,
            "WRITE reusing a READ transfer");
      end;

      --  A transfer that is still prepared or sent cannot start again, even
      --  once its engine has moved on.
      declare
         Message_Id : SMB.QWord;
      begin
         Share (State, Read_Write);
         Client.Start_Read (Value, State, Read_Write, 0, 4, Status);
         Send (Value, State, Message_Id, 0, 4, "READ left prepared",
               Acknowledge => False);
         Share (State, Read_Write, Reconnect => True);
         Client.Start_Read (Value, State, Read_Write, 0, 4, Status);
         Expect_Stage
           (Value, Status, SMB.Invalid_State_Status, Client.Transfer_Prepared,
            "READ over a prepared transfer");
         Client.Start_Write (Value, State, Read_Write, 0, Data, Status);
         Expect_Stage
           (Value, Status, SMB.Invalid_State_Status, Client.Transfer_Prepared,
            "WRITE over a prepared transfer");
      end;
      declare
         Message_Id : SMB.QWord;
         Other, Sent : Client.Transfer (4);
      begin
         Share (State, Read_Write);
         Client.Start_Read (Sent, State, Read_Write, 0, 4, Status);
         Send (Sent, State, Message_Id, 0, 4, "READ left sent");
         Share (State, Read_Write, Reconnect => True);
         Client.Start_Read (Sent, State, Read_Write, 0, 4, Status);
         Expect_Stage
           (Sent, Status, SMB.Invalid_State_Status, Client.Transfer_Sent,
            "READ over a sent transfer");
         Client.Start_Write (Sent, State, Read_Write, 0, Data, Status);
         Expect_Stage
           (Sent, Status, SMB.Invalid_State_Status, Client.Transfer_Sent,
            "WRITE over a sent transfer");
         --  Another request in flight blocks a start too.
         Client.Start_Read (Other, State, Read_Write, 0, 4, Status);
         Send (Other, State, Message_Id, 0, 4, "READ in flight");
         Client.Abort_Transfer (Sent, State, Status);
         Check (Status = SMB.Invalid_State_Status,
                "abort of a transfer from an earlier epoch");
         Client.Start_Read (Empty, State, Read_Write, 0, 0, Status);
         Check (Status = SMB.Invalid_State_Status,
                "READ while a request is in flight");
         Client.Start_Write
           (Empty, State, Read_Write, 0, SMB.Bytes'(1 .. 0 => 0), Status);
         Check (Status = SMB.Invalid_State_Status,
                "WRITE while a request is in flight");
      end;
   end Test_Starts;

   --  Prepare_Next: each state check alone, the handle, and the output size.
   procedure Test_Prepare_Next is
      A, B : Engine;
      On_A, On_B : Handle;
      Value, Other : Client.Transfer (4);
      Output : SMB.Bytes (0 .. 255);
      Used : Natural;
      Status : SMB.Core_Status;
      Message_Id : SMB.QWord;

      procedure Reject (Wanted : SMB.Core_Status;
                        Stage : Client.Transfer_Stage;
                        Label : String) is
      begin
         Output := (others => 16#EE#);
         Client.Prepare_Next (Value, A, Output, Used, Status);
         Check
           (Status = Wanted and then Used = 0
            and then Output = (Output'Range => 0)
            and then Client.Transfer_Stage_Of (Value) = Stage,
            Label & ": " & SMB.Core_Status'Image (Status) & " "
            & Client.Transfer_Stage'Image (Client.Transfer_Stage_Of (Value)));
      end Reject;
   begin
      Share (A, On_A);
      Share (B, On_B);
      Reject (SMB.Invalid_State_Status, Client.Ready, "transfer never started");

      Client.Start_Read (Value, A, On_A, 0, 4, Status);
      Client.Start_Read (Value, A, SMB.Engine.Handle_Token'(others => 0),
                         0, 4, Status);
      Reject (SMB.Invalid_State_Status, Client.Transfer_Failed,
              "failed transfer");

      Client.Start_Read (Value, A, On_A, 0, 4, Status);
      Output := (others => 16#EE#);
      Client.Prepare_Next (Value, B, Output, Used, Status);
      Check
        (Status = SMB.Invalid_State_Status and then Used = 0
         and then Client.Transfer_Stage_Of (Value) = Client.Ready
         and then not SMB.Engine.Has_Pending_Request (B),
         "transfer prepared on another engine");

      Client.Start_Read (Other, A, On_A, 0, 4, Status);
      Send (Other, A, Message_Id, 0, 4, "READ in flight",
            Acknowledge => False);
      Reject (SMB.Invalid_State_Status, Client.Ready,
              "another request in flight");

      Share (A, On_A, Reconnect => True);
      Reject (SMB.Invalid_State_Status, Client.Ready,
              "transfer from an earlier epoch");

      Client.Start_Read (Value, A, On_A, 0, 4, Status);
      Close_Open_Handle (A, On_A);
      Reject (SMB.Invalid_Handle_Status, Client.Transfer_Failed,
              "closed handle");

      Share (A, On_A);
      Client.Start_Read (Value, A, On_A, 0, 4, Status);
      Client.Prepare_Next (Value, A, Output (0 .. 111), Used, Status);
      Check
        (Status = SMB.Resource_Limit and then Used = 0
         and then Client.Transfer_Stage_Of (Value) = Client.Transfer_Failed
         and then not SMB.Engine.Has_Pending_Request (A),
         "READ request one byte over the output");
      Client.Start_Write (Value, A, On_A, 0, SMB.Bytes'(1, 2, 3, 4), Status);
      Client.Prepare_Next (Value, A, Output (0 .. 114), Used, Status);
      Check
        (Status = SMB.Resource_Limit and then Used = 0
         and then Client.Transfer_Stage_Of (Value) = Client.Transfer_Failed,
         "WRITE request one byte over the output");
      Client.Start_Write (Value, A, On_A, 0, SMB.Bytes'(1, 2, 3, 4), Status);
      Client.Prepare_Next (Value, A, Output (0 .. 62), Used, Status);
      Check
        (Status = SMB.Resource_Limit and then Used = 0,
         "output shorter than a header");
      Client.Start_Write (Value, A, On_A, 0, SMB.Bytes'(1, 2, 3, 4), Status);
      Client.Prepare_Next (Value, A, Output (0 .. 115), Used, Status);
      Check
        (Status = SMB.Ok and then Used = 116
         and then Output (112 .. 115) = SMB.Bytes'(1, 2, 3, 4)
         and then SMB.Wire.Verify_Signature (Output (0 .. 115), Key),
         "WRITE request that fills the output");
   end Test_Prepare_Next;

   --  Transfers split by the negotiated READ and WRITE sizes, on an engine
   --  past epoch 0.
   procedure Test_Chunks is
      State : Engine;
      Token : Handle;
      Value : Client.Transfer (2);
      Writer : Client.Transfer (4);
      Message_Id : SMB.QWord;
      Nt_Status : SMB.DWord;
      Status : SMB.Core_Status;
      Result : SMB.Bytes (10 .. 11) := (others => 16#EE#);
      Used : Natural;
   begin
      Share (State, Token);
      Share (State, Token, Reconnect => True, Maximum_Read => 1,
             Maximum_Write => 3);
      Check (SMB.Engine.Current_Epoch (State) > 0, "reconnected epoch");

      Client.Start_Read (Value, State, Token, 100, 2, Status);
      Send (Value, State, Message_Id, 100, 1, "first READ chunk");
      Client.Complete_Read
        (Value, State, Read_Response (Message_Id, (1 => 16#61#)),
         Nt_Status, Status);
      Check
        (Status = SMB.Ok and then Nt_Status = SMB.Success
         and then Client.Transfer_Stage_Of (Value) = Client.Ready
         and then Client.Transfer_Completed_Of (Value) = 1
         and then Client.Transfer_Position_Of (Value) = 101,
         "first READ chunk completion");
      Send (Value, State, Message_Id, 101, 1, "second READ chunk");
      Client.Complete_Read
        (Value, State, Read_Response (Message_Id, (1 => 16#62#)),
         Nt_Status, Status);
      Check
        (Status = SMB.Ok
         and then Client.Transfer_Stage_Of (Value) = Client.Transfer_Finished,
         "second READ chunk completion");
      Client.Copy_Read_Result (Value, Result, Used, Status);
      Check
        (Status = SMB.Ok and then Used = 2
         and then Result = SMB.Bytes'(16#61#, 16#62#),
         "chunked READ result");

      Client.Start_Write
        (Writer, State, Token, 200, (16#71#, 16#72#, 16#73#, 16#74#), Status);
      Send (Writer, State, Message_Id, 200, 3, "first WRITE chunk");
      Client.Complete_Write
        (Writer, State, Write_Response (Message_Id, 3), Nt_Status, Status);
      Check
        (Status = SMB.Ok and then Nt_Status = SMB.Success
         and then Client.Transfer_Stage_Of (Writer) = Client.Ready
         and then Client.Transfer_Position_Of (Writer) = 203,
         "first WRITE chunk completion");
      Send (Writer, State, Message_Id, 203, 1, "second WRITE chunk");
      Client.Complete_Write
        (Writer, State, Write_Response (Message_Id, 1), Nt_Status, Status);
      Check
        (Status = SMB.Ok
         and then Client.Transfer_Stage_Of (Writer) = Client.Transfer_Finished
         and then Client.Transfer_Completed_Of (Writer) = 4,
         "second WRITE chunk completion");
   end Test_Chunks;

   --  Send acknowledgement, completion, result and abort: each check alone.
   procedure Test_Completions is
      A, B : Engine;
      On_A, On_B : Handle;
      Reader, Writer, Twin : Client.Transfer (2);
      Message_Id, Twin_Id : SMB.QWord;
      Nt_Status : SMB.DWord;
      Status : SMB.Core_Status;
      Result : SMB.Bytes (0 .. 1);
      Used : Natural;
   begin
      Share (A, On_A);
      Client.Start_Read (Reader, A, On_A, 0, 2, Status);
      Client.Transfer_Send_Succeeded (Reader, A, Status);
      Expect_Stage (Reader, Status, SMB.Invalid_State_Status, Client.Ready,
                    "send acknowledgement before a request");
      Client.Abort_Transfer (Reader, A, Status);
      Check
        (Status = SMB.Invalid_State_Status
         and then SMB.Engine.Current_Phase (A) = SMB.Engine.Share_Connected,
         "abort before a request");

      --  The same request pending on two engines.
      Share (B, On_B);
      Client.Start_Read (Twin, B, On_B, 0, 2, Status);
      Send (Twin, B, Twin_Id, 0, 2, "READ on the second engine",
            Acknowledge => False);
      Send (Reader, A, Message_Id, 0, 2, "READ on the first engine",
            Acknowledge => False);
      Check (Message_Id = Twin_Id, "twin requests share a message id");
      Client.Transfer_Send_Succeeded (Reader, B, Status);
      Check (Status = SMB.Invalid_State_Status,
             "send acknowledged on another engine");
      Client.Abort_Transfer (Reader, B, Status);
      Check
        (Status = SMB.Invalid_State_Status
         and then SMB.Engine.Current_Phase (B) = SMB.Engine.Share_Connected,
         "abort on another engine");
      Client.Transfer_Send_Succeeded (Twin, B, Status);
      Client.Transfer_Send_Succeeded (Reader, A, Status);
      Client.Transfer_Send_Succeeded (Reader, A, Status);
      Check
        (Status = SMB.Invalid_State_Status
         and then Client.Transfer_Stage_Of (Reader) = Client.Transfer_Sent,
         "second send acknowledgement");
      Client.Complete_Read
        (Reader, B, Read_Response (Message_Id, (1, 2)), Nt_Status, Status);
      Check
        (Status = SMB.Invalid_State_Status and then Nt_Status = 0,
         "READ completed on another engine");
      Client.Complete_Write
        (Reader, A, Write_Response (Message_Id, 2), Nt_Status, Status);
      Check
        (Status = SMB.Invalid_State_Status and then Nt_Status = 0
         and then Client.Transfer_Stage_Of (Reader) = Client.Transfer_Sent,
         "WRITE completion of a READ");
      Client.Copy_Read_Result (Reader, Result, Used, Status);
      Check (Status = SMB.Invalid_State_Status and then Used = 0,
             "result of a READ in flight");
      Client.Complete_Read
        (Reader, A,
         Error_Response (8, Message_Id, SMB.Status_End_Of_File),
         Nt_Status, Status);
      Check
        (Status = SMB.Ok and then Nt_Status = SMB.Status_End_Of_File
         and then Client.Transfer_Stage_Of (Reader) = Client.Transfer_Finished
         and then Client.Transfer_Completed_Of (Reader) = 0
         and then not SMB.Engine.Has_Pending_Request (A)
         and then not SMB.Engine.Has_Validated_Response (A),
         "READ at the end of the file");
      Client.Copy_Read_Result (Reader, Result, Used, Status);
      Check (Status = SMB.Ok and then Used = 0, "empty READ result");

      Client.Start_Write (Writer, A, On_A, 0, (1, 2), Status);
      Send (Writer, A, Message_Id, 0, 2, "WRITE");
      Client.Complete_Read
        (Writer, A, Read_Response (Message_Id, (1, 2)), Nt_Status, Status);
      Check
        (Status = SMB.Invalid_State_Status and then Nt_Status = 0
         and then Client.Transfer_Stage_Of (Writer) = Client.Transfer_Sent,
         "READ completion of a WRITE");
      Client.Complete_Write
        (Writer, A, Write_Response (Message_Id, 0), Nt_Status, Status);
      Check
        (Status = SMB.Invalid_Protocol
         and then Client.Transfer_Stage_Of (Writer) = Client.Transfer_Failed
         and then SMB.Engine.Current_Phase (A) = SMB.Engine.Disconnected,
         "WRITE that wrote nothing");
      Client.Copy_Read_Result (Writer, Result, Used, Status);
      Check (Status = SMB.Invalid_State_Status and then Used = 0,
             "READ result of a WRITE");
   end Test_Completions;

   function Create_Response (Message_Id : SMB.QWord) return SMB.Bytes is
      Body_Bytes : SMB.Bytes (66 .. 143) := (others => 0);
   begin
      Body_Bytes (128 .. 143) := File_Id;
      return Signed_Response (5, Message_Id, 151, 89, Body_Bytes);
   end Create_Response;

   --  Prepare_Create, Prepare_Close, Send_Succeeded, Complete and
   --  Abort_Operation: arguments, output size, each state check alone,
   --  signed requests, error responses and a full handle table.
   procedure Test_Operations is
      State, Twin_State : Engine;
      Token, Twin_Token, Reader : Handle;
      Name : constant SMB.Bytes (1 .. 4) := (16#61#, 0, 16#62#, 0);
      Required : constant Natural := 64 + 56 + Name'Length;
      Output : SMB.Bytes (0 .. 255);
      Used : Natural;
      Status : SMB.Core_Status;
      Nt_Status : SMB.DWord;
      Result : Handle;

      procedure Expect
        (Value : Client.Operation;
         Wanted : SMB.Core_Status;
         Stage : Client.Operation_Stage;
         Label : String) is
      begin
         Check
           (Status = Wanted and then Client.Stage_Of (Value) = Stage,
            Label & ": " & SMB.Core_Status'Image (Status) & " "
            & Client.Operation_Stage'Image (Client.Stage_Of (Value)));
      end Expect;

      --  Prepare a CREATE of Name, check its signed header, and return its
      --  message id.
      procedure Create
        (Value : in out Client.Operation;
         On : in out Engine;
         Message_Id : out SMB.QWord;
         Label : String;
         Disposition : SMB.DWord := 1;
         Delete_Access : Boolean := False) is
      begin
         Output := (others => 16#EE#);
         Client.Prepare_Create
           (Value, On, Name, SMB.Engine.Read_Write, Delete_Access,
            Disposition, False, Output, Used, Status);
         Check
           (Status = SMB.Ok and then Used = Required
            and then SMB.Wire.Verify_Signature (Output (0 .. Used - 1), Key)
            and then SMB.Wire.U16 (Output, 14) = 1,
            Label & ": signed CREATE " & SMB.Core_Status'Image (Status));
         Message_Id := SMB.Wire.U64 (Output, 24);
      end Create;

      procedure Close
        (Value : in out Client.Operation;
         On : in out Engine;
         Target : Handle;
         Message_Id : out SMB.QWord;
         Label : String) is
      begin
         Output := (others => 16#EE#);
         Client.Prepare_Close (Value, On, Target, Output, Used, Status);
         Check
           (Status = SMB.Ok and then Used = 88
            and then SMB.Wire.Verify_Signature (Output (0 .. Used - 1), Key)
            and then SMB.Wire.U16 (Output, 14) = 1,
            Label & ": signed CLOSE " & SMB.Core_Status'Image (Status));
         Message_Id := SMB.Wire.U64 (Output, 24);
      end Close;
   begin
      Share (State, Token);
      Open_Handle (State, Reader, SMB.Engine.Read_Only);

      --  Arguments and output size.
      declare
         Zero, Six, Odd, Short, Short_Close, No_Handle : Client.Operation;
      begin
         Client.Prepare_Create
           (Zero, State, Name, SMB.Engine.Read_Only, False, 0, False,
            Output, Used, Status);
         Expect (Zero, SMB.Invalid_Value, Client.Failed, "disposition 0");
         Client.Prepare_Create
           (Six, State, Name, SMB.Engine.Read_Only, False, 6, False,
            Output, Used, Status);
         Expect (Six, SMB.Invalid_Value, Client.Failed, "disposition 6");
         Client.Prepare_Create
           (Odd, State, Name (1 .. 3), SMB.Engine.Read_Only, False, 1, False,
            Output, Used, Status);
         Expect (Odd, SMB.Invalid_Value, Client.Failed, "odd name length");
         Output := (others => 16#EE#);
         Client.Prepare_Create
           (Short, State, Name, SMB.Engine.Read_Only, False, 1, False,
            Output (0 .. Required - 2), Used, Status);
         Expect (Short, SMB.Resource_Limit, Client.Failed,
                 "CREATE one byte over the output");
         Check (Used = 0 and then Output (0 .. Required - 2) =
                  (0 .. Required - 2 => 0)
                and then not SMB.Engine.Has_Pending_Request (State),
                "CREATE output cleared");
         Output := (others => 16#EE#);
         Client.Prepare_Close
           (Short_Close, State, Token, Output (0 .. 86), Used, Status);
         Expect (Short_Close, SMB.Resource_Limit, Client.Failed,
                 "CLOSE one byte over the output");
         Client.Prepare_Close
           (No_Handle, State, SMB.Engine.Handle_Token'(others => 0), Output,
            Used, Status);
         Expect (No_Handle, SMB.Invalid_Handle_Status, Client.Failed,
                 "CLOSE of no handle");
      end;

      --  A whole CREATE at disposition 5, then CLOSE of a read-only handle
      --  with the same operation object.
      declare
         Value : Client.Operation;
         Message_Id : SMB.QWord;
      begin
         Create (Value, State, Message_Id, "CREATE at disposition 5", 5,
                 Delete_Access => True);
         Client.Prepare_Create
           (Value, State, Name, SMB.Engine.Read_Only, False, 1, False,
            Output, Used, Status);
         Expect (Value, SMB.Invalid_State_Status, Client.Prepared,
                 "CREATE over a prepared operation");
         Output := (others => 16#EE#);
         Client.Prepare_Close (Value, State, Token, Output, Used, Status);
         Check
           (Status = SMB.Invalid_State_Status and then Used = 0
            and then Output = (Output'Range => 0)
            and then Client.Stage_Of (Value) = Client.Prepared,
            "CLOSE over a prepared operation");
         Client.Send_Succeeded (Value, State, Status);
         Expect (Value, SMB.Ok, Client.Sent, "CREATE sent");
         Client.Send_Succeeded (Value, State, Status);
         Expect (Value, SMB.Invalid_State_Status, Client.Sent,
                 "CREATE sent twice");
         Client.Prepare_Create
           (Value, State, Name, SMB.Engine.Read_Only, False, 1, False,
            Output, Used, Status);
         Expect (Value, SMB.Invalid_State_Status, Client.Sent,
                 "CREATE over a sent operation");
         Client.Prepare_Close (Value, State, Token, Output, Used, Status);
         Expect (Value, SMB.Invalid_State_Status, Client.Sent,
                 "CLOSE over a sent operation");
         Client.Complete
           (Value, State, Create_Response (Message_Id), Nt_Status, Result,
            Status);
         Expect (Value, SMB.Ok, Client.Finished, "CREATE completion");
         Check
           (Client.Create_Delete_Access_Of (Value)
            and then Client.Create_Disposition_Of (Value) = 5,
            "CREATE metadata");
         Close (Value, State, Reader, Message_Id, "CLOSE of a read-only handle");
         Check
           (not Client.Create_Delete_Access_Of (Value)
            and then Client.Create_Disposition_Of (Value) = 0,
            "CLOSE clears the CREATE metadata");
         Client.Send_Succeeded (Value, State, Status);
         Client.Complete
           (Value, State, Signed_Response (6, Message_Id, 123, 60),
            Nt_Status, Result, Status);
         Expect (Value, SMB.Ok, Client.Finished, "CLOSE completion");
         Create (Value, State, Message_Id, "CREATE after a CLOSE");
         Check
           (Client.Close_Token_Of (Value) = (Owner => 0, Epoch => 0, Ticket => 0)
            and then Client.File_Id_Of (Value) = (0 .. 15 => 0),
            "CREATE after a CLOSE forgets the closed handle");
         Client.Abort_Operation (Value, State, Status);
         Share (State, Token);
         Open_Handle (State, Reader, SMB.Engine.Read_Only);
      end;

      --  Completion: before a send, a bad signature, and error statuses.
      declare
         Value, Error_Create, Error_Close : Client.Operation;
         Message_Id : SMB.QWord;
         Packet : SMB.Bytes (0 .. 151);
      begin
         Result := (Owner => 1, Epoch => 1, Ticket => 1);
         Client.Complete
           (Value, State, Create_Response (0), Nt_Status, Result, Status);
         Check
           (Status = SMB.Invalid_State_Status and then Nt_Status = 0
            and then Result = (Owner => 0, Epoch => 0, Ticket => 0),
            "completion before a request");
         Client.Abort_Operation (Value, State, Status);
         Check
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Share_Connected,
            "abort before a request");

         Create (Error_Create, State, Message_Id, "CREATE of a missing file");
         Client.Send_Succeeded (Error_Create, State, Status);
         Client.Complete
           (Error_Create, State,
            Error_Response (5, Message_Id, SMB.Status_Object_Name_Not_Found),
            Nt_Status, Result, Status);
         Check
           (Status = SMB.Ok
            and then Nt_Status = SMB.Status_Object_Name_Not_Found
            and then Result = (Owner => 0, Epoch => 0, Ticket => 0)
            and then Client.Stage_Of (Error_Create) = Client.Finished
            and then not SMB.Engine.Has_Validated_Response (State)
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Share_Connected,
            "CREATE of a missing file");

         Close (Error_Close, State, Token, Message_Id, "CLOSE refused");
         Client.Send_Succeeded (Error_Close, State, Status);
         Client.Complete
           (Error_Close, State,
            Error_Response (6, Message_Id, SMB.Status_Access_Denied),
            Nt_Status, Result, Status);
         Check
           (Status = SMB.Ok and then Nt_Status = SMB.Status_Access_Denied
            and then not SMB.Engine.Has_Validated_Response (State),
            "CLOSE refused");

         Create (Value, State, Message_Id, "CREATE with a bad signature");
         Client.Send_Succeeded (Value, State, Status);
         Packet := Create_Response (Message_Id);
         Packet (48) := Packet (48) xor 1;
         Client.Complete (Value, State, Packet, Nt_Status, Result, Status);
         Expect (Value, SMB.Signature_Error, Client.Failed,
                 "CREATE response with a bad signature");
      end;

      --  Each state check of Send_Succeeded and Abort_Operation alone: the
      --  same request pending on twin engines, and on an earlier epoch.
      declare
         Value, Twin, Later : Client.Operation;
         Message_Id, Twin_Id, Later_Id : SMB.QWord;
      begin
         Share (State, Token);
         Share (Twin_State, Twin_Token);
         Create (Value, State, Message_Id, "CREATE on the first engine");
         Create (Twin, Twin_State, Twin_Id, "CREATE on the second engine");
         Check (Message_Id = Twin_Id, "twin CREATEs share a message id");
         Client.Send_Succeeded (Value, Twin_State, Status);
         Expect (Value, SMB.Invalid_State_Status, Client.Prepared,
                 "CREATE acknowledged on another engine");
         Client.Abort_Operation (Value, Twin_State, Status);
         Check
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine.Current_Phase (Twin_State) =
              SMB.Engine.Share_Connected,
            "abort on another engine");
         Client.Send_Succeeded (Value, State, Status);
         Client.Send_Succeeded (Twin, Twin_State, Status);
         Client.Complete
           (Value, Twin_State, Create_Response (Message_Id), Nt_Status,
            Result, Status);
         Expect (Value, SMB.Invalid_State_Status, Client.Sent,
                 "CREATE completed on another engine");

         Share (State, Token, Reconnect => True);
         Close (Later, State, Token, Later_Id, "CLOSE past epoch 0");
         Client.Send_Succeeded (Later, State, Status);
         Expect (Later, SMB.Ok, Client.Sent, "CLOSE sent past epoch 0");
         Client.Complete
           (Later, State, Signed_Response (6, Later_Id, 123, 60), Nt_Status,
            Result, Status);
         Expect (Later, SMB.Ok, Client.Finished, "CLOSE past epoch 0");
      end;

      --  A request already pending, and a full handle table.
      declare
         Value, Blocked : Client.Operation;
         Message_Id : SMB.QWord;
         Spare : Handle;
      begin
         Share (State, Token);
         Create (Value, State, Message_Id, "CREATE in flight");
         Client.Prepare_Close (Blocked, State, Token, Output, Used, Status);
         Expect (Blocked, SMB.Invalid_State_Status, Client.Failed,
                 "CLOSE while a request is in flight");
         Check (SMB.Engine.Has_Pending_Request (State),
                "rejected CLOSE left the request in flight");
         Client.Abort_Operation (Value, State, Status);
         Check
           (Status = SMB.Ok
            and then Client.Stage_Of (Value) = Client.Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected,
            "abort of a prepared CREATE");
         Share (State, Token);
         Create (Value, State, Message_Id, "CREATE to abort once sent");
         Client.Send_Succeeded (Value, State, Status);
         Client.Abort_Operation (Value, State, Status);
         Check
           (Status = SMB.Ok
            and then Client.Stage_Of (Value) = Client.Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected,
            "abort of a sent CREATE");

         Share (State, Token);
         for Count in 2 .. SMB.Engine.Maximum_Handles loop
            Open_Handle (State, Spare);
         end loop;
         Client.Prepare_Create
           (Value, State, Name, SMB.Engine.Read_Write, False, 1, False,
            Output, Used, Status);
         Check
           (Status = SMB.Resource_Limit and then Used = 0
            and then Client.Stage_Of (Value) = Client.Failed
            and then not SMB.Engine.Has_Pending_Request (State),
            "CREATE into a full handle table "
            & SMB.Core_Status'Image (Status));
      end;
   end Test_Operations;

   --  A signed QUERY_DIRECTORY response carrying Page from offset 72.
   function Directory_Response
     (Message_Id : SMB.QWord;
      Page : SMB.Bytes;
      Nt_Status : SMB.DWord := SMB.Success) return SMB.Bytes
   is
      Packet : SMB.Bytes :=
        Response (14, Message_Id, 71 + Natural'Max (Page'Length, 1), 9,
                  Nt_Status);
   begin
      if Page'Length > 0 then
         SMB.Wire.Put_U16 (Packet, 66, 72);
         SMB.Wire.Put_U32 (Packet, 68, SMB.DWord (Page'Length));
         Packet (72 .. 71 + Page'Length) := Page;
      end if;
      SMB.Wire.Sign (Packet, Key);
      return Packet;
   end Directory_Response;

   --  One directory entry named "a".
   One_Entry : constant SMB.Bytes (0 .. 105) :=
     (60 => 2, 104 => 97, others => 0);

   --  Start_Directory, Prepare_Directory_Query, Directory_Send_Succeeded,
   --  Complete_Directory_Page, Next_Directory_Entry and Abort_Directory:
   --  the handle, each state check alone, sizes, statuses and the page
   --  limit.
   procedure Test_Directories is
      State : Engine;
      File, Folder, Folder_Write, Folder_Read_Write : Handle;
      Output : SMB.Bytes (0 .. 255);
      Used, Name_Used : Natural;
      Status : SMB.Core_Status;
      Nt_Status : SMB.DWord;
      Name : SMB.Bytes (0 .. 15);
      Info : SMB.Core_Protocol.Directory_Info;

      procedure Expect
        (Value : Client.Directory_Enumeration;
         Wanted : SMB.Core_Status;
         Stage : Client.Directory_Stage;
         Label : String) is
      begin
         Check
           (Status = Wanted and then Client.Directory_Stage_Of (Value) = Stage,
            Label & ": " & SMB.Core_Status'Image (Status) & " "
            & Client.Directory_Stage'Image (Client.Directory_Stage_Of (Value)));
      end Expect;

      --  Prepare and acknowledge the next query of Value.
      procedure Query
        (Value : in out Client.Directory_Enumeration;
         Message_Id : out SMB.QWord;
         Label : String;
         Acknowledge : Boolean := True) is
      begin
         Output := (others => 16#EE#);
         Client.Prepare_Directory_Query (Value, State, Output, Used, Status);
         Check
           (Status = SMB.Ok and then Used = Client.Directory_Request_Size
            and then SMB.Wire.Verify_Signature (Output (0 .. Used - 1), Key),
            Label & ": signed QUERY_DIRECTORY "
            & SMB.Core_Status'Image (Status));
         Message_Id := SMB.Wire.U64 (Output, 24);
         if Acknowledge then
            Client.Directory_Send_Succeeded (Value, State, Status);
            Check (Status = SMB.Ok, Label & ": send acknowledgement");
         end if;
      end Query;

      procedure Start
        (Value : in out Client.Directory_Enumeration;
         Token : Handle;
         Label : String) is
      begin
         Client.Start_Directory (Value, State, Token, Status);
         Expect (Value, SMB.Ok, Client.Query_Ready, Label);
      end Start;
   begin
      Share (State, File);
      Open_Handle (State, Folder, SMB.Engine.Read_Only, Directory => True);
      Open_Handle (State, Folder_Write, SMB.Engine.Write_Only,
                   Directory => True);
      Open_Handle (State, Folder_Read_Write, SMB.Engine.Read_Write,
                   Directory => True);

      --  Start_Directory: the handle, a second start, a request in flight
      --  and a held receipt.
      declare
         Write_Only, On_File, Twice, Busy, Holding :
           Client.Directory_Enumeration;
         Other : Client.Directory_Enumeration;
         Message_Id : SMB.QWord;
      begin
         Client.Start_Directory (Write_Only, State, Folder_Write, Status);
         Expect (Write_Only, SMB.Invalid_State_Status, Client.Directory_Idle,
                 "listing a write-only directory");
         Client.Start_Directory (On_File, State, File, Status);
         Expect (On_File, SMB.Invalid_State_Status, Client.Directory_Idle,
                 "listing a file");
         Start (Twice, Folder, "first start");
         Client.Start_Directory (Twice, State, Folder, Status);
         Expect (Twice, SMB.Invalid_State_Status, Client.Query_Ready,
                 "second start");
         Start (Other, Folder, "start before a query in flight");
         Query (Other, Message_Id, "query in flight", Acknowledge => False);
         Client.Start_Directory (Busy, State, Folder, Status);
         Expect (Busy, SMB.Invalid_State_Status, Client.Directory_Idle,
                 "start while a request is in flight");
         Client.Complete_Directory_Page
           (Other, State, Directory_Response (Message_Id, One_Entry),
            Nt_Status, Status);
         Expect (Other, SMB.Invalid_State_Status, Client.Query_Prepared,
                 "page before the send acknowledgement");
         Client.Directory_Send_Succeeded (Other, State, Status);
         Client.Directory_Send_Succeeded (Other, State, Status);
         Expect (Other, SMB.Invalid_State_Status, Client.Query_Sent,
                 "second send acknowledgement");
         SMB.Engine.Accept_Response
           (State, Directory_Response (Message_Id, One_Entry), Nt_Status,
            Status);
         Check (Status = SMB.Ok, "receipt held outside the coordinator");
         Client.Start_Directory (Holding, State, Folder, Status);
         Expect (Holding, SMB.Invalid_State_Status, Client.Directory_Idle,
                 "start while a receipt is held");
         SMB.Engine.Discard_Response_Receipt (State, Status);
      end;

      --  A read-write directory, a short page, end of listing and the
      --  cursor after a drained page.
      declare
         Value, Stale : Client.Directory_Enumeration;
         Message_Id : SMB.QWord;
      begin
         Share (State, File);
         Open_Handle (State, Folder_Read_Write, SMB.Engine.Read_Write,
                      Directory => True);
         Name := (others => 16#EE#);
         Info := (Name_Offset => 1, Name_Length => 1, Size => 1,
                  Attributes => 1, Next_Cursor => 1);
         Client.Next_Directory_Entry (Value, State, Name, Name_Used, Info, Status);
         Check
           (Status = SMB.Invalid_State_Status and then Name_Used = 0
            and then Info = (Name_Offset => 0, Name_Length => 0, Size => 0,
                             Attributes => 0, Next_Cursor => 0),
            "entry before a start");
         Output := (others => 16#EE#);
         Client.Prepare_Directory_Query (Value, State, Output, Used, Status);
         Check
           (Status = SMB.Invalid_State_Status and then Used = 0
            and then Output = (Output'Range => 0),
            "query before a start");
         Nt_Status := 16#EEEE#;
         Client.Complete_Directory_Page
           (Value, State, Directory_Response (0, One_Entry), Nt_Status,
            Status);
         Check (Status = SMB.Invalid_State_Status and then Nt_Status = 0,
                "page before a start");

         Start (Value, Folder_Read_Write, "read-write directory");
         Query (Value, Message_Id, "read-write directory");
         Client.Complete_Directory_Page
           (Value, State, Directory_Response (Message_Id, One_Entry),
            Nt_Status, Status);
         Expect (Value, SMB.Ok, Client.Page_Ready, "read-write page");
         Client.Next_Directory_Entry (Value, State, Name, Name_Used, Info, Status);
         Expect (Value, SMB.Ok, Client.Query_Ready, "read-write entry");
         Client.Next_Directory_Entry (Value, State, Name, Name_Used, Info, Status);
         Expect (Value, SMB.Invalid_State_Status, Client.Query_Ready,
                 "entry after the page is drained");
         Check (Client.Directory_Cursor_Of (Value) = One_Entry'Length,
                "cursor at the end of the drained page");
         Query (Value, Message_Id, "query after a drained page");
         Client.Complete_Directory_Page
           (Value, State,
            Directory_Response
              (Message_Id, SMB.Bytes'(1 .. 0 => 0), SMB.Status_No_More_Files),
            Nt_Status, Status);
         Check
           (Status = SMB.Ok and then Nt_Status = SMB.Status_No_More_Files
            and then Client.Directory_Stage_Of (Value) =
              Client.Directory_Finished
            and then Client.Directory_Cursor_Of (Value) = 0
            and then Client.Directory_Page_Length_Of (Value) = 0
            and then not SMB.Engine.Has_Validated_Response (State),
            "end of the listing");

         Start (Stale, Folder_Read_Write, "short response");
         Query (Stale, Message_Id, "short response");
         Client.Complete_Directory_Page
           (Stale, State, Directory_Response (Message_Id, One_Entry) (0 .. 70),
            Nt_Status, Status);
         Check
           (Status = SMB.Invalid_Length
            and then Client.Directory_Stage_Of (Stale) =
              Client.Directory_Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected,
            "71-byte QUERY_DIRECTORY response");
      end;

      --  Bad signature, short output, and Abort_Directory in each stage.
      declare
         Signed, Short, Ready, Idle_Ready, Sent, Paged, Finished, Busy :
           Client.Directory_Enumeration;
         Message_Id : SMB.QWord;
         Packet : SMB.Bytes (0 .. 177);
      begin
         Share (State, File);
         Open_Handle (State, Folder, SMB.Engine.Read_Only, Directory => True);
         Start (Signed, Folder, "bad signature");
         Query (Signed, Message_Id, "bad signature");
         Packet := Directory_Response (Message_Id, One_Entry);
         Packet (48) := Packet (48) xor 1;
         Client.Complete_Directory_Page
           (Signed, State, Packet, Nt_Status, Status);
         Expect (Signed, SMB.Signature_Error, Client.Directory_Failed,
                 "QUERY_DIRECTORY response with a bad signature");

         Share (State, File);
         Open_Handle (State, Folder, SMB.Engine.Read_Only, Directory => True);
         Start (Short, Folder, "short output");
         Output := (others => 16#EE#);
         Client.Prepare_Directory_Query
           (Short, State, Output (0 .. Client.Directory_Request_Size - 2),
            Used, Status);
         Check
           (Status = SMB.Resource_Limit and then Used = 0
            and then Client.Directory_Stage_Of (Short) =
              Client.Directory_Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected,
            "QUERY_DIRECTORY one byte over the output");

         Share (State, File);
         Open_Handle (State, Folder, SMB.Engine.Read_Only, Directory => True);
         Client.Abort_Directory (Finished, State, Status);
         Check (Status = SMB.Invalid_State_Status, "abort before a start");
         Start (Ready, Folder, "abort when ready");
         Start (Busy, Folder, "abort with another query in flight");
         Query (Busy, Message_Id, "other query", Acknowledge => False);
         Client.Abort_Directory (Ready, State, Status);
         Check
           (Status = SMB.Invalid_State_Status
            and then Client.Directory_Stage_Of (Ready) = Client.Query_Ready
            and then SMB.Engine.Has_Pending_Request (State),
            "abort while another query is in flight");
         Client.Abort_Directory (Busy, State, Status);
         Check
           (Status = SMB.Ok
            and then Client.Directory_Stage_Of (Busy) =
              Client.Directory_Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected,
            "abort of a prepared query");

         Share (State, File);
         Open_Handle (State, Folder, SMB.Engine.Read_Only, Directory => True);
         Start (Idle_Ready, Folder, "abort when ready");
         Client.Abort_Directory (Idle_Ready, State, Status);
         Check
           (Status = SMB.Ok
            and then Client.Directory_Stage_Of (Idle_Ready) =
              Client.Directory_Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Share_Connected,
            "abort of a ready listing");
         Start (Paged, Folder, "abort with a page");
         Query (Paged, Message_Id, "abort with a page");
         Client.Complete_Directory_Page
           (Paged, State, Directory_Response (Message_Id, One_Entry),
            Nt_Status, Status);
         Start (Sent, Folder, "abort of a sent query");
         Query (Sent, Message_Id, "abort of a sent query");
         SMB.Engine.Accept_Response
           (State, Directory_Response (Message_Id, One_Entry), Nt_Status,
            Status);
         Client.Abort_Directory (Paged, State, Status);
         Check
           (Status = SMB.Invalid_State_Status
            and then Client.Directory_Stage_Of (Paged) = Client.Page_Ready,
            "abort of a page while a receipt is held");
         Client.Abort_Directory (Sent, State, Status);
         Check
           (Status = SMB.Invalid_State_Status
            and then Client.Directory_Stage_Of (Sent) = Client.Query_Sent,
            "abort of a sent query while its receipt is held");
         SMB.Engine.Discard_Response_Receipt (State, Status);
         Client.Abort_Directory (Sent, State, Status);
         Check
           (Status = SMB.Invalid_State_Status
            and then Client.Directory_Stage_Of (Sent) = Client.Query_Sent
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Share_Connected,
            "abort of a sent query whose response was consumed");
         Client.Abort_Directory (Paged, State, Status);
         Check
           (Status = SMB.Ok
            and then Client.Directory_Stage_Of (Paged) =
              Client.Directory_Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Share_Connected,
            "abort of a page");
      end;

      --  The directory handle closed while a page is held.
      declare
         Value : Client.Directory_Enumeration;
         Message_Id : SMB.QWord;
      begin
         Share (State, File);
         Open_Handle (State, Folder, SMB.Engine.Read_Only, Directory => True);
         Start (Value, Folder, "listing of a handle to close");
         Query (Value, Message_Id, "listing of a handle to close");
         Client.Complete_Directory_Page
           (Value, State, Directory_Response (Message_Id, One_Entry),
            Nt_Status, Status);
         Close_Open_Handle (State, Folder);
         Client.Next_Directory_Entry (Value, State, Name, Name_Used, Info,
                                      Status);
         Expect (Value, SMB.Invalid_State_Status, Client.Page_Ready,
                 "entry after the handle closed");
         Client.Abort_Directory (Value, State, Status);
         Expect (Value, SMB.Invalid_State_Status, Client.Page_Ready,
                 "abort after the handle closed");
      end;

      --  The entry limit: pages of 580 one-letter entries, until the entry
      --  after the last allowed one fails.
      declare
         Entries : constant := 580;
         Page : SMB.Bytes (0 .. Entries * 112 - 7) := (others => 0);
         Value : Client.Directory_Enumeration;
         Message_Id : SMB.QWord;
         Total : Natural := 0;
      begin
         for Index in 0 .. Entries - 1 loop
            if Index < Entries - 1 then
               SMB.Wire.Put_U32 (Page, Index * 112, 112);
            end if;
            Page (Index * 112 + 60) := 2;
            Page (Index * 112 + 104) := 97;
         end loop;
         Share (State, File);
         Open_Handle (State, Folder, SMB.Engine.Read_Only, Directory => True);
         Start (Value, Folder, "entry limit");
         Pages : loop
            Client.Prepare_Directory_Query (Value, State, Output, Used, Status);
            exit Pages when Status /= SMB.Ok;
            Message_Id := SMB.Wire.U64 (Output, 24);
            Client.Directory_Send_Succeeded (Value, State, Status);
            Client.Complete_Directory_Page
              (Value, State, Directory_Response (Message_Id, Page), Nt_Status,
               Status);
            exit Pages when Status /= SMB.Ok;
            for Count in 1 .. Entries loop
               Client.Next_Directory_Entry
                 (Value, State, Name, Name_Used, Info, Status);
               exit Pages when Status /= SMB.Ok;
               Total := Total + 1;
            end loop;
         end loop Pages;
         Check
           (Status = SMB.Resource_Limit
            and then Total = SMB.Core_Protocol.Maximum_Directory_Entries
            and then Client.Directory_Stage_Of (Value) =
              Client.Directory_Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected,
            "entry past the limit after" & Natural'Image (Total)
            & " entries: " & SMB.Core_Status'Image (Status));
      end;

      --  The page limit: the query after the last allowed page fails before
      --  anything is written.
      declare
         Value : Client.Directory_Enumeration;
         Message_Id : SMB.QWord;
      begin
         Share (State, File);
         Open_Handle (State, Folder, SMB.Engine.Read_Only, Directory => True);
         Start (Value, Folder, "page limit");
         for Page in 1 .. SMB.Core_Protocol.Maximum_Directory_Pages loop
            Client.Prepare_Directory_Query (Value, State, Output, Used, Status);
            Message_Id := SMB.Wire.U64 (Output, 24);
            Client.Directory_Send_Succeeded (Value, State, Status);
            Client.Complete_Directory_Page
              (Value, State, Directory_Response (Message_Id, One_Entry),
               Nt_Status, Status);
            Client.Next_Directory_Entry
              (Value, State, Name, Name_Used, Info, Status);
            exit when Status /= SMB.Ok;
         end loop;
         Check
           (Status = SMB.Ok
            and then Client.Directory_Page_Count_Of (Value) =
              SMB.Core_Protocol.Maximum_Directory_Pages,
            "pages up to the limit");
         Output := (others => 16#EE#);
         Client.Prepare_Directory_Query (Value, State, Output, Used, Status);
         Check
           (Status = SMB.Resource_Limit and then Used = 0
            and then Output = (Output'Range => 0)
            and then Client.Directory_Stage_Of (Value) =
              Client.Directory_Failed,
            "query past the page limit");
      end;
   end Test_Directories;

   --  Prepare_Rename, Prepare_Disposition, Metadata_Send_Succeeded,
   --  Complete_Metadata and Abort_Metadata: the handle's access, each early
   --  rejection with the output left clear, and aborts.
   procedure Test_Metadata is
      State : Engine;
      File, Write_Only, Read_Write : Handle;
      New_Name : constant SMB.Bytes (1 .. 2) := (16#62#, 0);
      Output : SMB.Bytes (0 .. 255);
      Used : Natural;
      Status : SMB.Core_Status;
      Nt_Status : SMB.DWord;

      procedure Rejected
        (Value : in out Client.Metadata_Operation;
         Token : Handle;
         Label : String) is
      begin
         Output := (others => 16#EE#);
         Client.Prepare_Rename (Value, State, Token, New_Name, Output, Used,
                                Status);
         Check
           (Status = SMB.Invalid_State_Status and then Used = 0
            and then Output = (Output'Range => 0),
            Label & ": " & SMB.Core_Status'Image (Status));
      end Rejected;

      --  A whole rename on Token.
      procedure Rename (Token : Handle; Label : String) is
         Value : Client.Metadata_Operation;
         Message_Id : SMB.QWord;
      begin
         Client.Prepare_Rename (Value, State, Token, New_Name, Output, Used,
                                Status);
         Check
           (Status = SMB.Ok
            and then SMB.Wire.Verify_Signature (Output (0 .. Used - 1), Key),
            Label & ": signed SET_INFO " & SMB.Core_Status'Image (Status));
         Message_Id := SMB.Wire.U64 (Output, 24);
         Client.Metadata_Send_Succeeded (Value, State, Status);
         Check (Status = SMB.Ok, Label & ": send acknowledgement");
         Client.Complete_Metadata
           (Value, State, Signed_Response (17, Message_Id, 65, 2), Nt_Status,
            Status);
         Check
           (Status = SMB.Ok and then Nt_Status = SMB.Success
            and then Client.Metadata_Stage_Of (Value) =
              Client.Metadata_Finished,
            Label & ": completion " & SMB.Core_Status'Image (Status));
      end Rename;
   begin
      Share (State, File);
      Open_Handle (State, Write_Only, SMB.Engine.Write_Only);
      Open_Handle (State, Read_Write, SMB.Engine.Read_Write);
      Rename (Write_Only, "rename through a write-only handle");
      Rename (Read_Write, "rename through a read-write handle");
      declare
         Done : Client.Metadata_Operation;
         Message_Id : SMB.QWord;
      begin
         Client.Prepare_Rename (Done, State, File, New_Name, Output, Used,
                                Status);
         Message_Id := SMB.Wire.U64 (Output, 24);
         Client.Metadata_Send_Succeeded (Done, State, Status);
         Client.Complete_Metadata
           (Done, State, Signed_Response (17, Message_Id, 65, 2), Nt_Status,
            Status);
         Rejected (Done, File, "rename over a finished operation");
      end;

      declare
         First, Second, Busy, Holding, Closed, Nothing, Disposition :
           Client.Metadata_Operation;
         Gone : Handle;
         Message_Id : SMB.QWord;
      begin
         Client.Prepare_Disposition
           (Disposition, State, File, True, Output, Used, Status);
         Check
           (Status = SMB.Ok
            and then Client.Metadata_Snapshot_Of (Disposition).Name_Length = 0
            and then Client.Metadata_Snapshot_Of (Disposition).Delete_File,
            "disposition carries no name");
         Rejected (Disposition, File, "second preparation");
         Rejected (Busy, File, "rename while a request is in flight");
         Client.Abort_Metadata (Busy, State, Status);
         Check
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine.Has_Pending_Request (State),
            "abort before a preparation");
         Client.Abort_Metadata (Disposition, State, Status);
         Check
           (Status = SMB.Ok
            and then Client.Metadata_Stage_Of (Disposition) =
              Client.Metadata_Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected,
            "abort of a prepared disposition");

         Share (State, File);
         Open_Handle (State, Gone);
         Close_Open_Handle (State, Gone);
         Rejected (Closed, Gone, "rename through a closed handle");
         Rejected (Nothing, SMB.Engine.Handle_Token'(others => 0),
                   "rename through no handle");
         Client.Prepare_Rename (First, State, File, New_Name, Output, Used,
                                Status);
         Message_Id := SMB.Wire.U64 (Output, 24);
         Client.Metadata_Send_Succeeded (First, State, Status);
         SMB.Engine.Accept_Response
           (State, Signed_Response (17, Message_Id, 65, 2), Nt_Status, Status);
         Check (Status = SMB.Ok, "SET_INFO receipt held outside the coordinator");
         Rejected (Holding, File, "rename while a receipt is held");
         SMB.Engine.Discard_Response_Receipt (State, Status);
         Client.Abort_Metadata (First, State, Status);
         Check (Status = SMB.Invalid_State_Status,
                "abort after the response arrived");
         Client.Prepare_Rename (Second, State, File, New_Name, Output, Used,
                                Status);
         Client.Metadata_Send_Succeeded (Second, State, Status);
         Client.Abort_Metadata (Second, State, Status);
         Check
           (Status = SMB.Ok
            and then Client.Metadata_Stage_Of (Second) =
              Client.Metadata_Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected,
            "abort of a sent rename");
      end;
   end Test_Metadata;

   procedure Run is
   begin
      Test_Starts;
      Test_Prepare_Next;
      Test_Chunks;
      Test_Completions;
      Test_Operations;
      Test_Directories;
      Test_Metadata;
      Ada.Text_IO.Put_Line
        ("core client coordinator edges:" & Natural'Image (Checks)
         & " checks passed");
   end Run;
end Core_Client_Tests;
