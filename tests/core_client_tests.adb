with Ada.Text_IO;
with SMB;
with SMB.Core_Client;
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

   procedure Run is
   begin
      Test_Starts;
      Test_Prepare_Next;
      Test_Chunks;
      Test_Completions;
      Ada.Text_IO.Put_Line
        ("core client transfer edges:" & Natural'Image (Checks)
         & " checks passed");
   end Run;
end Core_Client_Tests;
