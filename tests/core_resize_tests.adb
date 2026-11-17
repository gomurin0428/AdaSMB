with Ada.Text_IO;
with SMB;
with SMB.Core_Protocol;
with SMB.Core_Resize;
with SMB.Engine;
with SMB.Wire;
with Engine_Fixtures; use Engine_Fixtures;

package body Core_Resize_Tests is
   use type SMB.Bytes;
   use type SMB.Core_Status;
   use type SMB.DWord;
   use type SMB.QWord;
   use type SMB.Word;
   use type SMB.Engine.Phase;
   use type SMB.Core_Resize.Resize_Stage;

   package Resize renames SMB.Core_Resize;
   subtype Engine is SMB.Engine.Engine_State;
   subtype Handle is SMB.Engine.Handle_Token;

   type QWord_Values is array (Positive range <>) of SMB.QWord;
   Checks : Natural := 0;
   Largest : constant SMB.QWord := 16#7FFF_FFFF_FFFF_FFFF#;

   procedure Check (Condition : Boolean; Message : String) is
   begin
      Checks := Checks + 1;
      Assert (Condition, Message);
   end Check;

   procedure Shared (State : in out Engine; Reconnect : Boolean := False) is
      Message_Id : SMB.QWord;
      Expected : SMB.Engine.Request_Expectation;
      Status : SMB.Core_Status;
   begin
      Setup_Share
        (State, Message_Id, Expected, Status, Reconnect => Reconnect);
      Assert (Status = SMB.Ok, "share fixture");
   end Shared;

   --  A signed SET_INFO response, Last + 1 bytes long.
   function Resize_Response
     (Message_Id : SMB.QWord;
      Structure : SMB.Word := 2;
      Nt_Status : SMB.DWord := SMB.Success;
      Last : Natural := 65;
      Signed : Boolean := True;
      Async_Id : SMB.QWord := 0) return SMB.Bytes
   is
      Packet : SMB.Bytes (0 .. Last) := (others => 0);
   begin
      SMB.Wire.Initialize_Header (Packet, 17, Message_Id, Tree_Id, Session_Id);
      SMB.Wire.Put_U32 (Packet, 8, Nt_Status);
      SMB.Wire.Put_U32 (Packet, 16, (if Signed then 9 else 1));
      if Async_Id /= 0 then
         SMB.Wire.Put_U32 (Packet, 16, (if Signed then 11 else 3));
         SMB.Wire.Put_U64 (Packet, 32, Async_Id);
         SMB.Wire.Put_U16 (Packet, 14, 0);
      end if;
      if Last >= 65 then
         SMB.Wire.Put_U16 (Packet, 64, Structure);
      end if;
      if Signed then
         SMB.Wire.Sign (Packet, Key);
      end if;
      return Packet;
   end Resize_Response;

   function Error_Response
     (Message_Id : SMB.QWord; Nt_Status : SMB.DWord) return SMB.Bytes
   is
      Packet : SMB.Bytes (0 .. 72) := (others => 0);
   begin
      SMB.Wire.Initialize_Header (Packet, 17, Message_Id, Tree_Id, Session_Id);
      SMB.Wire.Put_U32 (Packet, 8, Nt_Status);
      SMB.Wire.Put_U32 (Packet, 16, 9);
      SMB.Wire.Put_U16 (Packet, 64, 9);
      SMB.Wire.Sign (Packet, Key);
      return Packet;
   end Error_Response;

   procedure Send
     (Value : in out Resize.Resize_Operation;
      State : in out Engine;
      Token : Handle;
      Size : SMB.QWord;
      Message_Id : out SMB.QWord;
      Label : String)
   is
      Output : SMB.Bytes (0 .. 255) := (others => 16#EE#);
      Used : Natural;
      Status : SMB.Core_Status;
   begin
      Resize.Prepare (Value, State, Token, Size, Output, Used, Status);
      Check
        (Status = SMB.Ok and then Used = Resize.Request_Size
         and then Resize.Stage_Of (Value) = Resize.Resize_Prepared,
         Label & ": prepared " & SMB.Core_Status'Image (Status));
      Message_Id := SMB.Wire.U64 (Output, 24);
      Resize.Send_Succeeded (Value, State, Status);
      Check
        (Status = SMB.Ok and then Resize.Stage_Of (Value) = Resize.Resize_Sent,
         Label & ": send acknowledgement");
   end Send;

   --  The request byte by byte, at both ends of the size range, in an
   --  output of exactly its size, and the builder alone.
   procedure Test_Request is
      State : Engine;
      Token : Handle;
      Status : SMB.Core_Status;
      Used : Natural;
   begin
      Shared (State);
      Open_Handle (State, Token, SMB.Engine.Write_Only);
      for Size of QWord_Values'(0, 16#0102_0304_0506_0708#, Largest) loop
         declare
            Output : SMB.Bytes (0 .. Resize.Request_Size - 1) :=
              (others => 16#EE#);
            Value : Resize.Resize_Operation;
            Expected : SMB.Bytes (0 .. 39) :=
              (33, 0, 1, 20, 8, 0, 0, 0, 96, 0, others => 0);
         begin
            Expected (16 .. 31) := File_Id;
            SMB.Wire.Put_U64 (Expected, 32, Size);
            Resize.Prepare (Value, State, Token, Size, Output, Used, Status);
            Check
              (Status = SMB.Ok and then Used = 104
               and then SMB.Wire.Verify_Signature (Output, Key)
               and then SMB.Wire.U16 (Output, 4) = 64
               and then SMB.Wire.U16 (Output, 6) = 1
               and then SMB.Wire.U16 (Output, 12) = 17
               and then SMB.Wire.U16 (Output, 14) = 1
               and then SMB.Wire.U32 (Output, 16) = 8
               and then SMB.Wire.U32 (Output, 36) = Tree_Id
               and then SMB.Wire.U64 (Output, 40) = Session_Id
               and then Output (64 .. 103) = Expected
               and then Resize.Snapshot_Of (Value).Size = Size,
               "SET_INFO request for size" & SMB.QWord'Image (Size));
            Resize.Abort_Resize (Value, State, Status);
            Shared (State, Reconnect => True);
            Open_Handle (State, Token, SMB.Engine.Write_Only);
         end;
      end loop;
      declare
         Output : SMB.Bytes (Natural'Last - 39 .. Natural'Last) :=
           (others => 16#EE#);
         Id : constant SMB.Bytes (0 .. 15) :=
           (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16);
      begin
         SMB.Core_Protocol.Build_End_Of_File
           (Id, 16#1122_3344_5566_7788#, Output, Used, Status);
         Check
           (Status = SMB.Ok and then Used = 40
            and then Output (Output'First + 16 .. Output'First + 31) = Id
            and then SMB.Wire.U64 (Output, 32) = 16#1122_3344_5566_7788#,
            "SET_INFO body at the top of the index range");
      end;
      declare
         Output : SMB.Bytes (0 .. 38);
      begin
         SMB.Core_Protocol.Build_End_Of_File (File_Id, 1, Output, Used, Status);
         Check (Status = SMB.Resource_Limit and then Used = 0,
                "SET_INFO body one byte short");
      end;
   end Test_Request;

   --  Whole operations: each writable access mode, an error status, an
   --  interim response, and every malformed response.
   procedure Test_Responses is
      State : Engine;
      Token : Handle;
      Status : SMB.Core_Status;
      Message_Id : SMB.QWord;
      Nt_Status : SMB.DWord;

      procedure Fresh (Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Write)
      is
      begin
         Shared (State);
         Open_Handle (State, Token, Mode);
      end Fresh;

      procedure Malformed
        (Wanted : SMB.Core_Status;
         Label : String;
         Structure : SMB.Word := 2;
         Last : Natural := 65;
         Signed : Boolean := True;
         Id_Shift : SMB.QWord := 0)
      is
         Value : Resize.Resize_Operation;
      begin
         Fresh;
         Send (Value, State, Token, 10, Message_Id, Label);
         Resize.Complete
           (Value, State,
            Resize_Response
              (Message_Id + Id_Shift, Structure, Last => Last,
               Signed => Signed),
            Nt_Status, Status);
         Check
           (Status = Wanted
            and then Resize.Stage_Of (Value) = Resize.Resize_Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected,
            Label & ": " & SMB.Core_Status'Image (Status));
      end Malformed;
   begin
      for Mode in SMB.Engine.Write_Only .. SMB.Engine.Read_Write loop
         declare
            Value : Resize.Resize_Operation;
            Label : constant String :=
              SMB.Engine.Access_Kind'Image (Mode) & " handle";
         begin
            Fresh (Mode);
            Send (Value, State, Token, 4096, Message_Id, Label);
            Resize.Complete
              (Value, State, Resize_Response (Message_Id), Nt_Status, Status);
            Check
              (Status = SMB.Ok and then Nt_Status = SMB.Success
               and then Resize.Stage_Of (Value) = Resize.Resize_Finished
               and then not SMB.Engine.Has_Pending_Request (State)
               and then not SMB.Engine.Has_Validated_Response (State)
               and then SMB.Engine.Current_Phase (State) =
                 SMB.Engine.Share_Connected,
               Label & ": resized " & SMB.Core_Status'Image (Status));
         end;
      end loop;
      declare
         Value : Resize.Resize_Operation;
      begin
         Fresh;
         Send (Value, State, Token, 1, Message_Id, "disk full");
         Resize.Complete
           (Value, State, Error_Response (Message_Id, 16#C000_007F#),
            Nt_Status, Status);
         Check
           (Status = SMB.Ok and then Nt_Status = 16#C000_007F#
            and then Resize.Stage_Of (Value) = Resize.Resize_Finished
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Share_Connected,
            "disk full keeps the connection");
      end;
      declare
         Value : Resize.Resize_Operation;
         Async_Id : constant SMB.QWord := 16#0102_0304_0506_0708#;
         Interim : SMB.Bytes (0 .. 71) := (others => 0);
         Is_Interim : Boolean;
      begin
         Send (Value, State, Token, 2, Message_Id, "interim response");
         SMB.Wire.Initialize_Header (Interim, 17, Message_Id, 0, Session_Id);
         SMB.Wire.Put_U32 (Interim, 8, SMB.Status_Pending);
         SMB.Wire.Put_U32 (Interim, 16, 3);
         SMB.Wire.Put_U64 (Interim, 32, Async_Id);
         SMB.Wire.Put_U16 (Interim, 64, 9);
         SMB.Engine.Inspect_Interim_Response
           (State, Interim, Is_Interim, Status);
         Check (Status = SMB.Ok and then Is_Interim,
                "STATUS_PENDING interim response to SET_INFO");
         Resize.Complete
           (Value, State, Resize_Response (Message_Id, Async_Id => Async_Id),
            Nt_Status, Status);
         Check
           (Status = SMB.Ok and then Nt_Status = SMB.Success
            and then SMB.Engine.Current_Async_Id (State) = 0,
            "async final response " & SMB.Core_Status'Image (Status));
      end;
      declare
         Value : Resize.Resize_Operation;
         Folder : Handle;
      begin
         Fresh;
         Open_Handle (State, Folder, SMB.Engine.Read_Write, Directory => True);
         Send (Value, State, Folder, 1, Message_Id, "directory handle");
         Resize.Complete
           (Value, State, Error_Response (Message_Id, 16#C000_000D#),
            Nt_Status, Status);
         Check
           (Status = SMB.Ok and then Nt_Status = 16#C000_000D#
            and then Resize.Snapshot_Of (Value).Directory
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Share_Connected,
            "a directory's STATUS_INVALID_PARAMETER keeps the connection");
      end;
      Malformed (SMB.Invalid_Protocol, "structure size 3", Structure => 3);
      Malformed (SMB.Invalid_Length, "no structure", Last => 64);
      Malformed (SMB.Signature_Error, "unsigned", Signed => False);
      Malformed (SMB.Correlation_Error, "another message's response",
                 Id_Shift => 1);
   end Test_Responses;

   --  Each call out of order, a read-only handle, a size past the range,
   --  short output, and aborts.
   procedure Test_Order is
      State : Engine;
      File, Reader, Gone : Handle;
      Output : SMB.Bytes (0 .. 255);
      Short : SMB.Bytes (0 .. Resize.Request_Size - 2);
      Used : Natural;
      Status : SMB.Core_Status;
      Nt_Status : SMB.DWord;
      Message_Id : SMB.QWord;

      procedure Rejected
        (Value : in out Resize.Resize_Operation;
         Token : Handle;
         Label : String;
         Wanted : SMB.Core_Status := SMB.Invalid_State_Status;
         Size : SMB.QWord := 1)
      is
         Before : constant Engine := State;
      begin
         Output := (others => 16#EE#);
         Used := 77;
         Resize.Prepare (Value, State, Token, Size, Output, Used, Status);
         Check
           (Status = Wanted and then Used = 0
            and then Output = (Output'Range => 0)
            and then SMB.Engine."=" (State, Before),
            Label & ": " & SMB.Core_Status'Image (Status));
      end Rejected;
   begin
      Shared (State);
      Open_Handle (State, File, SMB.Engine.Read_Write);
      Open_Handle (State, Reader, SMB.Engine.Read_Only);
      declare
         Idle, Read_Only_Handle, Too_Large, Stale : Resize.Resize_Operation;
      begin
         Rejected (Read_Only_Handle, Reader, "read-only handle");
         Rejected (Too_Large, File, "size 2**63", SMB.Invalid_Value,
                   Size => Largest + 1);
         Rejected (Too_Large, File, "largest size", SMB.Invalid_Value,
                   Size => SMB.QWord'Last);
         Rejected
           (Stale,
            (Owner => File.Owner, Epoch => File.Epoch + 1,
             Ticket => File.Ticket),
            "handle of another epoch");
         Resize.Send_Succeeded (Idle, State, Status);
         Check
           (Status = SMB.Invalid_State_Status
            and then Resize.Stage_Of (Idle) = Resize.Resize_Idle,
            "send acknowledgement before a preparation");
         Resize.Complete
           (Idle, State, Resize_Response (1), Nt_Status, Status);
         Check
           (Status = SMB.Invalid_State_Status and then Nt_Status = 0,
            "completion before a preparation");
         Resize.Abort_Resize (Idle, State, Status);
         Check
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Share_Connected,
            "abort before a preparation");
         Resize.Prepare (Idle, State, File, 1, Short, Used, Status);
         Check
           (Status = SMB.Resource_Limit and then Used = 0
            and then not SMB.Engine.Has_Pending_Request (State),
            "output one byte short");
      end;
      Open_Handle (State, Gone, SMB.Engine.Read_Write);
      Close_Open_Handle (State, Gone);
      declare
         Closed, Nothing : Resize.Resize_Operation;
      begin
         Rejected (Closed, Gone, "closed handle");
         Rejected (Nothing, SMB.Engine.Handle_Token'(others => 0),
                   "no handle");
      end;
      declare
         Prepared, Busy, Holding, Again : Resize.Resize_Operation;
      begin
         Resize.Prepare (Prepared, State, File, 5, Output, Used, Status);
         Message_Id := SMB.Wire.U64 (Output, 24);
         Rejected (Busy, File, "request in flight");
         Rejected (Prepared, File, "second preparation");
         Resize.Complete
           (Prepared, State, Resize_Response (Message_Id), Nt_Status, Status);
         Check
           (Status = SMB.Invalid_State_Status
            and then Resize.Stage_Of (Prepared) = Resize.Resize_Prepared,
            "completion before the send acknowledgement");
         Resize.Send_Succeeded (Prepared, State, Status);
         Resize.Send_Succeeded (Prepared, State, Status);
         Check
           (Status = SMB.Invalid_State_Status
            and then Resize.Stage_Of (Prepared) = Resize.Resize_Sent,
            "second send acknowledgement");
         SMB.Engine.Accept_Response
           (State, Resize_Response (Message_Id), Nt_Status, Status);
         Check (Status = SMB.Ok, "receipt held outside the operation");
         Rejected (Holding, File, "receipt held");
         Resize.Complete
           (Prepared, State, Resize_Response (Message_Id), Nt_Status, Status);
         Check
           (Status = SMB.Invalid_State_Status
            and then Resize.Stage_Of (Prepared) = Resize.Resize_Sent,
            "completion while a receipt is held");
         SMB.Engine.Discard_Response_Receipt (State, Status);
         Resize.Abort_Resize (Prepared, State, Status);
         Check
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Share_Connected,
            "abort after the response arrived");
         Send (Again, State, File, 6, Message_Id, "after a discarded receipt");
         Resize.Complete
           (Again, State, Resize_Response (Message_Id), Nt_Status, Status);
         Resize.Abort_Resize (Again, State, Status);
         Check
           (Status = SMB.Invalid_State_Status
            and then Resize.Stage_Of (Again) = Resize.Resize_Finished,
            "abort of a finished resize");
         Rejected (Again, File, "preparation of a finished resize");
      end;
      declare
         Prepared, Sent : Resize.Resize_Operation;
      begin
         Resize.Prepare (Prepared, State, File, 7, Output, Used, Status);
         Resize.Abort_Resize (Prepared, State, Status);
         Check
           (Status = SMB.Ok
            and then Resize.Stage_Of (Prepared) = Resize.Resize_Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected,
            "abort of a prepared resize");
         Shared (State, Reconnect => True);
         Open_Handle (State, File, SMB.Engine.Read_Write);
         Send (Sent, State, File, 8, Message_Id, "resize to abort");
         Resize.Abort_Resize (Sent, State, Status);
         Check
           (Status = SMB.Ok
            and then Resize.Stage_Of (Sent) = Resize.Resize_Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected,
            "abort of a sent resize");
         Resize.Complete
           (Sent, State, Resize_Response (Message_Id), Nt_Status, Status);
         Check (Status = SMB.Invalid_State_Status,
                "completion after the abort");
      end;
   end Test_Order;

   procedure Run is
   begin
      Test_Request;
      Test_Responses;
      Test_Order;
      Ada.Text_IO.Put_Line
        ("SET_INFO end-of-file operation:" & Natural'Image (Checks)
         & " checks passed");
   end Run;
end Core_Resize_Tests;
