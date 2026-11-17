with Ada.Calendar;
with Ada.Calendar.Formatting;
with Ada.Text_IO;
with SMB;
with SMB.Client;
with SMB.Core_Protocol;
with SMB.Core_Query;
with SMB.Engine;
with SMB.Wire;
with Engine_Fixtures; use Engine_Fixtures;

package body Core_Query_Tests is
   use type SMB.Byte;
   use type SMB.Bytes;
   use type SMB.Core_Status;
   use type SMB.DWord;
   use type SMB.QWord;
   use type SMB.Word;
   use type SMB.Engine.Phase;
   use type SMB.Core_Query.Query_Stage;
   use type SMB.Core_Protocol.File_Information;

   package Query renames SMB.Core_Query;
   subtype Engine is SMB.Engine.Engine_State;
   subtype Handle is SMB.Engine.Handle_Token;

   Checks : Natural := 0;

   procedure Check (Condition : Boolean; Message : String) is
   begin
      Checks := Checks + 1;
      Assert (Condition, Message);
   end Check;

   --  A connected share.
   procedure Shared (State : in out Engine; Reconnect : Boolean := False) is
      Message_Id : SMB.QWord;
      Expected : SMB.Engine.Request_Expectation;
      Status : SMB.Core_Status;
   begin
      Setup_Share
        (State, Message_Id, Expected, Status, Reconnect => Reconnect);
      Assert (Status = SMB.Ok, "share fixture");
   end Shared;

   --  A FILE_NETWORK_OPEN_INFORMATION whose fields are told apart: every
   --  byte is distinct, and the reserved tail is not zero.
   function Sample return SMB.Bytes is
      Result : SMB.Bytes (0 .. 55);
   begin
      for Index in Result'Range loop
         Result (Index) := SMB.Byte (16#11# + Index);
      end loop;
      return Result;
   end Sample;

   Sample_Information : constant SMB.Core_Protocol.File_Information :=
     (Creation_Time => 16#1817_1615_1413_1211#,
      Last_Access_Time => 16#201F_1E1D_1C1B_1A19#,
      Last_Write_Time => 16#2827_2625_2423_2221#,
      Change_Time => 16#302F_2E2D_2C2B_2A29#,
      Allocation_Size => 16#3837_3635_3433_3231#,
      End_Of_File => 16#403F_3E3D_3C3B_3A39#,
      Attributes => 16#4443_4241#);

   Zero_Information : constant SMB.Core_Protocol.File_Information :=
     (others => <>);

   --  A signed QUERY_INFO response carrying Data at Offset, with Length in
   --  its OutputBufferLength.
   function Query_Response
     (Message_Id : SMB.QWord;
      Data : SMB.Bytes;
      Offset : Natural := 72;
      Length : SMB.DWord := 56;
      Structure : SMB.Word := 9;
      Nt_Status : SMB.DWord := SMB.Success;
      Trailing : Natural := 0;
      Signed : Boolean := True;
      Async_Id : SMB.QWord := 0) return SMB.Bytes
   is
      Last : constant Natural :=
        Natural'Max (71, Offset + Data'Length - 1) + Trailing;
      Packet : SMB.Bytes (0 .. Last) := (others => 0);
   begin
      SMB.Wire.Initialize_Header
        (Packet, 16, Message_Id, Tree_Id, Session_Id);
      SMB.Wire.Put_U32 (Packet, 8, Nt_Status);
      SMB.Wire.Put_U32 (Packet, 16, (if Signed then 9 else 1));
      if Async_Id /= 0 then
         --  An async final response: the async flag, the AsyncId in place
         --  of the TreeId, and no credit.
         SMB.Wire.Put_U32 (Packet, 16, (if Signed then 11 else 3));
         SMB.Wire.Put_U64 (Packet, 32, Async_Id);
         SMB.Wire.Put_U16 (Packet, 14, 0);
      end if;
      --  The data first, so that an offset inside the fixed part does not
      --  overwrite its fields.
      if Data'Length > 0 then
         Packet (Offset .. Offset + Data'Length - 1) := Data;
      end if;
      SMB.Wire.Put_U16 (Packet, 64, Structure);
      SMB.Wire.Put_U16 (Packet, 66, SMB.Word (Offset));
      SMB.Wire.Put_U32 (Packet, 68, Length);
      if Signed then
         SMB.Wire.Sign (Packet, Key);
      end if;
      return Packet;
   end Query_Response;

   function Error_Response
     (Message_Id : SMB.QWord; Nt_Status : SMB.DWord) return SMB.Bytes
   is
      Packet : SMB.Bytes (0 .. 72) := (others => 0);
   begin
      SMB.Wire.Initialize_Header
        (Packet, 16, Message_Id, Tree_Id, Session_Id);
      SMB.Wire.Put_U32 (Packet, 8, Nt_Status);
      SMB.Wire.Put_U32 (Packet, 16, 9);
      SMB.Wire.Put_U16 (Packet, 64, 9);
      SMB.Wire.Sign (Packet, Key);
      return Packet;
   end Error_Response;

   --  Prepares and acknowledges a query on Token; Message_Id is the
   --  request's.
   procedure Send
     (Value : in out Query.Query_Operation;
      State : in out Engine;
      Token : Handle;
      Message_Id : out SMB.QWord;
      Label : String)
   is
      Output : SMB.Bytes (0 .. 255) := (others => 16#EE#);
      Used : Natural;
      Status : SMB.Core_Status;
   begin
      Query.Prepare (Value, State, Token, Output, Used, Status);
      Check
        (Status = SMB.Ok and then Used = Query.Request_Size
         and then Query.Stage_Of (Value) = Query.Query_Prepared,
         Label & ": prepared " & SMB.Core_Status'Image (Status));
      Message_Id := SMB.Wire.U64 (Output, 24);
      Query.Send_Succeeded (Value, State, Status);
      Check
        (Status = SMB.Ok and then Query.Stage_Of (Value) = Query.Query_Sent,
         Label & ": send acknowledgement");
   end Send;

   --  The request, byte by byte, through each kind of handle.
   procedure Test_Request is
      State : Engine;
      Token : Handle;
      Output : SMB.Bytes (0 .. 255) := (others => 16#EE#);
      Used : Natural;
      Status : SMB.Core_Status;
      Value : Query.Query_Operation;
      Expected : constant SMB.Bytes (0 .. 40) :=
        (41, 0, 1, 34, 56, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         16#3C#, 16#3C#, 16#3C#, 16#3C#, 16#3C#, 16#3C#, 16#3C#, 16#3C#,
         16#3C#, 16#3C#, 16#3C#, 16#3C#, 16#3C#, 16#3C#, 16#3C#, 16#3C#,
         0);
   begin
      Shared (State);
      Open_Handle (State, Token, SMB.Engine.Read_Only);
      Query.Prepare (Value, State, Token, Output, Used, Status);
      Check
        (Status = SMB.Ok and then Used = 105
         and then SMB.Wire.Verify_Signature (Output (0 .. Used - 1), Key)
         and then SMB.Wire.U16 (Output, 4) = 64
         and then SMB.Wire.U16 (Output, 6) = 1
         and then SMB.Wire.U16 (Output, 12) = 16
         and then SMB.Wire.U16 (Output, 14) = 1
         and then SMB.Wire.U32 (Output, 16) = 8
         and then SMB.Wire.U32 (Output, 36) = Tree_Id
         and then SMB.Wire.U64 (Output, 40) = Session_Id
         and then Output (64 .. 104) = Expected
         and then Output (105 .. Output'Last) = (105 .. Output'Last => 0)
         and then SMB.Engine.Has_Pending_Request (State)
         and then Query.Snapshot_Of (Value).File_Id = File_Id
         and then Query.Result_Of (Value) = Zero_Information,
         "QUERY_INFO request bytes " & SMB.Core_Status'Image (Status));
   end Test_Request;

   --  An output of exactly the request's size, and a directory's handle.
   procedure Test_Exact_And_Directory is
      State : Engine;
      Folder : Handle;
      Output : SMB.Bytes (0 .. Query.Request_Size - 1) := (others => 16#EE#);
      Used : Natural;
      Status : SMB.Core_Status;
      Nt_Status : SMB.DWord;
      Value : Query.Query_Operation;
   begin
      Shared (State);
      Open_Handle (State, Folder, SMB.Engine.Read_Only, Directory => True);
      Query.Prepare (Value, State, Folder, Output, Used, Status);
      Check
        (Status = SMB.Ok and then Used = Output'Length
         and then SMB.Wire.Verify_Signature (Output, Key)
         and then Query.Snapshot_Of (Value).Directory,
         "directory query in an output of the request's size "
         & SMB.Core_Status'Image (Status));
      Query.Send_Succeeded (Value, State, Status);
      Query.Complete
        (Value, State, Query_Response (SMB.Wire.U64 (Output, 24), Sample),
         Nt_Status, Status);
      Check
        (Status = SMB.Ok and then Query.Result_Of (Value) = Sample_Information
         and then SMB.Engine.Current_Phase (State) =
           SMB.Engine.Share_Connected,
         "directory information " & SMB.Core_Status'Image (Status));
   end Test_Exact_And_Directory;

   --  A whole query on a handle of each access mode.
   procedure Test_Access_Modes is
      State : Engine;
      Status : SMB.Core_Status;
      Message_Id : SMB.QWord;
      Nt_Status : SMB.DWord;
   begin
      Shared (State);
      for Mode in SMB.Engine.Access_Kind loop
         declare
            Token : Handle;
            Value : Query.Query_Operation;
            Label : constant String :=
              SMB.Engine.Access_Kind'Image (Mode) & " handle";
         begin
            Open_Handle (State, Token, Mode);
            Send (Value, State, Token, Message_Id, Label);
            Query.Complete
              (Value, State, Query_Response (Message_Id, Sample), Nt_Status,
               Status);
            Check
              (Status = SMB.Ok and then Nt_Status = SMB.Success
               and then Query.Stage_Of (Value) = Query.Query_Finished
               and then Query.Result_Of (Value) = Sample_Information
               and then not SMB.Engine.Has_Pending_Request (State)
               and then not SMB.Engine.Has_Validated_Response (State)
               and then SMB.Engine.Current_Phase (State) =
                 SMB.Engine.Share_Connected,
               Label & ": information " & SMB.Core_Status'Image (Status));
         end;
      end loop;
   end Test_Access_Modes;

   --  Responses: an error status ends the query and keeps the connection;
   --  every malformed success response ends the connection.
   procedure Test_Responses is
      State : Engine;
      Token : Handle;
      Status : SMB.Core_Status;
      Message_Id : SMB.QWord;
      Nt_Status : SMB.DWord;

      procedure Fresh is
      begin
         Shared (State);
         Open_Handle (State, Token, SMB.Engine.Read_Write);
      end Fresh;

      --  A success response, built for the request, that must end the
      --  connection.
      procedure Malformed
        (Data : SMB.Bytes;
         Wanted : SMB.Core_Status;
         Label : String;
         Offset : Natural := 72;
         Length : SMB.DWord := 56;
         Structure : SMB.Word := 9;
         Signed : Boolean := True;
         Id_Shift : SMB.QWord := 0)
      is
         Value : Query.Query_Operation;
      begin
         Fresh;
         Send (Value, State, Token, Message_Id, Label);
         Query.Complete
           (Value, State,
            Query_Response
              (Message_Id + Id_Shift, Data, Offset, Length, Structure,
               Signed => Signed),
            Nt_Status, Status);
         Check
           (Status = Wanted
            and then Query.Stage_Of (Value) = Query.Query_Failed
            and then Query.Result_Of (Value) = Zero_Information
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected,
            Label & ": " & SMB.Core_Status'Image (Status));
      end Malformed;
   begin
      Fresh;
      declare
         Value : Query.Query_Operation;
      begin
         Send (Value, State, Token, Message_Id, "access denied");
         Query.Complete
           (Value, State, Error_Response (Message_Id, 16#C000_0022#),
            Nt_Status, Status);
         Check
           (Status = SMB.Ok and then Nt_Status = 16#C000_0022#
            and then Query.Stage_Of (Value) = Query.Query_Finished
            and then Query.Result_Of (Value) = Zero_Information
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Share_Connected
            and then not SMB.Engine.Has_Pending_Request (State),
            "access denied keeps the connection");
      end;
      declare
         Value : Query.Query_Operation;
         Async_Id : constant SMB.QWord := 16#0102_0304_0506_0708#;
         Interim : SMB.Bytes (0 .. 71) := (others => 0);
         Is_Interim : Boolean;
      begin
         Send (Value, State, Token, Message_Id, "interim response");
         SMB.Wire.Initialize_Header (Interim, 16, Message_Id, 0, Session_Id);
         SMB.Wire.Put_U32 (Interim, 8, SMB.Status_Pending);
         SMB.Wire.Put_U32 (Interim, 16, 3);
         SMB.Wire.Put_U64 (Interim, 32, Async_Id);
         SMB.Wire.Put_U16 (Interim, 64, 9);
         SMB.Engine.Inspect_Interim_Response
           (State, Interim, Is_Interim, Status);
         Check (Status = SMB.Ok and then Is_Interim,
                "STATUS_PENDING interim response to QUERY_INFO");
         Query.Complete
           (Value, State,
            Query_Response (Message_Id, Sample, Async_Id => Async_Id),
            Nt_Status, Status);
         Check
           (Status = SMB.Ok and then Nt_Status = SMB.Success
            and then Query.Result_Of (Value) = Sample_Information
            and then SMB.Engine.Current_Async_Id (State) = 0,
            "async final response " & SMB.Core_Status'Image (Status));
      end;
      declare
         Value : Query.Query_Operation;
      begin
         Send (Value, State, Token, Message_Id, "data further on");
         Query.Complete
           (Value, State,
            Query_Response (Message_Id, Sample, Offset => 80, Trailing => 7),
            Nt_Status, Status);
         Check
           (Status = SMB.Ok and then Query.Result_Of (Value) =
              Sample_Information,
            "data at offset 80, padding after it");
      end;

      Malformed (Sample (0 .. 47), SMB.Invalid_Protocol,
                 "48 bytes of information", Length => 48);
      Malformed (Sample & SMB.Bytes'(0 .. 7 => 0), SMB.Invalid_Protocol,
                 "64 bytes of information", Length => 64);
      Malformed ((1 .. 0 => 0), SMB.Invalid_Protocol, "no information",
                 Length => 0);
      Malformed (Sample, SMB.Invalid_Offset, "information inside the header",
                 Offset => 64);
      Malformed (Sample (0 .. 54), SMB.Invalid_Offset,
                 "information past the end");
      Malformed (Sample, SMB.Invalid_Protocol, "structure size 17",
                 Structure => 17);
      Malformed (Sample, SMB.Invalid_Protocol, "length past the I/O limit",
                 Length => 16#0001_0001#);
      Malformed (Sample, SMB.Signature_Error, "unsigned", Signed => False);
      Malformed (Sample, SMB.Correlation_Error, "another message's response",
                 Id_Shift => 1);
   end Test_Responses;

   --  Each call out of order, and aborts.
   procedure Test_Order is
      State : Engine;
      File, Gone : Handle;
      Output : SMB.Bytes (0 .. 255);
      Short : SMB.Bytes (0 .. Query.Request_Size - 2);
      Used : Natural;
      Status : SMB.Core_Status;
      Nt_Status : SMB.DWord;
      Message_Id : SMB.QWord;

      procedure Rejected
        (Value : in out Query.Query_Operation;
         Token : Handle;
         Label : String;
         Wanted : SMB.Core_Status := SMB.Invalid_State_Status)
      is
         Before : constant Engine := State;
      begin
         Output := (others => 16#EE#);
         Query.Prepare (Value, State, Token, Output, Used, Status);
         Check
           (Status = Wanted and then Used = 0
            and then Output = (Output'Range => 0)
            and then SMB.Engine."=" (State, Before),
            Label & ": " & SMB.Core_Status'Image (Status));
      end Rejected;
   begin
      Shared (State);
      Open_Handle (State, File);
      declare
         Idle : Query.Query_Operation;
      begin
         Query.Send_Succeeded (Idle, State, Status);
         Check
           (Status = SMB.Invalid_State_Status
            and then Query.Stage_Of (Idle) = Query.Query_Idle,
            "send acknowledgement before a preparation");
         Query.Complete
           (Idle, State, Query_Response (1, Sample), Nt_Status, Status);
         Check
           (Status = SMB.Invalid_State_Status and then Nt_Status = 0
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Share_Connected,
            "completion before a preparation");
         Query.Abort_Query (Idle, State, Status);
         Check
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Share_Connected,
            "abort before a preparation");
         Query.Prepare (Idle, State, File, Short, Used, Status);
         Check
           (Status = SMB.Resource_Limit and then Used = 0
            and then Query.Stage_Of (Idle) = Query.Query_Idle
            and then not SMB.Engine.Has_Pending_Request (State),
            "output one byte short");
      end;
      Open_Handle (State, Gone);
      Close_Open_Handle (State, Gone);
      declare
         Closed, Nothing, Stale : Query.Query_Operation;
      begin
         Rejected (Closed, Gone, "closed handle");
         Rejected (Nothing, SMB.Engine.Handle_Token'(others => 0),
                   "no handle");
         Rejected
           (Stale,
            (Owner => File.Owner, Epoch => File.Epoch + 1,
             Ticket => File.Ticket),
            "handle of another epoch");
      end;
      declare
         Prepared, Busy, Holding, Again : Query.Query_Operation;
      begin
         Query.Prepare (Prepared, State, File, Output, Used, Status);
         Message_Id := SMB.Wire.U64 (Output, 24);
         Rejected (Busy, File, "request in flight");
         Rejected (Prepared, File, "second preparation");
         Query.Complete
           (Prepared, State, Query_Response (Message_Id, Sample), Nt_Status,
            Status);
         Check
           (Status = SMB.Invalid_State_Status
            and then Query.Stage_Of (Prepared) = Query.Query_Prepared
            and then SMB.Engine.Has_Pending_Request (State),
            "completion before the send acknowledgement");
         Query.Send_Succeeded (Prepared, State, Status);
         Query.Send_Succeeded (Prepared, State, Status);
         Check
           (Status = SMB.Invalid_State_Status
            and then Query.Stage_Of (Prepared) = Query.Query_Sent,
            "second send acknowledgement");
         SMB.Engine.Accept_Response
           (State, Query_Response (Message_Id, Sample), Nt_Status, Status);
         Check (Status = SMB.Ok, "receipt held outside the operation");
         Rejected (Holding, File, "receipt held");
         Query.Complete
           (Prepared, State, Query_Response (Message_Id, Sample), Nt_Status,
            Status);
         Check
           (Status = SMB.Invalid_State_Status
            and then Query.Stage_Of (Prepared) = Query.Query_Sent,
            "completion while a receipt is held");
         SMB.Engine.Discard_Response_Receipt (State, Status);
         Query.Abort_Query (Prepared, State, Status);
         Check
           (Status = SMB.Invalid_State_Status
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Share_Connected,
            "abort after the response arrived");
         Send (Again, State, File, Message_Id, "after a discarded receipt");
         Query.Complete
           (Again, State, Query_Response (Message_Id, Sample), Nt_Status,
            Status);
         Query.Abort_Query (Again, State, Status);
         Check
           (Status = SMB.Invalid_State_Status
            and then Query.Stage_Of (Again) = Query.Query_Finished,
            "abort of a finished query");
         Rejected (Again, File, "preparation of a finished query");
      end;
      declare
         Prepared, Sent : Query.Query_Operation;
      begin
         Query.Prepare (Prepared, State, File, Output, Used, Status);
         Query.Abort_Query (Prepared, State, Status);
         Check
           (Status = SMB.Ok
            and then Query.Stage_Of (Prepared) = Query.Query_Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected
            and then not SMB.Engine.Has_Pending_Request (State),
            "abort of a prepared query");
         Shared (State, Reconnect => True);
         Open_Handle (State, File);
         Send (Sent, State, File, Message_Id, "query to abort");
         Query.Abort_Query (Sent, State, Status);
         Check
           (Status = SMB.Ok
            and then Query.Stage_Of (Sent) = Query.Query_Failed
            and then SMB.Engine.Current_Phase (State) =
              SMB.Engine.Disconnected,
            "abort of a sent query");
         Query.Complete
           (Sent, State, Query_Response (Message_Id, Sample), Nt_Status,
            Status);
         Check
           (Status = SMB.Invalid_State_Status,
            "completion after the abort");
      end;
   end Test_Order;

   --  Build_Query_Information, Network_Open_Information and the times of a
   --  directory entry, at the low and high ends of the index range.
   procedure Test_Protocol is
      Status : SMB.Core_Status;
      Used : Natural;
      Id : constant SMB.Bytes (0 .. 15) :=
        (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16);
   begin
      declare
         Output : SMB.Bytes (Natural'Last - 40 .. Natural'Last) :=
           (others => 16#EE#);
         First : constant Natural := Output'First;
      begin
         SMB.Core_Protocol.Build_Query_Information (Id, Output, Used, Status);
         Check
           (Status = SMB.Ok and then Used = 41
            and then SMB.Wire.U16 (Output, 0) = 41
            and then Output (First + 2) = 1
            and then Output (First + 3) = 34
            and then SMB.Wire.U32 (Output, 4) = 56
            and then Output (First + 8 .. First + 23) =
              (First + 8 .. First + 23 => 0)
            and then Output (First + 24 .. First + 39) = Id
            and then Output (First + 40) = 0,
            "QUERY_INFO body at the top of the index range");
      end;
      declare
         Output : SMB.Bytes (0 .. 39) := (others => 16#EE#);
      begin
         SMB.Core_Protocol.Build_Query_Information (Id, Output, Used, Status);
         Check
           (Status = SMB.Resource_Limit and then Used = 0,
            "QUERY_INFO body one byte short");
      end;
      declare
         Buffer : SMB.Bytes (Natural'Last - 59 .. Natural'Last) :=
           (others => 0);
      begin
         Buffer (Buffer'First + 4 .. Buffer'Last) := Sample;
         Check
           (SMB.Core_Protocol.Network_Open_Information (Buffer, 4) =
              Sample_Information,
            "information at the top of the index range");
      end;
      declare
         Buffer : SMB.Bytes (Natural'Last - 120 .. Natural'Last) :=
           (others => 0);
         Cursor : Natural := 8;
         Info : SMB.Core_Protocol.Directory_Info;
         Base : constant Natural := Buffer'First + 8;
      begin
         for Index in 0 .. 39 loop
            Buffer (Base + Index) := SMB.Byte (16#40# + Index);
         end loop;
         SMB.Wire.Put_U32 (Buffer, 8, 0);
         SMB.Wire.Put_U32 (Buffer, 8 + 60, 4);
         Buffer (Base + 64 .. Base + 103) := (others => 0);
         Buffer (Base + 104 .. Base + 107) := (16#61#, 0, 16#62#, 0);
         SMB.Core_Protocol.Parse_Directory_Entry
           (Buffer (Buffer'First .. Base + 107), Cursor, Info, Status);
         Check
           (Status = SMB.Ok
            and then Info.Creation_Time = 16#4F4E_4D4C_4B4A_4948#
            and then Info.Last_Access_Time = 16#5756_5554_5352_5150#
            and then Info.Last_Write_Time = 16#5F5E_5D5C_5B5A_5958#
            and then Info.Change_Time = 16#6766_6564_6362_6160#,
            "directory entry times " & SMB.Core_Status'Image (Status));
      end;
   end Test_Protocol;

   --  To_Time at both ends of Ada.Calendar's range, with a fraction of a
   --  second, and past either end.
   procedure Test_To_Time is
      use type Ada.Calendar.Time;

      function Image (Value : SMB.QWord) return String is
        (Ada.Calendar.Formatting.Image
           (SMB.Client.To_Time (Value), Time_Zone => 0));

      procedure Refused (Value : SMB.QWord; Label : String) is
         Ignored : Ada.Calendar.Time;
      begin
         Ignored := SMB.Client.To_Time (Value);
         Check (False, Label & ": converted");
      exception
         when Ada.Calendar.Time_Error =>
            Check (True, Label);
      end Refused;

      Unix_Epoch : constant SMB.QWord := 116_444_736_000_000_000;
   begin
      Check (Image (94_670_208_000_000_000) = "1901-01-01 00:00:00",
             "the first time Ada.Calendar holds");
      Check (Image (Unix_Epoch) = "1970-01-01 00:00:00", "the Unix epoch");
      Check (Image (125_962_992_000_000_000) = "2000-02-29 12:00:00",
             "a leap day");
      Check (Image (134_392_952_130_000_000) = "2026-11-16 09:33:33",
             "a recent time");
      Check (Image (252_139_391_990_000_000) = "2399-12-31 23:59:59",
             "the last second Ada.Calendar holds");
      Check
        (SMB.Client.To_Time (Unix_Epoch + 12_345_678)
           - SMB.Client.To_Time (Unix_Epoch) = 1.234_567_8,
         "a fraction of a second, to 100 nanoseconds");
      --  Every day of the range, each one day after the one before: with the
      --  ends right, that leaves no date wrong.
      declare
         First : constant SMB.QWord := 94_670_208_000_000_000;
         Day_Ticks : constant SMB.QWord := 864_000_000_000;
         Previous : Ada.Calendar.Time := SMB.Client.To_Time (First);
         Next : Ada.Calendar.Time;
         Apart : Boolean := True;
      begin
         for Day in 1 .. 182_255 loop
            Next := SMB.Client.To_Time (First + SMB.QWord (Day) * Day_Ticks);
            Apart := Apart and then Next - Previous = 86_400.0;
            Previous := Next;
         end loop;
         Check
           (Apart
            and then Ada.Calendar.Formatting.Image (Previous, Time_Zone => 0)
              = "2399-12-31 00:00:00",
            "182,256 days from 1901 to 2399, one day apart");
      end;
      Refused (0, "zero, a time the server does not keep");
      Refused (94_670_207_999_999_999, "just before 1901");
      Refused (252_139_392_000_000_000, "2400");
      Refused (252_783_072_000_000_000, "183,001 days on");
      Refused (SMB.QWord'Last, "the largest FILETIME");
   end Test_To_Time;

   procedure Run is
   begin
      Test_Protocol;
      Test_To_Time;
      Test_Request;
      Test_Exact_And_Directory;
      Test_Access_Modes;
      Test_Responses;
      Test_Order;
      Ada.Text_IO.Put_Line
        ("QUERY_INFO operation:" & Natural'Image (Checks)
         & " checks passed");
   end Run;
end Core_Query_Tests;
