with Ada.Text_IO;
with Ada.Unchecked_Deallocation;
with SMB;
with SMB.Core_Client;
with SMB.Core_Protocol;
with SMB.Core_Wire;
with SMB.Engine;
with SMB.Wire;
with Engine_Fixtures; use Engine_Fixtures;

package body Credit_Tests is
   use type SMB.Byte;
   use type SMB.Bytes;
   use type SMB.Core_Status;
   use type SMB.DWord;
   use type SMB.QWord;
   use type SMB.Word;
   use type SMB.Engine.Engine_State;
   use type SMB.Core_Client.Transfer_Stage;

   subtype Engine is SMB.Engine.Engine_State;
   subtype Handle is SMB.Engine.Handle_Token;
   Read_Chunk : constant := SMB.Core_Protocol.Maximum_Read_Chunk;
   Write_Chunk : constant := SMB.Core_Protocol.Maximum_Write_Chunk;
   Credit : constant := SMB.Core_Protocol.Maximum_IO_Chunk;

   type Bytes_Access is access SMB.Bytes;
   procedure Free is new Ada.Unchecked_Deallocation (SMB.Bytes, Bytes_Access);
   type Transfer_Access is access SMB.Core_Client.Transfer;
   procedure Free is new Ada.Unchecked_Deallocation
     (SMB.Core_Client.Transfer, Transfer_Access);

   Checks : Natural := 0;

   procedure Check (Condition : Boolean; Message : String) is
   begin
      Checks := Checks + 1;
      Assert (Condition, Message);
   end Check;

   procedure Shared
     (State : in out Engine;
      Large_MTU : Boolean;
      Credits : SMB.Word;
      Maximum_Read : Natural := 65_536;
      Stop_At : Fixture_Stage := Shared;
      Maximum_Write : Natural := 65_536)
   is
      Message_Id : SMB.QWord;
      Expected : SMB.Engine.Request_Expectation;
      Status : SMB.Core_Status;
   begin
      Setup_Share
        (State, Message_Id, Expected, Status, Stop_At => Stop_At,
         Maximum_Read => Maximum_Read, Maximum_Write => Maximum_Write,
         Large_MTU => Large_MTU, Credits => Credits);
      Assert (Status = SMB.Ok, "credit fixture");
   end Shared;

   --  A signed response with no body beyond its StructureSize, granting
   --  Grant credits.
   function Granting
     (Command : SMB.Wire.Command_Code;
      Message_Id : SMB.QWord;
      Grant : SMB.Word;
      Structure : SMB.Word) return SMB.Bytes
   is
      Packet : SMB.Bytes (0 .. 123) := (others => 0);
   begin
      SMB.Wire.Initialize_Header
        (Packet, Command, Message_Id, Tree_Id, Session_Id, Credit => Grant);
      SMB.Wire.Put_U32 (Packet, 16, 9);
      SMB.Wire.Put_U16 (Packet, 64, Structure);
      SMB.Wire.Sign (Packet, Key);
      return Packet;
   end Granting;

   --  A signed READ response carrying Length bytes of the pattern from
   --  Offset on, granting Grant credits. On the heap: it can be large.
   function Read_Response
     (Message_Id : SMB.QWord;
      Offset : Natural;
      Length : Natural;
      Grant : SMB.Word) return Bytes_Access
   is
      Packet : constant Bytes_Access := new SMB.Bytes (0 .. 79 + Length);
   begin
      Packet.all := (others => 0);
      SMB.Wire.Initialize_Header
        (Packet.all, 8, Message_Id, Tree_Id, Session_Id, Credit => Grant);
      SMB.Wire.Put_U32 (Packet.all, 16, 9);
      SMB.Wire.Put_U16 (Packet.all, 64, 17);
      Packet (66) := 80;
      SMB.Wire.Put_U32 (Packet.all, 68, SMB.DWord (Length));
      for Index in 0 .. Length - 1 loop
         Packet (80 + Index) := SMB.Byte ((Offset + Index) mod 251);
      end loop;
      SMB.Wire.Sign (Packet.all, Key);
      return Packet;
   end Read_Response;

   --  A signed WRITE response for Count bytes, granting Grant credits.
   function Write_Response
     (Message_Id : SMB.QWord;
      Count : Natural;
      Grant : SMB.Word) return SMB.Bytes
   is
      Packet : SMB.Bytes (0 .. 79) := (others => 0);
   begin
      SMB.Wire.Initialize_Header
        (Packet, 9, Message_Id, Tree_Id, Session_Id, Credit => Grant);
      SMB.Wire.Put_U32 (Packet, 16, 9);
      SMB.Wire.Put_U16 (Packet, 64, 17);
      SMB.Wire.Put_U32 (Packet, 68, SMB.DWord (Count));
      SMB.Wire.Sign (Packet, Key);
      return Packet;
   end Write_Response;

   --  The engine's count from the connection on: one credit for the
   --  NEGOTIATE, each request spends its charge, each response adds what
   --  it grants, at most Maximum_Credits.
   procedure Test_Counting is
      State : Engine;
      Message_Id : SMB.QWord;
      Expected : SMB.Engine.Request_Expectation;
      Status : SMB.Core_Status;
      Nt_Status : SMB.DWord;
   begin
      Shared (State, True, 1, Stop_At => Connected);
      Check (SMB.Engine.Current_Credits (State) = 1
             and then not SMB.Engine.Has_Large_MTU (State),
             "one credit on connection");
      Shared (State, True, 10, Stop_At => Negotiated);
      Check (SMB.Engine.Current_Credits (State) = 10
             and then SMB.Engine.Has_Large_MTU (State),
             "the NEGOTIATE spends one, its response grants ten");
      Shared (State, False, 10, Stop_At => Negotiated);
      Check (SMB.Engine.Current_Credits (State) = 10
             and then not SMB.Engine.Has_Large_MTU (State),
             "no LARGE_MTU without the capability");
      Shared (State, True, 40);
      --  NEGOTIATE, two SESSION_SETUPs and the TREE_CONNECT, each 1 - 1 + 40.
      Check (SMB.Engine.Current_Credits (State) = 157,
             "four exchanges at forty credits each:"
             & Natural'Image (SMB.Engine.Current_Credits (State)));
      declare
         Copy : Engine := State;
      begin
         SMB.Engine.Invalidate (Copy, Status);
         Check (SMB.Engine.Current_Credits (Copy) = 0
                and then not SMB.Engine.Has_Large_MTU (Copy),
                "Invalidate drops the credits and LARGE_MTU");
         SMB.Engine.Mark_Connected (Copy, Status);
         Check (Status = SMB.Ok and then SMB.Engine.Current_Credits (Copy) = 1,
                "a new connection starts at one credit");
      end;

      --  A one-credit request records charge 1 and asks for enough to reach
      --  the target; a response's grant is added.
      SMB.Engine.Begin_Request
        (State, 17, True, True, Message_Id, Expected, Status);
      Check (Status = SMB.Ok and then Expected.Credit_Charge = 1
             and then Expected.Credit_Request = 1
             and then SMB.Engine.Current_Credits (State) = 156,
             "one credit spent, the target already met");
      SMB.Engine.Accept_Response
        (State, Granting (17, Message_Id, 7, 2), Nt_Status, Status);
      SMB.Engine.Discard_Response_Receipt (State, Status);
      Check (SMB.Engine.Current_Credits (State) = 163,
             "a grant of seven is added");
      SMB.Engine.Begin_Request
        (State, 17, True, True, Message_Id, Expected, Status);
      SMB.Engine.Accept_Response
        (State, Granting (17, Message_Id, SMB.Word'Last, 2), Nt_Status,
         Status);
      SMB.Engine.Discard_Response_Receipt (State, Status);
      Check (SMB.Engine.Current_Credits (State) = SMB.Engine.Maximum_Credits,
             "the count stops at the maximum");

      --  An error response grants credits too.
      Shared (State, True, 1);
      SMB.Engine.Begin_Request
        (State, 17, True, True, Message_Id, Expected, Status);
      Check (Expected.Credit_Request = 33,
             "with no credits left, the request asks for its charge and the"
             & " target");
      declare
         Packet : SMB.Bytes (0 .. 72) := (others => 0);
      begin
         SMB.Wire.Initialize_Header
           (Packet, 17, Message_Id, Tree_Id, Session_Id, Credit => 5);
         SMB.Wire.Put_U32 (Packet, 8, 16#C000_0022#);
         SMB.Wire.Put_U32 (Packet, 16, 9);
         SMB.Wire.Put_U16 (Packet, 64, 9);
         SMB.Wire.Sign (Packet, Key);
         SMB.Engine.Accept_Response (State, Packet, Nt_Status, Status);
         SMB.Engine.Discard_Response_Receipt (State, Status);
         Check (Nt_Status = 16#C000_0022#
                and then SMB.Engine.Current_Credits (State) = 5,
                "an error response's grant is added");
      end;

      --  An interim response grants credits; the async final grants none.
      declare
         Interim : SMB.Bytes (0 .. 71) := (others => 0);
         Final : SMB.Bytes (0 .. 65) := (others => 0);
         Is_Interim : Boolean;
         Before : Natural;
      begin
         SMB.Engine.Begin_Request
           (State, 17, True, True, Message_Id, Expected, Status);
         Before := SMB.Engine.Current_Credits (State);
         SMB.Wire.Initialize_Header
           (Interim, 17, Message_Id, 0, Session_Id, Credit => 3);
         SMB.Wire.Put_U32 (Interim, 8, SMB.Status_Pending);
         SMB.Wire.Put_U32 (Interim, 16, 3);
         SMB.Wire.Put_U64 (Interim, 32, 16#0A0B#);
         SMB.Wire.Put_U16 (Interim, 64, 9);
         SMB.Engine.Inspect_Interim_Response
           (State, Interim, Is_Interim, Status);
         Check (Status = SMB.Ok and then Is_Interim
                and then SMB.Engine.Current_Credits (State) = Before + 3,
                "an interim response's grant is added");
         SMB.Wire.Initialize_Header
           (Final, 17, Message_Id, Tree_Id, Session_Id, Credit => 0);
         SMB.Wire.Put_U32 (Final, 16, 11);
         SMB.Wire.Put_U64 (Final, 32, 16#0A0B#);
         SMB.Wire.Put_U16 (Final, 64, 2);
         SMB.Wire.Sign (Final, Key);
         SMB.Engine.Accept_Response (State, Final, Nt_Status, Status);
         Check (Status = SMB.Ok
                and then SMB.Engine.Current_Credits (State) = Before + 3,
                "the async final response grants none");
         SMB.Engine.Discard_Response_Receipt (State, Status);
      end;
   end Test_Counting;

   --  The charge of a READ or WRITE: one per 64 KiB with LARGE_MTU and
   --  credits on hand, and one, with requests of at most 64 KiB, without.
   procedure Test_Charges is
      State : Engine;
      Message_Id : SMB.QWord;
      Expected : SMB.Engine.Request_Expectation;
      Status : SMB.Core_Status;

      procedure Refused
        (Command : SMB.Core_Wire.Command_Code;
         Amount : Natural;
         Wanted : SMB.Core_Status;
         Label : String)
      is
         Before : constant Engine := State;
      begin
         SMB.Engine.Begin_Request
           (State, Command, True, True, Message_Id, Expected, Status,
            Request_Amount => Amount);
         Check (Status = Wanted and then State = Before,
                Label & ": " & SMB.Core_Status'Image (Status));
      end Refused;
   begin
      Check (SMB.Core_Protocol.Credit_Charge (0) = 1
             and then SMB.Core_Protocol.Credit_Charge (1) = 1
             and then SMB.Core_Protocol.Credit_Charge (Credit) = 1
             and then SMB.Core_Protocol.Credit_Charge (Credit + 1) = 2
             and then SMB.Core_Protocol.Credit_Charge (Read_Chunk) = 15,
             "credit charges at the 64 KiB boundaries");

      --  The message id after a one-credit request goes up by one, after
      --  the fifteen-credit READ by fifteen.
      Shared (State, True, 40, Maximum_Read => Read_Chunk);
      declare
         Nt_Status : SMB.DWord;
         First, Read_Id : SMB.QWord;
      begin
         SMB.Engine.Begin_Request
           (State, 17, True, True, First, Expected, Status);
         SMB.Engine.Accept_Response
           (State, Granting (17, First, 1, 2), Nt_Status, Status);
         SMB.Engine.Discard_Response_Receipt (State, Status);
         SMB.Engine.Begin_Request
           (State, 8, True, True, Read_Id, Expected, Status,
            Request_Amount => Read_Chunk);
         Check (Status = SMB.Ok and then Read_Id = First + 1
                and then Expected.Credit_Charge = 15
                and then Expected.Credit_Request = 15
                and then SMB.Engine.Current_Credits (State) = 157 - 15,
                "a 960 KiB READ takes fifteen credits");
         SMB.Engine.Accept_Response
           (State, Granting (8, Read_Id, 15, 17), Nt_Status, Status);
         SMB.Engine.Discard_Response_Receipt (State, Status);
         SMB.Engine.Begin_Request
           (State, 17, True, True, Message_Id, Expected, Status);
         Check (Status = SMB.Ok and then Message_Id = Read_Id + 15,
                "and fifteen message ids");
      end;

      Shared (State, True, 1, Maximum_Read => Read_Chunk);
      Check (SMB.Engine.Current_Credits (State) = 1
             and then SMB.Engine.Current_Read_Chunk (State) = Credit,
             "one credit on hand: READs of 64 KiB");
      Refused (8, Credit + 1, SMB.Resource_Limit,
               "a two-credit READ with one credit");
      SMB.Engine.Begin_Request
        (State, 8, True, True, Message_Id, Expected, Status,
         Request_Amount => Credit);
      Check (Status = SMB.Ok and then Expected.Credit_Charge = 1
             and then Expected.Credit_Request = 33,
             "a one-credit READ with none left asks for 1 + 32");

      Shared (State, False, 40);
      Check (SMB.Engine.Current_Read_Chunk (State) = Credit,
             "without LARGE_MTU: READs of 64 KiB");
      Refused (8, Credit + 1, SMB.Invalid_Value,
               "a READ past 64 KiB without LARGE_MTU");
      SMB.Engine.Begin_Request
        (State, 8, True, True, Message_Id, Expected, Status,
         Request_Amount => Credit);
      Check (Status = SMB.Ok and then Expected.Credit_Charge = 1
             and then Expected.Credit_Request = 1,
             "without LARGE_MTU: one credit, and one asked for");

      Shared (State, True, 40, Maximum_Read => Read_Chunk);
      Refused (8, Read_Chunk + 1, SMB.Invalid_Value,
               "a READ past fifteen credits");
      Refused (8, 0, SMB.Invalid_Value, "a READ of nothing");

      --  A WRITE the same way.
      Shared (State, True, 40, Maximum_Write => Write_Chunk);
      SMB.Engine.Begin_Request
        (State, 9, True, True, Message_Id, Expected, Status,
         Request_Amount => Write_Chunk);
      Check (Status = SMB.Ok and then Expected.Credit_Charge = 15
             and then Expected.Credit_Request = 15
             and then SMB.Engine.Current_Credits (State) = 157 - 15,
             "a 960 KiB WRITE takes fifteen credits");
      Shared (State, True, 40, Maximum_Write => Write_Chunk);
      SMB.Engine.Begin_Request
        (State, 9, True, True, Message_Id, Expected, Status,
         Request_Amount => 2 * Credit + 1);
      Check (Status = SMB.Ok and then Expected.Credit_Charge = 3,
             "a WRITE of 128 KiB and a byte takes three");
      Shared (State, True, 40, Maximum_Write => Write_Chunk);
      Refused (9, Write_Chunk + 1, SMB.Invalid_Value,
               "a WRITE past fifteen credits");
      Refused (9, 0, SMB.Invalid_Value, "a WRITE of nothing");
      Shared (State, True, 1, Maximum_Write => Write_Chunk);
      Refused (9, Credit + 1, SMB.Resource_Limit,
               "a two-credit WRITE with one credit");
      Shared (State, False, 40);
      Refused (9, Credit + 1, SMB.Invalid_Value,
               "a WRITE past 64 KiB without LARGE_MTU");
      SMB.Engine.Begin_Request
        (State, 9, True, True, Message_Id, Expected, Status,
         Request_Amount => Credit);
      Check (Status = SMB.Ok and then Expected.Credit_Charge = 1
             and then Expected.Credit_Request = 1,
             "without LARGE_MTU: a 64 KiB WRITE takes one credit");
   end Test_Charges;

   --  Current_Read_Chunk against the credits on hand and the negotiated
   --  limit, and that limit's clamp in Parse_Response.
   procedure Test_Read_Chunk is
      State : Engine;
      Info : SMB.Core_Protocol.Response_Info;
      Status : SMB.Core_Status;

      function Negotiate_Response
        (Capabilities, Max_Read : SMB.DWord;
         Max_Write : SMB.DWord := 8_388_608) return SMB.Bytes
      is
         Packet : SMB.Bytes (0 .. 127) := (others => 0);
      begin
         SMB.Wire.Initialize_Header (Packet, 0, 0, 0, 0);
         SMB.Wire.Put_U32 (Packet, 16, 1);
         Packet (64) := 65;
         Packet (66) := 1;
         Packet (68) := 16#10#;
         Packet (69) := 2;
         SMB.Wire.Put_U32 (Packet, 88, Capabilities);
         SMB.Wire.Put_U32 (Packet, 96, Max_Read);
         SMB.Wire.Put_U32 (Packet, 100, Max_Write);
         return Packet;
      end Negotiate_Response;
   begin
      --  One credit, then a response that grants three.
      Shared (State, True, 1, Maximum_Read => Read_Chunk);
      declare
         Message_Id : SMB.QWord;
         Expected : SMB.Engine.Request_Expectation;
         Nt_Status : SMB.DWord;
      begin
         SMB.Engine.Begin_Request
           (State, 17, True, True, Message_Id, Expected, Status);
         SMB.Engine.Accept_Response
           (State, Granting (17, Message_Id, 3, 2), Nt_Status, Status);
         SMB.Engine.Discard_Response_Receipt (State, Status);
      end;
      Check (SMB.Engine.Current_Read_Chunk (State) = 3 * Credit,
             "three credits: READs of 192 KiB:"
             & Natural'Image (SMB.Engine.Current_Read_Chunk (State)));
      Shared (State, True, 40, Maximum_Read => 100_000);
      Check (SMB.Engine.Current_Read_Chunk (State) = 100_000,
             "the negotiated limit below the credits");
      Shared (State, True, 40, Maximum_Read => Read_Chunk);
      Check (SMB.Engine.Current_Read_Chunk (State) = Read_Chunk,
             "fifteen credits at most");

      --  Current_Write_Chunk the same way, with MaxWriteSize.
      Shared (State, True, 1, Maximum_Write => Write_Chunk);
      Check (SMB.Engine.Current_Write_Chunk (State) = Credit,
             "one credit: WRITEs of 64 KiB");
      --  Four exchanges granting two each leave five credits.
      Shared (State, True, 2, Maximum_Write => Write_Chunk);
      Check (SMB.Engine.Current_Credits (State) = 5
             and then SMB.Engine.Current_Write_Chunk (State) = 5 * Credit,
             "five credits: WRITEs of 320 KiB:"
             & Natural'Image (SMB.Engine.Current_Write_Chunk (State)));
      Shared (State, True, 40, Maximum_Write => 100_000);
      Check (SMB.Engine.Current_Write_Chunk (State) = 100_000,
             "the negotiated WRITE limit below the credits");
      Shared (State, True, 40, Maximum_Write => Write_Chunk);
      Check (SMB.Engine.Current_Write_Chunk (State) = Write_Chunk,
             "WRITEs: fifteen credits at most");
      Shared (State, False, 40);
      Check (SMB.Engine.Current_Write_Chunk (State) = Credit,
             "without LARGE_MTU: WRITEs of 64 KiB");
      SMB.Engine.Invalidate (State, Status);
      Check (SMB.Engine.Current_Write_Chunk (State) = 0,
             "no WRITEs after Invalidate");

      SMB.Core_Protocol.Parse_Response
        (Negotiate_Response (4, 8_388_608), 0, SMB.Success, Info, Status);
      Check (Status = SMB.Ok and then Info.Large_MTU
             and then Info.Max_Read = Read_Chunk
             and then Info.Max_Write = Write_Chunk,
             "LARGE_MTU: MaxReadSize and MaxWriteSize clamped to fifteen"
             & " credits");
      SMB.Core_Protocol.Parse_Response
        (Negotiate_Response (0, 8_388_608), 0, SMB.Success, Info, Status);
      Check (Status = SMB.Ok and then not Info.Large_MTU
             and then Info.Max_Read = Credit
             and then Info.Max_Write = Credit,
             "no LARGE_MTU bit: MaxReadSize and MaxWriteSize clamped to"
             & " 64 KiB");
      SMB.Core_Protocol.Parse_Response
        (Negotiate_Response (4, 8_388_608, 100_000), 0, SMB.Success, Info,
         Status);
      Check (Status = SMB.Ok and then Info.Max_Write = 100_000,
             "LARGE_MTU: a MaxWriteSize below the clamp is kept");
      SMB.Core_Protocol.Parse_Response
        (Negotiate_Response (16#FFFF_FF83#, 8_388_608), 0, SMB.Success, Info,
         Status);
      Check (Status = SMB.Ok and then not Info.Large_MTU
             and then Info.Max_Write = Credit,
             "every other capability a 2.1 server may claim: no LARGE_MTU");
   end Test_Read_Chunk;

   --  A 1 MiB READ through SMB.Core_Client: 960 KiB on fifteen credits, then
   --  64 KiB on one, the message ids fifteen apart; and in 64 KiB pieces
   --  without LARGE_MTU.
   procedure Test_Large_Read (Large_MTU : Boolean) is
      Total : constant := 1_048_576;
      Label : constant String :=
        (if Large_MTU then "LARGE_MTU READ" else "READ without LARGE_MTU");
      State : Engine;
      Token : Handle;
      --  1 MiB: on the heap, as the facade keeps it.
      Value : Transfer_Access := new SMB.Core_Client.Transfer (Total);
      Output : SMB.Bytes (0 .. 255);
      Used, Completed : Natural;
      Status : SMB.Core_Status;
      Nt_Status : SMB.DWord;
      Requests : Natural := 0;
      Previous_Id : SMB.QWord := 0;
      Result : Bytes_Access := new SMB.Bytes (0 .. Total - 1);
   begin
      Shared (State, Large_MTU, 40,
              Maximum_Read => (if Large_MTU then Read_Chunk else Credit));
      Open_Handle (State, Token, SMB.Engine.Read_Only);
      SMB.Core_Client.Start_Read (Value.all, State, Token, 0, Total, Status);
      Check (Status = SMB.Ok, Label & ": start");
      while SMB.Core_Client.Transfer_Stage_Of (Value.all) /=
        SMB.Core_Client.Transfer_Finished
      loop
         SMB.Core_Client.Prepare_Next (Value.all, State, Output, Used, Status);
         declare
            Offset : constant Natural :=
              SMB.Core_Client.Transfer_Completed_Of (Value.all);
            Amount : constant Natural :=
              Natural (SMB.Wire.U32 (Output, 64 + 4));
            Charge : constant SMB.Word := SMB.Wire.U16 (Output, 6);
            Request : constant SMB.Word := SMB.Wire.U16 (Output, 14);
            Message_Id : constant SMB.QWord := SMB.Wire.U64 (Output, 24);
            Expected_Amount : constant Natural :=
              (if Large_MTU and then Requests = 0 then Read_Chunk
               elsif Large_MTU then Total - Read_Chunk
               else Credit);
            Response : Bytes_Access;
         begin
            Check
              (Status = SMB.Ok
               and then SMB.Wire.Verify_Signature (Output (0 .. Used - 1), Key)
               and then Amount = Expected_Amount
               and then Charge = SMB.Word
                 (SMB.Core_Protocol.Credit_Charge (Amount))
               and then Request =
                 SMB.Engine.Credit_Request_For
                   (Large_MTU, SMB.Engine.Current_Credits (State), Charge)
               and then (Requests = 0
                         or else Message_Id =
                           Previous_Id
                           + (if Large_MTU and then Requests = 1 then 15
                              else 1)),
               Label & ": request" & Natural'Image (Requests + 1)
               & " of" & Natural'Image (Amount) & " bytes, charge"
               & SMB.Word'Image (Charge));
            Previous_Id := Message_Id;
            Requests := Requests + 1;
            SMB.Core_Client.Transfer_Send_Succeeded (Value.all, State, Status);
            Response := Read_Response (Message_Id, Offset, Amount, 15);
            SMB.Core_Client.Complete_Read
              (Value.all, State, Response.all, Nt_Status, Status);
            Free (Response);
            Check (Status = SMB.Ok and then Nt_Status = SMB.Success,
                   Label & ": response " & SMB.Core_Status'Image (Status));
         end;
      end loop;
      SMB.Core_Client.Copy_Read_Result (Value.all, Result.all, Completed, Status);
      declare
         Matches : Boolean := Status = SMB.Ok and then Completed = Total;
      begin
         for Index in 0 .. Total - 1 loop
            Matches := Matches
              and then Result (Index) = SMB.Byte (Index mod 251);
         end loop;
         Check (Matches and then Requests = (if Large_MTU then 2 else 16),
                Label & ": 1 MiB in" & Natural'Image (Requests)
                & " requests");
      end;
      Free (Result);
      Free (Value);
   end Test_Large_Read;

   --  A READ of 512 KiB that starts with one credit and gets 4, 2 and 1
   --  credits back: requests of 64, 256, 128 and 64 KiB.
   procedure Test_Small_Grants is
      Total : constant := 524_288;
      Grants : constant array (1 .. 4) of SMB.Word := (4, 2, 1, 1);
      Amounts : constant array (1 .. 4) of Natural :=
        (Credit, 4 * Credit, 2 * Credit, Credit);
      State : Engine;
      Token : Handle;
      Value : Transfer_Access := new SMB.Core_Client.Transfer (Total);
      Output : SMB.Bytes (0 .. 255);
      Used : Natural;
      Status : SMB.Core_Status;
      Nt_Status : SMB.DWord;
      Requests : Natural := 0;
   begin
      Shared (State, True, 1, Maximum_Read => Read_Chunk);
      Open_Handle (State, Token, SMB.Engine.Read_Only);
      SMB.Core_Client.Start_Read (Value.all, State, Token, 0, Total, Status);
      while SMB.Core_Client.Transfer_Stage_Of (Value.all) /=
        SMB.Core_Client.Transfer_Finished
        and then Requests < Amounts'Last
      loop
         Requests := Requests + 1;
         SMB.Core_Client.Prepare_Next (Value.all, State, Output, Used, Status);
         declare
            Offset : constant Natural :=
              SMB.Core_Client.Transfer_Completed_Of (Value.all);
            Amount : constant Natural :=
              Natural (SMB.Wire.U32 (Output, 64 + 4));
            Response : Bytes_Access;
         begin
            Check (Status = SMB.Ok and then Amount = Amounts (Requests),
                   "small grants: request" & Natural'Image (Requests)
                   & " of" & Natural'Image (Amount) & " bytes");
            SMB.Core_Client.Transfer_Send_Succeeded (Value.all, State, Status);
            Response := Read_Response
              (SMB.Wire.U64 (Output, 24), Offset, Amount, Grants (Requests));
            SMB.Core_Client.Complete_Read
              (Value.all, State, Response.all, Nt_Status, Status);
            Free (Response);
         end;
      end loop;
      Check (SMB.Core_Client.Transfer_Stage_Of (Value.all) =
               SMB.Core_Client.Transfer_Finished
             and then Requests = 4,
             "small grants: 512 KiB in four requests");
      Free (Value);
   end Test_Small_Grants;

   --  A 1 MiB WRITE through SMB.Core_Client: 960 KiB on fifteen credits,
   --  then 64 KiB on one, each request carrying its part of the data; and in
   --  64 KiB pieces without LARGE_MTU. Grants (when given) are the credits
   --  each response grants, and with them the requests' sizes.
   procedure Test_Large_Write
     (Large_MTU : Boolean;
      Label : String;
      Total : Natural := 1_048_576;
      Credits : SMB.Word := 40;
      Grants : SMB.Bytes := (1 .. 0 => 0);
      Amounts : SMB.Bytes := (1 .. 0 => 0))
   is
      State : Engine;
      Token : Handle;
      Data : Bytes_Access := new SMB.Bytes (0 .. Total - 1);
      Value : Transfer_Access := new SMB.Core_Client.Transfer (Total);
      Output : Bytes_Access :=
        new SMB.Bytes (0 .. SMB.Core_Wire.Header_Size + 48 + Write_Chunk - 1);
      Used : Natural;
      Status : SMB.Core_Status;
      Nt_Status : SMB.DWord;
      Requests : Natural := 0;
      Previous_Id : SMB.QWord := 0;
      Previous_Charge : SMB.Word := 0;
   begin
      for Index in Data'Range loop
         Data (Index) := SMB.Byte ((Index * 7 + 3) mod 253);
      end loop;
      Shared (State, Large_MTU, Credits,
              Maximum_Write => (if Large_MTU then Write_Chunk else Credit));
      Open_Handle (State, Token, SMB.Engine.Read_Write);
      SMB.Core_Client.Start_Write (Value.all, State, Token, 0, Data.all, Status);
      Check (Status = SMB.Ok, Label & ": start");
      while SMB.Core_Client.Transfer_Stage_Of (Value.all) /=
        SMB.Core_Client.Transfer_Finished
        and then Requests < 32
      loop
         SMB.Core_Client.Prepare_Next
           (Value.all, State, Output.all, Used, Status);
         declare
            Offset : constant Natural :=
              SMB.Core_Client.Transfer_Completed_Of (Value.all);
            Amount : constant Natural :=
              Natural (SMB.Wire.U32 (Output.all, 64 + 4));
            Charge : constant SMB.Word := SMB.Wire.U16 (Output.all, 6);
            Request : constant SMB.Word := SMB.Wire.U16 (Output.all, 14);
            Message_Id : constant SMB.QWord := SMB.Wire.U64 (Output.all, 24);
            Expected_Amount : constant Natural :=
              (if Amounts'Length > 0
               then Natural (Amounts (Amounts'First + Requests)) * Credit
               elsif Large_MTU and then Requests = 0 then Write_Chunk
               elsif Large_MTU then Total - Write_Chunk
               else Credit);
            Carried : Boolean :=
              Status = SMB.Ok
              and then Used = SMB.Core_Wire.Header_Size + 48 + Amount
              and then Amount <= Total - Offset
              and then SMB.Wire.U64 (Output.all, 64 + 8) = SMB.QWord (Offset);
         begin
            if Carried then
               for Index in 0 .. Amount - 1 loop
                  Carried := Carried
                    and then Output (SMB.Core_Wire.Header_Size + 48 + Index) =
                      Data (Offset + Index);
               end loop;
            end if;
            Check
              (Carried
               and then SMB.Wire.U16 (Output.all, 12) = 9
               and then SMB.Wire.Verify_Signature
                 (Output (0 .. Used - 1), Key)
               and then Amount = Expected_Amount
               and then Charge =
                 (if Large_MTU
                  then SMB.Word (SMB.Core_Protocol.Credit_Charge (Amount))
                  else 1)
               and then Request =
                 SMB.Engine.Credit_Request_For
                   (Large_MTU, SMB.Engine.Current_Credits (State), Charge)
               and then (Requests = 0
                         or else Message_Id =
                           Previous_Id + SMB.QWord (Previous_Charge)),
               Label & ": request" & Natural'Image (Requests + 1)
               & " of" & Natural'Image (Amount) & " bytes, charge"
               & SMB.Word'Image (Charge));
            Previous_Id := Message_Id;
            Previous_Charge := Charge;
            SMB.Core_Client.Transfer_Send_Succeeded (Value.all, State, Status);
            SMB.Core_Client.Complete_Write
              (Value.all, State,
               Write_Response
                 (Message_Id, Amount,
                  (if Grants'Length > 0
                   then SMB.Word (Grants (Grants'First + Requests))
                   else 15)),
               Nt_Status, Status);
            Requests := Requests + 1;
            Check (Status = SMB.Ok and then Nt_Status = SMB.Success,
                   Label & ": response " & SMB.Core_Status'Image (Status));
         end;
      end loop;
      Check (SMB.Core_Client.Transfer_Stage_Of (Value.all) =
               SMB.Core_Client.Transfer_Finished
             and then SMB.Core_Client.Transfer_Completed_Of (Value.all) = Total
             and then Requests =
               (if Amounts'Length > 0 then Amounts'Length
                elsif Large_MTU then 2 else 16),
             Label & ": all of it in" & Natural'Image (Requests)
             & " requests");
      Free (Output);
      Free (Value);
      Free (Data);
   end Test_Large_Write;

   procedure Run is
   begin
      Test_Counting;
      Test_Charges;
      Test_Read_Chunk;
      Test_Large_Read (True);
      Test_Large_Read (False);
      Test_Small_Grants;
      Test_Large_Write (True, "LARGE_MTU WRITE");
      Test_Large_Write (False, "WRITE without LARGE_MTU");
      --  512 KiB from one credit, getting 4, 2, 1 and 1 back: WRITEs of
      --  64, 256, 128 and 64 KiB.
      Test_Large_Write
        (True, "WRITE with small grants", Total => 524_288, Credits => 1,
         Grants => (4, 2, 1, 1), Amounts => (1, 4, 2, 1));
      Ada.Text_IO.Put_Line
        ("credits and multi-credit READs and WRITEs:" & Natural'Image (Checks)
         & " checks passed");
   end Run;
end Credit_Tests;
