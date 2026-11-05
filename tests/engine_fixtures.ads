with SMB;
with SMB.Engine;
with SMB.Wire;

--  An engine taken through NEGOTIATE, SESSION_SETUP and TREE_CONNECT with
--  hand-built responses, and signed responses to its requests.
package Engine_Fixtures is
   use type SMB.Core_Status;

   Session_Id : constant SMB.QWord := 16#1234#;
   Tree_Id : constant SMB.DWord := 16#1020_3040#;
   Key : constant SMB.Bytes (0 .. 15) :=
     (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
   File_Id : constant SMB.Bytes (0 .. 15) := (others => 16#3C#);
   --  The server's final SPNEGO token, with the MIC for Key.
   Final_Token : constant SMB.Bytes (0 .. 28) :=
     (16#A1#, 16#1B#, 16#30#, 16#19#,
      16#A0#, 16#03#, 16#0A#, 16#01#, 0,
      16#A3#, 16#12#, 16#04#, 16#10#,
      1, 0, 0, 0, 16#0A#, 16#FB#, 16#34#, 16#90#,
      16#3A#, 16#3E#, 16#4E#, 16#54#, 0, 0, 0, 0);

   procedure Assert (Condition : Boolean; Message : String);

   --  How far Setup_Share takes the engine.
   type Fixture_Stage is (Connected, Negotiated, Keyed, Authenticated, Shared);

   --  Reconnect keeps the engine's owner, so its epoch moves past zero.
   procedure Setup_Share
     (State : in out SMB.Engine.Engine_State;
      Message_Id : out SMB.QWord;
      Expected : out SMB.Engine.Request_Expectation;
      Status : out SMB.Core_Status;
      Stop_At : Fixture_Stage := Shared;
      Session : SMB.QWord := Session_Id;
      Reconnect : Boolean := False;
      Maximum_Read, Maximum_Write : Natural := 65_536);

   --  A signed response to the pending request: header, structure size, and
   --  Body_Bytes written from offset 66.
   function Signed_Response
     (Command : SMB.Wire.Command_Code;
      Message_Id : SMB.QWord;
      Last : Natural;
      Structure : SMB.Word;
      Body_Bytes : SMB.Bytes := (1 .. 0 => 0);
      Session : SMB.QWord := Session_Id) return SMB.Bytes;

   --  CREATE File_Id and register it.
   procedure Open_Handle
     (State : in out SMB.Engine.Engine_State;
      Token : out SMB.Engine.Handle_Token;
      Access_Mode : SMB.Engine.Access_Kind := SMB.Engine.Read_Only;
      Directory : Boolean := False);

   procedure Close_Open_Handle
     (State : in out SMB.Engine.Engine_State;
      Token : SMB.Engine.Handle_Token);
end Engine_Fixtures;
