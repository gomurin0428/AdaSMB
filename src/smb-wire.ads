package SMB.Wire is
   pragma SPARK_Mode (Off);

   SMB2_Header_Size : constant := 64;

   subtype Command_Code is SMB.Word;
   Negotiate_Command       : constant Command_Code := 0;
   Session_Setup_Command   : constant Command_Code := 1;
   Logoff_Command          : constant Command_Code := 2;
   Tree_Connect_Command    : constant Command_Code := 3;
   Tree_Disconnect_Command : constant Command_Code := 4;
   Create_Command          : constant Command_Code := 5;
   Close_Command           : constant Command_Code := 6;
   Flush_Command           : constant Command_Code := 7;
   Read_Command            : constant Command_Code := 8;
   Write_Command           : constant Command_Code := 9;
   Query_Directory_Command : constant Command_Code := 14;
   Set_Info_Command        : constant Command_Code := 17;

   function U16 (Data : SMB.Bytes; Offset : Natural) return SMB.Word;
   function U32 (Data : SMB.Bytes; Offset : Natural) return SMB.DWord;
   function U64 (Data : SMB.Bytes; Offset : Natural) return SMB.QWord;
   procedure Put_U16 (Data : in out SMB.Bytes; Offset : Natural;
                      Value : SMB.Word);
   procedure Put_U32 (Data : in out SMB.Bytes; Offset : Natural;
                      Value : SMB.DWord);
   procedure Put_U64 (Data : in out SMB.Bytes; Offset : Natural;
                      Value : SMB.QWord);

   --  Initializes the header and clears the rest of the packet.
   procedure Initialize_Header
     (Data       : in out SMB.Bytes;
      Command    : Command_Code;
      Message_Id : SMB.QWord;
      Tree_Id    : SMB.DWord := 0;
      Session_Id : SMB.QWord := 0;
      Credit     : SMB.Word := 1);

   type Expected_Header is record
      Command    : Command_Code;
      Message_Id : SMB.QWord;
      Tree_Id    : SMB.DWord;
      Session_Id : SMB.QWord;
      Signed     : Boolean;
   end record;

   function Validate_Header
     (Data : SMB.Bytes; Expected : Expected_Header) return SMB.DWord;

   procedure Sign (Data : in out SMB.Bytes; Key : SMB.Bytes);
   function Verify_Signature (Data : SMB.Bytes; Key : SMB.Bytes) return Boolean;
end SMB.Wire;
