package SMB.Core_Wire is
   pragma SPARK_Mode (On);
   use type SMB.DWord;

   Header_Size : constant := 64;

   type Command_Code is new SMB.Word;

   type Expected_Header is record
      Command       : Command_Code;
      Message_Id    : SMB.QWord;
      Tree_Id       : SMB.DWord;
      Session_Id    : SMB.QWord;
      Match_Tree    : Boolean;
      Match_Session : Boolean;
      Signed        : Boolean;
   end record;

   procedure Read_U16
     (Data : SMB.Bytes; Offset : Natural; Value : out SMB.Word;
      Status : out SMB.Core_Status)
   with Pre => Data'Length <= SMB.Maximum_Frame_Size;

   procedure Read_U32
     (Data : SMB.Bytes; Offset : Natural; Value : out SMB.DWord;
      Status : out SMB.Core_Status)
   with Pre => Data'Length <= SMB.Maximum_Frame_Size;

   procedure Read_U64
     (Data : SMB.Bytes; Offset : Natural; Value : out SMB.QWord;
      Status : out SMB.Core_Status)
   with Pre => Data'Length <= SMB.Maximum_Frame_Size;

   procedure Write_U16
     (Data : in out SMB.Bytes; Offset : Natural; Value : SMB.Word;
      Status : out SMB.Core_Status)
   with Pre => Data'Length <= SMB.Maximum_Frame_Size;

   procedure Write_U32
     (Data : in out SMB.Bytes; Offset : Natural; Value : SMB.DWord;
      Status : out SMB.Core_Status)
   with Pre => Data'Length <= SMB.Maximum_Frame_Size;

   procedure Write_U64
     (Data : in out SMB.Bytes; Offset : Natural; Value : SMB.QWord;
      Status : out SMB.Core_Status)
   with Pre => Data'Length <= SMB.Maximum_Frame_Size;

   procedure Initialize_Header
     (Data : in out SMB.Bytes;
      Command : Command_Code;
      Message_Id : SMB.QWord;
      Tree_Id : SMB.DWord;
      Session_Id : SMB.QWord;
      Credit : SMB.Word;
      Status : out SMB.Core_Status)
   with Pre => Data'Length <= SMB.Maximum_Frame_Size;

   function Header_Nt_Status (Data : SMB.Bytes) return SMB.DWord
   with Pre =>
     Data'Length >= Header_Size
     and then Data'Length <= SMB.Maximum_Frame_Size;

   procedure Validate_Header
     (Data : SMB.Bytes;
      Expected : Expected_Header;
      Nt_Status : out SMB.DWord;
      Status : out SMB.Core_Status)
   with Pre => Data'Length <= SMB.Maximum_Frame_Size,
     Post =>
       (if Status = SMB.Ok then
          Data'Length >= Header_Size
          and then Nt_Status = Header_Nt_Status (Data));

   procedure Sign
     (Data : in out SMB.Bytes;
      Key : SMB.Bytes;
      Status : out SMB.Core_Status)
   with Pre =>
     Data'Length <= SMB.Maximum_Frame_Size
     and Key'Length <= SMB.Maximum_Frame_Size;

   procedure Verify_Signature
     (Data : SMB.Bytes;
      Key : SMB.Bytes;
      Valid : out Boolean;
      Status : out SMB.Core_Status)
   with Pre =>
     Data'Length <= SMB.Maximum_Frame_Size
     and Key'Length <= SMB.Maximum_Frame_Size;
end SMB.Core_Wire;
