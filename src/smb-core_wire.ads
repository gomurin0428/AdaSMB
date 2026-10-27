with Interfaces;

package SMB.Core_Wire is
   pragma SPARK_Mode (On);
   use type SMB.DWord;
   use type SMB.Byte;
   use type SMB.Word;
   use type SMB.QWord;

   Header_Size : constant := 64;

   type Command_Code is new SMB.Word;

   function Encoded_U16 (Data : SMB.Bytes; Offset : Natural) return SMB.Word is
     (SMB.Word (Data (Data'First + Offset))
      or Interfaces.Shift_Left
        (SMB.Word (Data (Data'First + Offset + 1)), 8))
   with Pre =>
     Data'Length <= SMB.Maximum_Frame_Size
     and then Offset <= Data'Length
     and then Data'Length - Offset >= 2;

   function U16_Byte (Value : SMB.Word; Position : Natural)
     return SMB.Byte is
     (if Position = 0
      then SMB.Byte (Value and 16#FF#)
      else SMB.Byte (Interfaces.Shift_Right (Value, 8)))
   with Pre => Position < 2;

   function Encoded_U32 (Data : SMB.Bytes; Offset : Natural) return SMB.DWord is
     (SMB.DWord (Data (Data'First + Offset))
      or Interfaces.Shift_Left
        (SMB.DWord (Data (Data'First + Offset + 1)), 8)
      or Interfaces.Shift_Left
        (SMB.DWord (Data (Data'First + Offset + 2)), 16)
      or Interfaces.Shift_Left
        (SMB.DWord (Data (Data'First + Offset + 3)), 24))
   with Pre =>
     Data'Length <= SMB.Maximum_Frame_Size
     and then Offset <= Data'Length
     and then Data'Length - Offset >= 4;

   function U32_Byte (Value : SMB.DWord; Position : Natural)
     return SMB.Byte is
     (SMB.Byte (Interfaces.Shift_Right (Value, Position * 8) and 16#FF#))
   with Pre => Position < 4;

   function U64_Byte (Value : SMB.QWord; Position : Natural)
     return SMB.Byte is
     (SMB.Byte (Interfaces.Shift_Right (Value, Position * 8) and 16#FF#))
   with Pre => Position < 8;

   function Encoded_U64 (Data : SMB.Bytes; Offset : Natural) return SMB.QWord is
     (SMB.QWord (Data (Data'First + Offset))
      or Interfaces.Shift_Left
        (SMB.QWord (Data (Data'First + Offset + 1)), 8)
      or Interfaces.Shift_Left
        (SMB.QWord (Data (Data'First + Offset + 2)), 16)
      or Interfaces.Shift_Left
        (SMB.QWord (Data (Data'First + Offset + 3)), 24)
      or Interfaces.Shift_Left
        (SMB.QWord (Data (Data'First + Offset + 4)), 32)
      or Interfaces.Shift_Left
        (SMB.QWord (Data (Data'First + Offset + 5)), 40)
      or Interfaces.Shift_Left
        (SMB.QWord (Data (Data'First + Offset + 6)), 48)
      or Interfaces.Shift_Left
        (SMB.QWord (Data (Data'First + Offset + 7)), 56))
   with Pre =>
     Data'Length <= SMB.Maximum_Frame_Size
     and then Offset <= Data'Length
     and then Data'Length - Offset >= 8;

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
   with Pre => Data'Length <= SMB.Maximum_Frame_Size,
     Post =>
       (if Status = SMB.Ok then Value = Encoded_U16 (Data, Offset)
        else Value = 0);

   procedure Read_U32
     (Data : SMB.Bytes; Offset : Natural; Value : out SMB.DWord;
      Status : out SMB.Core_Status)
   with Pre => Data'Length <= SMB.Maximum_Frame_Size,
     Post =>
       (if Status = SMB.Ok then Value = Encoded_U32 (Data, Offset)
        else Value = 0);

   procedure Read_U64
     (Data : SMB.Bytes; Offset : Natural; Value : out SMB.QWord;
      Status : out SMB.Core_Status)
   with Pre => Data'Length <= SMB.Maximum_Frame_Size,
     Post =>
       (if Status = SMB.Ok then
          Offset <= Data'Length
          and then Data'Length - Offset >= 8
          and then Value = Encoded_U64 (Data, Offset)
        else Value = 0);

   procedure Write_U16
     (Data : in out SMB.Bytes; Offset : Natural; Value : SMB.Word;
      Status : out SMB.Core_Status)
   with Pre => Data'Length <= SMB.Maximum_Frame_Size,
     Post =>
       (if Offset <= Data'Length and then Data'Length - Offset >= 2
        then Status = SMB.Ok)
       and then
       (if Status = SMB.Ok then
          Offset <= Data'Length
          and then Data'Length - Offset >= 2
          and then
          Encoded_U16 (Data, Offset) = Value
          and then
            (for all Index in Data'Range =>
               (if Index < Data'First + Offset
                  or else Index > Data'First + Offset + 1
                then Data (Index) = Data'Old (Index)))
        else Data = Data'Old);

   procedure Write_U32
     (Data : in out SMB.Bytes; Offset : Natural; Value : SMB.DWord;
      Status : out SMB.Core_Status)
   with Pre => Data'Length <= SMB.Maximum_Frame_Size,
     Post =>
       (if Offset <= Data'Length and then Data'Length - Offset >= 4
        then Status = SMB.Ok)
       and then
       (if Status = SMB.Ok then
          Offset <= Data'Length
          and then Data'Length - Offset >= 4
          and then
          Encoded_U32 (Data, Offset) = Value
          and then
            (for all Position in 0 .. 3 =>
               Data (Data'First + Offset + Position) =
                 U32_Byte (Value, Position))
          and then
            (for all Index in Data'Range =>
               (if Index < Data'First + Offset
                  or else Index > Data'First + Offset + 3
                then Data (Index) = Data'Old (Index)))
        else Data = Data'Old);

   procedure Write_U64
     (Data : in out SMB.Bytes; Offset : Natural; Value : SMB.QWord;
      Status : out SMB.Core_Status)
   with Pre => Data'Length <= SMB.Maximum_Frame_Size,
     Post =>
       (if Offset <= Data'Length and then Data'Length - Offset >= 8
        then Status = SMB.Ok)
       and then
       (if Status = SMB.Ok then
          Offset <= Data'Length
          and then Data'Length - Offset >= 8
          and then
          Encoded_U64 (Data, Offset) = Value
          and then
            (for all Byte_Index in 0 .. 7 =>
               Data (Data'First + Offset + Byte_Index) =
                 U64_Byte (Value, Byte_Index))
          and then
            (for all Index in Data'Range =>
               (if Index < Data'First + Offset
                  or else Index > Data'First + Offset + 7
                then Data (Index) = Data'Old (Index)))
        else Data = Data'Old);

   procedure Initialize_Header
     (Data : in out SMB.Bytes;
      Command : Command_Code;
      Message_Id : SMB.QWord;
      Tree_Id : SMB.DWord;
      Session_Id : SMB.QWord;
      Credit : SMB.Word;
      Status : out SMB.Core_Status)
   with Pre => Data'Length <= SMB.Maximum_Frame_Size,
     Post =>
       (if Data'Length >= Header_Size then Status = SMB.Ok)
       and then
       (if Status = SMB.Ok then
          Encoded_U16 (Data, 4) = Header_Size
          and then Encoded_U16 (Data, 6) = 1
          and then
          Encoded_U16 (Data, 12) = SMB.Word (Command)
          and then Encoded_U16 (Data, 14) = Credit
          and then Encoded_U64 (Data, 24) = Message_Id
          and then Encoded_U32 (Data, 36) = Tree_Id
          and then Encoded_U64 (Data, 40) = Session_Id
          and then Encoded_U32 (Data, 16) = 0
          and then Encoded_U32 (Data, 20) = 0
          and then
            (for all Index in Data'Range =>
               (if Index - Data'First >= Header_Size
                then Data (Index) = Data'Old (Index)
                else True)));

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
     and Key'Length <= SMB.Maximum_Frame_Size,
     Post =>
       (if Data'Length >= Header_Size and then Key'Length > 0
        then Status = SMB.Ok)
       and then
       (if Status = SMB.Ok then
          (for all Index in Data'Range =>
             (if Index < Data'First + 48
              then Data (Index) = Data'Old (Index)))
          and then
          (for all Index in Data'Range =>
             (if Index > Data'First + 63
              then Data (Index) = Data'Old (Index)))
        else Data = Data'Old);

   procedure Verify_Signature
     (Data : SMB.Bytes;
      Key : SMB.Bytes;
      Valid : out Boolean;
      Status : out SMB.Core_Status)
   with Pre =>
     Data'Length <= SMB.Maximum_Frame_Size
     and Key'Length <= SMB.Maximum_Frame_Size;
end SMB.Core_Wire;
