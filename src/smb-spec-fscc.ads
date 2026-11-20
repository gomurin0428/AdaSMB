with SMB.Spec.Encoding;

--  The file information structures of MS-FSCC that this client sends in an
--  SMB2 SET_INFO request or asks for in a QUERY_INFO request, with their
--  information classes (MS-FSCC 2.4). Each is a predicate on the bytes of
--  the structure, its fields read at their offsets as in SMB.Spec.SMB2.
package SMB.Spec.FSCC
  with Ghost, SPARK_Mode
is
   use type SMB.Byte;
   use type SMB.DWord;
   use type SMB.QWord;

   --  2.4.11: FileDispositionInformation, one byte, DeletePending: "set to
   --  1 to indicate that a file SHOULD be deleted when it is closed;
   --  otherwise, 0".
   File_Disposition_Information : constant SMB.Byte := 13;

   function Is_Disposition_Information
     (Info : SMB.Bytes; Delete_Pending : Boolean) return Boolean is
     (Info'Length = 1
      and then Info (Info'First) = (if Delete_Pending then 1 else 0));

   --  2.4.14: FileEndOfFileInformation, EndOfFile, "A 64-bit signed
   --  integer ... The value of this field MUST be greater than or equal to
   --  0".
   File_End_Of_File_Information : constant SMB.Byte := 20;
   Maximum_End_Of_File : constant SMB.QWord := 2 ** 63 - 1;

   function Is_End_Of_File_Information
     (Info : SMB.Bytes; End_Of_File : SMB.QWord) return Boolean is
     (Info'Length = 8
      and then End_Of_File <= Maximum_End_Of_File
      and then SMB.Spec.Encoding.LE64 (Info, 0) = End_Of_File)
   with Pre => Info'Length <= SMB.Maximum_Frame_Size;

   --  2.4.42.2: FILE_RENAME_INFORMATION_TYPE_2: ReplaceIfExists (1 byte,
   --  a Boolean, 2.1.8: "A sender MUST use any nonzero value to denote a
   --  TRUE", and "a zero value to denote a FALSE"), Reserved (7 bytes, "can
   --  contain any value and MUST be ignored"), RootDirectory (8 bytes, "For
   --  network operations, this value MUST always be zero"), FileNameLength
   --  (4 bytes), FileName, then Padding, whose length "MUST be the number of
   --  bytes required to make the size of this structure at least 24" and
   --  which "MAY be set to 0". The name's form (UTF-16, and the full path
   --  from the share's root that MS-SMB2 3.3.5.21.1 requires) is not stated
   --  here: the caller prepares the name as it does CREATE's.
   File_Rename_Information : constant SMB.Byte := 10;
   Rename_Fields_Size : constant := 20;
   Rename_Minimum_Size : constant := 24;

   function Rename_Information_Length (Name_Length : Natural) return Natural is
     (Natural'Max (Rename_Minimum_Size, Rename_Fields_Size + Name_Length))
   with Pre => Name_Length <= SMB.Maximum_Frame_Size;

   function Is_Rename_Information
     (Info : SMB.Bytes; Replace_If_Exists : Boolean; Name : SMB.Bytes)
      return Boolean is
     (Info'Length = Rename_Information_Length (Name'Length)
      and then (Info (Info'First) /= 0) = Replace_If_Exists
      and then SMB.Spec.Encoding.LE64 (Info, 8) = 0
      and then SMB.Spec.Encoding.LE32 (Info, 16) = SMB.DWord (Name'Length)
      and then
        (for all Index in 0 .. Name'Length - 1 =>
           Info (Info'First + Rename_Fields_Size + Index) =
             Name (Name'First + Index)))
   with Pre =>
     Info'Length <= SMB.Maximum_Frame_Size
     and then Name'Length <= SMB.Maximum_Frame_Size;

   --  2.4.34: FileNetworkOpenInformation, which a QUERY_INFO for the class
   --  asks for: 56 bytes.
   File_Network_Open_Information : constant SMB.Byte := 34;
   Network_Open_Information_Size : constant := 56;
end SMB.Spec.FSCC;
